package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
	"github.com/codefionn/msgtausch/msgtausch-srv/proxy"
)

var (
	testDuration = flag.Duration("duration", 10*time.Minute, "How long to run the test")
	message      = flag.String("message", "msgtausch-longterm", "Message payload to send")
	interval     = flag.Duration("interval", 0, "Delay between messages (default no delay)")
	connections  = flag.Int("connections", 16, "Number of simultaneous proxy connections")
)

var (
	errRetry        = errors.New("retry")
	errContextAbort = errors.New("context abort")
)

func main() {
	flag.Parse()

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run() error {
	log.SetOutput(io.Discard)
	logger.SetLevel(logger.ERROR)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if *testDuration > 0 {
		durationTimer := time.NewTimer(*testDuration)
		defer durationTimer.Stop()
		go func() {
			<-durationTimer.C
			fmt.Println("duration elapsed, stopping")
			cancel()
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case sig := <-sigCh:
			fmt.Printf("received %s, stopping\n", sig)
			cancel()
		case <-ctx.Done():
		}
	}()

	serverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("failed to start server listener: %w", err)
	}
	defer serverLn.Close()

	var processedMessages atomic.Int64
	go runEchoServer(ctx, serverLn, &processedMessages)

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("failed to start proxy listener: %w", err)
	}
	defer proxyLn.Close()

	cfg := buildProxyConfig(proxyLn.Addr().String(), *testDuration)
	proxyInstance := proxy.NewProxy(cfg)
	defer proxyInstance.Close()

	proxyErr := make(chan error, 1)
	go func() {
		if err := proxyInstance.StartWithListener(proxyLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			proxyErr <- err
		}
		close(proxyErr)
	}()

	select {
	case err := <-proxyErr:
		if err != nil {
			return fmt.Errorf("proxy startup failed: %w", err)
		}
	case <-time.After(200 * time.Millisecond):
	}

	start := time.Now()
	sent, received, err := runClient(ctx, proxyLn.Addr().String(), serverLn.Addr().String(), *message, *interval, *connections)
	if err != nil {
		return fmt.Errorf("client encountered an error: %w", err)
	}
	cancel()

	elapsed := time.Since(start)

	fmt.Println("test finished")
	fmt.Printf("elapsed: %s\n", elapsed)
	fmt.Printf("messages sent: %d\n", sent)
	fmt.Printf("acknowledgements received: %d\n", received)
	fmt.Printf("server processed messages: %d\n", processedMessages.Load())

	return nil
}

func buildProxyConfig(listenAddr string, duration time.Duration) *config.Config {
	timeoutSeconds := durationToSeconds(duration, 24*time.Hour)
	return &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: listenAddr,
				Enabled:       true,
			},
		},
		TimeoutSeconds: timeoutSeconds,
	}
}

func durationToSeconds(d, fallback time.Duration) int {
	if d <= 0 {
		d = fallback
	}
	secs := int(d / time.Second)
	if secs < 1 {
		secs = 1
	}
	return secs
}

func runEchoServer(ctx context.Context, ln net.Listener, counter *atomic.Int64) {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if isRetryableAcceptError(err) {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			fmt.Fprintf(os.Stderr, "server accept error: %v\n", err)
			return
		}
		go handleEchoConnection(ctx, conn, counter)
	}
}

func handleEchoConnection(ctx context.Context, conn net.Conn, counter *atomic.Int64) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	for {
		if ctx.Err() != nil {
			return
		}

		line, err := readEchoLine(ctx, conn, reader)
		if err != nil {
			if errors.Is(err, errRetry) {
				continue
			}
			if errors.Is(err, errContextAbort) {
				return
			}
			fmt.Fprintf(os.Stderr, "server read error: %v\n", err)
			return
		}

		if err := writeEchoLine(ctx, conn, writer, line); err != nil {
			if errors.Is(err, errRetry) {
				continue
			}
			if errors.Is(err, errContextAbort) {
				return
			}
			fmt.Fprintf(os.Stderr, "server write error: %v\n", err)
			return
		}
		counter.Add(1)
	}
}

func runClient(ctx context.Context, proxyAddr, targetAddr, msg string, delay time.Duration, connectionCount int) (sent, received int64, err error) {
	if connectionCount < 1 {
		connectionCount = 1
	}

	clientCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var totalSent atomic.Int64
	var totalReceived atomic.Int64

	var wg sync.WaitGroup
	errCh := make(chan error, connectionCount)

	for i := 0; i < connectionCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sent, received, err := runConnection(clientCtx, proxyAddr, targetAddr, msg, delay)
			totalSent.Add(sent)
			totalReceived.Add(received)
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				cancel()
			}
		}()
	}

	wg.Wait()
	close(errCh)

	var firstErr error
	for err := range errCh {
		if firstErr == nil {
			firstErr = err
		}
	}

	return totalSent.Load(), totalReceived.Load(), firstErr
}
func runConnection(ctx context.Context, proxyAddr, targetAddr, msg string, delay time.Duration) (sent, received int64, err error) {
	conn, rw, err := connectToProxy(ctx, proxyAddr, targetAddr)
	if err != nil {
		if errors.Is(err, errContextAbort) {
			return 0, 0, nil
		}
		return 0, 0, err
	}
	defer conn.Close()

	cancelClose := closeOnContext(ctx, conn)
	defer cancelClose()

	ticker := createTicker(delay)
	defer stopTicker(ticker)

	payload := msg + "\n"

	for {
		if ctx.Err() != nil {
			return sent, received, nil
		}

		if err := writeMessage(ctx, conn, rw, payload); err != nil {
			if errors.Is(err, errRetry) {
				continue
			}
			if errors.Is(err, errContextAbort) {
				return sent, received, nil
			}
			return sent, received, err
		}
		sent++

		if err := readAcknowledgement(ctx, conn, rw.Reader); err != nil {
			if errors.Is(err, errRetry) {
				continue
			}
			if errors.Is(err, errContextAbort) {
				return sent, received, nil
			}
			return sent, received, err
		}
		received++

		if err := waitForDelay(ctx, ticker); err != nil {
			if errors.Is(err, errRetry) {
				continue
			}
			if errors.Is(err, errContextAbort) {
				return sent, received, nil
			}
			return sent, received, err
		}
	}
}

func connectToProxy(ctx context.Context, proxyAddr, targetAddr string) (net.Conn, *bufio.ReadWriter, error) {
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("dial proxy: %w", err)
	}

	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	if err := sendConnectRequest(ctx, conn, rw, targetAddr); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return conn, rw, nil
}

func sendConnectRequest(ctx context.Context, conn net.Conn, rw *bufio.ReadWriter, targetAddr string) error {
	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return wrapConnError(ctx, err, "set write deadline", false)
	}
	requestLine := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
	if _, err := rw.WriteString(requestLine); err != nil {
		return wrapConnError(ctx, err, "write connect request", true)
	}
	if err := rw.Flush(); err != nil {
		return wrapConnError(ctx, err, "flush connect request", true)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return wrapConnError(ctx, err, "set read deadline", false)
	}
	resp, err := http.ReadResponse(rw.Reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return wrapConnError(ctx, err, "read connect response", false)
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy connect failed: %s", resp.Status)
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return wrapConnError(ctx, err, "clear deadlines", false)
	}

	return nil
}

func writeMessage(ctx context.Context, conn net.Conn, rw *bufio.ReadWriter, payload string) error {
	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return wrapConnError(ctx, err, "set write deadline", false)
	}
	if _, err := rw.WriteString(payload); err != nil {
		return wrapConnError(ctx, err, "write payload", true)
	}
	if err := rw.Flush(); err != nil {
		return wrapConnError(ctx, err, "flush payload", true)
	}
	return nil
}

func readAcknowledgement(ctx context.Context, conn net.Conn, reader *bufio.Reader) error {
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return wrapConnError(ctx, err, "set read deadline", false)
	}
	if _, err := reader.ReadString('\n'); err != nil {
		if errors.Is(err, io.EOF) {
			return errContextAbort
		}
		return wrapConnError(ctx, err, "read acknowledgement", true)
	}
	return nil
}

func readEchoLine(ctx context.Context, conn net.Conn, reader *bufio.Reader) (string, error) {
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return "", wrapConnError(ctx, err, "set read deadline", false)
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) {
			return "", errContextAbort
		}
		return "", wrapConnError(ctx, err, "read", true)
	}
	return line, nil
}

func writeEchoLine(ctx context.Context, conn net.Conn, writer *bufio.Writer, line string) error {
	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return wrapConnError(ctx, err, "set write deadline", false)
	}
	if _, err := writer.WriteString(line); err != nil {
		return wrapConnError(ctx, err, "write response", true)
	}
	if err := writer.Flush(); err != nil {
		return wrapConnError(ctx, err, "flush response", true)
	}
	return nil
}

func createTicker(delay time.Duration) *time.Ticker {
	if delay <= 0 {
		return nil
	}
	return time.NewTicker(delay)
}

func stopTicker(t *time.Ticker) {
	if t != nil {
		t.Stop()
	}
}

func waitForDelay(ctx context.Context, ticker *time.Ticker) error {
	if ticker == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return errContextAbort
	case <-ticker.C:
		return nil
	}
}

func closeOnContext(ctx context.Context, conn net.Conn) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	return func() {
		close(done)
	}
}

func wrapConnError(ctx context.Context, err error, action string, allowTimeout bool) error {
	if err == nil {
		return nil
	}
	if shouldIgnoreConnectionError(ctx, err) {
		return errContextAbort
	}
	if allowTimeout {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			if ctx.Err() != nil {
				return errContextAbort
			}
			return errRetry
		}
	}
	return fmt.Errorf("%s: %w", action, err)
}

func isRetryableAcceptError(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.EAGAIN)
}

func shouldIgnoreConnectionError(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if ctx.Err() == nil {
		return false
	}
	return errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled)
}
