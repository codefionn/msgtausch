package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
	"github.com/codefionn/msgtausch/msgtausch-srv/proxy"
)

var (
	connections        = flag.Int("connections", 512, "Number of concurrent connections to maintain")
	requestsPerConn    = flag.Int("requests", 100, "Number of requests per connection")
	timeout            = flag.Duration("timeout", 2*time.Minute, "Overall test timeout")
	reopenProbability  = flag.Float64("reopenProbability", 0.05, "Probability of reopening a connection before a request")
	largePayloadSize   = flag.Int("largePayloadSize", 512*1024, "Size of large payloads in bytes")
	largePayloadChance = flag.Float64("largePayloadChance", 0.1, "Probability a request will use a large payload")
	writeDeadline      = flag.Duration("writeDeadline", 10*time.Second, "Write deadline per request")
	readDeadline       = flag.Duration("readDeadline", 10*time.Second, "Read deadline per request")
)

type latencyRecorder struct {
	mu     sync.Mutex
	values []time.Duration
}

func (lr *latencyRecorder) add(d time.Duration) {
	lr.mu.Lock()
	lr.values = append(lr.values, d)
	lr.mu.Unlock()
}

func (lr *latencyRecorder) percentile(p float64) time.Duration {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	if len(lr.values) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(lr.values))
	copy(sorted, lr.values)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	rank := int(math.Ceil(p*float64(len(sorted)))) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}

func (lr *latencyRecorder) count() int {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	return len(lr.values)
}

func main() {
	flag.Parse()

	if *connections < 1 {
		*connections = 1
	}
	if *requestsPerConn < 1 {
		*requestsPerConn = 1
	}
	*reopenProbability = clampProbability(*reopenProbability)
	*largePayloadChance = clampProbability(*largePayloadChance)

	log.SetOutput(io.Discard)
	logger.SetLevel(logger.ERROR)

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "test failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	serverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("start server: %w", err)
	}
	defer serverLn.Close()

	go runEchoServer(ctx, serverLn)

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("start proxy listener: %w", err)
	}
	defer proxyLn.Close()

	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: proxyLn.Addr().String(),
				Enabled:       true,
			},
		},
		TimeoutSeconds: timeoutSeconds(*timeout),
	}

	p := proxy.NewProxy(cfg)
	defer p.Close()
	proxyErr := make(chan error, 1)
	go func() {
		if err := p.StartWithListener(proxyLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			proxyErr <- err
		}
		close(proxyErr)
	}()

	select {
	case err := <-proxyErr:
		if err != nil {
			return fmt.Errorf("proxy start failed: %w", err)
		}
	case <-time.After(200 * time.Millisecond):
	}

	results := latencyRecorder{}
	var reopenCount atomic.Int64
	totalRequests := int64(*connections * *requestsPerConn)
	errCh := make(chan error, *connections)

	smallPayload := []byte("ping\n")
	largePayload := buildPayload(*largePayloadSize)

	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < *connections; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(time.Now().UnixNano()))
			if err := runClient(ctx, proxyLn.Addr().String(), serverLn.Addr().String(), smallPayload, largePayload, rng, &results, &reopenCount); err != nil {
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
	if err := <-errCh; err != nil {
		return err
	}

	elapsed := time.Since(start)

	p999 := results.percentile(0.999)
	p9999 := results.percentile(0.9999)

	fmt.Printf("Connections: %d, Requests per connection: %d (total %d)\n", *connections, *requestsPerConn, totalRequests)
	fmt.Printf("Reopened connections: %d\n", reopenCount.Load())
	fmt.Printf("Duration: %s, Samples: %d\n", elapsed, results.count())
	fmt.Printf("Latency p99.9: %s\n", p999)
	fmt.Printf("Latency p99.99: %s\n", p9999)

	return nil
}

func runClient(ctx context.Context, proxyAddr, targetAddr string, smallPayload, largePayload []byte, rng *rand.Rand, lr *latencyRecorder, reopenCount *atomic.Int64) error {
	conn, rw, err := connectThroughProxy(ctx, proxyAddr, targetAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	var readBuf []byte
	for i := 0; i < *requestsPerConn; i++ {
		if ctx.Err() != nil {
			return nil
		}

		if rng.Float64() < *reopenProbability {
			conn.Close()
			conn, rw, err = connectThroughProxy(ctx, proxyAddr, targetAddr)
			if err != nil {
				return fmt.Errorf("reconnect: %w", err)
			}
			reopenCount.Add(1)
		}

		payload := smallPayload
		if rng.Float64() < *largePayloadChance {
			payload = largePayload
		}

		if len(readBuf) < len(payload) {
			readBuf = make([]byte, len(payload))
		}

		start := time.Now()
		if err := writePayload(ctx, conn, rw, payload); err != nil {
			return err
		}
		if err := readEcho(ctx, conn, rw.Reader, readBuf[:len(payload)]); err != nil {
			return err
		}
		lr.add(time.Since(start))
	}

	return nil
}

func connectThroughProxy(ctx context.Context, proxyAddr, targetAddr string) (net.Conn, *bufio.ReadWriter, error) {
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("dial proxy: %w", err)
	}

	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	if err := sendConnect(ctx, conn, rw, targetAddr); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}

	return conn, rw, nil
}

func sendConnect(ctx context.Context, conn net.Conn, rw *bufio.ReadWriter, targetAddr string) error {
	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	requestLine := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
	if _, err := rw.WriteString(requestLine); err != nil {
		return err
	}
	if err := rw.Flush(); err != nil {
		return err
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	resp, err := http.ReadResponse(rw.Reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return err
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy connect failed: %s", resp.Status)
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return err
	}

	return nil
}

func writePayload(ctx context.Context, conn net.Conn, rw *bufio.ReadWriter, payload []byte) error {
	if err := conn.SetWriteDeadline(time.Now().Add(*writeDeadline)); err != nil {
		return err
	}
	if _, err := rw.Write(payload); err != nil {
		return err
	}
	if err := rw.Flush(); err != nil {
		return err
	}
	return nil
}

func readEcho(ctx context.Context, conn net.Conn, reader *bufio.Reader, buf []byte) error {
	if err := conn.SetReadDeadline(time.Now().Add(*readDeadline)); err != nil {
		return err
	}
	_, err := io.ReadFull(reader, buf)
	return err
}

func runEchoServer(ctx context.Context, ln net.Listener) {
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
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			fmt.Fprintf(os.Stderr, "server accept error: %v\n", err)
			return
		}
		go handleEchoConn(ctx, conn)
	}
}

func handleEchoConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	for {
		if ctx.Err() != nil {
			return
		}
		if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			fmt.Fprintf(os.Stderr, "server set read deadline: %v\n", err)
			return
		}
		data, err := reader.ReadBytes('\n')
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			fmt.Fprintf(os.Stderr, "server read error: %v\n", err)
			return
		}
		if err := conn.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
			fmt.Fprintf(os.Stderr, "server set write deadline: %v\n", err)
			return
		}
		if _, err := writer.Write(data); err != nil {
			fmt.Fprintf(os.Stderr, "server write error: %v\n", err)
			return
		}
		if err := writer.Flush(); err != nil {
			fmt.Fprintf(os.Stderr, "server flush error: %v\n", err)
			return
		}
	}
}

func buildPayload(size int) []byte {
	if size < 1 {
		size = 1
	}
	payload := make([]byte, size)
	for i := 0; i < size-1; i++ {
		payload[i] = 'x'
	}
	payload[size-1] = '\n'
	return payload
}

func timeoutSeconds(d time.Duration) int {
	secs := int(d.Seconds())
	if secs < 1 {
		return 1
	}
	return secs
}

func clampProbability(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 1:
		return 1
	default:
		return v
	}
}
