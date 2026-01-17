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

type categoryStats struct {
	rec   latencyRecorder
	count atomic.Int64
}

func (cs *categoryStats) add(d time.Duration) {
	cs.count.Add(1)
	cs.rec.add(d)
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
	ctx, cancel := setupContext()
	defer cancel()

	serverLn, proxyLn, err := prepareListeners()
	if err != nil {
		return err
	}
	defer serverLn.Close()
	defer proxyLn.Close()

	go runEchoServer(ctx, serverLn)

	cfg := proxyConfig(proxyLn.Addr().String())
	p, proxyErr := startProxy(cfg, proxyLn)
	defer p.Close()

	if err := waitForProxyStart(proxyErr); err != nil {
		return err
	}

	results := latencyRecorder{}
	var reopenCount atomic.Int64
	categories := initCategories()

	smallPayload := []byte("ping\n")
	largePayload := buildPayload(*largePayloadSize)

	start := time.Now()
	errCh := runClients(ctx, cancel, proxyLn.Addr().String(), serverLn.Addr().String(), smallPayload, largePayload, &results, &reopenCount, categories)
	if err := waitForFirstError(errCh); err != nil {
		return err
	}
	elapsed := time.Since(start)

	printReport(&results, reopenCount.Load(), elapsed, categories)
	return nil
}

func setupContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	stop := func() {
		signal.Stop(sigCh)
		cancel()
	}

	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	return ctx, stop
}

func prepareListeners() (serverLn, proxyLn net.Listener, err error) {
	serverLn, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, fmt.Errorf("start server: %w", err)
	}

	proxyLn, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = serverLn.Close()
		return nil, nil, fmt.Errorf("start proxy listener: %w", err)
	}

	return serverLn, proxyLn, nil
}

func proxyConfig(proxyAddr string) *config.Config {
	return &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: proxyAddr,
				Enabled:       true,
			},
		},
		TimeoutSeconds: timeoutSeconds(*timeout),
	}
}

func startProxy(cfg *config.Config, ln net.Listener) (p *proxy.Proxy, proxyErrCh <-chan error) {
	p = proxy.NewProxy(cfg)
	proxyErr := make(chan error, 1)
	go func() {
		if err := p.StartWithListener(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			proxyErr <- err
		}
		close(proxyErr)
	}()
	return p, proxyErr
}

func waitForProxyStart(proxyErr <-chan error) error {
	select {
	case err := <-proxyErr:
		if err != nil {
			return fmt.Errorf("proxy start failed: %w", err)
		}
	case <-time.After(200 * time.Millisecond):
	}
	return nil
}

func initCategories() map[string]*categoryStats {
	return map[string]*categoryStats{
		"small/reused": {},
		"small/reopen": {},
		"large/reused": {},
		"large/reopen": {},
	}
}

func runClients(ctx context.Context, cancel context.CancelFunc, proxyAddr, targetAddr string, smallPayload, largePayload []byte, lr *latencyRecorder, reopenCount *atomic.Int64, categories map[string]*categoryStats) <-chan error {
	errCh := make(chan error, *connections)
	var wg sync.WaitGroup

	for i := 0; i < *connections; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := newTestRand()
			if err := runClient(ctx, proxyAddr, targetAddr, smallPayload, largePayload, rng, lr, reopenCount, categories); err != nil {
				select {
				case errCh <- err:
				default:
				}
				cancel()
			}
		}()
	}

	go func() {
		wg.Wait()
		close(errCh)
	}()

	return errCh
}

func waitForFirstError(errCh <-chan error) error {
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

func printReport(results *latencyRecorder, reopenCount int64, elapsed time.Duration, categories map[string]*categoryStats) {
	totalRequests := int64(*connections * *requestsPerConn)
	p999 := results.percentile(0.999)
	p9999 := results.percentile(0.9999)

	fmt.Printf("Connections: %d, Requests per connection: %d (total %d)\n", *connections, *requestsPerConn, totalRequests)
	fmt.Printf("Reopened connections: %d\n", reopenCount)
	fmt.Printf("Duration: %s, Samples: %d\n", elapsed, results.count())
	fmt.Printf("Latency p99.9: %s\n", p999)
	fmt.Printf("Latency p99.99: %s\n", p9999)

	fmt.Println("Category breakdown (count, p99.9, p99.99):")
	for _, name := range []string{"small/reused", "small/reopen", "large/reused", "large/reopen"} {
		cs := categories[name]
		if cs == nil {
			continue
		}
		if c := cs.count.Load(); c > 0 {
			fmt.Printf("  %-13s count=%d p99.9=%s p99.99=%s\n",
				name, c, cs.rec.percentile(0.999), cs.rec.percentile(0.9999))
		}
	}
}

func runClient(ctx context.Context, proxyAddr, targetAddr string, smallPayload, largePayload []byte, rng *rand.Rand, lr *latencyRecorder, reopenCount *atomic.Int64, categories map[string]*categoryStats) error {
	conn, rw, err := connectThroughProxy(proxyAddr, targetAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	var readBuf []byte
	for i := 0; i < *requestsPerConn; i++ {
		if ctx.Err() != nil {
			return nil
		}

		conn, rw, reopened, err := maybeReconnect(conn, rw, rng, proxyAddr, targetAddr, reopenCount)
		if err != nil {
			return err
		}

		payload, isLarge := selectPayload(rng, smallPayload, largePayload)
		readBuf = ensureBufSize(readBuf, len(payload))

		elapsed, err := measureRoundTrip(conn, rw, payload, readBuf[:len(payload)])
		if err != nil {
			return err
		}
		lr.add(elapsed)
		recordCategory(isLarge, reopened, elapsed, categories)
	}

	return nil
}

func connectThroughProxy(proxyAddr, targetAddr string) (net.Conn, *bufio.ReadWriter, error) {
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("dial proxy: %w", err)
	}

	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	if err := sendConnect(conn, rw, targetAddr); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}

	return conn, rw, nil
}

func sendConnect(conn net.Conn, rw *bufio.ReadWriter, targetAddr string) error {
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

func writePayload(conn net.Conn, rw *bufio.ReadWriter, payload []byte) error {
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

func readEcho(conn net.Conn, reader *bufio.Reader, buf []byte) error {
	if err := conn.SetReadDeadline(time.Now().Add(*readDeadline)); err != nil {
		return err
	}
	_, err := io.ReadFull(reader, buf)
	return err
}

func maybeReconnect(conn net.Conn, rw *bufio.ReadWriter, rng *rand.Rand, proxyAddr, targetAddr string, reopenCount *atomic.Int64) (net.Conn, *bufio.ReadWriter, bool, error) {
	if rng.Float64() >= *reopenProbability {
		return conn, rw, false, nil
	}

	conn.Close()
	newConn, newRW, err := connectThroughProxy(proxyAddr, targetAddr)
	if err != nil {
		return nil, nil, false, fmt.Errorf("reconnect: %w", err)
	}

	reopenCount.Add(1)
	return newConn, newRW, true, nil
}

func selectPayload(rng *rand.Rand, smallPayload, largePayload []byte) ([]byte, bool) {
	if rng.Float64() < *largePayloadChance {
		return largePayload, true
	}
	return smallPayload, false
}

func ensureBufSize(buf []byte, size int) []byte {
	if len(buf) < size {
		return make([]byte, size)
	}
	return buf
}

func measureRoundTrip(conn net.Conn, rw *bufio.ReadWriter, payload, readBuf []byte) (time.Duration, error) {
	start := time.Now()
	if err := writePayload(conn, rw, payload); err != nil {
		return 0, err
	}
	if err := readEcho(conn, rw.Reader, readBuf); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

func recordCategory(isLarge, reopened bool, elapsed time.Duration, categories map[string]*categoryStats) {
	switch {
	case isLarge && reopened:
		categories["large/reopen"].add(elapsed)
	case isLarge && !reopened:
		categories["large/reused"].add(elapsed)
	case !isLarge && reopened:
		categories["small/reopen"].add(elapsed)
	default:
		categories["small/reused"].add(elapsed)
	}
}

func newTestRand() *rand.Rand {
	// Pseudo-random is sufficient for steering test traffic; cryptographic strength is not required.
	//nolint:gosec // G404: Use of weak random number generator (math/rand instead of crypto/rand) - acceptable for test purposes
	return rand.New(rand.NewSource(time.Now().UnixNano()))
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
