package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
	"github.com/codefionn/msgtausch/msgtausch-srv/proxy"
)

var (
	numRequests = flag.Int("numRequests", 100, "Total number of requests to send")
	concurrency = flag.Int("concurrency", 10, "Number of concurrent workers")
	testTimeout = flag.Duration("timeout", 30*time.Second, "Overall test timeout")
	dataSize    = flag.Int("dataSize", 1024*1024, "Size of payload in bytes per request")
)

type result struct {
	bytes int64
	err   error
}

type loadSummary struct {
	success  int
	errors   int
	total    int64
	duration time.Duration
}

func dataHandler(buf []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/data" {
			http.NotFound(w, r)
			return
		}
		if _, err := w.Write(buf); err != nil {
			logger.Error("failed to write data: %v", err)
		}
	}
}

func sendRequest(ctx context.Context, client *http.Client, targetURL string, expectedBytes int64, buffer []byte) result {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, http.NoBody)
	if err != nil {
		return result{0, fmt.Errorf("new request: %w", err)}
	}
	resp, err := client.Do(req)
	if err != nil {
		return result{0, fmt.Errorf("do request: %w", err)}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Error("Error closing response body: %v", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return result{0, fmt.Errorf("status %d", resp.StatusCode)}
	}

	bytesRead, err := io.CopyBuffer(io.Discard, resp.Body, buffer)
	if err != nil {
		return result{bytesRead, fmt.Errorf("read body: %w", err)}
	}
	if bytesRead != expectedBytes {
		return result{bytesRead, fmt.Errorf("read %d bytes, expected %d", bytesRead, expectedBytes)}
	}
	return result{bytesRead, nil}
}

func runRequests(ctx context.Context, client *http.Client, targetURL string) loadSummary {
	jobs := make(chan struct{})
	results := make(chan result, *numRequests)
	workerCount := min(*concurrency, *numRequests)
	var wg sync.WaitGroup
	wg.Add(workerCount)
	for range workerCount {
		go func() {
			defer wg.Done()
			buffer := make([]byte, 32*1024)
			for range jobs {
				results <- sendRequest(ctx, client, targetURL, int64(*dataSize), buffer)
			}
		}()
	}

	start := time.Now()
	go func() {
		defer close(jobs)
		for range *numRequests {
			select {
			case jobs <- struct{}{}:
			case <-ctx.Done():
				return
			}
		}
	}()
	wg.Wait()
	close(results)

	success, errors, total := 0, 0, int64(0)
	for res := range results {
		if res.err != nil {
			errors++
			continue
		}
		success++
		total += res.bytes
	}
	return loadSummary{success: success, errors: errors, total: total, duration: time.Since(start)}
}

func run() error {
	log.SetOutput(io.Discard)
	logger.SetLevel(logger.ERROR)

	if *numRequests < 1 {
		return fmt.Errorf("numRequests must be at least 1")
	}
	if *concurrency < 1 {
		return fmt.Errorf("concurrency must be at least 1")
	}
	if *dataSize < 0 {
		return fmt.Errorf("dataSize must not be negative")
	}

	// Context for overall timeout
	ctx, cancel := context.WithTimeout(context.Background(), *testTimeout)
	defer cancel()

	// Setup test data
	buf := make([]byte, *dataSize)
	for i := range buf {
		buf[i] = 'a'
	}

	// Start data server
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen for target server: %w", err)
	}
	targetAddr := targetLn.Addr().String()
	targetServer := &http.Server{Handler: dataHandler(buf)}
	go func() {
		if err := targetServer.Serve(targetLn); err != nil && err != http.ErrServerClosed {
			log.Printf("Data server error: %v", err)
		}
	}()
	defer targetServer.Close()

	// Start proxy
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen for proxy: %w", err)
	}
	proxyCfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: proxyLn.Addr().String(),
				Enabled:       true,
			},
		},
		TimeoutSeconds: 5,
	}
	p := proxy.NewProxy(proxyCfg)
	defer func() {
		if err := p.Stop(); err != nil {
			logger.Error("failed to stop proxy: %v", err)
		}
	}()
	go func() {
		if err := p.StartWithListener(proxyLn); err != nil {
			log.Printf("Proxy server error: %v", err)
		}
	}()

	// Prepare client using HTTP proxy
	proxyURL, err := url.Parse("http://" + proxyLn.Addr().String())
	if err != nil {
		return fmt.Errorf("parse proxy URL: %w", err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	targetURL := "http://" + targetAddr + "/data"

	summary := runRequests(ctx, client, targetURL)
	rps := float64(summary.success) / summary.duration.Seconds()
	mbps := float64(summary.total) / summary.duration.Seconds() / 1024 / 1024

	// Output
	fmt.Printf("Duration: %.2f s, Success: %d, Errors: %d\n", summary.duration.Seconds(), summary.success, summary.errors)
	fmt.Printf("RPS: %.2f, Throughput: %.2f MB/s\n", rps, mbps)

	if summary.errors > 0 || ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("test failed: timeout or %d request errors", summary.errors)
	}
	return nil
}

func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
