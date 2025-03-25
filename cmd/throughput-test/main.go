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

func sendRequest(ctx context.Context, client *http.Client, targetURL string, wg *sync.WaitGroup, results chan<- result) {
	defer wg.Done()
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, http.NoBody)
	if err != nil {
		results <- result{0, fmt.Errorf("new request: %w", err)}
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		results <- result{0, fmt.Errorf("do request: %w", err)}
		return
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Error("Error closing response body: %v", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		results <- result{0, fmt.Errorf("status %d", resp.StatusCode)}
		return
	}

	buffer := make([]byte, 1024*1024)
	bytesRead := int64(0)
	for {
		bytesReadPart, err := resp.Body.Read(buffer)

		bytesRead += int64(bytesReadPart)
		if err != nil {
			if err == io.EOF {
				break
			}

			results <- result{bytesRead, fmt.Errorf("read body: %w", err)}
			return
		}

		if bytesRead > int64(*dataSize) {
			results <- result{bytesRead, fmt.Errorf("read too much data: %d", bytesRead)}
			return
		}
	}

	results <- result{bytesRead, nil}
}

func main() {
	flag.Parse()

	log.SetOutput(io.Discard)
	logger.SetLevel(logger.ERROR)

	time.Sleep(200 * time.Millisecond)

	// Context for overall timeout
	ctx, cancel := context.WithTimeout(context.Background(), *testTimeout)
	defer cancel()

	// Setup test data
	buf := make([]byte, *dataSize)
	for i := range buf {
		buf[i] = 'a'
	}

	// Start data server
	targetLn, _ := net.Listen("tcp", "127.0.0.1:0")
	targetAddr := targetLn.Addr().String()
	go func() {
		if err := http.Serve(targetLn, dataHandler(buf)); err != nil {
			log.Printf("Data server error: %v", err)
		}
	}()

	// Start proxy
	proxyLn, _ := net.Listen("tcp", "127.0.0.1:0")
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
	go func() {
		if err := p.StartWithListener(proxyLn); err != nil {
			log.Printf("Proxy server error: %v", err)
		}
	}()

	// Prepare client using HTTP proxy
	proxyURL, _ := url.Parse("http://" + proxyLn.Addr().String())
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	targetURL := "http://" + targetAddr + "/data"

	// Run test
	var wg sync.WaitGroup
	results := make(chan result, *numRequests)
	perWorker := *numRequests / *concurrency
	extra := *numRequests % *concurrency
	start := time.Now()
	for i := 0; i < *concurrency; i++ {
		cnt := perWorker
		if i < extra {
			cnt++
		}
		if cnt == 0 {
			continue
		}
		wg.Add(cnt)
		for j := 0; j < cnt; j++ {
			go sendRequest(ctx, client, targetURL, &wg, results)
		}

		wg.Wait()
	}
	wg.Wait()
	close(results)

	// Collect results
	success, errors, total := 0, 0, int64(0)
	for res := range results {
		if res.err != nil {
			errors++
		} else {
			success++
			total += res.bytes
		}
	}
	dur := time.Since(start)
	rps := float64(success) / dur.Seconds()
	mbps := float64(total) / dur.Seconds() / 1024 / 1024

	// Output
	fmt.Printf("Duration: %.2f s, Success: %d, Errors: %d\n", dur.Seconds(), success, errors)
	fmt.Printf("RPS: %.2f, Throughput: %.2f MB/s\n", rps, mbps)

	// Exit
	if errors > 0 || ctx.Err() == context.DeadlineExceeded {
		fmt.Fprintln(os.Stderr, "Test failed: timeout or errors")
		return
	}
	os.Exit(0)
}
