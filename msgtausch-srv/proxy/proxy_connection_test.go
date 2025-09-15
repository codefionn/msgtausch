package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
)

// TestConnectionKeepaliveMultipleRequests tests that the proxy handles multiple sequential requests
// with connection keepalive properly, reusing connections to the backend server
func TestConnectionKeepaliveMultipleRequests(t *testing.T) {
	var connectionCount int32
	var requestCount int32
	var connectionsMu sync.Mutex
	activeConnections := make(map[net.Conn]bool)

	// Create a test HTTP server that tracks connections (unstarted to set custom listener)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Track request count
		atomic.AddInt32(&requestCount, 1)

		// Set keepalive response headers
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Keep-Alive", "timeout=60, max=100")
		w.Header().Set("Content-Type", "text/plain")

		// Echo back the request number for verification
		reqNum := atomic.LoadInt32(&requestCount)
		content := fmt.Sprintf("Response %d from keepalive server", reqNum)
		w.Write([]byte(content))
	})

	testServer := httptest.NewUnstartedServer(handler)

	// Create and wrap a custom listener before starting the server to avoid races
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	wrappedListener := &connectionTrackingListener{
		Listener:          ln,
		connectionCount:   &connectionCount,
		activeConnections: activeConnections,
		connectionsMu:     &connectionsMu,
	}
	testServer.Listener = wrappedListener
	testServer.Start()
	defer testServer.Close()

	// Create proxy configuration
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		TimeoutSeconds:           30,
		MaxConcurrentConnections: 100,
		Classifiers:              make(map[string]config.Classifier),
	}

	proxy := NewProxy(cfg)

	// Start proxy server
	proxyListener, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	if err != nil {
		t.Fatalf("Failed to create proxy listener: %v", err)
	}
	proxyAddr := proxyListener.Addr().String()

	go func() {
		if err := proxy.StartWithListener(proxyListener); err != http.ErrServerClosed && err != nil {
			t.Errorf("Proxy server error: %v", err)
		}
	}()
	defer proxy.Stop()

	// Wait for proxy to start
	time.Sleep(100 * time.Millisecond)

	t.Run("Multiple requests with connection reuse", func(t *testing.T) {
		// Create HTTP client with keepalive enabled and using our proxy
		transport := &http.Transport{
			Proxy: http.ProxyURL(&url.URL{Host: proxyAddr}),
			// Enable keepalive settings
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
			DisableKeepAlives:   false, // Ensure keepalive is enabled
		}

		client := &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		}

		const numRequests = 5

		// Make multiple sequential requests
		for i := 0; i < numRequests; i++ {
			req, err := http.NewRequest("GET", testServer.URL+fmt.Sprintf("/test%d", i+1), nil)
			if err != nil {
				t.Fatalf("Failed to create request %d: %v", i+1, err)
			}

			// Set headers to encourage keepalive
			req.Header.Set("Connection", "keep-alive")
			req.Header.Set("User-Agent", fmt.Sprintf("KeepAliveTest/%d", i+1))

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request %d through proxy failed: %v", i+1, err)
			}

			// Verify response
			if resp.StatusCode != http.StatusOK {
				t.Errorf("Request %d: expected status code %d, got %d", i+1, http.StatusOK, resp.StatusCode)
			}

			// Read and verify response body
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Request %d: failed to read response body: %v", i+1, err)
			}
			resp.Body.Close()

			expectedContent := fmt.Sprintf("Response %d from keepalive server", i+1)
			if string(body) != expectedContent {
				t.Errorf("Request %d: expected body %q, got %q", i+1, expectedContent, string(body))
			}

			// Check for keepalive headers in response
			if resp.Header.Get("Connection") != "keep-alive" {
				t.Logf("Request %d: Connection header is %q (expected keep-alive)", i+1, resp.Header.Get("Connection"))
			}

			t.Logf("Request %d completed successfully", i+1)

			// Small delay between requests to allow for connection reuse detection
			time.Sleep(50 * time.Millisecond)
		}

		// Verify that all requests were handled
		finalRequestCount := atomic.LoadInt32(&requestCount)
		if finalRequestCount != numRequests {
			t.Errorf("Expected %d requests to be handled, got %d", numRequests, finalRequestCount)
		}

		// Give connections time to be established and potentially reused
		time.Sleep(200 * time.Millisecond)

		// Check connection count - with keepalive, should be much fewer than numRequests
		finalConnectionCount := atomic.LoadInt32(&connectionCount)
		t.Logf("Total connections created: %d for %d requests", finalConnectionCount, numRequests)

		// With proper keepalive, we should see significantly fewer connections than requests
		// Allow some flexibility as the first connection might be created and additional ones
		// might be created depending on timing, but it should be much less than numRequests
		if finalConnectionCount > int32(numRequests-1) {
			t.Errorf("Too many connections created: %d (expected < %d for keepalive)", finalConnectionCount, numRequests)
			t.Logf("This suggests connection keepalive is not working properly")
		} else if finalConnectionCount <= 2 {
			t.Logf("Good: Only %d connections used for %d requests (keepalive working)", finalConnectionCount, numRequests)
		}

		// Close the transport to clean up connections
		transport.CloseIdleConnections()
	})

	t.Run("Sequential requests show connection reuse timing", func(t *testing.T) {
		// Reset counters
		atomic.StoreInt32(&connectionCount, 0)
		atomic.StoreInt32(&requestCount, 0)

		connectionsMu.Lock()
		for conn := range activeConnections {
			delete(activeConnections, conn)
		}
		connectionsMu.Unlock()

		// Create a fresh client for this test
		client := &http.Client{
			Transport: &http.Transport{
				Proxy:               http.ProxyURL(&url.URL{Host: proxyAddr}),
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 2,
				IdleConnTimeout:     30 * time.Second,
				DisableKeepAlives:   false,
			},
			Timeout: 5 * time.Second,
		}

		// Make multiple requests quickly to test connection reuse
		for i := 0; i < 3; i++ {
			start := time.Now()

			resp, err := client.Get(testServer.URL + fmt.Sprintf("/timing-test-%d", i+1))
			if err != nil {
				t.Fatalf("Timing test request %d failed: %v", i+1, err)
			}
			resp.Body.Close()

			duration := time.Since(start)
			connCount := atomic.LoadInt32(&connectionCount)

			t.Logf("Request %d completed in %v, total connections: %d", i+1, duration, connCount)

			// After the first request, subsequent requests should be faster due to connection reuse
			if i > 0 && duration > 500*time.Millisecond {
				t.Logf("Request %d took %v (might indicate new connection instead of reuse)", i+1, duration)
			}
		}

		finalConnCount := atomic.LoadInt32(&connectionCount)
		if finalConnCount > 2 {
			t.Logf("More connections (%d) created than expected for keepalive scenario", finalConnCount)
		}
	})
}

// TestHTTPConnectionPersistence tests HTTP connection persistence without CONNECT tunneling
// This test focuses on regular HTTP proxying (not HTTPS tunnels) to verify that
// the proxy properly maintains persistent connections for multiple HTTP requests
func TestHTTPConnectionPersistence(t *testing.T) {
	var proxyConnectionCount int32
	var requestCount int32

	// Create multiple backend servers to test connection distribution
	backends := make([]*httptest.Server, 3)
	for i := 0; i < 3; i++ {
		serverIndex := i
		backends[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&requestCount, 1)
			reqNum := atomic.LoadInt32(&requestCount)

			// Set connection headers for keepalive
			w.Header().Set("Connection", "keep-alive")
			w.Header().Set("Keep-Alive", "timeout=30, max=100")
			w.Header().Set("Server", fmt.Sprintf("backend-%d", serverIndex))

			content := fmt.Sprintf("Response %d from backend %d", reqNum, serverIndex)
			w.Write([]byte(content))
		}))
		defer backends[i].Close()
	}

	// Create proxy configuration
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		TimeoutSeconds:           30,
		MaxConcurrentConnections: 100,
		Classifiers:              make(map[string]config.Classifier),
	}

	proxy := NewProxy(cfg)

	// Create a connection tracking listener for the proxy
	proxyListener, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	if err != nil {
		t.Fatalf("Failed to create proxy listener: %v", err)
	}

	proxyTrackingListener := &connectionTrackingListener{
		Listener:          proxyListener,
		connectionCount:   &proxyConnectionCount,
		activeConnections: make(map[net.Conn]bool),
		connectionsMu:     &sync.Mutex{},
	}

	proxyAddr := proxyTrackingListener.Addr().String()

	go func() {
		if err := proxy.StartWithListener(proxyTrackingListener); err != http.ErrServerClosed && err != nil {
			t.Errorf("Proxy server error: %v", err)
		}
	}()
	defer proxy.Stop()

	// Wait for proxy to start
	time.Sleep(100 * time.Millisecond)

	t.Run("Single backend connection persistence", func(t *testing.T) {
		// Reset counters
		atomic.StoreInt32(&requestCount, 0)
		atomic.StoreInt32(&proxyConnectionCount, 0)

		// Create HTTP client configured for persistent connections
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(&url.URL{Host: proxyAddr}),
				// Optimize for connection reuse
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 5,
				IdleConnTimeout:     60 * time.Second,
				DisableKeepAlives:   false,
				MaxConnsPerHost:     2,     // Limit concurrent connections
				ForceAttemptHTTP2:   false, // Use HTTP/1.1 for clearer connection tracking
			},
			Timeout: 10 * time.Second,
		}

		// Make multiple requests to the same backend
		backend := backends[0]
		const numRequests = 8

		for i := 0; i < numRequests; i++ {
			req, err := http.NewRequest("GET", backend.URL+fmt.Sprintf("/api/test?req=%d", i+1), nil)
			if err != nil {
				t.Fatalf("Failed to create request %d: %v", i+1, err)
			}

			// Explicitly set keepalive headers
			req.Header.Set("Connection", "keep-alive")
			req.Header.Set("User-Agent", fmt.Sprintf("PersistenceTest/%d", i+1))

			start := time.Now()
			resp, err := client.Do(req)
			duration := time.Since(start)

			if err != nil {
				t.Fatalf("Request %d failed: %v", i+1, err)
			}

			// Verify response
			if resp.StatusCode != http.StatusOK {
				t.Errorf("Request %d: expected status 200, got %d", i+1, resp.StatusCode)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Request %d: failed to read response: %v", i+1, err)
			}
			resp.Body.Close()

			expectedPattern := fmt.Sprintf("Response %d from backend 0", i+1)
			if string(body) != expectedPattern {
				t.Errorf("Request %d: expected %q, got %q", i+1, expectedPattern, string(body))
			}

			// Log connection info
			proxyConns := atomic.LoadInt32(&proxyConnectionCount)
			t.Logf("Request %d: took %v, proxy connections: %d", i+1, duration, proxyConns)

			// Brief pause between requests to allow connection reuse
			time.Sleep(10 * time.Millisecond)
		}

		// Verify connection efficiency
		finalProxyConns := atomic.LoadInt32(&proxyConnectionCount)
		finalRequests := atomic.LoadInt32(&requestCount)

		t.Logf("Final stats: %d requests handled with %d proxy connections", finalRequests, finalProxyConns)

		// With HTTP connection persistence, we should have significantly fewer connections than requests
		if finalProxyConns > int32(numRequests/2) {
			t.Errorf("Too many proxy connections: %d for %d requests (persistence may not be working)", finalProxyConns, numRequests)
		}

		if finalRequests != numRequests {
			t.Errorf("Expected %d requests to be processed, got %d", numRequests, finalRequests)
		}
	})

	t.Run("Multiple backend connection distribution", func(t *testing.T) {
		// Reset counters
		atomic.StoreInt32(&requestCount, 0)
		atomic.StoreInt32(&proxyConnectionCount, 0)

		// Create client with connection pooling
		client := &http.Client{
			Transport: &http.Transport{
				Proxy:               http.ProxyURL(&url.URL{Host: proxyAddr}),
				MaxIdleConns:        15,
				MaxIdleConnsPerHost: 3,
				IdleConnTimeout:     30 * time.Second,
				DisableKeepAlives:   false,
				MaxConnsPerHost:     3,
			},
			Timeout: 5 * time.Second,
		}

		// Make requests distributed across multiple backends
		const requestsPerBackend = 3

		for backendIdx, backend := range backends {
			for reqIdx := 0; reqIdx < requestsPerBackend; reqIdx++ {
				req, err := http.NewRequest("GET",
					backend.URL+fmt.Sprintf("/multi/backend-%d/req-%d", backendIdx, reqIdx),
					nil)
				if err != nil {
					t.Fatalf("Failed to create request for backend %d, req %d: %v", backendIdx, reqIdx, err)
				}

				req.Header.Set("X-Backend-Target", fmt.Sprintf("%d", backendIdx))
				req.Header.Set("Connection", "keep-alive")

				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("Request to backend %d failed: %v", backendIdx, err)
				}

				if resp.StatusCode != http.StatusOK {
					t.Errorf("Backend %d request %d: expected status 200, got %d", backendIdx, reqIdx, resp.StatusCode)
				}

				// Verify we hit the right backend
				if resp.Header.Get("Server") != fmt.Sprintf("backend-%d", backendIdx) {
					t.Errorf("Request routed to wrong backend: expected backend-%d, got %s",
						backendIdx, resp.Header.Get("Server"))
				}

				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()

				// Small delay to allow connection reuse patterns to emerge
				time.Sleep(5 * time.Millisecond)
			}
		}

		// Verify connection distribution
		finalProxyConns := atomic.LoadInt32(&proxyConnectionCount)
		totalRequests := len(backends) * requestsPerBackend

		t.Logf("Multi-backend test: %d total requests across %d backends using %d proxy connections",
			totalRequests, len(backends), finalProxyConns)

		// We should have reasonable connection efficiency even with multiple backends
		maxExpectedConns := int32(len(backends) * 2) // Allow up to 2 connections per backend
		if finalProxyConns > maxExpectedConns {
			t.Errorf("Too many connections for multi-backend scenario: %d (expected <= %d)",
				finalProxyConns, maxExpectedConns)
		}
	})

	t.Run("Connection cleanup after idle timeout", func(t *testing.T) {
		// Create client with short idle timeout for testing cleanup
		client := &http.Client{
			Transport: &http.Transport{
				Proxy:               http.ProxyURL(&url.URL{Host: proxyAddr}),
				MaxIdleConns:        5,
				MaxIdleConnsPerHost: 2,
				IdleConnTimeout:     100 * time.Millisecond, // Very short timeout
				DisableKeepAlives:   false,
			},
			Timeout: 3 * time.Second,
		}

		// Make a few requests
		backend := backends[0]
		for i := 0; i < 3; i++ {
			resp, err := client.Get(backend.URL + fmt.Sprintf("/cleanup-test-%d", i))
			if err != nil {
				t.Fatalf("Cleanup test request %d failed: %v", i, err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}

		// Wait for idle timeout to trigger connection cleanup
		time.Sleep(200 * time.Millisecond)

		// Make another request - should create new connection due to cleanup
		resp, err := client.Get(backend.URL + "/cleanup-test-final")
		if err != nil {
			t.Fatalf("Final cleanup test request failed: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		t.Logf("Connection cleanup test completed - connections should have been cleaned up and recreated")
	})
}

// connectionTrackingListener wraps a net.Listener to track connection count
type connectionTrackingListener struct {
	net.Listener
	connectionCount   *int32
	activeConnections map[net.Conn]bool
	connectionsMu     *sync.Mutex
}

func (l *connectionTrackingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// Increment connection count
	atomic.AddInt32(l.connectionCount, 1)

	// Track active connection
	l.connectionsMu.Lock()
	l.activeConnections[conn] = true
	l.connectionsMu.Unlock()

	// Wrap connection to track when it closes
	return &connectionTrackingConn{
		Conn:              conn,
		activeConnections: l.activeConnections,
		connectionsMu:     l.connectionsMu,
	}, nil
}

// connectionTrackingConn wraps a net.Conn to track when it closes
type connectionTrackingConn struct {
	net.Conn
	activeConnections map[net.Conn]bool
	connectionsMu     *sync.Mutex
	closed            bool
}

func (c *connectionTrackingConn) Close() error {
	if !c.closed {
		c.connectionsMu.Lock()
		delete(c.activeConnections, c.Conn)
		c.connectionsMu.Unlock()
		c.closed = true
	}
	return c.Conn.Close()
}
