package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

func TestProxyIntegration(t *testing.T) {
	// Create a test HTTP server that we'll proxy to
	testContent := "Hello, Proxy!"
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back request headers in response
		for k, v := range r.Header {
			if k == "X-Test-Header" {
				w.Header().Set(k, v[0])
			}
		}

		// Echo back request method
		w.Header().Set("X-Request-Method", r.Method)

		// Handle different HTTP methods
		switch r.Method {
		case "POST":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = w.Write(body)
		default:
			_, _ = w.Write([]byte(testContent))
		}
	}))
	defer testServer.Close()

	// Create a basic test configuration
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:0", // Use port 0 to get random available port
				Enabled:       true,
			},
		},
		TimeoutSeconds:           5,
		Classifiers:              make(map[string]config.Classifier),
	}

	proxy := NewProxy(cfg)

	// Start proxy server using the proxy's method to include ConnContext
	listener, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	proxyAddr := listener.Addr().String()

	go func() {
		if err := proxy.StartWithListener(listener); err != http.ErrServerClosed && err != nil {
			t.Errorf("Proxy server error: %v", err)
		}
	}()
	defer proxy.Stop() // Use proxy's Stop method

	// Wait for proxy to start
	time.Sleep(100 * time.Millisecond)

	// Create HTTP client that uses our proxy
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", proxyAddr))
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	t.Run("GET request", func(t *testing.T) {
		req, err := http.NewRequest("GET", testServer.URL, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Test-Header", "test-value")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		// Verify response
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		if string(body) != testContent {
			t.Errorf("Expected body %q, got %q", testContent, string(body))
		}

		if resp.Header.Get("X-Test-Header") != "test-value" {
			t.Error("Custom header was not properly forwarded")
		}

		if resp.Header.Get("X-Request-Method") != "GET" {
			t.Error("Request method was not properly forwarded")
		}
	})

	t.Run("POST request", func(t *testing.T) {
		postData := map[string]string{"key": "value"}
		postBody, _ := json.Marshal(postData)

		req, err := http.NewRequest("POST", testServer.URL, strings.NewReader(string(postBody)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		// Verify response
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		if string(body) != string(postBody) {
			t.Errorf("Expected body %q, got %q", string(postBody), string(body))
		}

		if resp.Header.Get("X-Request-Method") != "POST" {
			t.Error("Request method was not properly forwarded")
		}
	})
}

// setupTLSServer creates a test HTTPS server with a self-signed certificate
func setupTLSServer(t *testing.T) (*httptest.Server, *x509.CertPool) {
	// Create a test HTTPS server
	testContent := "Hello, HTTPS Proxy!"
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(testContent))
	}))

	// Get the server's certificate
	cert := testServer.TLS.Certificates[0]
	certPool := x509.NewCertPool()
	certPool.AddCert(cert.Leaf)

	return testServer, certPool
}

// TestConnectMethod tests the HTTPS tunneling functionality via CONNECT method
func TestConnectMethod(t *testing.T) {
	// Setup a TLS server
	tlsServer, certPool := setupTLSServer(t)
	defer tlsServer.Close()

	// Parse the server URL to get host and port - just to validate it's a valid URL
	_, err := url.Parse(tlsServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse TLS server URL: %v", err)
	}

	// Test HTTPS request through the proxy
	t.Run("HTTPS via CONNECT", func(t *testing.T) {
		// Create a config with all options used
		cfg := &config.Config{
			Servers: []config.ServerConfig{
				{
					Type:          config.ProxyTypeStandard,
					ListenAddress: "127.0.0.1:0", // Use port 0 to get random available port
					Enabled:       true,
				},
			},
			TimeoutSeconds:           5,
			Classifiers:              make(map[string]config.Classifier),
		}

		proxy := NewProxy(cfg)

		// Start proxy server using the proxy's method to include ConnContext
		listener, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
		if err != nil {
			t.Fatalf("Failed to create listener: %v", err)
		}
		proxyAddr := listener.Addr().String()

		go func() {
			if err := proxy.StartWithListener(listener); err != http.ErrServerClosed && err != nil {
				t.Errorf("Proxy server error: %v", err)
			}
		}()
		defer proxy.Stop() // Use proxy's Stop method

		// Wait for proxy to start
		time.Sleep(100 * time.Millisecond)

		// Create HTTP client that uses our proxy for HTTPS requests
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(&url.URL{Host: proxyAddr}),
				TLSClientConfig: &tls.Config{
					RootCAs: certPool,
				},
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		}

		resp, err := client.Get(tlsServer.URL)
		if err != nil {
			t.Fatalf("HTTPS request failed: %v", err)
		}
		defer resp.Body.Close()

		// Verify response
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		expected := "Hello, HTTPS Proxy!"
		if string(body) != expected {
			t.Errorf("Expected body %q, got %q", expected, string(body))
		}
	})
}

func TestHttpThenConnectRequest(t *testing.T) {
	// Start backend HTTP server
	httpContent := "Hello, HTTP Proxy!"
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(httpContent))
	}))
	defer httpServer.Close()

	// Start backend HTTPS server
	httpsContent := "Hello, HTTPS Proxy!"
	httpsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(httpsContent))
	}))
	defer httpsServer.Close()

	cert := httpsServer.TLS.Certificates[0]
	certPool := x509.NewCertPool()
	certPool.AddCert(cert.Leaf)

	// Start proxy
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		TimeoutSeconds:           5,
		Classifiers:              make(map[string]config.Classifier),
	}
	proxy := NewProxy(cfg)
	listener, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	require.NoError(t, err)
	proxyAddr := listener.Addr().String()
	go func() {
		err := proxy.StartWithListener(listener)
		if err != http.ErrServerClosed && err != nil {
			t.Errorf("Proxy server error: %v", err)
		}
	}()
	defer proxy.Stop()
	time.Sleep(100 * time.Millisecond)

	proxyURL, _ := url.Parse("http://" + proxyAddr)

	// 1. HTTP request via proxy
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
	resp, err := httpClient.Get(httpServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, httpContent, string(body), "HTTP body mismatch")

	// 2. HTTPS (CONNECT) request via proxy
	httpsClient := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: certPool},
		},
	}
	resp2, err := httpsClient.Get(httpsServer.URL)
	require.NoError(t, err)
	defer resp2.Body.Close()
	body2, err := io.ReadAll(resp2.Body)
	require.NoError(t, err)
	assert.Equal(t, httpsContent, string(body2), "HTTPS body mismatch")
}

func TestHTTP2ViaConnect(t *testing.T) {
	// Setup TLS server with HTTP/2 support
	testContent := "Hello, HTTP2 Proxy!"
	// Use unstarted server to configure HTTP/2
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(testContent))
	}))
	// Enable HTTP/2 on TLS before starting
	srv.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	http2.ConfigureServer(srv.Config, &http2.Server{})
	srv.TLS = &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
	}
	srv.StartTLS()
	defer srv.Close()

	// Trust the server certificate
	cert := srv.TLS.Certificates[0]
	certPool := x509.NewCertPool()
	certPool.AddCert(cert.Leaf)

	// Configure and start the proxy
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		TimeoutSeconds:           5,
		Classifiers:              make(map[string]config.Classifier),
	}
	proxy := NewProxy(cfg)
	listener, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	require.NoError(t, err)
	proxyAddr := listener.Addr().String()
	go func() {
		if err := proxy.StartWithListener(listener); err != http.ErrServerClosed && err != nil {
			t.Errorf("Proxy server error: %v", err)
		}
	}()
	defer proxy.Stop()
	time.Sleep(100 * time.Millisecond)

	// Create client with HTTP/2 over proxy
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			TLSClientConfig:   &tls.Config{RootCAs: certPool},
			ForceAttemptHTTP2: true,
		},
	}

	// Perform GET request
	resp, err := client.Get(srv.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify HTTP/2
	assert.Equal(t, 2, resp.ProtoMajor, "Expected HTTP/2")
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, testContent, string(body), "HTTP/2 body mismatch")
}

// TestForwardRequestHeaderSkipping verifies that hop-by-hop and proxy-specific headers
// are correctly skipped when forwarding requests.
func TestForwardRequestHeaderSkipping(t *testing.T) {
	// Only proxy-specific headers should be skipped, per RFC 7230
	// Transfer-Encoding, TE, Trailer, and Keep-Alive are preserved for proper HTTP semantics
	skippedHeaders := map[string]struct{}{
		"Proxy-Connection":    {},
		"Connection":          {},
		"Proxy-Authenticate":  {},
		"Proxy-Authorization": {},
		"Upgrade":             {},
		// Note: Keep-Alive, TE, Trailer, and Transfer-Encoding are no longer skipped
	}

	// Create a test HTTP server that echoes received headers
	var receivedHeaders http.Header
	var headersMu sync.Mutex
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headersMu.Lock()
		receivedHeaders = r.Header.Clone()
		headersMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer testServer.Close()

	// Configure and start the proxy
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		TimeoutSeconds:           5,
		Classifiers:              make(map[string]config.Classifier),
	}
	proxyInstance := NewProxy(cfg)
	listener, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	require.NoError(t, err, "Failed to create listener")
	proxyAddr := listener.Addr().String()

	go func() {
		if err := proxyInstance.StartWithListener(listener); err != http.ErrServerClosed && err != nil {
			t.Errorf("Proxy server error: %v", err)
		}
	}()
	defer proxyInstance.Stop()

	// Wait for proxy to start
	time.Sleep(100 * time.Millisecond)

	// Create HTTP client that uses our proxy
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", proxyAddr))
	require.NoError(t, err, "Failed to parse proxy URL")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	// Create request with various headers
	req, err := http.NewRequest("GET", testServer.URL, http.NoBody)
	require.NoError(t, err, "Failed to create request")

	// Add headers that should be skipped
	for headerName := range skippedHeaders {
		req.Header.Add(headerName, "should-be-skipped")
	}

	// Add headers that should NOT be skipped
	keepHeaders := map[string]string{
		"X-Custom-Data": "value1",
		"User-Agent":    "test-client/1.0",
		"Accept":        "application/json",
	}
	for key, value := range keepHeaders {
		req.Header.Add(key, value)
	}

	// Send the request through the proxy
	resp, err := client.Do(req)
	require.NoError(t, err, "Client request failed")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body) // Ensure body is read and closed
	require.Equal(t, http.StatusOK, resp.StatusCode, "Expected OK status")

	// Verify headers received by the target server
	headersMu.Lock()
	defer headersMu.Unlock()

	require.NotNil(t, receivedHeaders, "Target server did not receive headers")

	// Check that skipped headers are NOT present
	for headerName := range skippedHeaders {
		assert.Empty(t, receivedHeaders.Get(headerName), "Header '%s' should have been skipped but was found", headerName)
	}

	// Check that non-skipped headers ARE present
	for key, value := range keepHeaders {
		assert.Equal(t, value, receivedHeaders.Get(key), "Header '%s' was not forwarded correctly", key)
	}
}

// countListener wraps a net.Listener to count accepted connections.
type countListener struct {
	net.Listener
	mu    sync.Mutex
	count int
}

func (l *countListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.count++
	l.mu.Unlock()
	return c, nil
}

func (l *countListener) ConnectionCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.count
}

// TestKeepAlive verifies that multiple requests reuse the same TCP connection via keep-alive.
func TestKeepAlive(t *testing.T) {
	// Setup origin HTTP server with a counting listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	cl := &countListener{Listener: ln}
	testContent := "KeepAlive OK"
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(testContent))
		}),
	}
	go srv.Serve(cl)
	defer srv.Close()

	originAddr := cl.Addr().String()

	// Configure and start the proxy.
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		TimeoutSeconds:           5,
		Classifiers:              make(map[string]config.Classifier),
	}
	proxy := NewProxy(cfg)
	pln, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	require.NoError(t, err)
	go func() {
		if err := proxy.StartWithListener(pln); err != http.ErrServerClosed && err != nil {
			t.Errorf("Proxy server error: %v", err)
		}
	}()
	defer proxy.Stop()
	time.Sleep(100 * time.Millisecond)

	// Create HTTP client using the proxy.
	proxyURL, _ := url.Parse("http://" + pln.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	// Perform multiple GET requests.
	for i := 0; i < 3; i++ {
		resp, err := client.Get("http://" + originAddr)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, testContent, string(body))
		resp.Body.Close()
	}

	// Ensure only one TCP connection was established.
	assert.Equal(t, 1, cl.ConnectionCount(), "Expected only one TCP connection due to keep-alive")
}
