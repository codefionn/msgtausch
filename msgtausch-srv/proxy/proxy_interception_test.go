package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHTTPInterception tests the HTTP interception functionality with the standard proxy
func TestHTTPInterception(t *testing.T) {
	// Create a test HTTP server that we'll proxy to
	testContent := "Hello, Intercepted Proxy!"
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

	// Create a configuration with HTTP interception enabled
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeHTTP, // Use HTTP proxy type for interception
				ListenAddress: "127.0.0.1:0",        // Use port 0 to get random available port
				Enabled:       true,
			},
		},
		TimeoutSeconds:           5,
		MaxConcurrentConnections: 100,
		Classifiers:              make(map[string]config.Classifier),
		Interception: config.InterceptionConfig{
			Enabled: true,
			HTTP:    true,
			HTTPS:   false,
		},
	}

	// Create and start the proxy
	proxy := NewProxy(cfg)

	// Setup a test interceptor to verify interception
	interceptorCalled := false
	testHeaderName := "X-Intercepted-Header"
	testHeaderValue := "test-value"

	// Add request hook to the HTTP interceptor
	proxy.servers[0].httpInterceptor.AddRequestHook("test-hook", func(req *http.Request) error {
		interceptorCalled = true
		req.Header.Set(testHeaderName, testHeaderValue)
		return nil
	})

	// Start proxy server using the proxy's method
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
	defer proxy.Stop()

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

	t.Run("GET request with interception", func(t *testing.T) {
		// Make a request to the test server through the proxy
		resp, err := client.Get(testServer.URL)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		// Verify interception occurred
		assert.True(t, interceptorCalled, "HTTP interceptor was not called")

		// Read response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		// Verify that the request was received by the test server with the intercepted header
		assert.Equal(t, "GET", resp.Header.Get("X-Request-Method"))
		assert.Equal(t, testContent, string(body))
	})

	t.Run("POST request with interception", func(t *testing.T) {
		// Reset interception flag
		interceptorCalled = false

		// Create a POST request with a body
		postBody := "This is a POST request"
		resp, err := client.Post(testServer.URL, "text/plain", strings.NewReader(postBody))
		if err != nil {
			t.Fatalf("Failed to make POST request: %v", err)
		}
		defer resp.Body.Close()

		// Verify interception occurred
		assert.True(t, interceptorCalled, "HTTP interceptor was not called for POST request")

		// Read response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		// Verify that the request was received by the test server
		assert.Equal(t, "POST", resp.Header.Get("X-Request-Method"))
		assert.Equal(t, postBody, string(body))
	})
}

// TestHTTPInterceptionWithResponseModification tests HTTP interception with response modification
func TestHTTPInterceptionWithResponseModification(t *testing.T) {
	// Create a test HTTP server
	originalContent := "Original Content"
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(originalContent))
	}))
	defer testServer.Close()

	// Create a configuration with HTTP interception enabled
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeHTTP, // Use HTTP proxy type for interception
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		TimeoutSeconds:           5,
		MaxConcurrentConnections: 100,
		Classifiers:              make(map[string]config.Classifier),
		Interception: config.InterceptionConfig{
			Enabled: true,
			HTTP:    true,
			HTTPS:   false,
		},
	}

	// Create and start the proxy
	proxy := NewProxy(cfg)

	// Setup response interception to modify the response
	modifiedContent := "Modified Content"
	responseInterceptorCalled := false

	// Add response hook to the HTTP interceptor
	proxy.servers[0].httpInterceptor.AddResponseHook("test-response-hook", func(resp *http.Response) error {
		responseInterceptorCalled = true

		// Replace the response body with modified content
		body := io.NopCloser(strings.NewReader(modifiedContent))
		resp.Body = body
		resp.ContentLength = int64(len(modifiedContent))
		resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(modifiedContent)))

		// Add a response header to indicate interception
		resp.Header.Set("X-Response-Intercepted", "true")
		return nil
	})

	// Start proxy server
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
	defer proxy.Stop()

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

	t.Run("Response interception", func(t *testing.T) {
		// Make a request to the test server through the proxy
		resp, err := client.Get(testServer.URL)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		// Verify response interception occurred
		assert.True(t, responseInterceptorCalled, "HTTP response interceptor was not called")
		assert.Equal(t, "true", resp.Header.Get("X-Response-Intercepted"))

		// Read response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		// Verify that the response was modified
		assert.Equal(t, modifiedContent, string(body))
		assert.NotEqual(t, originalContent, string(body))
	})
}

// TestHTTPSInterceptionWithStandardProxy tests the HTTPS interception functionality
// using the standard proxy server (not the direct HTTPSInterceptor)
func TestHTTPSInterceptionWithStandardProxy(t *testing.T) {
	caCertPath := "testdata/test_ca.crt"
	caKeyPath := "testdata/test_ca.key"

	// Setup test HTTPS server
	originalContent := "Original HTTPS Content"
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set a unique header to verify we're hitting the real server
		w.Header().Set("X-Test-Server", "true")
		_, _ = w.Write([]byte(originalContent))
	}))
	defer testServer.Close()

	// Log the original server's certificate details for debugging
	t.Logf("Original server cert: Serial=%v, Subject=%v, Issuer=%v",
		testServer.TLS.Certificates[0].Leaf.SerialNumber,
		testServer.TLS.Certificates[0].Leaf.Subject,
		testServer.TLS.Certificates[0].Leaf.Issuer)

	// Configure proxy with HTTPS interception enabled
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard, // Standard proxy handles CONNECT requests for HTTPS
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		TimeoutSeconds: 5,
		Classifiers:    make(map[string]config.Classifier),
		Interception: config.InterceptionConfig{
			Enabled:   true,
			HTTP:      true,
			HTTPS:     true,
			CAFile:    caCertPath,
			CAKeyFile: caKeyPath,
		},
	}

	// Create and start the proxy with detailed logging
	proxy := NewProxy(cfg)

	// Manually initialize the HTTPS interceptor for the standard proxy
	// since ProxyTypeStandard doesn't do this automatically
	caCertData, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("Failed to read CA certificate: %v", err)
	}

	caKeyData, err := os.ReadFile(caKeyPath)
	if err != nil {
		t.Fatalf("Failed to read CA key: %v", err)
	}

	// Create HTTPS interceptor and attach it to the first proxy server
	httpsInterceptor, err := NewHTTPSInterceptor(caCertData, caKeyData, proxy, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create HTTPS interceptor: %v", err)
	}

	// The standard proxy server is the first one in the servers slice
	if len(proxy.servers) == 0 {
		t.Fatal("No proxy servers initialized")
	}
	proxy.servers[0].httpsInterceptor = httpsInterceptor
	t.Logf("Manually initialized HTTPS interceptor: %v", httpsInterceptor != nil)

	// Start proxy server
	listener, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	proxyAddr := listener.Addr().String()
	t.Logf("Proxy URL: http://%s", proxyAddr)

	go func() {
		if err := proxy.StartWithListener(listener); err != http.ErrServerClosed && err != nil {
			t.Errorf("Proxy server error: %v", err)
		}
	}()
	defer proxy.Stop()

	// Wait for proxy to start
	time.Sleep(100 * time.Millisecond)

	// Create HTTP client that trusts our CA and uses our proxy
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", proxyAddr))
	if err != nil {
		t.Fatal(err)
	}

	// Create CA cert pool and add our CA certificate
	rootCAs := x509.NewCertPool()
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("Failed to read CA certificate: %v", err)
	}
	rootCAs.AppendCertsFromPEM(caCert)

	// Log proxy configuration to help with debugging
	t.Logf("HTTPS interception enabled in config: %v", cfg.Interception.HTTPS)

	// Important: Configure the transport to use the proxy for ALL requests including HTTPS
	// This ensures the CONNECT method is used for HTTPS connections
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs:            rootCAs,
				InsecureSkipVerify: true, // Allow test server's self-signed cert until it's replaced by our CA
			},
			// Force the use of HTTP/1.1 to ensure CONNECT is used properly
			ForceAttemptHTTP2:   false,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}

	t.Run("HTTPS interception", func(t *testing.T) {
		// Make a request to the test HTTPS server through the proxy
		resp, err := client.Get(testServer.URL)
		if err != nil {
			t.Fatalf("Failed to make HTTPS request: %v", err)
		}
		defer resp.Body.Close()

		// Get the certificate presented to the client
		if len(resp.TLS.PeerCertificates) == 0 {
			t.Fatal("No certificates found in TLS connection")
		}
		clientCert := resp.TLS.PeerCertificates[0]

		// Verify the certificate was issued by our CA, not the original server's CA
		t.Logf("Original server cert: Serial=%v, Subject=%v, Issuer=%v",
			testServer.TLS.Certificates[0].Leaf.SerialNumber,
			testServer.TLS.Certificates[0].Leaf.Subject,
			testServer.TLS.Certificates[0].Leaf.Issuer)

		t.Logf("Cert presented to client: Serial=%v, Subject=%v, Issuer=%v",
			clientCert.SerialNumber,
			clientCert.Subject,
			clientCert.Issuer)

		// Assert the certificate was modified
		assert.NotEqual(t, testServer.TLS.Certificates[0].Leaf.SerialNumber, clientCert.SerialNumber,
			"Certificate serial number should be different if intercepted")
		assert.NotEqual(t, testServer.TLS.Certificates[0].Leaf.Issuer, clientCert.Issuer,
			"Certificate issuer should be different if intercepted")

		// Verify the certificate was issued by our test CA
		assert.Contains(t, clientCert.Issuer.String(), "Msgtausch Test CA",
			"Certificate should be issued by our test CA")
	})

	t.Run("HTTPS non-interception when disabled", func(t *testing.T) {
		// Disable HTTPS interception
		proxy.config.Interception.HTTPS = false

		// Make a direct connection client that doesn't trust our CA
		// but still uses the proxy for the CONNECT tunnel
		directClient := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // Allow connecting to test server with self-signed cert
				},
			},
		}

		// Make a request - this should use CONNECT but not be intercepted
		resp, err := directClient.Get(testServer.URL)
		if err != nil {
			t.Fatalf("Failed to make direct HTTPS request: %v", err)
		}
		defer resp.Body.Close()
	})
}

// Test that when only HTTP interception is enabled (and HTTPS interception is disabled),
// a CONNECT tunnel carrying TLS is not mistakenly parsed as HTTP by the HTTP interceptor.
// Expected correct behavior: HTTPS request succeeds via raw tunnel without interception.
// Current bug: HTTP interceptor tries to read an HTTP request from TLS bytes and the request fails.
func TestCONNECTTunnelWithHTTPInterceptionOnly_TLSTunneledNotParsed(t *testing.T) {
	// Setup a simple HTTPS backend
	backendContent := "ok"
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(backendContent))
	}))
	defer tlsSrv.Close()

	// Configure a standard proxy with interception enabled, HTTP=true, HTTPS=false
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		TimeoutSeconds: 5,
		Classifiers:    make(map[string]config.Classifier),
		Interception: config.InterceptionConfig{
			Enabled: true,
			HTTP:    true,
			HTTPS:   false,
		},
	}

	proxy := NewProxy(cfg)

	// Start proxy server
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
	defer proxy.Stop()

	// Wait for proxy to start
	time.Sleep(100 * time.Millisecond)

	// HTTP client using the proxy, performing HTTPS through CONNECT
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			// We are not testing cert validation here; allow self-signed test server
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2:   false,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		Timeout: 10 * time.Second,
	}

	// Expected: this should succeed by tunneling TLS, not parsing as HTTP
	resp, err := client.Get(tlsSrv.URL)
	if err != nil {
		// Reproduce current bug: this path will trigger when the HTTP interceptor
		// attempts to parse TLS handshake as an HTTP request (malformed HTTP request).
		t.Fatalf("HTTPS over CONNECT via proxy failed (likely parsed as HTTP): %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	if got := string(body); got != backendContent {
		t.Fatalf("Unexpected backend body: got %q want %q", got, backendContent)
	}
}

// Test that non-HTTPS CONNECT targets are handled by the HTTP interceptor
// when HTTP interception is enabled, by verifying a request hook runs and
// modifies the tunneled plaintext HTTP request.
func TestCONNECTTunnel_NonHTTPS_UsesHTTPInterceptor(t *testing.T) {
	// Plain HTTP backend that asserts our interceptor-added header
	headerSeen := make(chan bool, 1)
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Intercepted") == "1" {
			headerSeen <- true
		} else {
			headerSeen <- false
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer httpSrv.Close()

	// Determine backend host:port, but use "localhost" in CONNECT target to avoid
	// the HTTPS heuristic that flags 127.0.0.1 as HTTPS.
	backendURL, err := url.Parse(httpSrv.URL)
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(backendURL.Host)
	require.NoError(t, err)
	target := net.JoinHostPort("localhost", port)

	// Proxy with HTTP interception enabled and HTTPS interception disabled
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{Type: config.ProxyTypeStandard, ListenAddress: "127.0.0.1:0", Enabled: true},
		},
		TimeoutSeconds: 5,
		Classifiers:    make(map[string]config.Classifier),
		Interception:   config.InterceptionConfig{Enabled: true, HTTP: true, HTTPS: false},
	}
	proxy := NewProxy(cfg)

	// Add a request hook to assert the interceptor path is used
	require.NotEmpty(t, proxy.servers)
	proxy.servers[0].httpInterceptor.AddRequestHook("mark", func(r *http.Request) error {
		r.Header.Set("X-Intercepted", "1")
		return nil
	})

	// Start proxy
	listener, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	require.NoError(t, err)
	proxyAddr := listener.Addr().String()
	go func() {
		if err := proxy.StartWithListener(listener); err != http.ErrServerClosed && err != nil {
			t.Errorf("Proxy server error: %v", err)
		}
	}()
	defer proxy.Stop()

	// Small delay for startup
	time.Sleep(100 * time.Millisecond)

	// Manually perform CONNECT to proxy, then send HTTP request through the tunnel
	conn, err := net.Dial("tcp", proxyAddr)
	require.NoError(t, err)
	defer conn.Close()

	// Send CONNECT request for non-HTTPS target
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	require.NoError(t, err)

	// Read the 200 Connection Established response
	br := bufio.NewReader(conn)
	// A minimal parse: read status line
	statusLine, err := br.ReadString('\n')
	require.NoError(t, err)
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("expected 200 from proxy for CONNECT, got: %q", statusLine)
	}
	// Read until blank line
	for {
		line, err := br.ReadString('\n')
		require.NoError(t, err)
		if line == "\r\n" { // end of headers
			break
		}
	}

	// Send a plaintext HTTP request over the tunnel
	_, err = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", target)
	require.NoError(t, err)

	// Read backend response status line
	respStatus, err := br.ReadString('\n')
	require.NoError(t, err)
	if !strings.Contains(respStatus, "200") {
		t.Fatalf("unexpected backend status via tunnel: %q", respStatus)
	}
	// Drain headers
	for {
		line, err := br.ReadString('\n')
		require.NoError(t, err)
		if line == "\r\n" { // end of headers
			break
		}
	}

	// Read a small body chunk
	buf := make([]byte, 2)
	_, _ = io.ReadFull(br, buf)

	// Verify hook executed (header seen by backend)
	select {
	case ok := <-headerSeen:
		if !ok {
			t.Fatalf("interceptor hook header not observed by backend")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for backend header observation")
	}
}

// TestExcludeClassifierInterception tests that the exclude classifier prevents interception for matching hosts
func TestExcludeClassifierInterception(t *testing.T) {
	// Test shouldInterceptTunnel function directly with different configurations

	// Test 1: No exclude classifier - should intercept
	t.Run("no exclude classifier allows interception", func(t *testing.T) {
		cfg := &config.Config{
			Servers: []config.ServerConfig{
				{
					Type:          config.ProxyTypeStandard,
					ListenAddress: "127.0.0.1:0",
					Enabled:       true,
				},
			},
			Interception: config.InterceptionConfig{
				Enabled: true,
				HTTP:    true,
				HTTPS:   true,
			},
		}

		proxy := NewProxy(cfg)
		server := proxy.servers[0]

		req := &http.Request{
			Method: "CONNECT",
			Host:   "example.com:443",
		}

		shouldIntercept := server.shouldInterceptTunnel(req)
		assert.True(t, shouldIntercept, "Should intercept when no exclude classifier is configured")
	})

	// Test 2: Exclude classifier matches - should NOT intercept
	t.Run("exclude classifier blocks interception for matching host", func(t *testing.T) {
		cfg := &config.Config{
			Servers: []config.ServerConfig{
				{
					Type:          config.ProxyTypeStandard,
					ListenAddress: "127.0.0.1:0",
					Enabled:       true,
				},
			},
			Classifiers: map[string]config.Classifier{
				"exclude-domains": &config.ClassifierDomain{
					Domain: "blocked.com",
					Op:     config.ClassifierOpEqual,
				},
			},
			Interception: config.InterceptionConfig{
				Enabled:           true,
				HTTP:              true,
				HTTPS:             true,
				ExcludeClassifier: &config.ClassifierRef{Id: "exclude-domains"},
			},
		}

		proxy := NewProxy(cfg)
		server := proxy.servers[0]

		// Test with excluded host
		req := &http.Request{
			Method: "CONNECT",
			Host:   "blocked.com:443",
		}

		shouldIntercept := server.shouldInterceptTunnel(req)
		assert.False(t, shouldIntercept, "Should NOT intercept when host matches exclude classifier")
	})

	// Test 3: Exclude classifier doesn't match - should intercept
	t.Run("exclude classifier allows interception for non-matching host", func(t *testing.T) {
		cfg := &config.Config{
			Servers: []config.ServerConfig{
				{
					Type:          config.ProxyTypeStandard,
					ListenAddress: "127.0.0.1:0",
					Enabled:       true,
				},
			},
			Classifiers: map[string]config.Classifier{
				"exclude-domains": &config.ClassifierDomain{
					Domain: "blocked.com",
					Op:     config.ClassifierOpEqual,
				},
			},
			Interception: config.InterceptionConfig{
				Enabled:           true,
				HTTP:              true,
				HTTPS:             true,
				ExcludeClassifier: &config.ClassifierRef{Id: "exclude-domains"},
			},
		}

		proxy := NewProxy(cfg)
		server := proxy.servers[0]

		// Test with non-excluded host
		req := &http.Request{
			Method: "CONNECT",
			Host:   "allowed.com:443",
		}

		shouldIntercept := server.shouldInterceptTunnel(req)
		assert.True(t, shouldIntercept, "Should intercept when host doesn't match exclude classifier")
	})

	// Test 4: Complex exclude classifier with OR logic
	t.Run("exclude classifier with OR logic", func(t *testing.T) {
		cfg := &config.Config{
			Servers: []config.ServerConfig{
				{
					Type:          config.ProxyTypeStandard,
					ListenAddress: "127.0.0.1:0",
					Enabled:       true,
				},
			},
			Classifiers: map[string]config.Classifier{
				"exclude-list": &config.ClassifierOr{
					Classifiers: []config.Classifier{
						&config.ClassifierDomain{
							Domain: "blocked1.com",
							Op:     config.ClassifierOpEqual,
						},
						&config.ClassifierDomain{
							Domain: "blocked2.com",
							Op:     config.ClassifierOpEqual,
						},
					},
				},
			},
			Interception: config.InterceptionConfig{
				Enabled:           true,
				HTTP:              true,
				HTTPS:             true,
				ExcludeClassifier: &config.ClassifierRef{Id: "exclude-list"},
			},
		}

		proxy := NewProxy(cfg)
		server := proxy.servers[0]

		// Test first blocked host
		req1 := &http.Request{Method: "CONNECT", Host: "blocked1.com:443"}
		shouldIntercept1 := server.shouldInterceptTunnel(req1)
		assert.False(t, shouldIntercept1, "Should NOT intercept blocked1.com")

		// Test second blocked host
		req2 := &http.Request{Method: "CONNECT", Host: "blocked2.com:443"}
		shouldIntercept2 := server.shouldInterceptTunnel(req2)
		assert.False(t, shouldIntercept2, "Should NOT intercept blocked2.com")

		// Test allowed host
		req3 := &http.Request{Method: "CONNECT", Host: "allowed.com:443"}
		shouldIntercept3 := server.shouldInterceptTunnel(req3)
		assert.True(t, shouldIntercept3, "Should intercept allowed.com")
	})

	// Test 5: Host with port handling
	t.Run("exclude classifier handles host with port", func(t *testing.T) {
		cfg := &config.Config{
			Servers: []config.ServerConfig{
				{
					Type:          config.ProxyTypeStandard,
					ListenAddress: "127.0.0.1:0",
					Enabled:       true,
				},
			},
			Classifiers: map[string]config.Classifier{
				"exclude-domains": &config.ClassifierDomain{
					Domain: "blocked.com",
					Op:     config.ClassifierOpEqual,
				},
			},
			Interception: config.InterceptionConfig{
				Enabled:           true,
				HTTP:              true,
				HTTPS:             true,
				ExcludeClassifier: &config.ClassifierRef{Id: "exclude-domains"},
			},
		}

		proxy := NewProxy(cfg)
		server := proxy.servers[0]

		// Test with port - should still be excluded (port is stripped)
		req := &http.Request{
			Method: "CONNECT",
			Host:   "blocked.com:8443",
		}

		shouldIntercept := server.shouldInterceptTunnel(req)
		assert.False(t, shouldIntercept, "Should NOT intercept when hostname matches exclude classifier (port should be stripped)")
	})
}

// TestExcludeClassifierDisabled tests behavior when interception is disabled
func TestExcludeClassifierDisabled(t *testing.T) {
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		Classifiers: map[string]config.Classifier{
			"exclude-domains": &config.ClassifierDomain{
				Domain: "blocked.com",
				Op:     config.ClassifierOpEqual,
			},
		},
		Interception: config.InterceptionConfig{
			Enabled:           false, // Interception disabled
			HTTP:              true,
			HTTPS:             true,
			ExcludeClassifier: &config.ClassifierRef{Id: "exclude-domains"},
		},
	}

	proxy := NewProxy(cfg)
	server := proxy.servers[0]

	req := &http.Request{
		Method: "CONNECT",
		Host:   "blocked.com:443",
	}

	shouldIntercept := server.shouldInterceptTunnel(req)
	assert.False(t, shouldIntercept, "Should NOT intercept when interception is globally disabled")
}
