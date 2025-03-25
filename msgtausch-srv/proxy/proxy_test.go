package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	go_socks5 "github.com/armon/go-socks5"
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
		MaxConcurrentConnections: 100,
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
			MaxConcurrentConnections: 100,
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

// setupMockSocks5Server starts a minimal mock SOCKS5 server for testing.
// It listens on a random port, performs a basic handshake (supporting no-auth and user/pass),
// connects to the target specified in the SOCKS5 request, and proxies data.
// Returns the listener address, a function to get connection count, and a cleanup function.
func setupMockSocks5Server(t *testing.T, requiredUser, requiredPass string) (string, func() int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen for mock SOCKS5 server: %v", err)
	}

	var connCount int // atomic? No, test runs sequentially
	connCountLock := &sync.Mutex{}

	getConnCount := func() int {
		connCountLock.Lock()
		defer connCountLock.Unlock()
		return connCount
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				// Check if the error is due to the listener being closed
				if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
					return // Listener closed, exit goroutine
				}
				t.Logf("Mock SOCKS5 server accept error: %v", err)
				return
			}

			connCountLock.Lock()
			connCount++
			connCountLock.Unlock()

			go handleMockSocks5Connection(t, conn, requiredUser, requiredPass)
		}
	}()

	cleanup := func() {
		ln.Close()
	}

	return ln.Addr().String(), getConnCount, cleanup
}

// handleMockSocks5Connection handles a single client connection for the mock server.
func handleMockSocks5Connection(t *testing.T, clientConn net.Conn, requiredUser, requiredPass string) {
	t.Helper()
	defer clientConn.Close()

	// 1. Version identification and method selection
	// Read: [0x05, nMethods, methods...]
	verMethod := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, verMethod); err != nil {
		t.Errorf("Mock SOCKS5: failed to read version/nMethods: %v", err)
		return
	}
	if verMethod[0] != 0x05 { // Version 5
		t.Errorf("Mock SOCKS5: unsupported version %x", verMethod[0])
		return
	}
	nMethods := int(verMethod[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(clientConn, methods); err != nil {
		t.Errorf("Mock SOCKS5: failed to read methods: %v", err)
		return
	}

	// Choose authentication method
	var chosenMethod byte = 0xFF // No acceptable methods initially
	hasUserPassAuth := false
	hasNoAuth := false
	for _, method := range methods {
		if method == 0x02 { // Username/Password
			hasUserPassAuth = true
		}
		if method == 0x00 { // No Authentication
			hasNoAuth = true
		}
	}

	if requiredUser != "" && hasUserPassAuth {
		chosenMethod = 0x02
	} else if requiredUser == "" && hasNoAuth {
		chosenMethod = 0x00
	} else {
		// Client didn't offer a suitable method
		chosenMethod = 0xFF // No acceptable methods
	}

	// Write: [0x05, chosenMethod]
	if _, err := clientConn.Write([]byte{0x05, chosenMethod}); err != nil {
		t.Errorf("Mock SOCKS5: failed to write method selection: %v", err)
		return
	}

	if chosenMethod == 0xFF {
		t.Logf("Mock SOCKS5: No acceptable authentication method offered by client.")
		return // Close connection
	}

	// 2. Authentication (if Username/Password chosen)
	if chosenMethod == 0x02 {
		// Read: [0x01, userLen, username, passLen, password]
		authHeader := make([]byte, 2)
		if _, err := io.ReadFull(clientConn, authHeader); err != nil {
			t.Errorf("Mock SOCKS5: failed to read auth header: %v", err)
			return
		}
		if authHeader[0] != 0x01 { // Auth version 1
			t.Errorf("Mock SOCKS5: unsupported auth version %x", authHeader[0])
			return
		}
		userLen := int(authHeader[1])
		userBuf := make([]byte, userLen)
		if _, err := io.ReadFull(clientConn, userBuf); err != nil {
			t.Errorf("Mock SOCKS5: failed to read username: %v", err)
			return
		}
		username := string(userBuf)

		passLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(clientConn, passLenBuf); err != nil {
			t.Errorf("Mock SOCKS5: failed to read passLen: %v", err)
			return
		}
		passLen := int(passLenBuf[0])
		passBuf := make([]byte, passLen)
		if _, err := io.ReadFull(clientConn, passBuf); err != nil {
			t.Errorf("Mock SOCKS5: failed to read password: %v", err)
			return
		}
		password := string(passBuf)

		// Validate credentials
		authStatus := byte(0x01) // General failure
		if username == requiredUser && password == requiredPass {
			authStatus = 0x00 // Success
		}

		// Write: [0x01, authStatus]
		if _, err := clientConn.Write([]byte{0x01, authStatus}); err != nil {
			t.Errorf("Mock SOCKS5: failed to write auth status: %v", err)
			return
		}
		if authStatus != 0x00 {
			t.Logf("Mock SOCKS5: Authentication failed for user '%s'", username)
			return // Close connection
		}
		t.Logf("Mock SOCKS5: Authentication successful for user '%s'", username)
	}

	// 3. Connection Request
	// Read: [0x05, cmd, 0x00, atyp, addr..., port...]
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, reqHeader); err != nil {
		t.Errorf("Mock SOCKS5: failed to read request header: %v", err)
		return
	}
	if reqHeader[0] != 0x05 { // Version 5
		t.Errorf("Mock SOCKS5: invalid request version %x", reqHeader[0])
		return
	}
	if reqHeader[1] != 0x01 { // CMD = CONNECT
		t.Errorf("Mock SOCKS5: unsupported command %x", reqHeader[1])
		// Reply: Command not supported
		clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Assuming IPv4 bind addr
		return
	}

	var targetHost string
	atyp := reqHeader[3]
	switch atyp {
	case 0x01: // IPv4
		ip := make(net.IP, 4)
		if _, err := io.ReadFull(clientConn, ip); err != nil {
			t.Errorf("Mock SOCKS5: failed to read IPv4 address: %v", err)
			return
		}
		targetHost = ip.String()
	case 0x03: // Domain name
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(clientConn, lenBuf); err != nil {
			t.Errorf("Mock SOCKS5: failed to read domain length: %v", err)
			return
		}
		domainBuf := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(clientConn, domainBuf); err != nil {
			t.Errorf("Mock SOCKS5: failed to read domain: %v", err)
			return
		}
		targetHost = string(domainBuf)
	case 0x04: // IPv6
		ip := make(net.IP, 16)
		if _, err := io.ReadFull(clientConn, ip); err != nil {
			t.Errorf("Mock SOCKS5: failed to read IPv6 address: %v", err)
			return
		}
		targetHost = "[" + ip.String() + "]" // Needs brackets for net.JoinHostPort
	default:
		t.Errorf("Mock SOCKS5: unsupported address type %x", atyp)
		// Reply: Address type not supported
		clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, portBuf); err != nil {
		t.Errorf("Mock SOCKS5: failed to read port: %v", err)
		return
	}
	targetPort := binary.BigEndian.Uint16(portBuf)
	targetAddr := net.JoinHostPort(targetHost, fmt.Sprintf("%d", targetPort))

	t.Logf("Mock SOCKS5: Received CONNECT request for %s", targetAddr)

	// 4. Connect to the actual target
	targetConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		t.Logf("Mock SOCKS5: Failed to connect to target %s: %v", targetAddr, err)
		// Determine appropriate reply code based on error (e.g., Host unreachable)
		replyCode := byte(0x01) // General server failure
		if opErr, ok := err.(*net.OpError); ok {
			if sysErr, ok := opErr.Err.(*os.SyscallError); ok {
				if sysErr.Err == syscall.ECONNREFUSED {
					replyCode = 0x05 // Connection refused
				} else if sysErr.Err == syscall.EHOSTUNREACH {
					replyCode = 0x04 // Host unreachable
				} else if sysErr.Err == syscall.ENETUNREACH {
					replyCode = 0x03 // Network unreachable
				}
			}
		}
		clientConn.Write([]byte{0x05, replyCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Assuming IPv4 bind addr
		return
	}
	defer targetConn.Close()
	t.Logf("Mock SOCKS5: Successfully connected to target %s", targetAddr)

	// 5. Send success reply to client
	// Reply: [0x05, 0x00, 0x00, atyp, bindAddr..., bindPort...]
	// Use 0.0.0.0:0 for bind address/port as we don't need specifics
	bindAddr := []byte{0, 0, 0, 0}
	bindPort := []byte{0, 0}
	reply := []byte{0x05, 0x00, 0x00, 0x01} // Assuming IPv4 bind addr
	reply = append(reply, bindAddr...)
	reply = append(reply, bindPort...)
	if _, err := clientConn.Write(reply); err != nil {
		t.Errorf("Mock SOCKS5: failed to write success reply: %v", err)
		return
	}

	// 6. Proxy data bidirectionally
	t.Logf("Mock SOCKS5: Starting data proxy between client and %s", targetAddr)
	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(targetConn, clientConn)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, targetConn)
		errChan <- err
	}()

	// Wait for copying to finish
	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil && err != io.EOF {
			t.Logf("Mock SOCKS5: proxy copy error: %v", err)
		}
	}
	t.Logf("Mock SOCKS5: Data proxy finished for %s", targetAddr)
}

// TestIsHostAllowed tests the host filtering functionality with classifiers,
// including the new allowlist and blocklist features.
func TestIsHostAllowed(t *testing.T) {
	// Create test configs with different IP classifiers
	tests := []struct {
		name       string
		config     *config.Config
		host       string
		remoteIP   string
		remotePort uint16
		expected   bool
	}{
		{
			name: "No classifiers - allow all",
			config: &config.Config{
				Classifiers: map[string]config.Classifier{},
			},
			host:       "example.com",
			remoteIP:   "192.168.1.1",
			remotePort: 443,
			expected:   true,
		},
		// New tests for allowlist functionality
		{
			name: "Allowlist - host allowed",
			config: func() *config.Config {
				cf := &config.Config{}
				cf.Allowlist = &config.ClassifierDomain{
					Domain: "example.com",
					Op:     config.ClassifierOpEqual,
				}
				return cf
			}(),
			host:       "example.com",
			remoteIP:   "192.168.1.1",
			remotePort: 443,
			expected:   true,
		},
		{
			name: "Allowlist - host not allowed",
			config: func() *config.Config {
				cf := &config.Config{}
				cf.Allowlist = &config.ClassifierDomain{
					Domain: "example.com",
					Op:     config.ClassifierOpEqual,
				}
				return cf
			}(),
			host:       "other.com",
			remoteIP:   "192.168.1.1",
			remotePort: 443,
			expected:   false,
		},
		{
			name: "Allowlist with OR - any match allowed",
			config: func() *config.Config {
				cf := &config.Config{}
				cf.Allowlist = &config.ClassifierOr{
					Classifiers: []config.Classifier{
						&config.ClassifierDomain{
							Domain: "example.com",
							Op:     config.ClassifierOpEqual,
						},
						&config.ClassifierDomain{
							Domain: "test.com",
							Op:     config.ClassifierOpEqual,
						},
					},
				}
				return cf
			}(),
			host:       "test.com",
			remoteIP:   "192.168.1.1",
			remotePort: 443,
			expected:   true,
		},
		// New tests for blocklist functionality
		{
			name: "Blocklist - host blocked",
			config: func() *config.Config {
				cf := &config.Config{
					// No classifiers, so normally would allow all
					Classifiers: map[string]config.Classifier{},
				}
				cf.Blocklist = &config.ClassifierDomain{
					Domain: "example.com",
					Op:     config.ClassifierOpEqual,
				}
				return cf
			}(),
			host:       "example.com",
			remoteIP:   "192.168.1.1",
			remotePort: 443,
			expected:   false,
		},
		{
			name: "Blocklist - host not blocked",
			config: func() *config.Config {
				cf := &config.Config{
					// No classifiers, so normally would allow all
					Classifiers: map[string]config.Classifier{},
				}
				cf.Blocklist = &config.ClassifierDomain{
					Domain: "example.com",
					Op:     config.ClassifierOpEqual,
				}
				return cf
			}(),
			host:       "other.com",
			remoteIP:   "192.168.1.1",
			remotePort: 443,
			expected:   true,
		},
		// Test for blocklist and allowlist together
		{
			name: "Blocklist overrides Allowlist - host blocked",
			config: func() *config.Config {
				cf := &config.Config{}
				cf.Blocklist = &config.ClassifierDomain{
					Domain: "example.com",
					Op:     config.ClassifierOpEqual,
				}
				cf.Allowlist = &config.ClassifierDomain{
					Domain: "example.com", // Same domain in allowlist
					Op:     config.ClassifierOpEqual,
				}
				return cf
			}(),
			host:       "example.com",
			remoteIP:   "192.168.1.1",
			remotePort: 443,
			expected:   false, // Blocklist takes precedence
		},
		{
			name: "Blocklist and Allowlist - host not in blocklist but in allowlist",
			config: func() *config.Config {
				cf := &config.Config{}
				cf.Blocklist = &config.ClassifierDomain{
					Domain: "bad.com",
					Op:     config.ClassifierOpEqual,
				}
				cf.Allowlist = &config.ClassifierDomain{
					Domain: "example.com",
					Op:     config.ClassifierOpEqual,
				}
				return cf
			}(),
			host:       "example.com",
			remoteIP:   "192.168.1.1",
			remotePort: 443,
			expected:   true,
		},
		{
			name: "Blocklist and Allowlist - host not in blocklist or allowlist",
			config: func() *config.Config {
				cf := &config.Config{}
				cf.Blocklist = &config.ClassifierDomain{
					Domain: "bad.com",
					Op:     config.ClassifierOpEqual,
				}
				cf.Allowlist = &config.ClassifierDomain{
					Domain: "example.com",
					Op:     config.ClassifierOpEqual,
				}
				return cf
			}(),
			host:       "other.com",
			remoteIP:   "192.168.1.1",
			remotePort: 443,
			expected:   false, // Not in allowlist
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewProxy(tt.config)
			result := p.isHostAllowed(tt.host, tt.remoteIP, tt.remotePort)
			if result != tt.expected {
				t.Errorf("isHostAllowed() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestSocks5Forward(t *testing.T) {
	// 1. Setup backend test server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Hello from backend")
	}))
	defer backendServer.Close()
	backendURL, _ := url.Parse(backendServer.URL)
	backendHost := backendURL.Host

	// Test cases
	testCases := []struct {
		name           string
		socksUser      string // "" for no auth
		socksPass      string // "" for no auth
		configUser     string // Configured in msgtausch
		configPass     string // Configured in msgtausch
		expectSuccess  bool
		expectSocksHit bool // Whether the mock SOCKS server should be hit
	}{
		{
			name:           "No Auth Success",
			socksUser:      "",
			socksPass:      "",
			configUser:     "",
			configPass:     "",
			expectSuccess:  true,
			expectSocksHit: true,
		},
		{
			name:           "Auth Success",
			socksUser:      "testuser",
			socksPass:      "testpass",
			configUser:     "testuser",
			configPass:     "testpass",
			expectSuccess:  true,
			expectSocksHit: true,
		},
		{
			name:           "Auth Failure - Wrong Password",
			socksUser:      "testuser",
			socksPass:      "testpass",
			configUser:     "testuser",
			configPass:     "wrongpass",
			expectSuccess:  false, // Expecting 502 Bad Gateway or similar from msgtausch
			expectSocksHit: true,  // Mock server still gets the connection attempt
		},
		{
			name:           "Auth Failure - Missing Credentials in Config",
			socksUser:      "testuser",
			socksPass:      "testpass",
			configUser:     "", // Config doesn't provide creds
			configPass:     "",
			expectSuccess:  false,
			expectSocksHit: true,
		},
		{
			name:       "Auth Failure - Config Has Creds, Server Doesn't Need Them",
			socksUser:  "", // Server needs no auth
			socksPass:  "",
			configUser: "testuser", // But config provides them
			configPass: "testpass",
			// This should still succeed, as msgtausch offers both auth methods (0x00, 0x02)
			// and the mock server will pick 0x00 (no auth).
			expectSuccess:  true,
			expectSocksHit: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 2. Setup Mock SOCKS5 server for this test case
			mockSocksAddr, getSocksConnCount, cleanupSocks := setupMockSocks5Server(t, tc.socksUser, tc.socksPass)
			defer cleanupSocks()

			// 3. Setup msgtausch proxy config
			domainClassifier := config.ClassifierDomain{ // Concrete type
				Op:     config.ClassifierOpEqual,
				Domain: strings.Split(backendHost, ":")[0],
			}
			// Assign concrete type to interface type variable - use pointer!
			var classifierInterface config.Classifier = &domainClassifier
			cfg := &config.Config{
				Servers: []config.ServerConfig{
					{
						Type:          config.ProxyTypeStandard,
						ListenAddress: "127.0.0.1:0", // Dynamic port for msgtausch
						Enabled:       true,
					},
				},
				TimeoutSeconds: 5,
				Classifiers:    map[string]config.Classifier{},
				Forwards: []config.Forward{
					&config.ForwardSocks5{
						ClassifierData: classifierInterface,
						Address:        mockSocksAddr,
						// Use pointers for optional user/pass
						Username: func() *string {
							if tc.configUser == "" {
								return nil
							}
							return &tc.configUser
						}(),
						Password: func() *string {
							if tc.configPass == "" {
								return nil
							}
							return &tc.configPass
						}(),
					},
				},
			}

			// 4. Instantiate and start msgtausch proxy
			proxyServer := NewProxy(cfg)
			proxyLn, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
			require.NoError(t, err, "Failed to listen for msgtausch proxy")
			proxyAddr := proxyLn.Addr().String()
			serverErrChan := make(chan error, 1) // Channel to capture server error

			go func() {
				// Call without context
				err := proxyServer.StartWithListener(proxyLn)
				if err != nil && err != http.ErrServerClosed {
					t.Logf("msgtausch proxy server error: %v", err)
					serverErrChan <- err // Send error to channel
				}
				close(serverErrChan) // Close channel when server stops
			}()
			// Give server time to start
			time.Sleep(100 * time.Millisecond)

			// 5. Create HTTP client configured to use msgtausch
			proxyURL, _ := url.Parse("http://" + proxyAddr)
			httpClient := &http.Client{
				Transport: &http.Transport{
					Proxy: http.ProxyURL(proxyURL),
					// Disable TLS verification for the backend test server (it uses self-signed cert)
					// This isn't strictly needed for HTTP, but good practice if backend was HTTPS
					// TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
					DialContext: (&net.Dialer{ // Shorter timeout for testing
						Timeout: 3 * time.Second,
					}).DialContext,
				},
				Timeout: 5 * time.Second,
			}

			// 6. Make request to backend via msgtausch
			req, err := http.NewRequest("GET", backendServer.URL, http.NoBody)
			require.NoError(t, err)
			resp, err := httpClient.Do(req)

			// 7. Assertions
			if tc.expectSuccess {
				require.NoError(t, err, "Request via proxy failed unexpectedly")
				require.NotNil(t, resp, "Response should not be nil on success")
				assert.Equal(t, http.StatusOK, resp.StatusCode, "Expected OK status from backend")
				bodyBytes, _ := io.ReadAll(resp.Body)
				assert.Equal(t, "Hello from backend", string(bodyBytes), "Expected correct body from backend")
			} else {
				// We expect msgtausch to fail the connection or return an error status
				if err != nil {
					// This is okay, could be a dial error if SOCKS auth failed immediately
					t.Logf("Received expected error: %v", err)
					assert.Error(t, err, "Expected an error when request should fail")
				} else {
					// Or msgtausch might return a gateway error status code
					require.NotNil(t, resp, "Response should not be nil even on expected failure")
					defer resp.Body.Close()
					t.Logf("Received status code %d on expected failure", resp.StatusCode)
					assert.True(t, resp.StatusCode >= 500, "Expected status code >= 500 on failure, got %d", resp.StatusCode)
				}
			}

			// 8. Check if mock SOCKS server was hit
			socksConns := getSocksConnCount()
			if tc.expectSocksHit {
				assert.GreaterOrEqual(t, socksConns, 1, "Expected mock SOCKS server to be hit at least once")
			} else {
				assert.Equal(t, 0, socksConns, "Expected mock SOCKS server *not* to be hit")
			}

			// Explicitly stop the proxy
			proxyServer.Stop()

			// Give a moment for cleanup
			time.Sleep(100 * time.Millisecond)

			// Check if the server goroutine returned an error
			if err := <-serverErrChan; err != nil {
				t.Errorf("Proxy server exited with error: %v", err)
			}
		})
	}
}

func TestSocks5ForwardWithGoSocks5(t *testing.T) {
	// 1. Start a real go-socks5 server (no auth)
	socksServer, err := go_socks5.New(&go_socks5.Config{})
	if err != nil {
		t.Fatalf("Failed to create go-socks5 server: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen for go-socks5: %v", err)
	}
	defer ln.Close()
	go func() { _ = socksServer.Serve(ln) }()

	// 2. Start backend HTTP server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "from-backend")
	}))
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)
	backendHost := backendURL.Host

	// 3. Setup msgtausch config to forward via SOCKS5
	domainClassifier := config.ClassifierDomain{
		Op:     config.ClassifierOpEqual,
		Domain: strings.Split(backendHost, ":")[0],
	}
	var classifierInterface config.Classifier = &domainClassifier
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		TimeoutSeconds: 5,
		Classifiers:    map[string]config.Classifier{},
		Forwards: []config.Forward{
			&config.ForwardSocks5{
				ClassifierData: classifierInterface,
				Address:        ln.Addr().String(),
			},
		},
	}

	proxyServer := NewProxy(cfg)
	proxyLn, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	require.NoError(t, err)
	defer proxyLn.Close()
	serverErrChan := make(chan error, 1)
	go func() {
		err := proxyServer.StartWithListener(proxyLn)
		if err != nil && err != http.ErrServerClosed {
			serverErrChan <- err
		}
		close(serverErrChan)
	}()
	t.Cleanup(func() { proxyServer.Stop() })
	time.Sleep(100 * time.Millisecond)

	// 4. Make HTTP request via msgtausch (which uses go-socks5)
	proxyURL, _ := url.Parse("http://" + proxyLn.Addr().String())
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			DialContext: (&net.Dialer{
				Timeout: 3 * time.Second,
			}).DialContext,
		},
		Timeout: 5 * time.Second,
	}
	resp, err := httpClient.Get(backend.URL)
	require.NoError(t, err, "Request via msgtausch proxy and go-socks5 failed")
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "from-backend")
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
		MaxConcurrentConnections: 10,
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
		MaxConcurrentConnections: 10,
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
	skippedHeaders := map[string]struct{}{
		"Proxy-Connection":    {},
		"Connection":          {},
		"Keep-Alive":          {},
		"Proxy-Authenticate":  {},
		"Proxy-Authorization": {},
		"Te":                  {},
		"Trailer":             {},
		"Transfer-Encoding":   {},
		"Upgrade":             {},
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
		MaxConcurrentConnections: 10,
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
		MaxConcurrentConnections: 10,
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

// TestSimpleForwardClassifier tests a simple forward with classifier
func TestSimpleForwardClassifier(t *testing.T) {
	// Setup a backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "backend-response")
	}))
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)

	// Setup mock SOCKS5 server
	mockSocksAddr, getSocksConnCount, cleanupSocks := setupMockSocks5Server(t, "", "")
	defer cleanupSocks()

	// Create classifier that matches the backend hostname (without port)
	classifier := &config.ClassifierDomain{
		Domain: strings.Split(backendURL.Host, ":")[0], // Use only hostname part
		Op:     config.ClassifierOpEqual,
	}

	// Setup proxy config with single forward
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		TimeoutSeconds: 5,
		Classifiers:    map[string]config.Classifier{},
		Forwards: []config.Forward{
			&config.ForwardSocks5{
				ClassifierData: classifier,
				Address:        mockSocksAddr,
			},
		},
	}

	// Start proxy
	proxyServer := NewProxy(cfg)
	proxyLn, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	require.NoError(t, err, "Failed to listen for proxy")
	proxyAddr := proxyLn.Addr().String()

	go func() {
		err := proxyServer.StartWithListener(proxyLn)
		if err != nil && err != http.ErrServerClosed {
			t.Logf("proxy server error: %v", err)
		}
	}()
	defer proxyServer.Stop()
	time.Sleep(100 * time.Millisecond)

	// Create HTTP client
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			DialContext: (&net.Dialer{
				Timeout: 3 * time.Second,
			}).DialContext,
		},
		Timeout: 5 * time.Second,
	}

	t.Logf("Backend running on %s, SOCKS proxy on %s", backendURL.Host, mockSocksAddr)

	// Test: Request should go through SOCKS5
	initialSocksCount := getSocksConnCount()

	resp, err := httpClient.Get(backend.URL)
	require.NoError(t, err, "Request failed")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "backend-response", string(body))

	// Verify SOCKS5 was used
	finalSocksCount := getSocksConnCount()
	t.Logf("SOCKS connections: initial=%d, final=%d", initialSocksCount, finalSocksCount)
	assert.Greater(t, finalSocksCount, initialSocksCount, "SOCKS5 server should have been used")
}

// TestMultipleForwardsWithDomainClassifiers tests multiple forwards with different domain classifiers
func TestMultipleForwardsWithDomainClassifiers(t *testing.T) {
	// This test is simplified to demonstrate the concept since all test servers use 127.0.0.1
	// In practice, different forwards would route to different domains

	// Setup backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "backend-response")
	}))
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)

	// Setup two mock SOCKS5 servers
	mockSocks1Addr, getSocks1ConnCount, cleanupSocks1 := setupMockSocks5Server(t, "", "")
	defer cleanupSocks1()

	mockSocks2Addr, getSocks2ConnCount, cleanupSocks2 := setupMockSocks5Server(t, "", "")
	defer cleanupSocks2()

	// Create classifiers - use hostname matching since all test servers use 127.0.0.1
	classifier1 := &config.ClassifierDomain{
		Domain: "127.0.0.1", // All our test servers use this
		Op:     config.ClassifierOpEqual,
	}

	// This classifier will never match in our test setup
	classifier2 := &config.ClassifierDomain{
		Domain: "example.com", // This won't match our test server
		Op:     config.ClassifierOpEqual,
	}

	// Setup proxy config with multiple forwards
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		TimeoutSeconds: 5,
		Classifiers:    map[string]config.Classifier{},
		Forwards: []config.Forward{
			// Forward 1: Routes 127.0.0.1 to SOCKS5 server 1 (will match)
			&config.ForwardSocks5{
				ClassifierData: classifier1,
				Address:        mockSocks1Addr,
			},
			// Forward 2: Routes example.com to SOCKS5 server 2 (won't match)
			&config.ForwardSocks5{
				ClassifierData: classifier2,
				Address:        mockSocks2Addr,
			},
			// Forward 3: Default network for anything else
			&config.ForwardDefaultNetwork{
				ClassifierData: &config.ClassifierTrue{},
			},
		},
	}

	// Start proxy
	proxyServer := NewProxy(cfg)
	proxyLn, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	require.NoError(t, err, "Failed to listen for proxy")
	proxyAddr := proxyLn.Addr().String()

	go func() {
		err := proxyServer.StartWithListener(proxyLn)
		if err != nil && err != http.ErrServerClosed {
			t.Logf("proxy server error: %v", err)
		}
	}()
	defer proxyServer.Stop()
	time.Sleep(100 * time.Millisecond)

	// Create HTTP client
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			DialContext: (&net.Dialer{
				Timeout: 3 * time.Second,
			}).DialContext,
		},
		Timeout: 5 * time.Second,
	}

	t.Logf("Backend running on %s", backendURL.Host)
	t.Logf("SOCKS1 proxy on %s", mockSocks1Addr)
	t.Logf("SOCKS2 proxy on %s", mockSocks2Addr)

	// Test: Request should go through SOCKS5 server 1 since it matches 127.0.0.1
	initialSocks1Count := getSocks1ConnCount()
	initialSocks2Count := getSocks2ConnCount()

	resp, err := httpClient.Get(backend.URL)
	require.NoError(t, err, "Request failed")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "backend-response", string(body))

	// Verify SOCKS5 server 1 was used, SOCKS5 server 2 was not
	finalSocks1Count := getSocks1ConnCount()
	finalSocks2Count := getSocks2ConnCount()

	t.Logf("SOCKS1 connections: initial=%d, final=%d", initialSocks1Count, finalSocks1Count)
	t.Logf("SOCKS2 connections: initial=%d, final=%d", initialSocks2Count, finalSocks2Count)

	assert.Greater(t, finalSocks1Count, initialSocks1Count, "SOCKS5 server 1 should have been used")
	assert.Equal(t, initialSocks2Count, finalSocks2Count, "SOCKS5 server 2 should NOT have been used")
}

// TestMultipleForwardsWithClassifiers tests that the proxy correctly routes traffic
// based on classifiers when multiple forwards are configured
func TestMultipleForwardsWithClassifiers(t *testing.T) {
	// Setup multiple backend servers to represent different targets
	backend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "backend1-response")
	}))
	defer backend1.Close()
	backend1URL, _ := url.Parse(backend1.URL)

	backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "backend2-response")
	}))
	defer backend2.Close()
	backend2URL, _ := url.Parse(backend2.URL)

	// Setup two mock SOCKS5 servers
	mockSocks1Addr, getSocks1ConnCount, cleanupSocks1 := setupMockSocks5Server(t, "", "")
	defer cleanupSocks1()

	mockSocks2Addr, getSocks2ConnCount, cleanupSocks2 := setupMockSocks5Server(t, "", "")
	defer cleanupSocks2()

	// Create classifiers for routing using domain-based classification
	// Extract hostnames (without port) - all test servers use 127.0.0.1 so we need port-based classification instead
	backend1Port, _ := strconv.Atoi(strings.Split(backend1URL.Host, ":")[1])
	backend2Port, _ := strconv.Atoi(strings.Split(backend2URL.Host, ":")[1])

	classifier1 := &config.ClassifierPort{
		Port: backend1Port,
	}

	classifier2 := &config.ClassifierPort{
		Port: backend2Port,
	}

	// Setup msgtausch proxy with multiple forwards
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		TimeoutSeconds: 5,
		Classifiers:    map[string]config.Classifier{},
		Forwards: []config.Forward{
			// Forward 1: Routes backend1Port to SOCKS5 server 1
			&config.ForwardSocks5{
				ClassifierData: classifier1,
				Address:        mockSocks1Addr,
			},
			// Forward 2: Routes backend2Port to SOCKS5 server 2
			&config.ForwardSocks5{
				ClassifierData: classifier2,
				Address:        mockSocks2Addr,
			},
			// Forward 3: Default network for anything else
			&config.ForwardDefaultNetwork{
				ClassifierData: &config.ClassifierTrue{},
			},
		},
	}

	// Start msgtausch proxy
	proxyServer := NewProxy(cfg)
	proxyLn, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	require.NoError(t, err, "Failed to listen for msgtausch proxy")
	proxyAddr := proxyLn.Addr().String()

	go func() {
		err := proxyServer.StartWithListener(proxyLn)
		if err != nil && err != http.ErrServerClosed {
			t.Logf("msgtausch proxy server error: %v", err)
		}
	}()
	defer proxyServer.Stop()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Create HTTP client configured to use msgtausch
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			DialContext: (&net.Dialer{
				Timeout: 3 * time.Second,
			}).DialContext,
		},
		Timeout: 5 * time.Second,
	}

	// Log the backend addresses for debugging
	t.Logf("Backend1 running on %s (port %d), Backend2 running on %s (port %d)",
		backend1URL.Host, backend1Port, backend2URL.Host, backend2Port)
	t.Logf("SOCKS1 proxy on %s, SOCKS2 proxy on %s", mockSocks1Addr, mockSocks2Addr)

	// Test 1: Request to backend1 should go through SOCKS5 server 1
	t.Run("Backend1 routes through SOCKS5 server 1", func(t *testing.T) {
		// Get baseline connection counts
		baselineSocks1Count := getSocks1ConnCount()
		baselineSocks2Count := getSocks2ConnCount()

		// Make request to backend1
		resp, err := httpClient.Get(backend1.URL)
		require.NoError(t, err, "Request to backend1 failed")
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "backend1-response", string(body))

		// Verify that SOCKS5 server 1 was used
		finalSocks1Count := getSocks1ConnCount()
		finalSocks2Count := getSocks2ConnCount()

		t.Logf("SOCKS1 connections: baseline=%d, final=%d", baselineSocks1Count, finalSocks1Count)
		t.Logf("SOCKS2 connections: baseline=%d, final=%d", baselineSocks2Count, finalSocks2Count)

		assert.Greater(t, finalSocks1Count, baselineSocks1Count, "SOCKS5 server 1 should have been used")
		assert.Equal(t, baselineSocks2Count, finalSocks2Count, "SOCKS5 server 2 should NOT have been used")
	})

	// Test 2: Request to backend2 should go through SOCKS5 server 2
	t.Run("Backend2 routes through SOCKS5 server 2", func(t *testing.T) {
		// Get baseline connection counts
		baselineSocks1Count := getSocks1ConnCount()
		baselineSocks2Count := getSocks2ConnCount()

		// Make request to backend2
		resp, err := httpClient.Get(backend2.URL)
		require.NoError(t, err, "Request to backend2 failed")
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "backend2-response", string(body))

		// Verify that SOCKS5 server 2 was used
		finalSocks1Count := getSocks1ConnCount()
		finalSocks2Count := getSocks2ConnCount()

		t.Logf("SOCKS1 connections: baseline=%d, final=%d", baselineSocks1Count, finalSocks1Count)
		t.Logf("SOCKS2 connections: baseline=%d, final=%d", baselineSocks2Count, finalSocks2Count)

		assert.Equal(t, baselineSocks1Count, finalSocks1Count, "SOCKS5 server 1 should NOT have been used")
		assert.Greater(t, finalSocks2Count, baselineSocks2Count, "SOCKS5 server 2 should have been used")
	})

	// Test 3: Request to unknown host should use default network (direct connection)
	t.Run("Unknown host uses default network", func(t *testing.T) {
		// Create a third backend server for testing default routing
		backend3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "backend3-direct")
		}))
		defer backend3.Close()

		// Get baseline connection counts
		baselineSocks1Count := getSocks1ConnCount()
		baselineSocks2Count := getSocks2ConnCount()

		// Make request to backend3 (should not match any classifier)
		resp, err := httpClient.Get(backend3.URL)
		require.NoError(t, err, "Request to backend3 failed")
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "backend3-direct", string(body))

		// Verify that neither SOCKS5 server was used (direct connection)
		finalSocks1Count := getSocks1ConnCount()
		finalSocks2Count := getSocks2ConnCount()

		t.Logf("SOCKS1 connections: baseline=%d, final=%d", baselineSocks1Count, finalSocks1Count)
		t.Logf("SOCKS2 connections: baseline=%d, final=%d", baselineSocks2Count, finalSocks2Count)

		assert.Equal(t, baselineSocks1Count, finalSocks1Count, "SOCKS5 server 1 should NOT have been used for direct connection")
		assert.Equal(t, baselineSocks2Count, finalSocks2Count, "SOCKS5 server 2 should NOT have been used for direct connection")
	})
}

// TestForwardClassifierWithPortAndDomain tests more complex classifier scenarios
func TestForwardClassifierWithPortAndDomain(t *testing.T) {
	// Setup backend servers on different ports
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "backend-response")
	}))
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)
	backendHost := strings.Split(backendURL.Host, ":")[0]
	backendPortStr := strings.Split(backendURL.Host, ":")[1]
	backendPort, _ := strconv.Atoi(backendPortStr)

	// Setup mock SOCKS5 server
	mockSocksAddr, getSocksConnCount, cleanupSocks := setupMockSocks5Server(t, "", "")
	defer cleanupSocks()

	// Create AND classifier: domain AND port
	andClassifier := &config.ClassifierAnd{
		Classifiers: []config.Classifier{
			&config.ClassifierDomain{
				Domain: backendHost,
				Op:     config.ClassifierOpEqual,
			},
			&config.ClassifierPort{
				Port: backendPort,
			},
		},
	}

	// Setup msgtausch proxy
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		TimeoutSeconds: 5,
		Classifiers:    map[string]config.Classifier{},
		Forwards: []config.Forward{
			// Forward only if both domain AND port match
			&config.ForwardSocks5{
				ClassifierData: andClassifier,
				Address:        mockSocksAddr,
			},
			// Default network for everything else
			&config.ForwardDefaultNetwork{
				ClassifierData: &config.ClassifierTrue{},
			},
		},
	}

	// Start proxy
	proxyServer := NewProxy(cfg)
	proxyLn, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	require.NoError(t, err)
	proxyAddr := proxyLn.Addr().String()

	go func() {
		err := proxyServer.StartWithListener(proxyLn)
		if err != nil && err != http.ErrServerClosed {
			t.Logf("proxy server error: %v", err)
		}
	}()
	defer proxyServer.Stop()
	time.Sleep(100 * time.Millisecond)

	// Create HTTP client
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			DialContext: (&net.Dialer{
				Timeout: 3 * time.Second,
			}).DialContext,
		},
		Timeout: 5 * time.Second,
	}

	t.Run("AND classifier matches both domain and port", func(t *testing.T) {
		initialSocksCount := getSocksConnCount()

		// Make request to backend (should match both domain and port)
		resp, err := httpClient.Get(backend.URL)
		require.NoError(t, err, "Request failed")
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "backend-response", string(body))

		// Verify SOCKS5 was used
		finalSocksCount := getSocksConnCount()
		assert.Greater(t, finalSocksCount, initialSocksCount, "SOCKS5 server should have been used for matching AND classifier")
	})

	t.Run("Different port does not match AND classifier", func(t *testing.T) {
		// Create another backend on a different port
		backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "backend2-direct")
		}))
		defer backend2.Close()

		initialSocksCount := getSocksConnCount()

		// Make request to backend2 (different port, so AND classifier should not match)
		resp, err := httpClient.Get(backend2.URL)
		require.NoError(t, err, "Request to backend2 failed")
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "backend2-direct", string(body))

		// Verify SOCKS5 was NOT used (should use default network)
		finalSocksCount := getSocksConnCount()
		assert.Equal(t, initialSocksCount, finalSocksCount, "SOCKS5 server should NOT have been used for non-matching AND classifier")
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
