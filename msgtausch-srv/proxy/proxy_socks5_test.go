package proxy

import (
	"encoding/binary"
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
)

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
				// Avoid using t.Logf in goroutine after test completion
				// Use standard output to record the accept error for debugging
				fmt.Printf("Mock SOCKS5 server accept error: %v\n", err)
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
	// Avoid using t.Logf in goroutine: print to stdout for debug
	fmt.Printf("Mock SOCKS5: Successfully connected to target %s\n", targetAddr)

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
	fmt.Printf("Mock SOCKS5: Starting data proxy between client and %s\n", targetAddr)
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
			fmt.Printf("Mock SOCKS5: proxy copy error: %v\n", err)
		}
	}
	fmt.Printf("Mock SOCKS5: Data proxy finished for %s\n", targetAddr)
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
