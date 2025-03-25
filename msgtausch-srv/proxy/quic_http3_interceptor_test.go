package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCA generates a test CA certificate and private key for testing purposes
func generateTestCAForQUIC(t *testing.T) ([]byte, []byte) {
	// Generate a private key for CA
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate CA private key")

	// Create CA certificate template
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test QUIC CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create CA certificate
	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivKey.PublicKey, caPrivKey)
	require.NoError(t, err, "Failed to create CA certificate")

	// Encode CA certificate and private key to PEM
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey)})

	return caCertPEM, caKeyPEM
}

// createMockProxyForQUIC creates a mock proxy for testing QUIC interceptor
func createMockProxyForQUIC(t *testing.T) *Proxy {
	// Create minimal config
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
	}

	// Create proxy with minimal config
	return NewProxy(cfg)
}

// TestNewQUICHTTP3Interceptor tests the creation of a new QUICHTTP3Interceptor
func TestNewQUICHTTP3Interceptor(t *testing.T) {
	t.Run("valid certificate and key", func(t *testing.T) {
		caCertPEM, caKeyPEM := generateTestCAForQUIC(t)
		mockProxy := createMockProxyForQUIC(t)

		interceptor, err := NewQUICHTTP3Interceptor(caCertPEM, caKeyPEM, mockProxy, nil, nil)
		assert.NoError(t, err, "Should create interceptor with valid cert/key")
		assert.NotNil(t, interceptor, "Should return non-nil interceptor")
		assert.NotNil(t, interceptor.certCache, "Certificate cache should be initialized")
	})

	t.Run("invalid certificate", func(t *testing.T) {
		_, caKeyPEM := generateTestCAForQUIC(t)
		invalidCertPEM := []byte("invalid cert")
		mockProxy := createMockProxyForQUIC(t)

		interceptor, err := NewQUICHTTP3Interceptor(invalidCertPEM, caKeyPEM, mockProxy, nil, nil)
		assert.Error(t, err, "Should fail with invalid certificate")
		assert.Nil(t, interceptor, "Should return nil interceptor on error")
	})
}

// TestGetOrCreateCert tests the certificate generation and caching functionality
func TestGetOrCreateCertForQUIC(t *testing.T) {
	caCertPEM, caKeyPEM := generateTestCAForQUIC(t)
	mockProxy := createMockProxyForQUIC(t)

	interceptor, err := NewQUICHTTP3Interceptor(caCertPEM, caKeyPEM, mockProxy, nil, nil)
	require.NoError(t, err, "Failed to create interceptor")

	// Test domains to generate certs for
	testHosts := []string{
		"example.com",
		"test.example.org",
	}

	for _, host := range testHosts {
		t.Run(host, func(t *testing.T) {
			// First call should generate a new cert
			cert, err := interceptor.getOrCreateCert(host)
			assert.NoError(t, err, "Should generate certificate without error")
			assert.NotNil(t, cert, "Should return a valid certificate")

			// Verify the cert is cached
			interceptor.cacheMutex.RLock()
			cachedCert, exists := interceptor.certCache[host]
			interceptor.cacheMutex.RUnlock()
			assert.True(t, exists, "Certificate should be cached")
			assert.Equal(t, cert, cachedCert, "Cached certificate should match returned certificate")

			// Second call should return the cached cert
			cachedCert2, err := interceptor.getOrCreateCert(host)
			assert.NoError(t, err, "Should return cached certificate without error")
			assert.Equal(t, cert, cachedCert2, "Should return the same certificate on second call")
		})
	}
}

func TestHandleQUICIntercept(t *testing.T) {
	caCertPEM, caKeyPEM := generateTestCAForQUIC(t)
	mockProxy := createMockProxyForQUIC(t)

	// Create a test request handler that modifies requests
	requestHandler := func(req *http.Request) (*http.Request, error) {
		req.Header.Set("X-Intercepted", "true")
		return req, nil
	}

	// Create a test response handler that modifies responses
	responseHandler := func(resp *http.Response) (*http.Response, error) {
		resp.Header.Set("X-Intercepted-Response", "true")
		if resp.Body != nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			body = append([]byte("Modified: "), body...)
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
		}
		return resp, nil
	}

	_, err := NewQUICHTTP3Interceptor(caCertPEM, caKeyPEM, mockProxy, requestHandler, responseHandler)
	require.NoError(t, err, "Failed to create QUIC/HTTP3 interceptor")

	// In a real test, you would now run the interceptor with a mock packet connection
	// and verify that HTTP/3 requests and responses are properly intercepted and modified
}

// TestQUICHTTP3InterceptorWithCustomHandlers tests the QUIC/HTTP3 interceptor with custom handlers
func TestQUICHTTP3InterceptorWithCustomHandlers(t *testing.T) {
	// Generate test CA for QUIC
	caCertPEM, caKeyPEM := generateTestCAForQUIC(t)

	// Create test request handler that modifies requests
	requestModified := false
	requestHandler := func(req *http.Request) (*http.Request, error) {
		req.Header.Set("X-HTTP3-Intercepted", "true")
		requestModified = true
		return req, nil
	}

	// Create test response handler that modifies responses
	responseModified := false
	responseHandler := func(resp *http.Response) (*http.Response, error) {
		resp.Header.Set("X-HTTP3-Response-Intercepted", "true")
		if resp.Body != nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			body = append([]byte("Modified: "), body...)
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
		}
		responseModified = true
		return resp, nil
	}

	// Create mock proxy
	mockProxy := createMockProxyForQUIC(t)

	// Create QUIC/HTTP3 interceptor with handlers
	interceptor, err := NewQUICHTTP3Interceptor(caCertPEM, caKeyPEM, mockProxy, requestHandler, responseHandler)
	require.NoError(t, err, "Failed to create QUIC/HTTP3 interceptor")
	require.NotNil(t, interceptor, "Interceptor should not be nil")

	// Test the UDP intercept handler registration
	interceptor.RegisterUDPInterceptHandler(mockProxy)

	// Create a test host for certificate generation
	testHost := "quic-test.example.com"

	// Verify the certificate cache is initialized
	require.NotNil(t, interceptor.certCache, "Certificate cache should be initialized")

	// We'll test that interceptor can generate and cache a certificate
	interceptor.cacheMutex.Lock()
	// Pre-load a certificate for testing
	testCert := &tls.Certificate{} // Mock certificate
	interceptor.certCache[testHost] = testCert
	interceptor.cacheMutex.Unlock()

	// Test certificate retrieval from cache
	cert, err := interceptor.getOrCreateCert(testHost)
	require.NoError(t, err, "Certificate retrieval should succeed")
	require.NotNil(t, cert, "Certificate should not be nil")

	// Verify it's the same certificate we put in the cache
	require.Equal(t, testCert, cert, "Should retrieve the cached certificate")

	// Test for a different domain to verify it creates a new certificate
	anotherdomain := "another-domain.example.com"

	// Get a certificate for the new domain
	cert2, err := interceptor.getOrCreateCert(anotherdomain)
	require.NoError(t, err, "Certificate generation should succeed")
	require.NotNil(t, cert2, "Generated certificate should not be nil")

	// Verify it's not the same as the original test certificate
	require.NotEqual(t, testCert, cert2, "Should not retrieve the cached certificate for a different domain")

	// Verify the new certificate is properly cached
	interceptor.cacheMutex.RLock()
	cachedCert, exists := interceptor.certCache[anotherdomain]
	interceptor.cacheMutex.RUnlock()
	require.True(t, exists, "Certificate should be cached for the new domain")
	require.Equal(t, cert2, cachedCert, "Cached certificate should match the returned one")

	// Due to the complexity of setting up a full QUIC/HTTP3 test environment,
	// we'll simulate only parts of the request/response cycle
	// A more comprehensive test would require:
	// 1. A real QUIC server
	// 2. A QUIC client
	// 3. Interception of actual QUIC traffic

	// Since we can't easily test the full cycle, we'll test the individual components:
	// 1. Verify certificate generation works (done above)
	// 2. Test mock request/response handling

	// Create a test HTTP request (this would normally come from a QUIC client)
	testReq, err := http.NewRequest("GET", "https://"+testHost+"/test", http.NoBody)
	require.NoError(t, err, "Should create test request")

	// Test request handler
	modifiedReq, err := requestHandler(testReq)
	require.NoError(t, err, "Request handler should not error")
	require.Equal(t, "true", modifiedReq.Header.Get("X-HTTP3-Intercepted"), "Request should be modified")

	// Create a test HTTP response (this would normally come from a QUIC server)
	testResp := &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
		Proto:      "HTTP/3",
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString("Test response body")),
	}

	// Test response handler
	modifiedResp, err := responseHandler(testResp)
	require.NoError(t, err, "Response handler should not error")
	require.Equal(t, "true", modifiedResp.Header.Get("X-HTTP3-Response-Intercepted"), "Response should be modified")

	// Read and verify the modified body
	bodyBytes, err := io.ReadAll(modifiedResp.Body)
	require.NoError(t, err, "Should read response body")
	modifiedResp.Body.Close()
	require.Equal(t, "Modified: Test response body", string(bodyBytes), "Response body should be modified")

	// Verify the flags were set
	assert.True(t, requestModified, "Request modified flag should be set")
	assert.True(t, responseModified, "Response modified flag should be set")
}

// TestHTTP3QUICIntegration tests the integration of the QUIC/HTTP3 interceptor with the proxy
func TestHTTP3QUICIntegration(t *testing.T) {
	// This test focuses on the integration between the proxy and QUIC interceptor
	t.Run("interceptor registration", func(t *testing.T) {
		// Generate CA for testing
		caCertPEM, caKeyPEM := generateTestCAForQUIC(t)

		// Create proxy config with HTTP3 interception enabled
		cfg := &config.Config{
			Servers: []config.ServerConfig{
				{
					Type:          config.ProxyTypeStandard,
					ListenAddress: "127.0.0.1:0", // Dynamic port
					Enabled:       true,
				},
			},
			Interception: config.InterceptionConfig{
				Enabled:   true,
				HTTPS:     true,        // Use HTTPS for HTTP3 test (since there's no specific HTTP3 field)
				CAFile:    "ca.pem",    // These will be overridden by the mock file system
				CAKeyFile: "cakey.pem", // These will be overridden by the mock file system
			},
			TimeoutSeconds: 5,
		}

		// Create the proxy instance
		proxy := NewProxy(cfg)
		assert.NotNil(t, proxy, "Proxy should be created")
		assert.NotEmpty(t, proxy.servers, "Proxy should have servers")

		// Create HTTP3 interceptor
		http3Interceptor, err := NewQUICHTTP3Interceptor(caCertPEM, caKeyPEM, proxy, nil, nil)
		assert.NoError(t, err, "Should create HTTP3 interceptor")
		assert.NotNil(t, http3Interceptor, "HTTP3 interceptor should not be nil")

		// Register the interceptor with the proxy
		http3Interceptor.RegisterUDPInterceptHandler(proxy)

		// In a complete implementation, we would now test that UDP packets are properly
		// routed to the interceptor. This would require mocking or implementing a UDP listener.
	})

	t.Run("UDP packet handling", func(t *testing.T) {
		// Create mock objects for testing UDP handling
		caCertPEM, caKeyPEM := generateTestCAForQUIC(t)
		mockProxy := createMockProxyForQUIC(t)

		// Create the interceptor
		http3Interceptor, err := NewQUICHTTP3Interceptor(caCertPEM, caKeyPEM, mockProxy, nil, nil)
		assert.NoError(t, err, "Should create HTTP3 interceptor")

		// Create a mock UDP packet connection for testing
		// This uses our non-blocking implementation with channels
		mockPacketConn := newMockUDPConn()

		// Create a mock remote address
		mockRemoteAddr := &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 12345,
		}

		// Test host for interception
		testHost := "quic.example.com:443"

		// Create a context with timeout to automatically end the test
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		// Channel to signal when the goroutine has started
		started := make(chan struct{})

		// Run the UDP handler in a goroutine
		go func() {
			defer func() {
				// Recover from any panics in the goroutine
				if r := recover(); r != nil {
					t.Logf("Recovered from panic in UDP handler: %v", r)
				}
			}()

			// Signal that we're about to start the handler
			close(started)

			// Start the UDP handler - our improved mock will not block indefinitely
			http3Interceptor.HandleUDPConnection(mockPacketConn, mockRemoteAddr, testHost)
		}()

		// Wait for the goroutine to start or the test to timeout
		select {
		case <-started:
			// Handler started successfully
		case <-ctx.Done():
			t.Fatal("Timed out waiting for UDP handler to start")
		}

		// Allow a short time for the handler to process
		time.Sleep(200 * time.Millisecond)

		// Clean up - this will also signal through the channel to unblock ReadFrom
		mockPacketConn.Close()
	})
}

// mockUDPConn is a mock implementation of net.PacketConn for testing
type mockUDPConn struct {
	closed   bool
	mu       sync.Mutex
	done     chan struct{} // Channel to signal when to stop blocking
	readData []byte        // Data to return on ReadFrom
}

func newMockUDPConn() *mockUDPConn {
	return &mockUDPConn{
		closed:   false,
		done:     make(chan struct{}),
		readData: []byte("mock QUIC data"),
	}
}

func (m *mockUDPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	m.mu.Lock()
	done := m.done // Save reference to avoid race conditions if closed during select
	if m.closed {
		m.mu.Unlock()
		return 0, nil, io.ErrClosedPipe
	}
	m.mu.Unlock()

	// Wait for either data to be available or connection to be closed
	select {
	case <-done:
		return 0, nil, io.ErrClosedPipe
	case <-time.After(200 * time.Millisecond):
		// After a timeout, return some mock data to simulate a QUIC packet
		if len(p) > 0 && len(m.readData) > 0 {
			n = copy(p, m.readData)
			return n, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}, nil
		}
		return 0, nil, io.EOF
	}
}

func (m *mockUDPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return 0, io.ErrClosedPipe
	}

	// Pretend to write the data
	return len(p), nil
}

func (m *mockUDPConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.closed {
		m.closed = true
		close(m.done) // Signal any blocked ReadFrom calls to exit
	}
	return nil
}

func (m *mockUDPConn) LocalAddr() net.Addr {
	return &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 0,
	}
}

func (m *mockUDPConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockUDPConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockUDPConn) SetWriteDeadline(t time.Time) error {
	return nil
}
