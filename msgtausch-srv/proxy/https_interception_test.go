package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHTTPSInterception tests the HTTPS interception functionality
// verifying that the certificate presented to the client is different from the original
func TestHTTPSInterception(t *testing.T) {
	// Use test CA certificate and key files from testdata directory
	// Use relative paths from the test file location
	caCertPath := "testdata/test_ca.crt"
	caKeyPath := "testdata/test_ca.key"

	// Read the test CA certificate and key for verification
	caCertData, err := os.ReadFile(caCertPath)
	require.NoError(t, err, "Failed to read CA certificate file")
	caKeyData, err := os.ReadFile(caKeyPath)
	require.NoError(t, err, "Failed to read CA key file")

	// Verify we can parse the CA certificate and key
	_, err = tls.X509KeyPair(caCertData, caKeyData)
	require.NoError(t, err, "Failed to parse CA certificate")

	// Create a test HTTPS server with its own certificate
	testContent := "Hello, HTTPS Intercepted Proxy!"
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "original-server")
		_, _ = w.Write([]byte(testContent))
	}))
	defer testServer.Close()

	// Get the original server certificate for later comparison
	originalCerts := testServer.TLS.Certificates
	require.Greater(t, len(originalCerts), 0, "No TLS certificates found in test server")

	// Create a configuration with HTTPS interception enabled
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeHTTPS,
				ListenAddress: "127.0.0.1:0", // Use port 0 to get random available port
				Enabled:       true,
			},
		},
		TimeoutSeconds:           5,
		MaxConcurrentConnections: 100,
		Classifiers:              make(map[string]config.Classifier),
		Interception: config.InterceptionConfig{
			Enabled:   true,
			HTTP:      true,
			HTTPS:     true,
			CAFile:    caCertPath,
			CAKeyFile: caKeyPath,
		},
	}

	// Create and start the proxy
	proxy := NewProxy(cfg)

	// Verify that the HTTPS interceptor was properly initialized
	require.NotNil(t, proxy.servers[0].httpsInterceptor, "HTTPS interceptor was not initialized")

	// Add debug logging
	logger.Info("HTTPS interception enabled in config: %v", cfg.Interception.HTTPS)
	logger.Info("HTTPS interceptor initialized: %v", proxy.servers[0].httpsInterceptor != nil)
	// Start proxy server
	listener, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	require.NoError(t, err, "Failed to create listener")
	proxyAddr := listener.Addr().String()

	go func() {
		if err := proxy.StartWithListener(listener); err != http.ErrServerClosed && err != nil {
			t.Errorf("Proxy server error: %v", err)
		}
	}()
	defer proxy.Stop()

	// Wait for proxy to start
	time.Sleep(100 * time.Millisecond)

	// Create a custom certificate pool for the client to trust our CA
	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caCertData), "Failed to add CA certificate to pool")

	// Create HTTP client that uses our proxy and trusts our CA
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", proxyAddr))
	require.NoError(t, err)

	// Add debug logging for proxy URL
	logger.Info("Proxy URL: %s", proxyURL.String())

	// For debugging: print the test server URL
	logger.Info("Test server URL: %s", testServer.URL)

	// Setup a certificate verifier to capture the presented certificate
	var interceptedCert *x509.Certificate
	certMutex := &sync.Mutex{}

	// Configure TLS
	tlsConfig := &tls.Config{
		RootCAs: caPool,
		// Allow InsecureSkipVerify for testing purposes only
		InsecureSkipVerify: true,
		// This callback is used to capture the certificate for verification in the test
		VerifyConnection: func(cs tls.ConnectionState) error {
			// Store the presented certificate for later inspection
			if len(cs.PeerCertificates) > 0 {
				certMutex.Lock()
				interceptedCert = cs.PeerCertificates[0]
				certMutex.Unlock()
				logger.Debug("Received certificate with CN: %s, Issuer: %s",
					interceptedCert.Subject.CommonName,
					interceptedCert.Issuer.CommonName)
			}
			return nil
		},
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: tlsConfig,
		},
	}

	t.Run("HTTPS interception with certificate modification", func(t *testing.T) {
		// Make a direct request to get the original certificate

		// Make a direct request to capture the original certificate
		var originalServerCert *x509.Certificate
		directTLSConfig := &tls.Config{
			InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) > 0 {
					originalServerCert = cs.PeerCertificates[0]
					logger.Info("Original server cert: Serial=%v, Subject=%v, Issuer=%v",
						originalServerCert.SerialNumber,
						originalServerCert.Subject,
						originalServerCert.Issuer)
				}
				return nil
			},
		}

		directClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: directTLSConfig,
			},
		}

		// Get the original certificate
		dresp, err := directClient.Get(testServer.URL)
		require.NoError(t, err, "Failed to make direct HTTPS request")
		_, _ = io.Copy(io.Discard, dresp.Body)
		_ = dresp.Body.Close()

		// Now make a request through the proxy to get the intercepted certificate
		// Add a sleep to ensure proxy is fully ready
		time.Sleep(500 * time.Millisecond)

		// Debug: Print relevant info before making the request
		logger.Info("Making HTTPS request through proxy to %s", testServer.URL)
		testServerURL, _ := url.Parse(testServer.URL)
		logger.Info("Test server host: %s (port: %s)", testServerURL.Hostname(), testServerURL.Port())

		resp, err := client.Get(testServer.URL)
		require.NoError(t, err, "Failed to make HTTPS request through proxy")
		defer resp.Body.Close()

		// Verify the request was successful
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Read response body
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err, "Failed to read response body")
		assert.Equal(t, testContent, string(body))

		// Verify that we captured the certificate and it's not the original
		certMutex.Lock()
		cert := interceptedCert
		certMutex.Unlock()
		require.NotNil(t, cert, "No certificate captured during TLS handshake")

		// Get original certificate for comparison
		originalCert, err := x509.ParseCertificate(originalCerts[0].Certificate[0])
		require.NoError(t, err, "Failed to parse original certificate")

		// Verify that the intercepted cert is different from the original server cert
		assert.NotEqual(t, originalCert.SerialNumber, cert.SerialNumber,
			"Certificate serial number was not changed")

		// Issuer should be our CA, not the original server's issuer
		assert.Equal(t, "Msgtausch Test CA", cert.Issuer.CommonName,
			"Certificate issuer was not changed to our CA")

		// The intercepted cert should have the same common name as the original host
		parsed, err := url.Parse(testServer.URL)
		require.NoError(t, err, "Failed to parse test server URL")
		hostname := parsed.Hostname()
		assert.Equal(t, hostname, cert.Subject.CommonName,
			"Subject common name doesn't match the expected hostname")

		// Log certificate details for debugging
		logger.Info("Original cert: Serial=%v, Issuer=%v, Subject=%v",
			originalCert.SerialNumber, originalCert.Issuer, originalCert.Subject)
		logger.Info("Intercepted cert: Serial=%v, Issuer=%v, Subject=%v",
			cert.SerialNumber, cert.Issuer, cert.Subject)
	})
}

// The test CA certificate and key are located in the testdata directory
// File paths: testdata/test_ca.crt and testdata/test_ca.key
// DO NOT use these certificates in production - they are only for testing!
