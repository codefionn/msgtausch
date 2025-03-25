package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHTTPSCertificateReplacement tests that the HTTPS interceptor correctly
// generates new certificates for intercepted connections that differ from
// the original server certificate
func TestHTTPSCertificateReplacement(t *testing.T) {
	// Test CA paths
	caCertPath := "testdata/test_ca.crt"
	caKeyPath := "testdata/test_ca.key"

	// Read test CA certificate and key
	caCertData, err := os.ReadFile(caCertPath)
	require.NoError(t, err, "Failed to read CA certificate file")
	caKeyData, err := os.ReadFile(caKeyPath)
	require.NoError(t, err, "Failed to read CA key file")

	// Create a test server with TLS
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "Hello, TLS!")
	}))
	defer server.Close()

	// Get the original server certificate
	conn, err := tls.Dial("tcp", server.Listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
	})
	require.NoError(t, err, "Failed to connect to test server")
	originalCerts := conn.ConnectionState().PeerCertificates
	require.NotEmpty(t, originalCerts, "No certificates returned from test server")
	originalCert := originalCerts[0]
	conn.Close()

	// Log the original certificate details
	logger.Info("Original certificate: Serial=%v, Issuer=%v, Subject=%v",
		originalCert.SerialNumber, originalCert.Issuer, originalCert.Subject)

	// Create the HTTPS interceptor manually
	httpsInterceptor, err := NewHTTPSInterceptor(caCertData, caKeyData, nil, nil, nil)
	require.NoError(t, err, "Failed to create HTTPS interceptor")

	// Generate a replacement certificate for the server's hostname
	hostname := "example.com" // Use a fixed hostname for testing
	replacementCert, err := httpsInterceptor.getOrCreateCert(hostname)
	require.NoError(t, err, "Failed to generate replacement certificate")
	require.NotNil(t, replacementCert, "Replacement certificate is nil")

	// Parse the replacement certificate to inspect it
	x509Cert, err := x509.ParseCertificate(replacementCert.Certificate[0])
	require.NoError(t, err, "Failed to parse replacement certificate")

	// Log the replacement certificate details
	logger.Info("Replacement certificate: Serial=%v, Issuer=%v, Subject=%v",
		x509Cert.SerialNumber, x509Cert.Issuer, x509Cert.Subject)

	// Verify the replacement certificate is different from the original
	assert.NotEqual(t, originalCert.SerialNumber, x509Cert.SerialNumber,
		"Replacement certificate has the same serial number as the original")

	// Verify the replacement certificate has our CA as issuer
	assert.Equal(t, "Msgtausch Test CA", x509Cert.Issuer.CommonName,
		"Replacement certificate does not have our test CA as issuer")

	// Verify the replacement certificate has the correct common name
	assert.Equal(t, hostname, x509Cert.Subject.CommonName,
		"Replacement certificate has incorrect common name")

	// Test that the replacement cert is properly verifiable with our CA
	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caCertData),
		"Failed to add CA certificate to pool")

	// Create verification options
	opts := x509.VerifyOptions{
		Roots:         caPool,
		Intermediates: x509.NewCertPool(),
		DNSName:       hostname,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Verify the certificate against our CA
	chains, err := x509Cert.Verify(opts)
	require.NoError(t, err, "Replacement certificate failed verification against our CA")
	require.NotEmpty(t, chains, "No verification chains found for replacement certificate")

	// Success!
	logger.Info("Successfully verified certificate replacement")
}
