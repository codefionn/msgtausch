package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	port := getenv("PORT", "5678")
	useTLS := strings.EqualFold(getenv("TLS", "false"), "true")

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if useTLS {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("hello-https path=" + r.URL.Path))
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("hello-http path=" + r.URL.Path))
	})

	mux.HandleFunc("/curl-http", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("curl-http-response path=" + r.URL.Path + " method=" + r.Method))
	})

	mux.HandleFunc("/curl-https", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("curl-https-response path=" + r.URL.Path + " method=" + r.Method))
	})

	mux.HandleFunc("/connect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("connect-response path=" + r.URL.Path + " method=" + r.Method))
	})

	srv := &http.Server{Addr: ":" + port, Handler: mux}

	if useTLS {
		cert, key, err := selfSignedCert()
		if err != nil {
			log.Fatalf("failed to generate self-signed cert: %v", err)
		}
		tlsCert, err := tls.X509KeyPair(cert, key)
		if err != nil {
			log.Fatalf("invalid key pair: %v", err)
		}
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
		log.Printf("HTTPS backend listening on :%s", port)
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("https server error: %v", err)
		}
		return
	}

	log.Printf("HTTP backend listening on :%s", port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("http server error: %v", err)
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func selfSignedCert() ([]byte, []byte, error) {
	// Check if we have CA files available for signing
	caCertFile := getenv("CA_CERT_FILE", "/ca/test_ca.crt")
	caKeyFile := getenv("CA_KEY_FILE", "/ca/test_ca.key")

	// Try to load CA certificate and key
	if caCertPEM, err := os.ReadFile(caCertFile); err == nil {
		if caKeyPEM, err := os.ReadFile(caKeyFile); err == nil {
			return generateCASignedCert(caCertPEM, caKeyPEM)
		}
	}

	// Fallback to self-signed if CA files not available
	log.Printf("CA files not available, using self-signed certificate")
	return generateSelfSignedCert()
}

func generateCASignedCert(caCertPEM, caKeyPEM []byte) ([]byte, []byte, error) {
	// Parse CA certificate
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA certificate")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	// Parse CA private key
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA private key")
	}
	caKey, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		// Try parsing as PKCS1 private key
		caKey, err = x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse CA private key: %v", err)
		}
	}

	// Generate server private key
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate server key: %v", err)
	}

	// Generate serial number
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial: %v", err)
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "https-backend",
		},
		DNSNames:              []string{"https-backend", "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Sign certificate with CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})

	log.Printf("Generated CA-signed certificate for https-backend")
	return certPEM, keyPEM, nil
}

func generateSelfSignedCert() ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "msgtausch-test-backend"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPEM, keyPEM, nil
}
