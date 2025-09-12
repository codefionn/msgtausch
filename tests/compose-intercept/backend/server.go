package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
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
