package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
)

// HTTPSInterceptor handles MITM for HTTPS traffic via CONNECT method.
type HTTPSInterceptor struct {
	CA              tls.Certificate   // CA certificate and private key
	caCert          *x509.Certificate // Parsed CA cert
	caKey           crypto.PrivateKey // Parsed CA key (supports RSA and EC)
	certCache       map[string]*tls.Certificate
	cacheMutex      sync.RWMutex
	certWaitGroups  map[string]*sync.WaitGroup                   // Wait groups for ongoing certificate generation
	waitMutex       sync.RWMutex                                 // Mutex for the wait groups map
	proxy           *Proxy                                       // Reference to proxy for creating TCP connections
	requestHandler  func(*http.Request) (*http.Request, error)   // Optional request handler for modifying requests
	responseHandler func(*http.Response) (*http.Response, error) // Optional response handler for modifying responses
}

// NewHTTPSInterceptor creates a new HTTPSInterceptor with the given CA cert and key (PEM encoded).
func NewHTTPSInterceptor(caCertPEM, caKeyPEM []byte, proxy *Proxy, requestHandler func(*http.Request) (*http.Request, error), responseHandler func(*http.Response) (*http.Response, error)) (*HTTPSInterceptor, error) {
	ca, err := tls.X509KeyPair(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate/key: %w", err)
	}
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA cert: %w", err)
	}
	block, _ = pem.Decode(caKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CA key PEM")
	}
	// Try to parse the key as PKCS#1 first (RSA)
	var caKey crypto.PrivateKey
	pkcs1Key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// If that fails, try PKCS#8 format (supports both RSA and EC)
		logger.Debug("Failed to parse key as PKCS#1, trying PKCS#8: %v", err)
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			// If PKCS#8 also fails, try EC private key format
			logger.Debug("Failed to parse key as PKCS#8, trying EC: %v", err)
			ecKey, ecErr := x509.ParseECPrivateKey(block.Bytes)
			if ecErr != nil {
				return nil, fmt.Errorf("failed to parse CA key (tried PKCS#1, PKCS#8, and EC): %w", ecErr)
			}
			caKey = ecKey
		} else {
			// PKCS#8 key can be RSA or EC
			switch key := pkcs8Key.(type) {
			case *rsa.PrivateKey, *ecdsa.PrivateKey:
				caKey = key
			default:
				return nil, fmt.Errorf("CA key is not a supported private key type (RSA or EC)")
			}
		}
	} else {
		caKey = pkcs1Key
	}
	return &HTTPSInterceptor{
		CA:              ca,
		caCert:          caCert,
		caKey:           caKey,
		certCache:       make(map[string]*tls.Certificate),
		certWaitGroups:  make(map[string]*sync.WaitGroup),
		proxy:           proxy,
		requestHandler:  requestHandler,
		responseHandler: responseHandler,
	}, nil
}

// HandleHTTPSIntercept handles an incoming CONNECT request and intercepts HTTPS traffic.
func (h *HTTPSInterceptor) HandleHTTPSIntercept(w http.ResponseWriter, req *http.Request) {
	// Extract host and hostname for certificate generation
	host := req.Host
	// Ensure we have a port
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	// Extract the hostname without port for certificate generation
	hostname := strings.Split(host, ":")[0]
	logger.Info("HTTPS interceptor handling HTTP CONNECT request for %s (hostname: %s)", host, hostname)

	// Hijack the connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		logger.Error("HTTPS interception failed: ResponseWriter does not support hijacking")
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		logger.Error("HTTPS interception failed: Failed to hijack connection: %v", err)
		return
	}

	// Respond OK to client
	_, err = fmt.Fprintf(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	if err != nil {
		logger.Error("HTTPS interception failed: Failed to send 200 response: %v", err)
		if closeErr := clientConn.Close(); closeErr != nil {
			logger.Error("Error closing client connection: %v", closeErr)
		}
		return
	}

	// Extract client IP from the connection
	clientIP, _, err := net.SplitHostPort(clientConn.RemoteAddr().String())
	if err != nil {
		logger.Debug("Failed to extract client IP from connection %s: %v", clientConn.RemoteAddr().String(), err)
		clientIP = "" // fallback to empty string
	}

	// Hand off to the TCP connection handler, using the hostname for certificate generation
	// but the full host:port for the actual connection
	h.HandleTCPConnectionWithClientIP(clientConn, host, clientIP)
}

// getOrCreateCert returns a certificate for the given host, generating it if necessary.
func (h *HTTPSInterceptor) getOrCreateCert(host string) (*tls.Certificate, error) {
	domainName := strings.Split(host, ":")[0]

	// First check if we already have a certificate for this host
	h.cacheMutex.RLock()
	cert, ok := h.certCache[host]
	h.cacheMutex.RUnlock()
	if ok {
		logger.Debug("Using cached certificate for %s", host)
		return cert, nil
	}

	// Now check if another goroutine is already generating this certificate
	h.waitMutex.RLock()
	wg, isGenerating := h.certWaitGroups[host]
	h.waitMutex.RUnlock()

	if isGenerating {
		logger.Debug("Waiting for another goroutine to generate certificate for %s", host)
		// Another goroutine is generating this cert, wait for it to finish
		wg.Wait()

		// Once we're here, the certificate should be in the cache
		h.cacheMutex.RLock()
		cert, ok = h.certCache[host]
		h.cacheMutex.RUnlock()
		if ok {
			return cert, nil
		}
		// If we get here, something went wrong in the other goroutine
		return nil, fmt.Errorf("certificate generation failed for %s", host)
	}

	// No other goroutine is generating this cert, we'll do it
	logger.Debug("Generating new certificate for %s", host)

	// Create a wait group for this cert generation and add it to the map
	wg = &sync.WaitGroup{}
	wg.Add(1)
	h.waitMutex.Lock()
	h.certWaitGroups[host] = wg
	h.waitMutex.Unlock()

	// Make sure we signal completion when we're done
	defer func() {
		wg.Done()
		h.waitMutex.Lock()
		delete(h.certWaitGroups, host)
		h.waitMutex.Unlock()
	}()

	// Need to acquire write lock for the cert cache
	h.cacheMutex.Lock()
	defer h.cacheMutex.Unlock()

	// Check again under write lock to avoid race condition where
	// another goroutine has somehow already created the certificate
	cert, ok = h.certCache[host]
	if ok {
		logger.Debug("Another goroutine already generated certificate for %s", host)
		return cert, nil
	}

	// Generate new cert
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: domainName,
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * 365 * time.Hour), // 1 year
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{domainName},
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, h.caCert, &priv.PublicKey, h.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	newCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create X509 key pair: %w", err)
	}

	// Store in cache - we already have the write lock from above
	h.certCache[host] = &newCert
	logger.Debug("Generated and cached new certificate for %s", host)

	return &newCert, nil
}

// HandleTCPConnection intercepts HTTPS traffic from a raw TCP connection.
// This method accepts a direct TCP connection rather than an HTTP request,
// and parses the HTTP traffic flowing through the TLS tunnel.
// The host can be empty an empty string if unknown.
func (h *HTTPSInterceptor) HandleTCPConnection(clientConn net.Conn, host string) {
	// Extract client IP from connection if not provided
	clientIP, _, err := net.SplitHostPort(clientConn.RemoteAddr().String())
	if err != nil {
		logger.Debug("Failed to extract client IP from connection %s: %v", clientConn.RemoteAddr().String(), err)
		clientIP = "" // fallback to empty string
	}
	h.HandleTCPConnectionWithClientIP(clientConn, host, clientIP)
}

// HandleTCPConnectionWithClientIP intercepts HTTPS traffic from a raw TCP connection with a known client IP.
// This method accepts a direct TCP connection rather than an HTTP request,
// and parses the HTTP traffic flowing through the TLS tunnel.
// The host can be empty an empty string if unknown.
func (h *HTTPSInterceptor) HandleTCPConnectionWithClientIP(clientConn net.Conn, host, clientIP string) {
	logger.Debug("HTTPS interceptor handling direct TCP connection to %s (will parse HTTP traffic)", host)

	// For cleanliness, ensure we close the connection when done
	defer func() {
		if closeErr := clientConn.Close(); closeErr != nil {
			logger.Error("Error closing client connection: %v", closeErr)
		}
	}()

	var hostname string
	var tlsClientConn *tls.Conn

	// If host is empty, we need to extract it from SNI
	if host == "" {
		logger.Debug("Host is empty, extracting from TLS SNI")

		// Create a TLS config that captures the SNI hostname
		var sniHostname string
		tlsConfig := &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				sniHostname = hello.ServerName
				if sniHostname == "" {
					return nil, fmt.Errorf("no SNI hostname provided")
				}
				logger.Debug("Extracted SNI hostname: %s", sniHostname)

				// Get or generate certificate for the SNI hostname
				cert, err := h.getOrCreateCert(sniHostname)
				if err != nil {
					return nil, fmt.Errorf("failed to get/create certificate for %s: %v", sniHostname, err)
				}
				return cert, nil
			},
			MinVersion: tls.VersionTLS12,
		}

		tlsClientConn = tls.Server(clientConn, tlsConfig)
		if err := tlsClientConn.Handshake(); err != nil {
			logger.Error("HTTPS interception failed: TLS handshake failed: %v", err)
			return
		}

		if sniHostname == "" {
			logger.Error("HTTPS interception failed: Could not extract hostname from SNI")
			return
		}

		hostname = sniHostname
		host = hostname + ":443"
		logger.Debug("Extracted host from SNI: %s", host)
	} else {
		// Check if we have a host with a port
		if !strings.Contains(host, ":") {
			host += ":443"
		}

		// Extract hostname without port for certificate generation
		hostname = strings.Split(host, ":")[0]
		logger.Debug("Extracted hostname for certificate: %s", hostname)

		// Get or generate certificate for hostname (not host:port)
		cert, err := h.getOrCreateCert(hostname)
		if err != nil {
			logger.Error("HTTPS interception failed: Failed to get/create certificate: %v", err)
			return
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{*cert},
			ServerName:   hostname,
			MinVersion:   tls.VersionTLS12,
		}
		logger.Debug("Using hostname %s for TLS ServerName", hostname)
		tlsClientConn = tls.Server(clientConn, tlsConfig)
		if err := tlsClientConn.Handshake(); err != nil {
			logger.Error("HTTPS interception failed: TLS handshake failed: %v", err)
			return
		}
	}
	defer func() {
		if closeErr := tlsClientConn.Close(); closeErr != nil {
			logger.Error("Error closing TLS client connection: %v", closeErr)
		}
	}()

	logger.Debug("HTTPS interceptor established TLS with client for %s", host)

	// Connect to upstream server using proxy's connection method
	logger.Debug("HTTPS interceptor connecting to upstream server %s", host)

	// Check if we have a proxy reference
	if h.proxy == nil {
		logger.Error("HTTPS interception failed: No proxy reference for creating TCP connection")
		return
	}

	// Use the proxy's createForwardTCPClient to establish connection
	// Create context with client IP for proper connection tracking
	ctx := WithClientIP(context.Background(), clientIP)
	rawConn, err := h.proxy.createForwardTCPClient(ctx, host)
	if err != nil {
		logger.Error("HTTPS interception failed: Unable to connect to upstream: %v", err)
		return
	}

	// Establish TLS over the raw connection
	upstreamConn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: true})
	if err := upstreamConn.Handshake(); err != nil {
		logger.Error("HTTPS interception failed: TLS handshake with upstream failed: %v", err)
		if closeErr := rawConn.Close(); closeErr != nil {
			logger.Error("Error closing raw connection: %v", closeErr)
		}
		return
	}
	defer func() {
		if closeErr := upstreamConn.Close(); closeErr != nil {
			logger.Error("Error closing upstream connection: %v", closeErr)
		}
	}()

	logger.Debug("HTTPS interceptor established connection to upstream server %s", host)

	_ = tlsClientConn.SetDeadline(time.Now().Add(time.Duration(h.proxy.config.TimeoutSeconds) * time.Second))
	_ = upstreamConn.SetDeadline(time.Now().Add(time.Duration(h.proxy.config.TimeoutSeconds) * time.Second))

	logger.Debug("Starting TLS tunnel for %s", host)

	// Use wait group to coordinate goroutine completion
	wg := &sync.WaitGroup{}
	wg.Add(2)

	// Create buffered readers for both connections
	clientReader := bufio.NewReader(tlsClientConn)
	upstreamReader := bufio.NewReader(upstreamConn)

	// Track if this is a WebSocket connection
	var isWebSocket atomic.Bool
	isWebSocket.Store(false)

	// Client -> Upstream
	go func() {
		defer wg.Done()

		for {
			// If we've already detected WebSocket, switch to direct copying
			if isWebSocket.Load() {
				// For WebSockets, we just copy bytes directly
				buffer := make([]byte, 32*1024)
				for {
					_ = tlsClientConn.SetReadDeadline(time.Now().Add(time.Duration(h.proxy.config.TimeoutSeconds) * time.Second))
					n, err := clientReader.Read(buffer)
					if err != nil {
						if err != io.EOF && !isClosedConnError(err) {
							logger.Error("WebSocket client read error: %v", err)
						}
						return
					}

					_ = upstreamConn.SetWriteDeadline(time.Now().Add(time.Duration(h.proxy.config.TimeoutSeconds) * time.Second))
					_, err = upstreamConn.Write(buffer[:n])
					if err != nil {
						logger.Error("WebSocket upstream write error: %v", err)
						return
					}
				}
			}

			// For HTTP traffic, parse the request
			_ = tlsClientConn.SetReadDeadline(time.Now().Add(time.Duration(h.proxy.config.TimeoutSeconds) * time.Second))
			req, err := http.ReadRequest(clientReader)
			if err != nil {
				if err != io.EOF && !isClosedConnError(err) {
					logger.Error("Error reading HTTP request: %v", err)
				}
				return
			}

			if logger.IsLevelEnabled(logger.DEBUG) {
				// Construct full URL for logging
				fullURL := req.URL.String()
				if req.URL.Host == "" && req.Header.Get("Host") != "" {
					// For requests without host in URL, construct it from Host header
					scheme := "https" // We know this is HTTPS interception
					fullURL = fmt.Sprintf("%s://%s%s", scheme, req.Header.Get("Host"), req.URL.Path)
					if req.URL.RawQuery != "" {
						fullURL += "?" + req.URL.RawQuery
					}
				} else if req.URL.Host == "" && host != "" {
					fullURL = fmt.Sprintf("https://%s%s", host, req.URL.Path)
				}
				logger.Debug("Intercepted HTTPS request: %s %s %s (URL: %s)", req.Method, req.URL, req.Proto, fullURL)
			}

			// Reject CONNECT requests to prevent tunneling bypasses
			if req.Method == http.MethodConnect {
				logger.Warn("Rejected CONNECT request to %s - method not allowed in HTTPS interceptor", req.URL.String())
				// Send 405 Method Not Allowed response
				response := &http.Response{
					Status:        "405 Method Not Allowed",
					StatusCode:    http.StatusMethodNotAllowed,
					Proto:         req.Proto,
					ProtoMajor:    req.ProtoMajor,
					ProtoMinor:    req.ProtoMinor,
					Header:        make(http.Header),
					Body:          io.NopCloser(strings.NewReader("Method Not Allowed")),
					ContentLength: 18,
				}
				response.Header.Set("Content-Type", "text/plain")
				response.Header.Set("Content-Length", "18")
				_ = response.Write(tlsClientConn)
				return
			}

			// Check for WebSocket upgrade request
			if strings.ToLower(req.Header.Get("Upgrade")) == "websocket" {
				logger.Debug("Detected WebSocket upgrade request")
				isWebSocket.Store(true)

				// For WebSocket requests, just pass through with minimal modification
				if h.requestHandler != nil {
					modifiedReq, err := h.requestHandler(req)
					if err != nil {
						logger.Error("Error in request handler for WebSocket: %v", err)
					} else if modifiedReq != nil {
						req = modifiedReq
					}
				}
			} else {
				// Regular HTTP request - read and potentially modify the body
				var bodyData []byte
				if req.Body != nil {
					bodyData, err = io.ReadAll(req.Body)
					if closeErr := req.Body.Close(); closeErr != nil {
						logger.Error("Error closing request body: %v", closeErr)
					}
					if err != nil {
						logger.Error("Error reading request body: %v", err)
						return
					}

					// Replace the body with our processed version
					req.Body = io.NopCloser(bytes.NewReader(bodyData))
					req.ContentLength = int64(len(bodyData))
					req.Header.Set("Content-Length", fmt.Sprintf("%d", len(bodyData)))
				}

				// Apply custom request handler if configured
				if h.requestHandler != nil {
					modifiedReq, err := h.requestHandler(req)
					if err != nil {
						logger.Error("Error in request handler: %v", err)
					} else if modifiedReq != nil {
						req = modifiedReq
						logger.Debug("Request modified by custom handler")
					}
				} else if req.Body != nil {
					logger.Debug("Request body size: %d bytes", len(bodyData))
				}
			}

			// Add Host header if URL has a Host but no Host header is set
			if req.Header.Get("Host") == "" && req.URL.Host != "" {
				req.Header.Set("Host", req.URL.Host)
			}

			// Write the request to the upstream server
			_ = upstreamConn.SetWriteDeadline(time.Now().Add(time.Duration(h.proxy.config.TimeoutSeconds) * time.Second))
			err = req.Write(upstreamConn)
			if err != nil {
				logger.Error("Error writing request to upstream: %v", err)
				return
			}

			// For WebSocket connections, after sending the upgrade request,
			// we switch to direct copying mode and let the loop handle it in the next iteration
			if isWebSocket.Load() {
				logger.Debug("Switching to WebSocket mode after upgrade request")
				// Continue to the next iteration which will use direct copying
			}
		}
	}()

	// Upstream -> Client
	go func() {
		defer wg.Done()

		for {
			// If we've already detected WebSocket, switch to direct copying
			if isWebSocket.Load() {
				// For WebSockets, we just copy bytes directly
				buffer := make([]byte, 32*1024)
				for {
					_ = upstreamConn.SetReadDeadline(time.Now().Add(time.Duration(h.proxy.config.TimeoutSeconds) * time.Second))
					n, err := upstreamReader.Read(buffer)
					if err != nil {
						if err != io.EOF && !isClosedConnError(err) {
							logger.Error("WebSocket upstream read error: %v", err)
						}
						return
					}

					_ = tlsClientConn.SetWriteDeadline(time.Now().Add(time.Duration(h.proxy.config.TimeoutSeconds) * time.Second))
					_, err = tlsClientConn.Write(buffer[:n])
					if err != nil {
						logger.Error("WebSocket client write error: %v", err)
						return
					}
				}
			}

			// For HTTP traffic, parse the response
			_ = upstreamConn.SetReadDeadline(time.Now().Add(time.Duration(h.proxy.config.TimeoutSeconds) * time.Second))
			resp, err := http.ReadResponse(upstreamReader, nil)
			if err != nil {
				if err != io.EOF && !isClosedConnError(err) {
					logger.Error("Error reading HTTP response: %v", err)
				}
				return
			}

			logger.Debug("Intercepted HTTP response with status: %s", resp.Status)

			// Check for WebSocket upgrade response
			if resp.StatusCode == http.StatusSwitchingProtocols &&
				strings.ToLower(resp.Header.Get("Upgrade")) == "websocket" {
				logger.Debug("Detected WebSocket upgrade response")
				isWebSocket.Store(true)

				// For WebSocket upgrade response, just pass through
				_ = tlsClientConn.SetWriteDeadline(time.Now().Add(time.Duration(h.proxy.config.TimeoutSeconds) * time.Second))
				err = resp.Write(tlsClientConn)
				if err != nil {
					logger.Error("Error writing WebSocket upgrade response: %v", err)
					return
				}

				// After sending the upgrade response, we'll handle WebSocket protocol in the next iteration
			} else {
				// Regular HTTP response - read and potentially modify the body
				var bodyData []byte
				if resp.Body != nil {
					bodyData, err = io.ReadAll(resp.Body)
					if closeErr := resp.Body.Close(); closeErr != nil {
						logger.Error("Error closing response body: %v", closeErr)
					}
					if err != nil {
						logger.Error("Error reading response body: %v", err)
						return
					}

					// Replace the body with our processed version
					resp.Body = io.NopCloser(bytes.NewReader(bodyData))
					resp.ContentLength = int64(len(bodyData))
					resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(bodyData)))
				}

				// Apply custom response handler if configured
				if h.responseHandler != nil {
					modifiedResp, err := h.responseHandler(resp)
					if err != nil {
						logger.Error("Error in response handler: %v", err)
					} else if modifiedResp != nil {
						if resp.Body != nil {
							if closeErr := resp.Body.Close(); closeErr != nil {
								logger.Error("Error closing response body: %v", closeErr)
							}
						}
						resp = modifiedResp
						logger.Debug("Response modified by custom handler")
					}
				} else if resp.Body != nil {
					logger.Debug("Response body size: %d bytes", len(bodyData))
				}

				// Write the response back to the client
				_ = tlsClientConn.SetWriteDeadline(time.Now().Add(time.Duration(h.proxy.config.TimeoutSeconds) * time.Second))
				err = resp.Write(tlsClientConn)
				if resp.Body != nil {
					if closeErr := resp.Body.Close(); closeErr != nil {
						logger.Error("Error closing response body: %v", closeErr)
					}
				}
				if err != nil {
					logger.Error("Error writing response to client: %v", err)
					return
				}
			}
		}
	}()

	// Wait for both operations to complete
	wg.Wait()
	logger.Debug("HTTPS interceptor tunnel closed for %s", host)
}
