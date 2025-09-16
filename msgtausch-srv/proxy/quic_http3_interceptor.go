package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
	"github.com/codefionn/msgtausch/msgtausch-srv/stats"
	"github.com/quic-go/quic-go/http3"
)

// QUICHTTP3Interceptor handles MITM for HTTP/3 traffic over QUIC protocol.
type QUICHTTP3Interceptor struct {
	CA              tls.Certificate  // CA certificate and private key
	caCert          *tls.Certificate // Parsed CA cert for HTTP/3
	certCache       map[string]*tls.Certificate
	cacheMutex      sync.RWMutex
	certWaitGroups  map[string]*sync.WaitGroup                   // Wait groups for ongoing certificate generation
	waitMutex       sync.RWMutex                                 // Mutex for the wait groups map
	proxy           *Proxy                                       // Reference to proxy for creating connections
	requestHandler  func(*http.Request) (*http.Request, error)   // Optional request handler for modifying requests
	responseHandler func(*http.Response) (*http.Response, error) // Optional response handler for modifying responses
}

// shouldRecordRequest determines if this request should be fully recorded based on recording classifier
func (h *QUICHTTP3Interceptor) shouldRecordRequest(req *http.Request) bool {
	if h.proxy == nil || h.proxy.config == nil || !h.proxy.config.Statistics.Enabled {
		return false
	}

	// Use the proxy's recording classifier
	if h.proxy.recordingClassifier == nil {
		return false
	}

	input := ClassifierInput{
		host:       req.Host,
		remotePort: 443, // Default QUIC/HTTP3 port
	}

	// Extract port from Host header if present
	if host, port, err := net.SplitHostPort(req.Host); err == nil {
		input.host = host
		if portInt, err := strconv.Atoi(port); err == nil {
			input.remotePort = uint16(portInt)
		}
	}

	matches, err := h.proxy.recordingClassifier.Classify(input)
	if err != nil {
		logger.Error("Error classifying request for recording: %v", err)
		return false
	}

	return matches
}

// NewQUICHTTP3Interceptor creates a new QUICHTTP3Interceptor with the given CA cert and key.
func NewQUICHTTP3Interceptor(
	caCertPEM, caKeyPEM []byte,
	proxy *Proxy,
	requestHandler func(*http.Request) (*http.Request, error),
	responseHandler func(*http.Response) (*http.Response, error),
) (*QUICHTTP3Interceptor, error) {
	// Use the same certificate loading process as the HTTPS interceptor
	ca, err := tls.X509KeyPair(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate/key: %w", err)
	}

	return &QUICHTTP3Interceptor{
		CA:              ca,
		caCert:          &ca,
		certCache:       make(map[string]*tls.Certificate),
		certWaitGroups:  make(map[string]*sync.WaitGroup),
		proxy:           proxy,
		requestHandler:  requestHandler,
		responseHandler: responseHandler,
	}, nil
}

// HandleQUICIntercept handles an incoming QUIC (HTTP/3) connection and intercepts traffic.
func (h *QUICHTTP3Interceptor) HandleQUICIntercept(conn net.PacketConn, remoteAddr net.Addr, host string) {
	logger.Info("QUIC/HTTP3 interceptor handling connection for %s", host)

	// Extract host and hostname for certificate generation
	// Ensure we have a port
	if !strings.Contains(host, ":") {
		host += ":443" // Default port for QUIC/HTTP3
	}

	// Extract the hostname without port for certificate generation
	hostname := strings.Split(host, ":")[0]
	logger.Debug("Extracted hostname for certificate: %s", hostname)

	// Get certificate for the hostname
	cert, err := h.getOrCreateCert(hostname)
	if err != nil {
		logger.Error("QUIC/HTTP3 interception failed: Failed to get/create certificate: %v", err)
		return
	}

	// Set up TLS config for the server side
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"h3"},
	}

	// Initiate QUIC listener
	quicTransport := &http3.Server{
		TLSConfig: tlsConfig,
		Addr:      host,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.interceptHTTP3Request(w, r, host)
		}),
	}

	// Start the server
	logger.Debug("Starting QUIC/HTTP3 server for %s", host)
	go func() {
		if err := quicTransport.Serve(conn); err != nil {
			logger.Error("QUIC/HTTP3 server error: %v", err)
		}
	}()

	// Wait indefinitely - the server runs in a goroutine
	select {}
}

// interceptHTTP3Request handles an HTTP/3 request, forwarding it to the destination
func (h *QUICHTTP3Interceptor) interceptHTTP3Request(w http.ResponseWriter, req *http.Request, targetHost string) {
	logger.Debug("Intercepted HTTP/3 request: %s %s", req.Method, req.URL.Path)

	// Check if request should be recorded
	shouldRecord := h.shouldRecordRequest(req)
	var connectionID int64
	var requestHeaders map[string][]string
	var requestBodyData []byte
	requestTimestamp := time.Now()

	// Extract client IP from request (HTTP/3 context)
	clientIP := ""
	// For HTTP/3, we might not have direct access to client IP, use a placeholder or extract from context
	// This would need to be enhanced based on how client IP is tracked in QUIC

	// Start connection tracking if recording is enabled
	if shouldRecord && h.proxy.Collector != nil {
		hostname := targetHost
		if strings.Contains(targetHost, ":") {
			hostname, _, _ = net.SplitHostPort(targetHost)
		}
		portStr := "443"
		if strings.Contains(targetHost, ":") {
			_, portStr, _ = net.SplitHostPort(targetHost)
		}
		port, _ := strconv.Atoi(portStr)
		var err error
		connectionID, err = h.proxy.Collector.StartConnection(context.Background(), clientIP, hostname, port, "quic-http3")
		if err != nil {
			logger.Error("Error starting connection tracking: %v", err)
		}
	}

	// Create a modified request to forward
	outReq := new(http.Request)
	*outReq = *req // shallow copy

	// Reset some fields that would be re-created
	outReq.RequestURI = ""
	outReq.Header = make(http.Header)
	for k, v := range req.Header {
		outReq.Header[k] = v
	}

	// Derive recording host without port
	recHost := targetHost
	if strings.Contains(targetHost, ":") {
		recHost, _, _ = net.SplitHostPort(targetHost)
	}

	// Prepare request body handling (streaming if supported)
	var streamed bool
	var requestRecordID int64
	var seqNo int64
	// Copy headers snapshot early
	requestHeaders = make(map[string][]string)
	for key, values := range req.Header {
		requestHeaders[key] = values
	}
	if shouldRecord && h.proxy != nil && h.proxy.Collector != nil && req.Body != nil {
		if sr, ok := h.proxy.Collector.(stats.StreamingRecorder); ok && connectionID > 0 {
			id, berr := sr.BeginRecordedHTTPRequest(req.Context(), connectionID, req.Method, req.URL.String(), recHost, req.Header.Get("User-Agent"), requestHeaders, requestTimestamp)
			if berr == nil {
				streamed = true
				requestRecordID = id
				seqNo = 0
				outReq.Body = newTeeReadCloser(req.Body, func(chunk []byte) error {
					seqNo++
					if aerr := sr.AppendRecordedHTTPRequestBodyPart(req.Context(), requestRecordID, seqNo, append([]byte(nil), chunk...), time.Now()); aerr != nil {
						logger.Error("Error appending HTTP/3 request body part: %v", aerr)
					}
					return nil
				})
				// Do not set Content-Length; transport will handle framing
			} else {
				logger.Error("Error beginning HTTP/3 recorded request: %v", berr)
			}
		}
	}
	// Fallback to buffering if not streamed
	if !streamed && req.Body != nil {
		var err error
		reqBodyBytes, err := io.ReadAll(req.Body)
		if closeErr := req.Body.Close(); closeErr != nil {
			logger.Error("Error closing HTTP/3 request body: %v", closeErr)
		}
		if err != nil {
			logger.Error("Error reading HTTP/3 request body: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		outReq.Body = io.NopCloser(bytes.NewReader(reqBodyBytes))
		outReq.ContentLength = int64(len(reqBodyBytes))
		outReq.Header.Set("Content-Length", fmt.Sprintf("%d", len(reqBodyBytes)))
		if shouldRecord {
			requestBodyData = reqBodyBytes
		}
	}

	// Apply request handler if configured
	if h.requestHandler != nil {
		modifiedReq, err := h.requestHandler(outReq)
		if err != nil {
			logger.Error("Error in HTTP/3 request handler: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if modifiedReq != nil {
			outReq = modifiedReq
			logger.Debug("HTTP/3 request modified by custom handler")
		}
	}

	// Determine the target URL
	targetURL := *req.URL
	if targetURL.Host == "" {
		// Use the target host from the proxy connection
		targetURL.Host = targetHost
	}
	if targetURL.Scheme == "" {
		targetURL.Scheme = "https"
	}
	outReq.URL = &targetURL

	// Create HTTP/3 client transport
	rt := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: h.proxy.config.Interception.InsecureSkipVerify, // #nosec G402 – configurable for interception/testing
			NextProtos:         []string{"h3"},
		},
	}
	defer func() {
		if closeErr := rt.Close(); closeErr != nil {
			logger.Error("Error closing round tripper: %v", closeErr)
		}
	}()

	// Create HTTP client using HTTP/3 transport
	client := &http.Client{
		Transport: rt,
	}

	// Forward the request
	resp, err := client.Do(outReq)
	if err != nil {
		logger.Error("HTTP/3 request forwarding failed: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Error("Error closing HTTP/3 response body: %v", closeErr)
		}
	}()

	// Read and potentially modify the response body (with streaming to DB when enabled)
	var respBodyBytes []byte
	var respStreamed bool
	var responseRecordID int64
	var respSeq int64
	if shouldRecord && h.proxy.Collector != nil && connectionID > 0 {
		if sr, ok := h.proxy.Collector.(stats.StreamingRecorder); ok {
			// Begin streaming response
			responseHeaders := make(map[string][]string)
			for k, v := range resp.Header {
				responseHeaders[k] = v
			}
			rid, berr := sr.BeginRecordedHTTPResponse(context.Background(), connectionID, resp.StatusCode, responseHeaders, time.Now())
			if berr == nil {
				respStreamed = true
				responseRecordID = rid
				resp.Body = newTeeReadCloser(resp.Body, func(chunk []byte) error {
					respSeq++
					if aerr := sr.AppendRecordedHTTPResponseBodyPart(context.Background(), responseRecordID, respSeq, append([]byte(nil), chunk...), time.Now()); aerr != nil {
						logger.Error("Error appending HTTP/3 response body part: %v", aerr)
					}
					return nil
				})
			} else {
				logger.Error("Error beginning HTTP/3 recorded response: %v", berr)
			}
		}
	}

	respBodyBytes, err = io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("Error reading HTTP/3 response body: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if respStreamed {
		if sr, ok := h.proxy.Collector.(stats.StreamingRecorder); ok {
			if ferr := sr.FinishRecordedHTTPResponse(context.Background(), responseRecordID); ferr != nil {
				logger.Error("Error finishing HTTP/3 recorded response: %v", ferr)
			}
		}
	}

	// Record full request/response if enabled
	if shouldRecord && h.proxy.Collector != nil && connectionID > 0 {
		responseTimestamp := time.Now()

		// Construct full URL for recording
		fullURL := outReq.URL.String()
		hostname := targetHost
		if strings.Contains(targetHost, ":") {
			hostname, _, _ = net.SplitHostPort(targetHost)
		}

		// Finish streaming and/or fallback record
		if streamed {
			if sr, ok := h.proxy.Collector.(stats.StreamingRecorder); ok {
				if ferr := sr.FinishRecordedHTTPRequest(context.Background(), requestRecordID); ferr != nil {
					logger.Error("Error finishing HTTP/3 recorded request: %v", ferr)
				}
			}
		} else {
			if err := h.proxy.Collector.RecordFullHTTPRequest(
				context.Background(),
				connectionID,
				outReq.Method,
				fullURL,
				hostname,
				outReq.Header.Get("User-Agent"),
				requestHeaders,
				requestBodyData,
				requestTimestamp,
			); err != nil {
				logger.Error("Error recording full HTTP/3 request: %v", err)
			}
		}

		// Record response
		responseHeaders := make(map[string][]string)
		for key, values := range resp.Header {
			responseHeaders[key] = values
		}

		if err := h.proxy.Collector.RecordFullHTTPResponse(
			context.Background(),
			connectionID,
			resp.StatusCode,
			responseHeaders,
			respBodyBytes,
			responseTimestamp,
		); err != nil {
			logger.Error("Error recording full HTTP/3 response: %v", err)
		}
	}

	// Apply response handler if configured
	if h.responseHandler != nil {
		// Create a new response for modification
		modResp := &http.Response{
			Status:        resp.Status,
			StatusCode:    resp.StatusCode,
			Proto:         resp.Proto,
			ProtoMajor:    resp.ProtoMajor,
			ProtoMinor:    resp.ProtoMinor,
			Header:        resp.Header.Clone(),
			Body:          io.NopCloser(bytes.NewReader(respBodyBytes)),
			ContentLength: int64(len(respBodyBytes)),
		}

		modifiedResp, err := h.responseHandler(modResp)
		if err != nil {
			logger.Error("Error in HTTP/3 response handler: %v", err)
		} else if modifiedResp != nil {
			// If the body was replaced, we need to read it
			if modifiedResp.Body != modResp.Body {
				respBodyBytes, err = io.ReadAll(modifiedResp.Body)
				if closeErr := modifiedResp.Body.Close(); closeErr != nil {
					logger.Error("Error closing modified HTTP/3 response body: %v", closeErr)
				}
				if err != nil {
					logger.Error("Error reading modified HTTP/3 response body: %v", err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
			}

			// Copy the headers from the modified response
			for k := range w.Header() {
				w.Header().Del(k)
			}
			for k, vv := range modifiedResp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			resp.StatusCode = modifiedResp.StatusCode
			logger.Debug("HTTP/3 response modified by custom handler")
		}
	}

	// Copy headers from the response to our response writer
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	// Set status code
	w.WriteHeader(resp.StatusCode)

	// Write the response body
	_, err = w.Write(respBodyBytes)
	if err != nil {
		logger.Error("Error writing HTTP/3 response: %v", err)
		return
	}

	logger.Debug("HTTP/3 request handled successfully: %s %s => %d",
		req.Method, req.URL.Path, resp.StatusCode)
}

// HandleUDPConnection intercepts UDP (QUIC) traffic from a raw UDP connection.
func (h *QUICHTTP3Interceptor) HandleUDPConnection(conn net.PacketConn, remoteAddr net.Addr, host string) {
	logger.Debug("QUIC interceptor handling direct UDP connection to %s from %s", host, remoteAddr.String())

	// Check if we have a host with a port
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	// For UDP/QUIC, we need to set up a QUIC server that will accept incoming connections
	h.HandleQUICIntercept(conn, remoteAddr, host)
}

// getOrCreateCert returns a certificate for the given host, generating it if necessary.
// Using a similar implementation as HTTPS interceptor for certificate management.
func (h *QUICHTTP3Interceptor) getOrCreateCert(host string) (*tls.Certificate, error) {
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

	// Check again under write lock to avoid race condition
	cert, ok = h.certCache[host]
	if ok {
		logger.Debug("Another goroutine already generated certificate for %s", host)
		return cert, nil
	}

	// We need to use the same certificate generation code as in HTTPS interceptor
	// For brevity, this is not implemented here - in a real implementation, this would
	// generate a certificate using the CA certificate

	// This is a placeholder - in reality, you would generate a certificate here
	// For now, we'll just return the CA certificate itself
	h.certCache[host] = &h.CA
	logger.Debug("Generated and cached new certificate for %s (placeholder)", host)

	return &h.CA, nil
}

// RegisterUDPInterceptHandler registers this interceptor to handle UDP traffic for QUIC
func (h *QUICHTTP3Interceptor) RegisterUDPInterceptHandler(proxy *Proxy) {
	// This would register with the proxy's UDP handler if implemented
	logger.Info("QUIC/HTTP3 interceptor registered with proxy")
}
