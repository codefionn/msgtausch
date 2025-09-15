package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
)

// HTTPInterceptor handles interception and modification of HTTP traffic.
type HTTPInterceptor struct {
	proxy         *Proxy                  // Reference to proxy for creating TCP connections
	requestHooks  map[string]RequestHook  // Request modification hooks by ID
	responseHooks map[string]ResponseHook // Response modification hooks by ID
	hookMutex     sync.RWMutex            // Mutex for hooks maps
}

// RequestHook is a function that can modify an HTTP request before it's sent upstream
type RequestHook func(*http.Request) error

// ResponseHook is a function that can modify an HTTP response before it's sent back to the client
type ResponseHook func(*http.Response) error

// NewHTTPInterceptor creates a new HTTPInterceptor
func NewHTTPInterceptor(proxy *Proxy) *HTTPInterceptor {
	return &HTTPInterceptor{
		proxy:         proxy,
		requestHooks:  make(map[string]RequestHook),
		responseHooks: make(map[string]ResponseHook),
	}
}

// AddRequestHook adds a hook that will be called for each intercepted request
func (h *HTTPInterceptor) AddRequestHook(id string, hook RequestHook) {
	h.hookMutex.Lock()
	defer h.hookMutex.Unlock()
	h.requestHooks[id] = hook
	logger.Debug("Added HTTP request hook: %s", id)
}

// RemoveRequestHook removes a request hook by ID
func (h *HTTPInterceptor) RemoveRequestHook(id string) {
	h.hookMutex.Lock()
	defer h.hookMutex.Unlock()
	delete(h.requestHooks, id)
	logger.Debug("Removed HTTP request hook: %s", id)
}

// AddResponseHook adds a hook that will be called for each intercepted response
func (h *HTTPInterceptor) AddResponseHook(id string, hook ResponseHook) {
	h.hookMutex.Lock()
	defer h.hookMutex.Unlock()
	h.responseHooks[id] = hook
	logger.Debug("Added HTTP response hook: %s", id)
}

// RemoveResponseHook removes a response hook by ID
func (h *HTTPInterceptor) RemoveResponseHook(id string) {
	h.hookMutex.Lock()
	defer h.hookMutex.Unlock()
	delete(h.responseHooks, id)
	logger.Debug("Removed HTTP response hook: %s", id)
}

// applyRequestHooks applies all registered request hooks to the given request
func (h *HTTPInterceptor) applyRequestHooks(req *http.Request) error {
	h.hookMutex.RLock()
	defer h.hookMutex.RUnlock()

	for id, hook := range h.requestHooks {
		err := hook(req)
		if err != nil {
			logger.Error("HTTP request hook %s failed: %v", id, err)
			return fmt.Errorf("request hook %s failed: %w", id, err)
		}
	}

	return nil
}

// applyResponseHooks applies all registered response hooks to the given response
func (h *HTTPInterceptor) applyResponseHooks(resp *http.Response) error {
	h.hookMutex.RLock()
	defer h.hookMutex.RUnlock()

	for id, hook := range h.responseHooks {
		err := hook(resp)
		if err != nil {
			logger.Error("HTTP response hook %s failed: %v", id, err)
			return fmt.Errorf("response hook %s failed: %w", id, err)
		}
	}

	return nil
}

// shouldRecordRequest determines if this request should be fully recorded based on recording classifier
func (h *HTTPInterceptor) shouldRecordRequest(req *http.Request) bool {
	if h.proxy == nil || h.proxy.config == nil || !h.proxy.config.Statistics.Enabled {
		return false
	}

	// Use the server's recording classifier if available, otherwise use proxy's
	var recordingClassifier Classifier
	if server := h.getServerFromContext(req.Context()); server != nil && server.recordingClassifier != nil {
		recordingClassifier = server.recordingClassifier
	} else if h.proxy.recordingClassifier != nil {
		recordingClassifier = h.proxy.recordingClassifier
	} else {
		return false
	}

	input := ClassifierInput{
		host:       req.Host,
		remotePort: 80, // Default HTTP port, will be overridden if available
	}

	// Extract port from Host header if present
	if host, port, err := net.SplitHostPort(req.Host); err == nil {
		input.host = host
		if portInt, err := strconv.Atoi(port); err == nil {
			input.remotePort = uint16(portInt)
		}
	}

	matches, err := recordingClassifier.Classify(input)
	if err != nil {
		logger.Error("Error classifying request for recording: %v", err)
		return false
	}

	return matches
}

// getServerFromContext extracts server from request context if available
func (h *HTTPInterceptor) getServerFromContext(ctx context.Context) *Server {
	// This would need to be implemented based on how server context is passed
	// For now, return nil and rely on proxy-level classifier
	return nil
}

// InterceptRequest handles intercepting an HTTP request, applying hooks, and forwarding it
func (h *HTTPInterceptor) InterceptRequest(w http.ResponseWriter, req *http.Request) {
	// Construct full URL for logging
	fullURL := req.URL.String()
	if req.URL.Host == "" && req.Header.Get("Host") != "" {
		scheme := "http"
		fullURL = fmt.Sprintf("%s://%s%s", scheme, req.Header.Get("Host"), req.URL.Path)
		if req.URL.RawQuery != "" {
			fullURL += "?" + req.URL.RawQuery
		}
	}
	logger.Debug("HTTP interceptor handling request to %s (URL: %s)", req.URL.String(), fullURL)

	// Reject CONNECT requests to prevent tunneling bypasses
	if req.Method == http.MethodConnect {
		logger.Warn("Rejected CONNECT request to %s - method not allowed in interceptor", req.URL.String())
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Clone the request to avoid modifying the original
	clonedReq := req.Clone(req.Context())

	// Apply request hooks
	err := h.applyRequestHooks(clonedReq)
	if err != nil {
		logger.Error("Failed to apply request hooks: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Check if request should be recorded
	shouldRecord := h.shouldRecordRequest(req)
	var requestBody []byte
	if shouldRecord && clonedReq.Body != nil {
		// Read the request body for recording
		requestBody, err = io.ReadAll(clonedReq.Body)
		if err != nil {
			logger.Error("Failed to read request body for recording: %v", err)
		} else {
			// Replace the body with a reader for the actual request
			clonedReq.Body = io.NopCloser(bytes.NewReader(requestBody))
		}
	}

	// Check if we have a proxy reference
	if h.proxy == nil {
		logger.Error("HTTP interception failed: No proxy reference for creating connection")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Remove hop-by-hop headers
	removeHopByHopHeaders(clonedReq.Header)

	// Remove proxy-specific headers
	removeProxyHeaders(clonedReq.Header)

	// Ensure the Host header is correctly set
	if clonedReq.Host != "" {
		clonedReq.Header.Set("Host", clonedReq.Host)
	}

	// Create a client to forward the request
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return h.proxy.createForwardTCPClient(ctx, addr)
			},
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		// Don't automatically follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Forward the request
	resp, err := client.Do(clonedReq)
	if err != nil {
		logger.Error("HTTP interception failed: Unable to forward request: %v", err)
		// Use our custom Bad Gateway response.
		// If err is a *Error, its code will be used. Otherwise, ErrCodeHTTPForwardFailed.
		writeProxyErrorResponse(w, err, ErrCodeHTTPForwardFailed)
		return
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Error("Error closing response body: %v", closeErr)
		}
	}()

	// Apply response hooks
	err = h.applyResponseHooks(resp)
	if err != nil {
		logger.Error("Failed to apply response hooks: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Read response body for recording if needed
	var responseBody []byte
	if shouldRecord {
		responseBody, err = io.ReadAll(resp.Body)
		if err != nil {
			logger.Error("Failed to read response body for recording: %v", err)
		} else {
			// Replace the body with a reader for the actual response
			resp.Body = io.NopCloser(bytes.NewReader(responseBody))
		}
	}

	// Copy headers from the upstream response to our response
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Set the status code
	w.WriteHeader(resp.StatusCode)

	// Copy the response body
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		logger.Error("Error copying response body: %v", err)
		return
	}

	// Record the full request/response if needed
	if shouldRecord && h.proxy.Collector != nil {
		connectionID := int64(0) // TODO: Get actual connection ID from context
		timestamp := time.Now()

		// Convert headers to map[string][]string format
		requestHeaders := make(map[string][]string)
		for key, values := range req.Header {
			requestHeaders[key] = values
		}

		responseHeaders := make(map[string][]string)
		for key, values := range resp.Header {
			responseHeaders[key] = values
		}

		// Record request
		if err := h.proxy.Collector.RecordFullHTTPRequest(req.Context(), connectionID,
			req.Method, fullURL, req.Host, req.UserAgent(), requestHeaders, requestBody, timestamp); err != nil {
			logger.Error("Failed to record full HTTP request: %v", err)
		}

		// Record response
		if err := h.proxy.Collector.RecordFullHTTPResponse(req.Context(), connectionID,
			resp.StatusCode, responseHeaders, responseBody, timestamp); err != nil {
			logger.Error("Failed to record full HTTP response: %v", err)
		}
	}

	logger.Debug("HTTP interceptor completed request to %s with status %d (URL: %s)", req.URL.String(), resp.StatusCode, fullURL)
}

// HandleTCPConnection handles a raw TCP connection for HTTP interception
func (h *HTTPInterceptor) HandleTCPConnection(clientConn net.Conn, host string) {
	logger.Debug("HTTP interceptor handling direct TCP connection to %s", host)

	// For cleanliness, ensure we close the connection when done
	defer func() {
		if closeErr := clientConn.Close(); closeErr != nil {
			logger.Error("Error closing client connection: %v", closeErr)
		}
	}()

	// Check if we have a proxy reference
	if h.proxy == nil {
		logger.Error("HTTP interception failed: No proxy reference for creating TCP connection")
		return
	}

	// Connect to upstream server using proxy's connection method
	upstreamConn, err := h.proxy.createForwardTCPClient(context.Background(), host)
	if err != nil {
		logger.Error("HTTP interception failed: Unable to connect to upstream: %v", err)
		return
	}
	defer func() {
		if closeErr := upstreamConn.Close(); closeErr != nil {
			logger.Error("Error closing upstream connection: %v", closeErr)
		}
	}()

	logger.Debug("HTTP interceptor established connection to upstream server %s", host)

	// Create buffered readers for both connections
	clientReader := bufio.NewReader(clientConn)
	upstreamReader := bufio.NewReader(upstreamConn)

	// Peek at the first few bytes to detect if this is TLS or HTTP
	firstBytes, err := clientReader.Peek(1)
	if err != nil {
		if err != io.EOF && !isClosedConnError(err) {
			logger.Error("Error peeking at connection: %v", err)
		}
		return
	}

	// Check for TLS handshake (first byte is 0x16 for TLS handshake)
	if len(firstBytes) > 0 && firstBytes[0] == 0x16 {
		logger.Debug("Detected TLS handshake, switching to raw TCP tunnel mode")
		// This is a TLS connection, fallback to raw tunneling
		h.rawTunnel(clientConn, upstreamConn)
		return
	}

	// Read the first request to check for CONNECT method before starting goroutines
	firstReq, err := http.ReadRequest(clientReader)
	if err != nil {
		if err != io.EOF && !isClosedConnError(err) {
			logger.Error("Error reading initial HTTP request: %v", err)
		}
		return
	}

	// Reject CONNECT requests to prevent tunneling bypasses
	if firstReq.Method == http.MethodConnect {
		logger.Warn("Rejected CONNECT request to %s - method not allowed in interceptor", firstReq.URL.String())
		// Send 405 Method Not Allowed response
		response := &http.Response{
			Status:        "405 Method Not Allowed",
			StatusCode:    http.StatusMethodNotAllowed,
			Proto:         firstReq.Proto,
			ProtoMajor:    firstReq.ProtoMajor,
			ProtoMinor:    firstReq.ProtoMinor,
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader("Method Not Allowed")),
			ContentLength: 18,
		}
		response.Header.Set("Content-Type", "text/plain")
		response.Header.Set("Content-Length", "18")
		_ = response.Write(clientConn)
		return
	}

	// Track if this is a WebSocket connection
	var isWebSocket atomic.Bool
	isWebSocket.Store(false)

	// Track current request URL for logging (shared between goroutines)
	var currentURL atomic.Value

	// Check if the first request is a WebSocket upgrade
	if strings.ToLower(firstReq.Header.Get("Upgrade")) == "websocket" {
		logger.Debug("Detected WebSocket upgrade request")
		isWebSocket.Store(true)
	}

	// Use wait group to coordinate goroutine completion
	wg := &sync.WaitGroup{}
	wg.Add(2)

	// Client -> Upstream
	go func() {
		defer wg.Done()

		// Process the first request that we already read
		processedRequests := 0
		requestsToProcess := []*http.Request{firstReq}

		for len(requestsToProcess) > 0 || processedRequests == 0 {
			var req *http.Request

			if len(requestsToProcess) > 0 {
				// Process a queued request
				req = requestsToProcess[0]
				requestsToProcess = requestsToProcess[1:]
			} else {
				// If we've already detected WebSocket, switch to direct copying
				if isWebSocket.Load() {
					// For WebSockets, we just copy bytes directly
					buffer := make([]byte, 32*1024)
					for {
						n, err := clientReader.Read(buffer)
						if err != nil {
							if err != io.EOF && !isClosedConnError(err) {
								logger.Error("WebSocket client read error: %v", err)
							}
							return
						}

						_, err = upstreamConn.Write(buffer[:n])
						if err != nil {
							logger.Error("WebSocket upstream write error: %v", err)
							return
						}
					}
				}

				// For HTTP traffic, parse the request
				var err error
				req, err = http.ReadRequest(clientReader)
				if err != nil {
					if err != io.EOF && !isClosedConnError(err) {
						logger.Error("Error reading HTTP request: %v", err)
					}
					return
				}
			}

			processedRequests++

			// Construct full URL for logging
			fullURL := req.URL.String()
			if req.URL.Host == "" && req.Header.Get("Host") != "" {
				scheme := "http"
				fullURL = fmt.Sprintf("%s://%s%s", scheme, req.Header.Get("Host"), req.URL.Path)
				if req.URL.RawQuery != "" {
					fullURL += "?" + req.URL.RawQuery
				}
			}
			// Store URL for response logging
			currentURL.Store(fullURL)
			logger.Debug("Intercepted HTTP request: %s %s %s (URL: %s)", req.Method, req.URL, req.Proto, fullURL)

			// Check for WebSocket upgrade request
			if strings.ToLower(req.Header.Get("Upgrade")) == "websocket" {
				logger.Debug("Detected WebSocket upgrade request")
				isWebSocket.Store(true)
			}

			// Read and potentially modify the body
			var bodyData []byte
			if req.Body != nil {
				var err error
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

			// Apply custom request hooks
			err := h.applyRequestHooks(req)
			if err != nil {
				logger.Error("Error applying request hooks: %v", err)
				return
			}

			// Remove hop-by-hop headers
			removeHopByHopHeaders(req.Header)

			// Remove proxy-specific headers
			removeProxyHeaders(req.Header)

			// Add Host header if URL has a Host but no Host header is set
			if req.Header.Get("Host") == "" && req.Host != "" {
				req.Header.Set("Host", req.Host)
			}

			// Write the request to the upstream server
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
					n, err := upstreamReader.Read(buffer)
					if err != nil {
						if err != io.EOF && !isClosedConnError(err) {
							logger.Error("WebSocket upstream read error: %v", err)
						}
						return
					}

					_, err = clientConn.Write(buffer[:n])
					if err != nil {
						logger.Error("WebSocket client write error: %v", err)
						return
					}
				}
			}

			// For HTTP traffic, parse the response
			resp, err := http.ReadResponse(upstreamReader, nil)
			if err != nil {
				if err != io.EOF && !isClosedConnError(err) {
					logger.Error("Error reading HTTP response: %v", err)
				}
				return
			}

			// Log response with URL context
			fullURL := "unknown"
			if storedURL := currentURL.Load(); storedURL != nil {
				fullURL = storedURL.(string)
			}
			logger.Debug("Intercepted HTTP response with status: %s (URL: %s)", resp.Status, fullURL)

			// Check for WebSocket upgrade response
			if resp.StatusCode == http.StatusSwitchingProtocols &&
				strings.ToLower(resp.Header.Get("Upgrade")) == "websocket" {
				logger.Debug("Detected WebSocket upgrade response")
				isWebSocket.Store(true)
			}

			// Read and potentially modify the body
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

			// Apply custom response hooks
			err = h.applyResponseHooks(resp)
			if err != nil {
				logger.Error("Error applying response hooks: %v", err)
				return
			}

			// Write the response back to the client
			err = resp.Write(clientConn)
			if err != nil {
				logger.Error("Error writing response to client: %v", err)
				return
			}

			// For WebSocket connections, after sending the upgrade response,
			// we switch to direct copying mode
			if isWebSocket.Load() {
				logger.Debug("Switching to WebSocket mode after upgrade response")
			}
		}
	}()

	// Wait for both operations to complete
	wg.Wait()
	logger.Debug("HTTP interceptor tunnel closed for %s", host)
}

// removeHopByHopHeaders removes hop-by-hop headers according to RFC 2616
// but preserves WebSocket upgrade headers
func removeHopByHopHeaders(header http.Header) {
	// Check if this is a WebSocket upgrade request
	isWebSocketUpgrade := strings.ToLower(header.Get("Upgrade")) == "websocket"

	// List of hop-by-hop headers from RFC 2616
	hopByHopHeaders := []string{
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"TE",
		"Trailers",
		"Transfer-Encoding",
	}

	// For WebSocket upgrades, preserve Connection and Upgrade headers
	if !isWebSocketUpgrade {
		hopByHopHeaders = append(hopByHopHeaders, "Connection", "Upgrade")
	}

	// Remove standard hop-by-hop headers
	for _, h := range hopByHopHeaders {
		header.Del(h)
	}

	// For non-WebSocket requests, remove headers listed in Connection header
	if !isWebSocketUpgrade {
		if c := header.Get("Connection"); c != "" {
			for _, f := range strings.Split(c, ",") {
				if f = strings.TrimSpace(f); f != "" {
					header.Del(f)
				}
			}
		}
	}
}

// removeProxyHeaders removes proxy-specific headers
func removeProxyHeaders(header http.Header) {
	// List of common proxy headers
	proxyHeaders := []string{
		"Proxy-Connection",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Proto",
	}

	// Remove proxy headers
	for _, h := range proxyHeaders {
		header.Del(h)
	}
}

// rawTunnel handles raw TCP tunneling when TLS data is detected
// This is used as a fallback when the HTTP interceptor detects TLS handshake bytes
func (h *HTTPInterceptor) rawTunnel(clientConn, upstreamConn net.Conn) {
	logger.Debug("Starting raw TCP tunnel")

	var wg sync.WaitGroup
	wg.Add(2)

	// Copy client to upstream
	go func() {
		defer wg.Done()
		_, err := io.Copy(upstreamConn, clientConn)
		if err != nil && !isClosedConnError(err) {
			logger.Error("Raw tunnel: client to upstream copy error: %v", err)
		}
		// Close write side to signal EOF
		if tcpConn, ok := upstreamConn.(*net.TCPConn); ok {
			if err := tcpConn.CloseWrite(); err != nil {
				logger.Debug("Failed to close write on upstream connection: %v", err)
			}
		}
	}()

	// Copy upstream to client
	go func() {
		defer wg.Done()
		_, err := io.Copy(clientConn, upstreamConn)
		if err != nil && !isClosedConnError(err) {
			logger.Error("Raw tunnel: upstream to client copy error: %v", err)
		}
		// Close write side to signal EOF
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			if err := tcpConn.CloseWrite(); err != nil {
				logger.Debug("Failed to close write on client connection: %v", err)
			}
		}
	}()

	wg.Wait()
	logger.Debug("Raw TCP tunnel closed")
}
