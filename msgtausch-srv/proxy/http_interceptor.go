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
	"github.com/codefionn/msgtausch/msgtausch-srv/stats"
)

// HTTPInterceptor handles interception and modification of HTTP traffic.
type HTTPInterceptor struct {
	proxy         *Proxy                  // Reference to proxy for creating TCP connections
	requestHooks  map[string]RequestHook  // Request modification hooks by ID
	responseHooks map[string]ResponseHook // Response modification hooks by ID
	hookMutex     sync.RWMutex            // Mutex for hooks maps
}

// buildFullURL efficiently constructs a full URL from request components using strings.Builder
func buildFullURL(scheme, host, path, rawQuery string) string {
	// Pre-calculate capacity: scheme + "://" + host + path + "?" + rawQuery
	capacity := len(scheme) + 3 + len(host) + len(path)
	if rawQuery != "" {
		capacity += 1 + len(rawQuery)
	}

	var b strings.Builder
	b.Grow(capacity)
	b.WriteString(scheme)
	b.WriteString("://")
	b.WriteString(host)
	b.WriteString(path)
	if rawQuery != "" {
		b.WriteByte('?')
		b.WriteString(rawQuery)
	}
	return b.String()
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
		fullURL = buildFullURL("http", req.Header.Get("Host"), req.URL.Path, req.URL.RawQuery)
	}
	logger.DebugCtx(req.Context(), "HTTP interceptor handling request to %s (URL: %s)", req.URL.String(), fullURL)

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
	var streamed bool
	var requestRecordID int64
	var seqNo int64
	if shouldRecord && clonedReq.Body != nil {
		// If collector supports streaming, tee the body to DB while forwarding
		if h.proxy != nil && h.proxy.Collector != nil {
			if sr, ok := h.proxy.Collector.(stats.StreamingRecorder); ok {
				// Build headers snapshot for metadata with pre-allocated capacity
				requestHeaders := make(map[string][]string, len(req.Header))
				for k, v := range req.Header {
					requestHeaders[k] = v
				}
				rid, berr := sr.BeginRecordedHTTPRequest(req.Context(), 0, req.Method, fullURL, req.Host, req.UserAgent(), requestHeaders, time.Now())
				if berr == nil {
					streamed = true
					requestRecordID = rid
					seqNo = 0
					orig := clonedReq.Body
					clonedReq.Body = newTeeReadCloser(orig, func(chunk []byte) error {
						seqNo++
						// store copy to avoid reuse of buffer
						if aerr := sr.AppendRecordedHTTPRequestBodyPart(req.Context(), requestRecordID, seqNo, append([]byte(nil), chunk...), time.Now()); aerr != nil {
							logger.Error("Error appending request body part: %v", aerr)
						}
						return nil
					})
				} else {
					logger.Error("Failed to begin streaming recorded request: %v", berr)
				}
			}
		}
		// Fallback: buffer body fully if streaming not used
		if !streamed {
			requestBody, err = io.ReadAll(clonedReq.Body)
			if err != nil {
				logger.Error("Failed to read request body for recording: %v", err)
			} else {
				clonedReq.Body = io.NopCloser(bytes.NewReader(requestBody))
			}
		}
	}

	// Check if we have a proxy reference
	if h.proxy == nil {
		logger.Error("HTTP interception failed: No proxy reference for creating connection")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Remove hop-by-hop and proxy-specific headers in a single pass
	cleanRequestHeaders(clonedReq.Header)

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
			MaxIdleConns:          h.proxy.config.MaxIdleConns,
			MaxIdleConnsPerHost:   h.proxy.config.MaxIdleConnsPerHost,
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

	// If we streamed, mark the request as finished
	if streamed {
		if h.proxy != nil && h.proxy.Collector != nil {
			if sr, ok := h.proxy.Collector.(stats.StreamingRecorder); ok {
				if ferr := sr.FinishRecordedHTTPRequest(req.Context(), requestRecordID); ferr != nil {
					logger.Error("Failed to finish streaming recorded request: %v", ferr)
				}
			}
		}
	}

	// Apply response hooks
	err = h.applyResponseHooks(resp)
	if err != nil {
		logger.Error("Failed to apply response hooks: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Read/stream response body for recording if needed
	var responseBody []byte
	var respStreamed bool
	var responseRecordID int64
	var respSeq int64
	if shouldRecord {
		if h.proxy != nil && h.proxy.Collector != nil {
			if sr, ok := h.proxy.Collector.(stats.StreamingRecorder); ok {
				// Begin streaming response record with pre-allocated capacity
				responseHeaders := make(map[string][]string, len(resp.Header))
				for k, v := range resp.Header {
					responseHeaders[k] = v
				}
				rid, berr := sr.BeginRecordedHTTPResponse(req.Context(), 0, resp.StatusCode, responseHeaders, time.Now())
				if berr == nil {
					respStreamed = true
					responseRecordID = rid
					respSeq = 0
					orig := resp.Body
					resp.Body = newTeeReadCloser(orig, func(chunk []byte) error {
						respSeq++
						if aerr := sr.AppendRecordedHTTPResponseBodyPart(req.Context(), responseRecordID, respSeq, append([]byte(nil), chunk...), time.Now()); aerr != nil {
							logger.Error("Error appending response body part: %v", aerr)
						}
						return nil
					})
				} else {
					logger.Error("Failed to begin streaming recorded response: %v", berr)
				}
			}
		}
		// Fallback to buffering if not streaming
		if !respStreamed {
			responseBody, err = io.ReadAll(resp.Body)
			if err != nil {
				logger.Error("Failed to read response body for recording: %v", err)
			} else {
				resp.Body = io.NopCloser(bytes.NewReader(responseBody))
			}
		}
	}

	// Copy headers from the upstream response to our response (optimized batch copy)
	dstHeader := w.Header()
	for key, values := range resp.Header {
		dstHeader[key] = append(dstHeader[key], values...)
	}

	// Set the status code
	w.WriteHeader(resp.StatusCode)

	// Copy the response body
	_, err = copyBuffer(w, resp.Body)
	if err != nil {
		logger.Error("Error copying response body: %v", err)
		return
	}

	// Finish response streaming if used
	if respStreamed {
		if h.proxy != nil && h.proxy.Collector != nil {
			if sr, ok := h.proxy.Collector.(stats.StreamingRecorder); ok {
				if ferr := sr.FinishRecordedHTTPResponse(req.Context(), responseRecordID); ferr != nil {
					logger.Error("Failed to finish streaming recorded response: %v", ferr)
				}
			}
		}
	}

	// Record the full request/response if needed
	if shouldRecord && h.proxy.Collector != nil {
		connectionID := int64(0) // TODO: Get actual connection ID from context
		timestamp := time.Now()

		// Convert headers to map[string][]string format with pre-allocated capacity
		requestHeaders := make(map[string][]string, len(req.Header))
		for key, values := range req.Header {
			requestHeaders[key] = values
		}

		responseHeaders := make(map[string][]string, len(resp.Header))
		for key, values := range resp.Header {
			responseHeaders[key] = values
		}

		// Record request only if we didn't stream it
		if !streamed {
			if err := h.proxy.Collector.RecordFullHTTPRequest(req.Context(), connectionID,
				req.Method, fullURL, req.Host, req.UserAgent(), requestHeaders, requestBody, timestamp); err != nil {
				logger.Error("Failed to record full HTTP request: %v", err)
			}
		}

		// Record response only if we didn't stream it
		if !respStreamed {
			if err := h.proxy.Collector.RecordFullHTTPResponse(req.Context(), connectionID,
				resp.StatusCode, responseHeaders, responseBody, timestamp); err != nil {
				logger.Error("Failed to record full HTTP response: %v", err)
			}
		}
	}

	logger.DebugCtx(req.Context(), "HTTP interceptor completed request to %s with status %d (URL: %s)", req.URL.String(), resp.StatusCode, fullURL)
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
					bufPtr := getBuffer()
					buffer := *bufPtr
					for {
						n, err := clientReader.Read(buffer)
						if err != nil {
							if err != io.EOF && !isClosedConnError(err) {
								logger.Error("WebSocket client read error: %v", err)
							}
							putBuffer(bufPtr)
							return
						}

						_, err = upstreamConn.Write(buffer[:n])
						if err != nil {
							logger.Error("WebSocket upstream write error: %v", err)
							putBuffer(bufPtr)
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
				fullURL = buildFullURL("http", req.Header.Get("Host"), req.URL.Path, req.URL.RawQuery)
			}
			// Store URL for response logging
			currentURL.Store(fullURL)
			logger.DebugCtx(req.Context(), "Intercepted HTTP request: %s %s %s (URL: %s)", req.Method, req.URL, req.Proto, fullURL)

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

			// Remove hop-by-hop and proxy-specific headers in a single pass
			cleanRequestHeaders(req.Header)

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
				bufPtr := getBuffer()
				buffer := *bufPtr
				for {
					n, err := upstreamReader.Read(buffer)
					if err != nil {
						if err != io.EOF && !isClosedConnError(err) {
							logger.Error("WebSocket upstream read error: %v", err)
						}
						putBuffer(bufPtr)
						return
					}

					_, err = clientConn.Write(buffer[:n])
					if err != nil {
						logger.Error("WebSocket client write error: %v", err)
						putBuffer(bufPtr)
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

			// Detect Server-Sent Events (SSE) / streaming responses
			contentType := strings.ToLower(resp.Header.Get("Content-Type"))
			isEventStream := strings.Contains(contentType, "text/event-stream")

			if isEventStream {
				// For event streams, stream directly without buffering to preserve latency
				logger.Debug("Detected event-stream response; streaming without buffering (URL: %s)", fullURL)
				// Clear deadlines to avoid cutting long-lived streams
				// Note: in HTTP interceptor we do not manage deadlines here; streaming directly
				if err := resp.Write(clientConn); err != nil {
					if err != io.EOF && !isClosedConnError(err) {
						logger.Error("Error streaming event-stream response: %v", err)
					}
					return
				}
				if resp.Body != nil {
					if closeErr := resp.Body.Close(); closeErr != nil {
						logger.Error("Error closing streaming response body: %v", closeErr)
					}
				}
				continue
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

// HandleTCPConnectionWithContext handles a raw TCP connection for HTTP interception with context for UUID logging
func (h *HTTPInterceptor) HandleTCPConnectionWithContext(ctx context.Context, clientConn net.Conn, host string) {
	logger.DebugCtx(ctx, "HTTP interceptor handling direct TCP connection to %s", host)

	// For cleanliness, ensure we close the connection when done
	defer func() {
		if err := clientConn.Close(); err != nil {
			logger.Error("Failed to close client connection: %v", err)
		}
	}()

	// Track processed requests for debugging
	processedRequests := 0

	// Connect to the upstream server
	upstreamConn, err := h.proxy.createForwardTCPClient(ctx, host)
	if err != nil {
		logger.Error("Failed to connect to upstream server %s: %v", host, err)
		return
	}
	defer func() {
		if closeErr := upstreamConn.Close(); closeErr != nil {
			logger.Error("Failed to close upstream connection: %v", closeErr)
		}
	}()

	logger.DebugCtx(ctx, "HTTP interceptor established connection to upstream server %s", host)

	// Create atomic value to track WebSocket upgrade status
	var isWebSocket atomic.Bool
	var currentURL atomic.Value // Store the current request URL for response logging

	// Interceptor function for request traffic
	intercept := func(clientReader *bufio.Reader, upstreamWriter io.Writer) {
		for {
			// Read HTTP request
			var req *http.Request
			if processedRequests == 0 {
				// For the first request, we might have TLS Client Hello
				// Try to read a line to detect if it's an HTTP request
				firstLine, _, err := clientReader.ReadLine()
				if err != nil {
					if err != io.EOF {
						logger.Error("Error reading first line: %v", err)
					}
					return
				}

				// Check if it's an HTTP request line
				firstLineStr := string(firstLine)
				if strings.HasPrefix(firstLineStr, "GET ") ||
					strings.HasPrefix(firstLineStr, "POST ") ||
					strings.HasPrefix(firstLineStr, "PUT ") ||
					strings.HasPrefix(firstLineStr, "DELETE ") ||
					strings.HasPrefix(firstLineStr, "HEAD ") ||
					strings.HasPrefix(firstLineStr, "OPTIONS ") ||
					strings.HasPrefix(firstLineStr, "PATCH ") ||
					strings.HasPrefix(firstLineStr, "CONNECT ") {
					// It's an HTTP request, reconstruct the request
					reqBytes := make([]byte, len(firstLine)+2)
					copy(reqBytes, firstLine)
					reqBytes[len(firstLine)] = '\r'
					reqBytes[len(firstLine)+1] = '\n'
					remainingReq := &bytes.Buffer{}
					remainingReq.Write(reqBytes)

					// Read the rest of the headers
					for {
						line, _, err := clientReader.ReadLine()
						if err != nil {
							logger.Error("Error reading request headers: %v", err)
							return
						}
						remainingReq.Write(line)
						remainingReq.WriteString("\r\n")
						if len(line) == 0 {
							break // End of headers
						}
					}

					// Parse the HTTP request
					req, err = http.ReadRequest(bufio.NewReader(remainingReq))
					if err != nil {
						logger.Error("Error parsing HTTP request: %v", err)
						return
					}
				} else {
					// Not an HTTP request, pass through directly
					logger.DebugCtx(ctx, "Non-HTTP traffic detected, switching to raw tunnel mode")
					if _, err := upstreamWriter.Write(firstLine); err != nil {
						logger.Error("Error writing to upstream: %v", err)
					}
					return
				}
			} else {
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
				fullURL = buildFullURL("http", req.Header.Get("Host"), req.URL.Path, req.URL.RawQuery)
			}
			// Store URL for response logging
			currentURL.Store(fullURL)
			logger.DebugCtx(ctx, "Intercepted HTTP request: %s %s %s (URL: %s)", req.Method, req.URL, req.Proto, fullURL)

			// Check for WebSocket upgrade request
			if strings.ToLower(req.Header.Get("Upgrade")) == "websocket" {
				logger.DebugCtx(ctx, "Detected WebSocket upgrade request")
				isWebSocket.Store(true)
			}

			// Apply request hooks
			h.hookMutex.RLock()
			for hookID, hook := range h.requestHooks {
				if err := hook(req); err != nil {
					logger.Error("Request hook %s failed: %v", hookID, err)
				}
			}
			h.hookMutex.RUnlock()

			// Forward the request to upstream
			if err := req.Write(upstreamWriter); err != nil {
				logger.Error("Error writing request to upstream: %v", err)
				return
			}

			// If this is a WebSocket upgrade request, switch to raw tunneling
			if isWebSocket.Load() {
				logger.DebugCtx(ctx, "Switching to raw tunnel mode for WebSocket connection")
				return
			}
		}
	}

	// Interceptor function for response traffic
	interceptResponse := func(upstreamReader *bufio.Reader, clientWriter io.Writer) {
		for {
			// If we're in WebSocket mode, don't parse HTTP responses
			if isWebSocket.Load() {
				logger.DebugCtx(ctx, "In WebSocket mode, skipping HTTP response parsing")
				return
			}

			// Read HTTP response
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
			logger.DebugCtx(ctx, "Intercepted HTTP response with status: %s (URL: %s)", resp.Status, fullURL)

			// Check for WebSocket upgrade response
			if resp.StatusCode == http.StatusSwitchingProtocols &&
				strings.ToLower(resp.Header.Get("Upgrade")) == "websocket" {
				logger.DebugCtx(ctx, "Detected WebSocket upgrade response, switching to raw tunnel mode")
				isWebSocket.Store(true)
			}

			// Apply response hooks
			h.hookMutex.RLock()
			for hookID, hook := range h.responseHooks {
				if err := hook(resp); err != nil {
					logger.Error("Response hook %s failed: %v", hookID, err)
				}
			}
			h.hookMutex.RUnlock()

			// Forward the response to client
			if err := resp.Write(clientWriter); err != nil {
				resp.Body.Close()
				logger.Error("Error writing response to client: %v", err)
				return
			}

			// Close the response body after writing
			resp.Body.Close()

			// If this is a WebSocket upgrade response, switch to raw tunneling
			if isWebSocket.Load() {
				logger.DebugCtx(ctx, "Switching to raw tunnel mode after WebSocket upgrade response")
				return
			}
		}
	}

	// Start the bidirectional data flow
	var wg sync.WaitGroup

	// Handle client to upstream (requests)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				logger.Error("Panic in request interceptor: %v", r)
			}
		}()

		clientReader := bufio.NewReader(clientConn)

		// Start request interception
		intercept(clientReader, upstreamConn)

		// After interception ends, continue with raw tunneling if needed
		if _, err := copyBuffer(upstreamConn, clientReader); err != nil && !isClosedConnError(err) {
			logger.Error("Error copying client to upstream: %v", err)
		}
	}()

	// Handle upstream to client (responses)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				logger.Error("Panic in response interceptor: %v", r)
			}
		}()

		upstreamReader := bufio.NewReader(upstreamConn)

		// Start response interception
		interceptResponse(upstreamReader, clientConn)

		// After interception ends, continue with raw tunneling if needed
		if _, err := copyBuffer(clientConn, upstreamReader); err != nil && !isClosedConnError(err) {
			logger.Error("Error copying upstream to client: %v", err)
		}
	}()

	// Wait for both operations to complete
	wg.Wait()
	logger.DebugCtx(ctx, "HTTP interceptor tunnel closed for %s", host)
}

// cleanRequestHeaders removes hop-by-hop and proxy-specific headers in a single pass
// but preserves WebSocket upgrade headers according to RFC 7230
func cleanRequestHeaders(header http.Header) {
	// Check if this is a WebSocket upgrade request
	isWebSocketUpgrade := strings.ToLower(header.Get("Upgrade")) == "websocket"

	// Pre-allocate slice for headers to delete
	toDelete := make([]string, 0, 10)

	// Single pass through all headers
	for key := range header {
		keyLower := strings.ToLower(key)

		// Check against all removal criteria in one pass
		shouldRemove := false

		// Hop-by-hop headers
		if keyLower == "proxy-authenticate" || keyLower == "proxy-authorization" {
			shouldRemove = true
		}

		// For non-WebSocket requests, remove Connection and Upgrade
		if !isWebSocketUpgrade && (keyLower == "connection" || keyLower == "upgrade") {
			shouldRemove = true
		}

		// Proxy-specific headers
		if keyLower == "proxy-connection" || keyLower == "x-forwarded-for" ||
			keyLower == "x-forwarded-host" || keyLower == "x-forwarded-proto" {
			shouldRemove = true
		}

		if shouldRemove {
			toDelete = append(toDelete, key)
		}
	}

	// Delete marked headers
	for _, key := range toDelete {
		header.Del(key)
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

// rawTunnel handles raw TCP tunneling when TLS data is detected
// This is used as a fallback when the HTTP interceptor detects TLS handshake bytes
func (h *HTTPInterceptor) rawTunnel(clientConn, upstreamConn net.Conn) {
	logger.Debug("Starting raw TCP tunnel")

	var wg sync.WaitGroup
	wg.Add(2)

	// Copy client to upstream
	go func() {
		defer wg.Done()
		_, err := copyBuffer(upstreamConn, clientConn)
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
		_, err := copyBuffer(clientConn, upstreamConn)
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
