package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
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

	// Track if this is a WebSocket connection
	var isWebSocket atomic.Bool
	isWebSocket.Store(false)

	// Track current request URL for logging (shared between goroutines)
	var currentURL atomic.Value

	// Use wait group to coordinate goroutine completion
	wg := &sync.WaitGroup{}
	wg.Add(2)

	// Client -> Upstream
	go func() {
		defer wg.Done()

		for {
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
			req, err := http.ReadRequest(clientReader)
			if err != nil {
				if err != io.EOF && !isClosedConnError(err) {
					logger.Error("Error reading HTTP request: %v", err)
				}
				return
			}

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

			// Reject CONNECT requests to prevent tunneling bypasses
			if req.Method == http.MethodConnect {
				logger.Warn("Rejected CONNECT request to %s - method not allowed in interceptor", req.URL.String())
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
				_ = response.Write(clientConn)
				return
			}

			// Check for WebSocket upgrade request
			if strings.ToLower(req.Header.Get("Upgrade")) == "websocket" {
				logger.Debug("Detected WebSocket upgrade request")
				isWebSocket.Store(true)
			}

			// Read and potentially modify the body
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

			// Apply custom request hooks
			err = h.applyRequestHooks(req)
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
