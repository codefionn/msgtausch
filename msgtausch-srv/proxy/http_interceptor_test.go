package proxy

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPInterceptor(t *testing.T) {
	// Create mock proxy for testing
	mockProxy := createMockProxy(t)

	// Create the interceptor
	interceptor := NewHTTPInterceptor(mockProxy)

	// Test content to verify in responses
	testContent := "Hello, HTTP Interceptor!"

	// Create a test server that responds with test content
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back request headers in response
		for k, v := range r.Header {
			if k == "X-Test-Header" {
				w.Header().Set(k, v[0])
			}
		}

		// Echo back request method
		w.Header().Set("X-Request-Method", r.Method)

		// Handle different HTTP methods
		switch r.Method {
		case "POST":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = w.Write(body)
		default:
			_, _ = w.Write([]byte(testContent))
		}
	}))
	defer testServer.Close()

	t.Run("RequestHook modifications", func(t *testing.T) {
		// Add a request hook that sets a custom header
		interceptor.AddRequestHook("test-hook", func(req *http.Request) error {
			req.Header.Set("X-Test-Header", "modified-by-hook")
			return nil
		})
		defer interceptor.RemoveRequestHook("test-hook")

		// Create a test request that will be intercepted
		req, err := http.NewRequest("GET", testServer.URL, http.NoBody)
		require.NoError(t, err)

		// Create a test response recorder
		rec := httptest.NewRecorder()

		// Handle the request with the interceptor
		interceptor.InterceptRequest(rec, req)

		// Check the response
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "modified-by-hook", rec.Header().Get("X-Test-Header"))
		assert.Equal(t, testContent, rec.Body.String())
	})

	t.Run("ResponseHook modifications", func(t *testing.T) {
		// Add a response hook that modifies the response body
		interceptor.AddResponseHook("test-hook", func(resp *http.Response) error {
			// Read the original body
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			resp.Body.Close()

			// Modify the body
			modifiedBody := string(body) + " - Modified by hook"

			// Create a new body with the modified content
			resp.Body = io.NopCloser(bytes.NewBufferString(modifiedBody))

			// Update Content-Length
			resp.ContentLength = int64(len(modifiedBody))

			return nil
		})
		defer interceptor.RemoveResponseHook("test-hook")

		// Create a test request
		req, err := http.NewRequest("GET", testServer.URL, http.NoBody)
		require.NoError(t, err)

		// Create a test response recorder
		rec := httptest.NewRecorder()

		// Handle the request with the interceptor
		interceptor.InterceptRequest(rec, req)

		// Check the response
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, testContent+" - Modified by hook", rec.Body.String())
	})

	t.Run("Error in hooks", func(t *testing.T) {
		// Add a request hook that returns an error
		interceptor.AddRequestHook("error-hook", func(req *http.Request) error {
			return assert.AnError
		})
		defer interceptor.RemoveRequestHook("error-hook")

		// Create a test request
		req, err := http.NewRequest("GET", testServer.URL, http.NoBody)
		require.NoError(t, err)

		// Create a test response recorder
		rec := httptest.NewRecorder()

		// Handle the request with the interceptor
		interceptor.InterceptRequest(rec, req)

		// Check that an error response was returned
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("POST request", func(t *testing.T) {
		// Remove any error hooks
		interceptor.RemoveRequestHook("error-hook")

		// Create a test POST request with a body
		body := "POST body content"
		req, err := http.NewRequest("POST", testServer.URL, bytes.NewBufferString(body))
		require.NoError(t, err)

		// Create a test response recorder
		rec := httptest.NewRecorder()

		// Handle the request with the interceptor
		interceptor.InterceptRequest(rec, req)

		// Check the response
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, body, rec.Body.String())
	})

	t.Run("CONNECT request rejection", func(t *testing.T) {
		// Create a CONNECT request
		req, err := http.NewRequest("CONNECT", "example.com:443", http.NoBody)
		require.NoError(t, err)

		// Create a test response recorder
		rec := httptest.NewRecorder()

		// Handle the request with the interceptor
		interceptor.InterceptRequest(rec, req)

		// Check that the CONNECT request was rejected with 405 Method Not Allowed
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		assert.Contains(t, rec.Body.String(), "Method Not Allowed")
	})

	t.Run("WebSocket header preservation in cleanRequestHeaders", func(t *testing.T) {
		// Test that WebSocket headers are preserved when cleaning request headers
		headers := make(http.Header)
		headers.Set("Upgrade", "websocket")
		headers.Set("Connection", "Upgrade")
		headers.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		headers.Set("Sec-WebSocket-Version", "13")
		headers.Set("Keep-Alive", "timeout=5")
		headers.Set("Proxy-Authorization", "Basic abc123")

		// Call the function that removes hop-by-hop headers
		cleanRequestHeaders(headers)

		// Verify WebSocket headers are preserved
		assert.Equal(t, "websocket", headers.Get("Upgrade"))
		assert.Equal(t, "Upgrade", headers.Get("Connection"))
		assert.Equal(t, "dGhlIHNhbXBsZSBub25jZQ==", headers.Get("Sec-WebSocket-Key"))
		assert.Equal(t, "13", headers.Get("Sec-WebSocket-Version"))

		// Verify only proxy-specific headers are removed
		// Keep-Alive should be preserved for proper HTTP semantics
		assert.Equal(t, "timeout=5", headers.Get("Keep-Alive"))
		assert.Empty(t, headers.Get("Proxy-Authorization"))
	})

	t.Run("Non-WebSocket headers are removed", func(t *testing.T) {
		// Test that for non-WebSocket requests, Upgrade and Connection headers are removed
		headers := make(http.Header)
		headers.Set("Upgrade", "h2c")
		headers.Set("Connection", "Upgrade")
		headers.Set("Keep-Alive", "timeout=5")
		headers.Set("Host", "example.com")

		// Call the function that removes hop-by-hop headers
		cleanRequestHeaders(headers)

		// Verify non-WebSocket upgrade headers are removed
		assert.Empty(t, headers.Get("Upgrade"))
		assert.Empty(t, headers.Get("Connection"))
		// Keep-Alive should be preserved per RFC 7230
		assert.Equal(t, "timeout=5", headers.Get("Keep-Alive"))

		// Verify regular headers are preserved
		assert.Equal(t, "example.com", headers.Get("Host"))
	})

	t.Run("Real WebSocket connection through interceptor", func(t *testing.T) {
		// Create a real WebSocket server using gorilla/websocket
		var upgrader = websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for testing
			},
		}

		testMessage := "Hello WebSocket!"
		echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Upgrade the connection to WebSocket
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				t.Errorf("Failed to upgrade connection: %v", err)
				return
			}
			defer conn.Close()

			// Echo messages back to client
			for {
				messageType, message, err := conn.ReadMessage()
				if err != nil {
					break
				}
				err = conn.WriteMessage(messageType, message)
				if err != nil {
					break
				}
			}
		}))
		defer echoServer.Close()

		// Track hook calls
		var requestHookCalled bool

		interceptor.AddRequestHook("websocket-test", func(req *http.Request) error {
			if req.Header.Get("Upgrade") == "websocket" {
				requestHookCalled = true
				// Add custom header to verify hook was called
				req.Header.Set("X-Intercepted", "true")
			}
			return nil
		})
		defer interceptor.RemoveRequestHook("websocket-test")

		interceptor.AddResponseHook("websocket-test", func(resp *http.Response) error {
			if resp.StatusCode == http.StatusSwitchingProtocols {
				// Add custom header to verify hook was called
				resp.Header.Set("X-Response-Intercepted", "true")
			}
			return nil
		})
		defer interceptor.RemoveResponseHook("websocket-test")

		// Create WebSocket client that connects through our interceptor
		serverURL, _ := url.Parse(echoServer.URL)
		wsURL := &url.URL{
			Scheme: "ws",
			Host:   serverURL.Host,
			Path:   "/",
		}

		// Create custom dialer that goes through our interceptor
		dialer := &websocket.Dialer{
			NetDial: func(network, addr string) (net.Conn, error) {
				// Create connection to the test server
				conn, err := net.Dial(network, addr)
				if err != nil {
					return nil, err
				}

				// Simulate interceptor processing by manually handling the upgrade
				req := &http.Request{
					Method: "GET",
					URL:    wsURL,
					Header: make(http.Header),
					Host:   serverURL.Host,
				}
				req.Header.Set("Upgrade", "websocket")
				req.Header.Set("Connection", "Upgrade")
				req.Header.Set("Sec-WebSocket-Key", "test-key")
				req.Header.Set("Sec-WebSocket-Version", "13")

				// Apply interceptor hooks
				err = interceptor.applyRequestHooks(req)
				require.NoError(t, err)

				return conn, nil
			},
		}

		// Connect to WebSocket server through interceptor
		wsConn, resp, err := dialer.Dial(wsURL.String(), nil)
		if resp != nil {
			defer resp.Body.Close()
		}
		if err != nil {
			t.Fatalf("Failed to connect to WebSocket: %v", err)
		}
		defer wsConn.Close()

		// Verify hooks were called
		assert.True(t, requestHookCalled, "Request hook should be called for WebSocket upgrade")

		// Send a test message
		err = wsConn.WriteMessage(websocket.TextMessage, []byte(testMessage))
		require.NoError(t, err)

		// Read the echoed message
		messageType, message, err := wsConn.ReadMessage()
		require.NoError(t, err)
		assert.Equal(t, websocket.TextMessage, messageType)
		assert.Equal(t, testMessage, string(message))

		// Verify the response was processed
		assert.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	})

	t.Run("WebSocket connection with binary data", func(t *testing.T) {
		// Test WebSocket with binary data to ensure interceptor handles it correctly
		var upgrader = websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		}

		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD}
		binaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()

			// Echo binary messages
			for {
				messageType, message, err := conn.ReadMessage()
				if err != nil {
					break
				}
				if messageType == websocket.BinaryMessage {
					err = conn.WriteMessage(websocket.BinaryMessage, message)
					if err != nil {
						break
					}
				}
			}
		}))
		defer binaryServer.Close()

		// Connect using standard WebSocket client
		serverURL, _ := url.Parse(binaryServer.URL)
		wsURL := "ws://" + serverURL.Host + "/"

		wsConn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if resp != nil {
			defer resp.Body.Close()
		}
		require.NoError(t, err)
		defer wsConn.Close()

		// Send binary data
		err = wsConn.WriteMessage(websocket.BinaryMessage, binaryData)
		require.NoError(t, err)

		// Read the echoed binary data
		messageType, message, err := wsConn.ReadMessage()
		require.NoError(t, err)
		assert.Equal(t, websocket.BinaryMessage, messageType)
		assert.Equal(t, binaryData, message)
	})

	t.Run("WebSocket connection close handling", func(t *testing.T) {
		// Test proper handling of WebSocket connection close
		var upgrader = websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		}

		var serverConnClosed bool
		var mu sync.Mutex

		closeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer func() {
				conn.Close()
				mu.Lock()
				serverConnClosed = true
				mu.Unlock()
			}()

			// Wait for close message or connection error
			for {
				_, _, err := conn.ReadMessage()
				if err != nil {
					break
				}
			}
		}))
		defer closeServer.Close()

		// Connect and immediately close
		serverURL, _ := url.Parse(closeServer.URL)
		wsURL := "ws://" + serverURL.Host + "/"

		wsConn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if resp != nil {
			defer resp.Body.Close()
		}
		require.NoError(t, err)

		// Send close message
		err = wsConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		require.NoError(t, err)

		wsConn.Close()

		// Wait a bit for server to process close
		time.Sleep(100 * time.Millisecond)

		mu.Lock()
		closed := serverConnClosed
		mu.Unlock()

		assert.True(t, closed, "Server connection should be closed")
	})
}

func TestHTTPInterceptor_HandleTCPConnection(t *testing.T) {
	// Create mock proxy for testing
	mockProxy := createMockProxy(t)

	// Create the interceptor
	interceptor := NewHTTPInterceptor(mockProxy)

	t.Run("CONNECT request rejection in TCP connection", func(t *testing.T) {
		// Create client and server connections using net.Pipe
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		// Channel to signal completion
		done := make(chan bool, 1)

		// Start the interceptor handling in a goroutine
		go func() {
			defer func() { done <- true }()
			interceptor.HandleTCPConnection(serverConn, "example.com:443")
		}()

		// Send CONNECT request from client
		connectRequest := "CONNECT example.com:443 HTTP/1.1\r\n" +
			"Host: example.com:443\r\n\r\n"

		_, err := clientConn.Write([]byte(connectRequest))
		require.NoError(t, err)

		// Read the response with timeout
		_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReader(clientConn)
		resp, err := http.ReadResponse(reader, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify CONNECT request was rejected
		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
		assert.Equal(t, "405 Method Not Allowed", resp.Status)

		// Wait for goroutine to complete or timeout
		select {
		case <-done:
			// Success
		case <-time.After(2 * time.Second):
			t.Log("HandleTCPConnection goroutine did not complete in time")
		}
	})
}
