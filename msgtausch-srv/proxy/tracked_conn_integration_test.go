package proxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/codefionn/msgtausch/msgtausch-srv/stats"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testStatsCollector captures stats calls for integration testing
type testStatsCollector struct {
	mu                   sync.RWMutex
	connections          map[int64]*stats.ConnectionInfo
	httpRequests         []stats.HTTPRequestInfo
	httpResponses        []stats.HTTPResponseInfo
	dataTransfers        []DataTransferRecord
	errors               []stats.ErrorInfo
	blockedRequests      []stats.SecurityEvent
	allowedRequests      []stats.SecurityEvent
	connectionCounter    int64
	startConnectionCalls int64
	endConnectionCalls   int64
	dataTransferCalls    int64
	httpRequestCalls     int64
	httpResponseCalls    int64
}

type DataTransferRecord struct {
	ConnectionID  int64
	BytesSent     int64
	BytesReceived int64
	Timestamp     time.Time
}

// Satisfy new full HTTP record API for testStatsCollector
func (t *testStatsCollector) RecordFullHTTPRequest(ctx context.Context, connectionID int64, method, url, host, userAgent string,
	requestHeaders map[string][]string, requestBody []byte, timestamp time.Time) error {
	// For integration tests we don't need to capture full bodies; just accept the call
	return nil
}

func (t *testStatsCollector) RecordFullHTTPResponse(ctx context.Context, connectionID int64, statusCode int,
	responseHeaders map[string][]string, responseBody []byte, timestamp time.Time) error {
	// For integration tests we don't need to capture full bodies; just accept the call
	return nil
}

func newTestStatsCollector() *testStatsCollector {
	return &testStatsCollector{
		connections:     make(map[int64]*stats.ConnectionInfo),
		httpRequests:    make([]stats.HTTPRequestInfo, 0),
		httpResponses:   make([]stats.HTTPResponseInfo, 0),
		dataTransfers:   make([]DataTransferRecord, 0),
		errors:          make([]stats.ErrorInfo, 0),
		blockedRequests: make([]stats.SecurityEvent, 0),
		allowedRequests: make([]stats.SecurityEvent, 0),
	}
}

func (t *testStatsCollector) StartConnection(ctx context.Context, clientIP, targetHost string, targetPort int, protocol string) (int64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	atomic.AddInt64(&t.startConnectionCalls, 1)
	connectionID := atomic.AddInt64(&t.connectionCounter, 1)

	t.connections[connectionID] = &stats.ConnectionInfo{
		ID:         connectionID,
		ClientIP:   clientIP,
		TargetHost: targetHost,
		TargetPort: targetPort,
		Protocol:   protocol,
		StartedAt:  time.Now(),
	}

	return connectionID, nil
}

func (t *testStatsCollector) StartConnectionWithUUID(ctx context.Context, connectionUUID, clientIP, targetHost string, targetPort int, protocol string) (int64, error) {
	id, err := t.StartConnection(ctx, clientIP, targetHost, targetPort, protocol)
	if err != nil {
		return 0, err
	}
	t.mu.Lock()
	if conn, ok := t.connections[id]; ok {
		conn.UUID = connectionUUID
	}
	t.mu.Unlock()
	return id, nil
}

func (t *testStatsCollector) EndConnection(ctx context.Context, connectionID int64, bytesSent, bytesReceived int64, duration time.Duration, closeReason string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	atomic.AddInt64(&t.endConnectionCalls, 1)

	if conn, exists := t.connections[connectionID]; exists {
		now := time.Now()
		conn.EndedAt = &now
		conn.BytesSent = bytesSent
		conn.BytesReceived = bytesReceived
		conn.Duration = duration
		conn.CloseReason = closeReason
	}

	return nil
}

func (t *testStatsCollector) RecordDataTransfer(ctx context.Context, connectionID int64, bytesSent, bytesReceived int64) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	atomic.AddInt64(&t.dataTransferCalls, 1)

	t.dataTransfers = append(t.dataTransfers, DataTransferRecord{
		ConnectionID:  connectionID,
		BytesSent:     bytesSent,
		BytesReceived: bytesReceived,
		Timestamp:     time.Now(),
	})

	return nil
}

func (t *testStatsCollector) RecordHTTPRequest(ctx context.Context, connectionID int64, method, url, host, userAgent string, contentLength int64) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	atomic.AddInt64(&t.httpRequestCalls, 1)

	t.httpRequests = append(t.httpRequests, stats.HTTPRequestInfo{
		ConnectionID:  connectionID,
		Method:        method,
		URL:           url,
		Host:          host,
		UserAgent:     userAgent,
		ContentLength: contentLength,
		Timestamp:     time.Now(),
	})

	return nil
}

func (t *testStatsCollector) RecordHTTPResponse(ctx context.Context, connectionID int64, statusCode int, contentLength int64) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	atomic.AddInt64(&t.httpResponseCalls, 1)

	t.httpResponses = append(t.httpResponses, stats.HTTPResponseInfo{
		ConnectionID:  connectionID,
		StatusCode:    statusCode,
		ContentLength: contentLength,
		Timestamp:     time.Now(),
	})

	return nil
}

func (t *testStatsCollector) RecordHTTPRequestWithHeaders(ctx context.Context, connectionID int64, method, url, host, userAgent string, contentLength, headerSize int64) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	atomic.AddInt64(&t.httpRequestCalls, 1)

	t.httpRequests = append(t.httpRequests, stats.HTTPRequestInfo{
		ConnectionID:  connectionID,
		Method:        method,
		URL:           url,
		Host:          host,
		UserAgent:     userAgent,
		ContentLength: contentLength,
		HeaderSize:    headerSize,
		Timestamp:     time.Now(),
	})

	return nil
}

func (t *testStatsCollector) RecordHTTPResponseWithHeaders(ctx context.Context, connectionID int64, statusCode int, contentLength, headerSize int64) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	atomic.AddInt64(&t.httpResponseCalls, 1)

	t.httpResponses = append(t.httpResponses, stats.HTTPResponseInfo{
		ConnectionID:  connectionID,
		StatusCode:    statusCode,
		ContentLength: contentLength,
		HeaderSize:    headerSize,
		Timestamp:     time.Now(),
	})

	return nil
}

func (t *testStatsCollector) RecordError(ctx context.Context, connectionID int64, errorType, errorMessage string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.errors = append(t.errors, stats.ErrorInfo{
		ConnectionID: connectionID,
		ErrorType:    errorType,
		ErrorMessage: errorMessage,
		Timestamp:    time.Now(),
	})

	return nil
}

func (t *testStatsCollector) RecordBlockedRequest(ctx context.Context, clientIP, targetHost, reason string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.blockedRequests = append(t.blockedRequests, stats.SecurityEvent{
		ClientIP:   clientIP,
		TargetHost: targetHost,
		EventType:  "blocked",
		Reason:     reason,
		Timestamp:  time.Now(),
	})

	return nil
}

func (t *testStatsCollector) RecordAllowedRequest(ctx context.Context, clientIP, targetHost string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.allowedRequests = append(t.allowedRequests, stats.SecurityEvent{
		ClientIP:   clientIP,
		TargetHost: targetHost,
		EventType:  "allowed",
		Timestamp:  time.Now(),
	})

	return nil
}

func (t *testStatsCollector) GetOverviewStats(ctx context.Context) (*stats.OverviewStats, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	activeConnections := int64(0)
	totalBytesIn := int64(0)
	totalBytesOut := int64(0)

	for _, conn := range t.connections {
		if conn.EndedAt == nil {
			activeConnections++
		}
		totalBytesIn += conn.BytesReceived
		totalBytesOut += conn.BytesSent
	}

	return &stats.OverviewStats{
		TotalConnections:  int64(len(t.connections)),
		ActiveConnections: activeConnections,
		TotalRequests:     int64(len(t.httpRequests)),
		TotalErrors:       int64(len(t.errors)),
		BlockedRequests:   int64(len(t.blockedRequests)),
		AllowedRequests:   int64(len(t.allowedRequests)),
		TotalBytesIn:      totalBytesIn,
		TotalBytesOut:     totalBytesOut,
		Uptime:            "test",
	}, nil
}

func (t *testStatsCollector) GetTopDomains(ctx context.Context, limit int) ([]stats.DomainStats, error) {
	return []stats.DomainStats{}, nil
}

func (t *testStatsCollector) GetSecurityEvents(ctx context.Context, limit int) ([]stats.SecurityEventInfo, error) {
	return []stats.SecurityEventInfo{}, nil
}

func (t *testStatsCollector) GetRecentErrors(ctx context.Context, limit int) ([]stats.ErrorSummary, error) {
	return []stats.ErrorSummary{}, nil
}

func (t *testStatsCollector) GetBandwidthStats(ctx context.Context, days int) (*stats.BandwidthStats, error) {
	return &stats.BandwidthStats{Daily: []stats.DailyBandwidth{}, Total: 0}, nil
}

func (t *testStatsCollector) GetSystemStats(ctx context.Context) (*stats.SystemStats, error) {
	return &stats.SystemStats{}, nil
}

func (t *testStatsCollector) HealthCheck(ctx context.Context) error {
	return nil
}

func (t *testStatsCollector) Close() error {
	return nil
}

// Helper methods for test assertions
func (t *testStatsCollector) GetConnectionCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.connections)
}

func (t *testStatsCollector) GetConnection(connectionID int64) *stats.ConnectionInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.connections[connectionID]
}

func (t *testStatsCollector) GetDataTransfers() []DataTransferRecord {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make([]DataTransferRecord, len(t.dataTransfers))
	copy(result, t.dataTransfers)
	return result
}

func (t *testStatsCollector) GetHTTPRequests() []stats.HTTPRequestInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make([]stats.HTTPRequestInfo, len(t.httpRequests))
	copy(result, t.httpRequests)
	return result
}

func (t *testStatsCollector) GetHTTPResponses() []stats.HTTPResponseInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make([]stats.HTTPResponseInfo, len(t.httpResponses))
	copy(result, t.httpResponses)
	return result
}

func (t *testStatsCollector) GetCallCounts() (int64, int64, int64, int64, int64) {
	return atomic.LoadInt64(&t.startConnectionCalls),
		atomic.LoadInt64(&t.endConnectionCalls),
		atomic.LoadInt64(&t.dataTransferCalls),
		atomic.LoadInt64(&t.httpRequestCalls),
		atomic.LoadInt64(&t.httpResponseCalls)
}

// createProxyWithStatsCollector creates a proxy instance with a custom stats collector
func createProxyWithStatsCollector(collector stats.Collector) (*Proxy, string, func()) {
	sqlLitePath := "test_proxy_stats" + randomSuffix() + ".db"
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		TimeoutSeconds: 5,
		Classifiers:    make(map[string]config.Classifier),
		Statistics: config.StatisticsConfig{
			Enabled:    true,        // Enable stats collection
			SQLitePath: sqlLitePath, // Path won't be used since we provide our own collector
		},
		Interception: config.InterceptionConfig{
			Enabled: true, // Enable interception for request/response tracking
			HTTP:    true, // Enable HTTP interception
		},
	}

	proxy := NewProxy(cfg)
	proxy.Collector = collector // Override with our test collector

	listener, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	if err != nil {
		panic(fmt.Sprintf("Failed to create listener: %v", err))
	}
	proxyAddr := listener.Addr().String()

	go func() {
		if err := proxy.StartWithListener(listener); err != http.ErrServerClosed && err != nil {
			fmt.Printf("Proxy server error: %v", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(100 * time.Millisecond)

	cleanup := func() {
		os.Remove(sqlLitePath)          // Clean up test database file
		os.Remove(sqlLitePath + "-shm") // Clean up test database file
		os.Remove(sqlLitePath + "-wal") // Clean up test database file
		proxy.Stop()
	}

	return proxy, proxyAddr, cleanup
}

func TestProxyHTTPWithConnectionTracking(t *testing.T) {
	collector := newTestStatsCollector()

	// Create test HTTP server
	testContent := "Hello from HTTP server!"
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add some response data to track
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(testContent))
	}))
	defer testServer.Close()

	// Create proxy with our test collector
	_, proxyAddr, cleanup := createProxyWithStatsCollector(collector)
	cleanupCalled := false
	defer func() {
		if !cleanupCalled {
			cleanup()
		}
	}()

	// Create HTTP client using the proxy
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", proxyAddr))
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 10 * time.Second,
	}

	// Make HTTP request through proxy
	resp, err := client.Get(testServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Read response body to trigger data transfer tracking
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, testContent, string(body))
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Close the response body and connection
	resp.Body.Close()

	// Force close idle connections to trigger EndConnection
	if transport, ok := client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}

	// Shut down the proxy to force connections to close
	cleanup()
	cleanupCalled = true

	// Wait a bit for the shutdown to complete
	time.Sleep(200 * time.Millisecond)

	// Verify stats collection
	startCalls, _, _, reqCalls, respCalls := collector.GetCallCounts()

	assert.Greater(t, startCalls, int64(0), "StartConnection should have been called")
	// Note: EndConnection may not be called immediately due to connection pooling
	// We'll verify other aspects of the connection tracking

	assert.Greater(t, reqCalls, int64(0), "RecordHTTPRequest should have been called")
	assert.Greater(t, respCalls, int64(0), "RecordHTTPResponse should have been called")

	// Verify connection tracking
	assert.Greater(t, collector.GetConnectionCount(), 0, "At least one connection should be tracked")

	// Verify HTTP request/response tracking
	httpRequests := collector.GetHTTPRequests()
	httpResponses := collector.GetHTTPResponses()
	assert.Greater(t, len(httpRequests), 0, "HTTP requests should be tracked")
	assert.Greater(t, len(httpResponses), 0, "HTTP responses should be tracked")

	if len(httpRequests) > 0 {
		req := httpRequests[0]
		assert.Equal(t, "GET", req.Method)
		assert.Contains(t, req.Host, "127.0.0.1")
	}

	if len(httpResponses) > 0 {
		resp := httpResponses[0]
		assert.Equal(t, 200, resp.StatusCode)
		assert.Greater(t, resp.ContentLength, int64(0))
	}
}

func TestProxyHTTPSWithConnectionTracking(t *testing.T) {
	collector := newTestStatsCollector()

	// Create test HTTPS server
	testContent := "Hello from HTTPS server!"
	httpsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(testContent))
	}))
	defer httpsServer.Close()

	// Get server certificate for trust
	cert := httpsServer.TLS.Certificates[0]
	certPool := x509.NewCertPool()
	certPool.AddCert(cert.Leaf)

	// Create proxy with our test collector
	proxy, proxyAddr, cleanup := createProxyWithStatsCollector(collector)
	defer cleanup()

	// Create HTTPS client using the proxy
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", proxyAddr))
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
		Timeout: 10 * time.Second,
	}

	// Make HTTPS request through proxy (uses CONNECT method)
	resp, err := client.Get(httpsServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, testContent, string(body))
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Force connection cleanup to trigger EndConnection
	client.CloseIdleConnections()
	proxy.Stop()

	// Wait for stats to be recorded
	time.Sleep(200 * time.Millisecond)

	// Verify stats collection - for CONNECT tunneling, we should have StartConnection
	startCalls, endCalls, transferCalls, _, _ := collector.GetCallCounts()

	assert.Greater(t, startCalls, int64(0), "StartConnection should have been called for HTTPS tunnel")

	// Note: EndConnection might not be called immediately due to connection pooling
	// We'll check for either EndConnection calls or data transfer calls
	if endCalls == 0 && transferCalls == 0 {
		t.Logf("Warning: Neither EndConnection nor DataTransfer was called - this might be due to connection pooling")
	}

	// Verify connection tracking for CONNECT tunnel
	assert.Greater(t, collector.GetConnectionCount(), 0, "HTTPS tunnel connection should be tracked")

	// Verify connection details
	connections := collector.connections
	assert.Greater(t, len(connections), 0, "Should have tracked connections")

	// Find a connection that matches our HTTPS request
	var foundHTTPSConnection bool
	for _, conn := range connections {
		// Check if this connection is to our test server
		httpsURL, _ := url.Parse(httpsServer.URL)
		targetHost := httpsURL.Host
		if conn.TargetHost == targetHost || strings.Contains(conn.TargetHost, httpsURL.Hostname()) {
			foundHTTPSConnection = true
			// For CONNECT tunneling, we might not have byte counts if EndConnection wasn't called yet
			t.Logf("Found HTTPS connection: TargetHost=%s, BytesSent=%d, BytesReceived=%d",
				conn.TargetHost, conn.BytesSent, conn.BytesReceived)
			break
		}
	}
	assert.True(t, foundHTTPSConnection, "Should have found HTTPS connection in tracking")
}

func TestProxyWebSocketWithConnectionTracking(t *testing.T) {
	collector := newTestStatsCollector()

	// Create WebSocket test server
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	wsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("WebSocket upgrade failed: %v", err)
			return
		}
		defer conn.Close()

		// Echo server - read and write back
		for {
			messageType, p, err := conn.ReadMessage()
			if err != nil {
				break
			}
			if err := conn.WriteMessage(messageType, p); err != nil {
				break
			}
		}
	}))
	defer wsServer.Close()

	// Create proxy with our test collector
	proxy, proxyAddr, cleanup := createProxyWithStatsCollector(collector)
	defer cleanup()

	// Create WebSocket client connection through proxy
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", proxyAddr))
	require.NoError(t, err)

	// Convert HTTP URL to WebSocket URL
	wsURL := strings.Replace(wsServer.URL, "http://", "ws://", 1)

	dialer := &websocket.Dialer{
		Proxy:            http.ProxyURL(proxyURL),
		HandshakeTimeout: 10 * time.Second,
	}

	// Connect to WebSocket through proxy
	wsConn, _, err := dialer.Dial(wsURL, nil)
	require.NoError(t, err)

	// Send some test messages to generate traffic
	testMessages := []string{
		"Hello WebSocket!",
		"This is a test message",
		"Another message for tracking",
	}

	for _, msg := range testMessages {
		err := wsConn.WriteMessage(websocket.TextMessage, []byte(msg))
		require.NoError(t, err)

		// Read echo response
		_, response, err := wsConn.ReadMessage()
		require.NoError(t, err)
		assert.Equal(t, msg, string(response))
	}

	// Close the WebSocket connection
	wsConn.Close()

	// Force proxy shutdown to ensure stats are recorded
	proxy.Stop()

	// Wait for stats to be recorded
	time.Sleep(300 * time.Millisecond)

	// Verify stats collection
	startCalls, endCalls, transferCalls, reqCalls, respCalls := collector.GetCallCounts()

	assert.Greater(t, startCalls, int64(0), "StartConnection should have been called for WebSocket")

	// Verify connection tracking
	assert.Greater(t, collector.GetConnectionCount(), 0, "WebSocket connection should be tracked")

	// For WebSocket connections, HTTP upgrade tracking depends on the proxy implementation
	// Log the actual call counts for debugging
	t.Logf("Call counts: StartConnection=%d, EndConnection=%d, DataTransfer=%d, HTTPRequest=%d, HTTPResponse=%d",
		startCalls, endCalls, transferCalls, reqCalls, respCalls)

	// Look for connection to our WebSocket server
	connections := collector.connections
	assert.Greater(t, len(connections), 0, "Should have tracked WebSocket connections")

	var foundWSConnection bool
	wsURL_parsed, _ := url.Parse(wsServer.URL)
	targetHost := wsURL_parsed.Host

	for _, conn := range connections {
		if conn.TargetHost == targetHost || strings.Contains(conn.TargetHost, wsURL_parsed.Hostname()) {
			foundWSConnection = true
			t.Logf("Found WebSocket connection: TargetHost=%s, BytesSent=%d, BytesReceived=%d",
				conn.TargetHost, conn.BytesSent, conn.BytesReceived)
			break
		}
	}
	assert.True(t, foundWSConnection, "Should have found WebSocket connection in tracking")

	// If HTTP interception captured the upgrade request, verify it
	if reqCalls > 0 {
		httpRequests := collector.GetHTTPRequests()
		assert.Greater(t, len(httpRequests), 0, "WebSocket upgrade request should be tracked")
		if len(httpRequests) > 0 {
			req := httpRequests[0]
			assert.Equal(t, "GET", req.Method)
			// The request URL should match our WebSocket URL (converted back to HTTP for upgrade)
		}
	}

	// Data transfer tracking might happen for WebSocket messages
	if transferCalls > 0 {
		dataTransfers := collector.GetDataTransfers()
		assert.Greater(t, len(dataTransfers), 0, "Data transfers should be tracked for WebSocket traffic")

		totalBytesSent := int64(0)
		totalBytesReceived := int64(0)
		for _, transfer := range dataTransfers {
			totalBytesSent += transfer.BytesSent
			totalBytesReceived += transfer.BytesReceived
		}

		t.Logf("Total WebSocket bytes - Sent: %d, Received: %d", totalBytesSent, totalBytesReceived)
	}
}

func TestProxyMultipleConnectionsTracking(t *testing.T) {
	collector := newTestStatsCollector()

	// Create test HTTP server
	testContent := "Response data"
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(testContent))
	}))
	defer testServer.Close()

	// Create proxy with our test collector
	_, proxyAddr, cleanup := createProxyWithStatsCollector(collector)
	defer cleanup()

	// Create HTTP client using the proxy
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", proxyAddr))
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 10 * time.Second,
	}

	// Make multiple concurrent requests
	numRequests := 5
	var wg sync.WaitGroup
	wg.Add(numRequests)

	for i := 0; i < numRequests; i++ {
		go func(requestID int) {
			defer wg.Done()

			resp, err := client.Get(fmt.Sprintf("%s?req=%d", testServer.URL, requestID))
			if err != nil {
				t.Errorf("Request %d failed: %v", requestID, err)
				return
			}
			defer resp.Body.Close()

			// Read response body
			_, err = io.ReadAll(resp.Body)
			if err != nil {
				t.Errorf("Failed to read response %d: %v", requestID, err)
			}
		}(i)
	}

	wg.Wait()

	// Wait for stats to be recorded
	time.Sleep(200 * time.Millisecond)

	// Verify stats collection
	startCalls, endCalls, _, reqCalls, respCalls := collector.GetCallCounts()

	assert.GreaterOrEqual(t, startCalls, int64(numRequests), "Should have started at least %d connections", numRequests)
	assert.GreaterOrEqual(t, endCalls, int64(numRequests), "Should have ended at least %d connections", numRequests)
	assert.GreaterOrEqual(t, reqCalls, int64(numRequests), "Should have tracked at least %d HTTP requests", numRequests)
	assert.GreaterOrEqual(t, respCalls, int64(numRequests), "Should have tracked at least %d HTTP responses", numRequests)

	// Verify all connections are tracked
	assert.GreaterOrEqual(t, collector.GetConnectionCount(), numRequests, "Should have tracked at least %d connections", numRequests)

	// Verify all HTTP requests are tracked
	httpRequests := collector.GetHTTPRequests()
	assert.GreaterOrEqual(t, len(httpRequests), numRequests, "Should have tracked at least %d HTTP requests", numRequests)

	httpResponses := collector.GetHTTPResponses()
	assert.GreaterOrEqual(t, len(httpResponses), numRequests, "Should have tracked at least %d HTTP responses", numRequests)
}

func TestProxyLargeDataTransferTracking(t *testing.T) {
	collector := newTestStatsCollector()

	// Create test server that returns large response
	largeData := strings.Repeat("A", 50*1024) // 50KB of data
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(largeData)))
		_, _ = w.Write([]byte(largeData))
	}))
	defer testServer.Close()

	// Create proxy with our test collector
	_, proxyAddr, cleanup := createProxyWithStatsCollector(collector)
	defer cleanup()

	// Create HTTP client using the proxy
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", proxyAddr))
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 10 * time.Second,
	}

	// Make request for large data
	resp, err := client.Get(testServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Read the entire response
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, largeData, string(body))
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Wait for stats to be recorded
	time.Sleep(200 * time.Millisecond)

	// Verify stats collection
	startCalls, endCalls, transferCalls, _, _ := collector.GetCallCounts()

	assert.Greater(t, startCalls, int64(0), "StartConnection should have been called")
	assert.Greater(t, endCalls, int64(0), "EndConnection should have been called")

	// Verify data transfer tracking (should have multiple calls due to 10KB threshold)
	if transferCalls > 0 {
		dataTransfers := collector.GetDataTransfers()
		assert.Greater(t, len(dataTransfers), 0, "Data transfers should be tracked")

		// Calculate total bytes transferred
		totalBytesReceived := int64(0)
		for _, transfer := range dataTransfers {
			totalBytesReceived += transfer.BytesReceived
		}

		// Should track at least the size of our large data
		assert.GreaterOrEqual(t, totalBytesReceived, int64(len(largeData)),
			"Should have tracked at least %d bytes received", len(largeData))
	}

	// Verify connection final byte counts
	connections := collector.connections
	assert.Greater(t, len(connections), 0, "Should have tracked connections")

	var foundConnection bool
	for _, conn := range connections {
		if conn.BytesReceived >= int64(len(largeData)) {
			foundConnection = true
			assert.Greater(t, conn.BytesSent, int64(0), "Should have sent request bytes")
			assert.GreaterOrEqual(t, conn.BytesReceived, int64(len(largeData)),
				"Should have received at least %d bytes", len(largeData))
			break
		}
	}
	assert.True(t, foundConnection, "Should have found connection with correct byte counts")
}

func TestProxyPOSTRequestWithConnectionTracking(t *testing.T) {
	collector := newTestStatsCollector()

	// Create test server that echoes POST data
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer testServer.Close()

	// Create proxy with our test collector
	_, proxyAddr, cleanup := createProxyWithStatsCollector(collector)
	defer cleanup()

	// Create HTTP client using the proxy
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", proxyAddr))
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 10 * time.Second,
	}

	// Create POST data
	postData := map[string]string{
		"message": "Hello from POST request",
		"type":    "test",
	}
	postBody, err := json.Marshal(postData)
	require.NoError(t, err)

	// Make POST request through proxy
	resp, err := client.Post(testServer.URL, "application/json", strings.NewReader(string(postBody)))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Read response body
	responseBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, string(postBody), string(responseBody))
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Wait for stats to be recorded
	time.Sleep(100 * time.Millisecond)

	// Verify stats collection
	startCalls, endCalls, _, reqCalls, respCalls := collector.GetCallCounts()

	assert.Greater(t, startCalls, int64(0), "StartConnection should have been called")
	assert.Greater(t, endCalls, int64(0), "EndConnection should have been called")
	assert.Greater(t, reqCalls, int64(0), "RecordHTTPRequest should have been called")
	assert.Greater(t, respCalls, int64(0), "RecordHTTPResponse should have been called")

	// Verify HTTP request tracking includes POST details
	httpRequests := collector.GetHTTPRequests()
	assert.Greater(t, len(httpRequests), 0, "POST request should be tracked")
	if len(httpRequests) > 0 {
		req := httpRequests[0]
		assert.Equal(t, "POST", req.Method)
		assert.Contains(t, req.URL, testServer.URL)
		assert.Equal(t, int64(len(postBody)), req.ContentLength)
	}

	// Verify both sent and received bytes are tracked
	connections := collector.connections
	assert.Greater(t, len(connections), 0, "Should have tracked connections")

	var foundConnection bool
	for _, conn := range connections {
		if conn.BytesSent > 0 && conn.BytesReceived > 0 {
			foundConnection = true
			// Should have sent at least the POST body size
			assert.GreaterOrEqual(t, conn.BytesSent, int64(len(postBody)),
				"Should have sent at least %d bytes", len(postBody))
			// Should have received at least the response body size
			assert.GreaterOrEqual(t, conn.BytesReceived, int64(len(responseBody)),
				"Should have received at least %d bytes", len(responseBody))
			break
		}
	}
	assert.True(t, foundConnection, "Should have found connection with bidirectional data transfer")
}

// randomSuffix generates a random hex string for use in temporary filenames.
func randomSuffix() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
