package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/codefionn/msgtausch/msgtausch-srv/stats"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockStatsCollector implements the stats.Collector interface for testing
type MockStatsCollector struct {
	mu                      sync.RWMutex
	connections             map[int64]*stats.ConnectionInfo
	httpRequests            map[int64]*stats.HTTPRequestInfo
	httpResponses           map[int64]*stats.HTTPResponseInfo
	fullHTTPRequests        map[int64]*stats.RecordedHTTPRequest
	fullHTTPResponses       map[int64]*stats.RecordedHTTPResponse
	nextConnectionID        int64
	startConnectionCalls    []StartConnectionCall
	recordFullRequestCalls  []RecordFullRequestCall
	recordFullResponseCalls []RecordFullResponseCall
}

type StartConnectionCall struct {
	ClientIP   string
	TargetHost string
	TargetPort int
	Protocol   string
}

type RecordFullRequestCall struct {
	ConnectionID   int64
	Method         string
	URL            string
	Host           string
	UserAgent      string
	RequestHeaders map[string][]string
	RequestBody    []byte
	Timestamp      time.Time
}

type RecordFullResponseCall struct {
	ConnectionID    int64
	StatusCode      int
	ResponseHeaders map[string][]string
	ResponseBody    []byte
	Timestamp       time.Time
}

func NewMockStatsCollector() *MockStatsCollector {
	return &MockStatsCollector{
		connections:             make(map[int64]*stats.ConnectionInfo),
		httpRequests:            make(map[int64]*stats.HTTPRequestInfo),
		httpResponses:           make(map[int64]*stats.HTTPResponseInfo),
		fullHTTPRequests:        make(map[int64]*stats.RecordedHTTPRequest),
		fullHTTPResponses:       make(map[int64]*stats.RecordedHTTPResponse),
		nextConnectionID:        1,
		startConnectionCalls:    make([]StartConnectionCall, 0),
		recordFullRequestCalls:  make([]RecordFullRequestCall, 0),
		recordFullResponseCalls: make([]RecordFullResponseCall, 0),
	}
}

func (m *MockStatsCollector) StartConnection(ctx context.Context, clientIP, targetHost string, targetPort int, protocol string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := m.nextConnectionID
	m.nextConnectionID++

	m.connections[id] = &stats.ConnectionInfo{
		ID:         id,
		ClientIP:   clientIP,
		TargetHost: targetHost,
		TargetPort: targetPort,
		Protocol:   protocol,
		StartedAt:  time.Now(),
	}

	m.startConnectionCalls = append(m.startConnectionCalls, StartConnectionCall{
		ClientIP:   clientIP,
		TargetHost: targetHost,
		TargetPort: targetPort,
		Protocol:   protocol,
	})

	return id, nil
}

func (m *MockStatsCollector) StartConnectionWithUUID(ctx context.Context, connectionUUID, clientIP, targetHost string, targetPort int, protocol string) (int64, error) {
	id, err := m.StartConnection(ctx, clientIP, targetHost, targetPort, protocol)
	if err != nil {
		return 0, err
	}
	m.mu.Lock()
	if conn, exists := m.connections[id]; exists {
		conn.UUID = connectionUUID
	}
	m.mu.Unlock()
	return id, nil
}

func (m *MockStatsCollector) EndConnection(ctx context.Context, connectionID int64, bytesSent, bytesReceived int64, duration time.Duration, closeReason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if conn, exists := m.connections[connectionID]; exists {
		now := time.Now()
		conn.EndedAt = &now
		conn.BytesSent = bytesSent
		conn.BytesReceived = bytesReceived
		conn.Duration = duration
		conn.CloseReason = closeReason
	}

	return nil
}

func (m *MockStatsCollector) RecordHTTPRequest(ctx context.Context, connectionID int64, method, url, host, userAgent string, contentLength int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.httpRequests[connectionID] = &stats.HTTPRequestInfo{
		ConnectionID:  connectionID,
		Method:        method,
		URL:           url,
		Host:          host,
		UserAgent:     userAgent,
		ContentLength: contentLength,
		Timestamp:     time.Now(),
	}

	return nil
}

func (m *MockStatsCollector) RecordHTTPResponse(ctx context.Context, connectionID int64, statusCode int, contentLength int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.httpResponses[connectionID] = &stats.HTTPResponseInfo{
		ConnectionID:  connectionID,
		StatusCode:    statusCode,
		ContentLength: contentLength,
		Timestamp:     time.Now(),
	}

	return nil
}

func (m *MockStatsCollector) RecordHTTPRequestWithHeaders(ctx context.Context, connectionID int64, method, url, host, userAgent string, contentLength, headerSize int64) error {
	return m.RecordHTTPRequest(ctx, connectionID, method, url, host, userAgent, contentLength)
}

func (m *MockStatsCollector) RecordHTTPResponseWithHeaders(ctx context.Context, connectionID int64, statusCode int, contentLength, headerSize int64) error {
	return m.RecordHTTPResponse(ctx, connectionID, statusCode, contentLength)
}

func (m *MockStatsCollector) RecordError(ctx context.Context, connectionID int64, errorType, errorMessage string) error {
	return nil
}

func (m *MockStatsCollector) RecordDataTransfer(ctx context.Context, connectionID int64, bytesSent, bytesReceived int64) error {
	return nil
}

func (m *MockStatsCollector) RecordBlockedRequest(ctx context.Context, clientIP, targetHost, reason string) error {
	return nil
}

func (m *MockStatsCollector) RecordAllowedRequest(ctx context.Context, clientIP, targetHost string) error {
	return nil
}

func (m *MockStatsCollector) RecordFullHTTPRequest(ctx context.Context, connectionID int64, method, url, host, userAgent string, requestHeaders map[string][]string, requestBody []byte, timestamp time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.fullHTTPRequests[connectionID] = &stats.RecordedHTTPRequest{
		ConnectionID:    connectionID,
		Method:          method,
		URL:             url,
		Host:            host,
		UserAgent:       userAgent,
		RequestHeaders:  requestHeaders,
		RequestBody:     requestBody,
		RequestBodySize: int64(len(requestBody)),
		Timestamp:       timestamp,
	}

	m.recordFullRequestCalls = append(m.recordFullRequestCalls, RecordFullRequestCall{
		ConnectionID:   connectionID,
		Method:         method,
		URL:            url,
		Host:           host,
		UserAgent:      userAgent,
		RequestHeaders: requestHeaders,
		RequestBody:    requestBody,
		Timestamp:      timestamp,
	})

	return nil
}

func (m *MockStatsCollector) RecordFullHTTPResponse(ctx context.Context, connectionID int64, statusCode int, responseHeaders map[string][]string, responseBody []byte, timestamp time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.fullHTTPResponses[connectionID] = &stats.RecordedHTTPResponse{
		ConnectionID:     connectionID,
		StatusCode:       statusCode,
		ResponseHeaders:  responseHeaders,
		ResponseBody:     responseBody,
		ResponseBodySize: int64(len(responseBody)),
		Timestamp:        timestamp,
	}

	m.recordFullResponseCalls = append(m.recordFullResponseCalls, RecordFullResponseCall{
		ConnectionID:    connectionID,
		StatusCode:      statusCode,
		ResponseHeaders: responseHeaders,
		ResponseBody:    responseBody,
		Timestamp:       timestamp,
	})

	return nil
}

func (m *MockStatsCollector) GetOverviewStats(ctx context.Context) (*stats.OverviewStats, error) {
	return &stats.OverviewStats{}, nil
}

func (m *MockStatsCollector) GetTopDomains(ctx context.Context, limit int) ([]stats.DomainStats, error) {
	return []stats.DomainStats{}, nil
}

func (m *MockStatsCollector) GetSecurityEvents(ctx context.Context, limit int) ([]stats.SecurityEventInfo, error) {
	return []stats.SecurityEventInfo{}, nil
}

func (m *MockStatsCollector) GetRecentErrors(ctx context.Context, limit int) ([]stats.ErrorSummary, error) {
	return []stats.ErrorSummary{}, nil
}

func (m *MockStatsCollector) GetBandwidthStats(ctx context.Context, days int) (*stats.BandwidthStats, error) {
	return &stats.BandwidthStats{}, nil
}

func (m *MockStatsCollector) GetSystemStats(ctx context.Context) (*stats.SystemStats, error) {
	return &stats.SystemStats{}, nil
}

func (m *MockStatsCollector) HealthCheck(ctx context.Context) error {
	return nil
}

func (m *MockStatsCollector) Close() error {
	return nil
}

// Helper methods for test assertions
func (m *MockStatsCollector) GetStartConnectionCalls() []StartConnectionCall {
	m.mu.RLock()
	defer m.mu.RUnlock()
	calls := make([]StartConnectionCall, len(m.startConnectionCalls))
	copy(calls, m.startConnectionCalls)
	return calls
}

func (m *MockStatsCollector) GetRecordFullRequestCalls() []RecordFullRequestCall {
	m.mu.RLock()
	defer m.mu.RUnlock()
	calls := make([]RecordFullRequestCall, len(m.recordFullRequestCalls))
	copy(calls, m.recordFullRequestCalls)
	return calls
}

func (m *MockStatsCollector) GetRecordFullResponseCalls() []RecordFullResponseCall {
	m.mu.RLock()
	defer m.mu.RUnlock()
	calls := make([]RecordFullResponseCall, len(m.recordFullResponseCalls))
	copy(calls, m.recordFullResponseCalls)
	return calls
}

func (m *MockStatsCollector) GetFullHTTPRequest(connectionID int64) *stats.RecordedHTTPRequest {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.fullHTTPRequests[connectionID]
}

func (m *MockStatsCollector) GetFullHTTPResponse(connectionID int64) *stats.RecordedHTTPResponse {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.fullHTTPResponses[connectionID]
}

// Test helper functions

func createTestHTTPSServer(_ *testing.T, responseBody string, responseHeaders map[string]string) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set custom headers
		for key, value := range responseHeaders {
			w.Header().Set(key, value)
		}

		// Read and echo request body in response
		if r.Body != nil {
			body, _ := io.ReadAll(r.Body)
			if len(body) > 0 {
				w.Header().Set("Echo-Request-Body", string(body))
			}
		}

		w.WriteHeader(200)
		_, _ = w.Write([]byte(responseBody))
	}))
}

func createProxyWithRecording(t *testing.T, recordingClassifier config.Classifier, mockCollector *MockStatsCollector) (*Proxy, net.Listener) {
	// Create listener on random port
	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	// Configure proxy with recording enabled - use standard proxy type, not HTTPS
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: listener.Addr().String(),
				Enabled:       true,
			},
		},
		TimeoutSeconds: 10,
		Statistics: config.StatisticsConfig{
			Enabled:   true,
			Recording: recordingClassifier,
		},
		Interception: config.InterceptionConfig{
			Enabled:            true,
			HTTPS:              true,
			InsecureSkipVerify: true,
		},
	}

	// Create proxy - this will automatically compile the recording classifier
	proxy := NewProxy(cfg)

	// Replace the embedded stats collector with our mock
	proxy.Collector = mockCollector

	// Generate test CA for HTTPS interception
	caCertPEM, caKeyPEM := generateTestCA(t)

	// Set up HTTPS interceptor for standard proxy type with interception enabled
	for i := range proxy.servers {
		if cfg.Interception.HTTPS {
			httpsInterceptor, err := NewHTTPSInterceptor(caCertPEM, caKeyPEM, proxy, nil, nil)
			require.NoError(t, err)
			proxy.servers[i].httpsInterceptor = httpsInterceptor
		}
	}

	return proxy, listener
}

// Test HTTPS Interceptor Recording

func TestHTTPSInterceptorRecording(t *testing.T) {
	// Create test server
	responseBody := "Test response body with special characters: ñáéíóú"
	responseHeaders := map[string]string{
		"Content-Type":    "text/plain; charset=utf-8",
		"X-Custom-Header": "custom-value",
		"X-Test-Response": "https-interceptor",
	}
	testServer := createTestHTTPSServer(t, responseBody, responseHeaders)
	defer testServer.Close()

	// Create recording classifier that matches all requests
	recordingClassifier := &config.ClassifierTrue{}

	// Create mock stats collector
	mockCollector := NewMockStatsCollector()

	// Create proxy with recording
	proxy, listener := createProxyWithRecording(t, recordingClassifier, mockCollector)
	defer listener.Close()

	// Start proxy
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		proxy.StartWithListener(listener)
	}()
	defer func() {
		proxy.Stop()
		wg.Wait()
	}()

	// Create HTTP client that uses the proxy
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", listener.Addr().String()))
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 10 * time.Second,
	}

	// Prepare request with body and headers
	requestBody := `{"test": "data", "message": "Hello, HTTPS recording!"}`
	req, err := http.NewRequest("POST", testServer.URL+"/test?param=value", strings.NewReader(requestBody))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Test-Recording-Client/1.0")
	req.Header.Set("X-Custom-Request", "test-value")
	req.Header.Set("Authorization", "Bearer test-token")

	// Send request through proxy
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Read response
	respBodyBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Verify response
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, responseBody, string(respBodyBytes))

	// Wait a bit for recording to complete
	time.Sleep(100 * time.Millisecond)

	// Verify that connection was started (there might be multiple calls due to proxy setup)
	connectionCalls := mockCollector.GetStartConnectionCalls()
	require.GreaterOrEqual(t, len(connectionCalls), 1, "At least one connection should be started")

	// Find the HTTPS connection call
	var httpsCall *StartConnectionCall
	for _, call := range connectionCalls {
		if call.Protocol == "https" {
			httpsCall = &call
			break
		}
	}
	require.NotNil(t, httpsCall, "Should have at least one HTTPS connection call")
	// The port will be the test server's port, not necessarily 443
	assert.Greater(t, httpsCall.TargetPort, 0, "Target port should be positive")
	assert.Equal(t, "127.0.0.1", httpsCall.TargetHost, "Target host should be localhost")

	// Verify that full request was recorded
	requestCalls := mockCollector.GetRecordFullRequestCalls()
	require.Len(t, requestCalls, 1)

	recordedRequest := requestCalls[0]
	assert.Equal(t, "POST", recordedRequest.Method)
	assert.Contains(t, recordedRequest.URL, "/test?param=value")
	assert.Equal(t, "Test-Recording-Client/1.0", recordedRequest.UserAgent)
	assert.Equal(t, requestBody, string(recordedRequest.RequestBody))

	// Verify request headers were recorded
	assert.Equal(t, "application/json", recordedRequest.RequestHeaders["Content-Type"][0])
	assert.Equal(t, "test-value", recordedRequest.RequestHeaders["X-Custom-Request"][0])
	assert.Equal(t, "Bearer test-token", recordedRequest.RequestHeaders["Authorization"][0])

	// Verify that full response was recorded
	responseCalls := mockCollector.GetRecordFullResponseCalls()
	require.Len(t, responseCalls, 1)

	recordedResponse := responseCalls[0]
	assert.Equal(t, 200, recordedResponse.StatusCode)
	assert.Equal(t, responseBody, string(recordedResponse.ResponseBody))

	// Verify response headers were recorded
	assert.Equal(t, "text/plain; charset=utf-8", recordedResponse.ResponseHeaders["Content-Type"][0])
	assert.Equal(t, "custom-value", recordedResponse.ResponseHeaders["X-Custom-Header"][0])
	assert.Equal(t, "https-interceptor", recordedResponse.ResponseHeaders["X-Test-Response"][0])
}

func TestHTTPSInterceptorRecordingWithClassifier(t *testing.T) {
	// Create test server
	testServer := createTestHTTPSServer(t, "Test response", map[string]string{})
	defer testServer.Close()

	// Create recording classifier that only matches requests to specific domains
	recordingClassifier := &config.ClassifierDomain{
		Op:     config.ClassifierOpContains,
		Domain: "127.0.0.1", // Only record requests to localhost
	}

	// Create mock stats collector
	mockCollector := NewMockStatsCollector()

	// Create proxy with recording
	proxy, listener := createProxyWithRecording(t, recordingClassifier, mockCollector)
	defer listener.Close()

	// Start proxy
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		proxy.StartWithListener(listener)
	}()
	defer func() {
		proxy.Stop()
		wg.Wait()
	}()

	// Create HTTP client that uses the proxy
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", listener.Addr().String()))
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 10 * time.Second,
	}

	// Send request through proxy
	resp, err := client.Get(testServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Wait a bit for recording to complete
	time.Sleep(100 * time.Millisecond)

	// Verify that full request and response were recorded (should match 127.0.0.1)
	requestCalls := mockCollector.GetRecordFullRequestCalls()
	responseCalls := mockCollector.GetRecordFullResponseCalls()

	if strings.Contains(testServer.URL, "127.0.0.1") {
		assert.Len(t, requestCalls, 1, "Request should be recorded for localhost")
		assert.Len(t, responseCalls, 1, "Response should be recorded for localhost")
	} else {
		assert.Len(t, requestCalls, 0, "Request should not be recorded for non-localhost")
		assert.Len(t, responseCalls, 0, "Response should not be recorded for non-localhost")
	}
}

func TestHTTPSInterceptorNoRecordingWhenDisabled(t *testing.T) {
	// Create test server
	testServer := createTestHTTPSServer(t, "Test response", map[string]string{})
	defer testServer.Close()

	// Create mock stats collector
	mockCollector := NewMockStatsCollector()

	// Create listener on random port
	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	defer listener.Close()

	// Configure proxy WITHOUT recording enabled
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeHTTPS,
				ListenAddress: listener.Addr().String(),
				Enabled:       true,
			},
		},
		TimeoutSeconds: 10,
		Statistics: config.StatisticsConfig{
			Enabled: false, // Statistics disabled
		},
		Interception: config.InterceptionConfig{
			Enabled:            true,
			HTTPS:              true,
			InsecureSkipVerify: true,
		},
	}

	// Create proxy
	proxy := NewProxy(cfg)
	proxy.Collector = mockCollector

	// Generate test CA for HTTPS interception
	caCertPEM, caKeyPEM := generateTestCA(t)

	// Set up HTTPS interceptor
	for i := range proxy.servers {
		httpsInterceptor, err := NewHTTPSInterceptor(caCertPEM, caKeyPEM, proxy, nil, nil)
		require.NoError(t, err)
		proxy.servers[i].httpsInterceptor = httpsInterceptor
	}

	// Start proxy
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		proxy.StartWithListener(listener)
	}()
	defer func() {
		proxy.Stop()
		wg.Wait()
	}()

	// Create HTTP client that uses the proxy
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", listener.Addr().String()))
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 10 * time.Second,
	}

	// Send request through proxy
	resp, err := client.Get(testServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// Verify that no recording calls were made
	requestCalls := mockCollector.GetRecordFullRequestCalls()
	responseCalls := mockCollector.GetRecordFullResponseCalls()

	assert.Len(t, requestCalls, 0, "No requests should be recorded when statistics are disabled")
	assert.Len(t, responseCalls, 0, "No responses should be recorded when statistics are disabled")
}

// Test QUIC Interceptor Recording

func TestQUICInterceptorRecording(t *testing.T) {
	// Create mock stats collector
	mockCollector := NewMockStatsCollector()

	// Generate test CA for QUIC interception
	caCertPEM, caKeyPEM := generateTestCA(t)

	// Create recording classifier that matches all requests
	recordingClassifier := &config.ClassifierTrue{}

	// Create proxy with minimal configuration for testing
	cfg := &config.Config{
		Statistics: config.StatisticsConfig{
			Enabled:   true,
			Recording: recordingClassifier,
		},
	}
	proxy := NewProxy(cfg)
	proxy.Collector = mockCollector

	// Create QUIC interceptor
	quicInterceptor, err := NewQUICHTTP3Interceptor(caCertPEM, caKeyPEM, proxy, nil, nil)
	require.NoError(t, err)

	// Test the shouldRecordRequest function
	t.Run("ShouldRecordRequest", func(t *testing.T) {
		// Create test request
		req, err := http.NewRequest("GET", "https://example.com/test", nil)
		require.NoError(t, err)

		req.Header.Set("User-Agent", "Test-QUIC-Client/1.0")
		req.Header.Set("X-Test-Header", "test-value")

		// Test that request should be recorded
		shouldRecord := quicInterceptor.shouldRecordRequest(req)
		assert.True(t, shouldRecord, "Request should be recorded when classifier matches")
	})

	t.Run("ShouldNotRecordWhenStatsDisabled", func(t *testing.T) {
		// Create proxy with statistics disabled
		disabledCfg := &config.Config{
			Statistics: config.StatisticsConfig{
				Enabled: false,
			},
		}
		disabledProxy := NewProxy(disabledCfg)

		// Create QUIC interceptor with disabled stats
		disabledInterceptor, err := NewQUICHTTP3Interceptor(caCertPEM, caKeyPEM, disabledProxy, nil, nil)
		require.NoError(t, err)

		// Create test request
		req, err := http.NewRequest("GET", "https://example.com/test", nil)
		require.NoError(t, err)

		// Test that request should not be recorded
		shouldRecord := disabledInterceptor.shouldRecordRequest(req)
		assert.False(t, shouldRecord, "Request should not be recorded when statistics are disabled")
	})

	t.Run("ShouldNotRecordWhenClassifierDoesNotMatch", func(t *testing.T) {
		// Create recording classifier that never matches
		noMatchClassifier := &config.ClassifierFalse{}

		// Create proxy with no-match classifier
		noMatchCfg := &config.Config{
			Statistics: config.StatisticsConfig{
				Enabled:   true,
				Recording: noMatchClassifier,
			},
		}
		noMatchProxy := NewProxy(noMatchCfg)

		// Create QUIC interceptor with no-match classifier
		noMatchInterceptor, err := NewQUICHTTP3Interceptor(caCertPEM, caKeyPEM, noMatchProxy, nil, nil)
		require.NoError(t, err)

		// Create test request
		req, err := http.NewRequest("GET", "https://example.com/test", nil)
		require.NoError(t, err)

		// Test that request should not be recorded
		shouldRecord := noMatchInterceptor.shouldRecordRequest(req)
		assert.False(t, shouldRecord, "Request should not be recorded when classifier does not match")
	})
}

// Test edge cases and error handling

func TestRecordingEdgeCases(t *testing.T) {
	t.Run("EmptyRequestBody", func(t *testing.T) {
		// Create test server
		testServer := createTestHTTPSServer(t, "Empty body response", map[string]string{})
		defer testServer.Close()

		// Create recording classifier that matches all requests
		recordingClassifier := &config.ClassifierTrue{}

		// Create mock stats collector
		mockCollector := NewMockStatsCollector()

		// Create proxy with recording
		proxy, listener := createProxyWithRecording(t, recordingClassifier, mockCollector)
		defer listener.Close()

		// Start proxy
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			proxy.StartWithListener(listener)
		}()
		defer func() {
			proxy.Stop()
			wg.Wait()
		}()

		// Create HTTP client that uses the proxy
		proxyURL, err := url.Parse(fmt.Sprintf("http://%s", listener.Addr().String()))
		require.NoError(t, err)

		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			Timeout: 10 * time.Second,
		}

		// Send GET request (no body)
		resp, err := client.Get(testServer.URL)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Wait for recording
		time.Sleep(100 * time.Millisecond)

		// Verify that request was recorded with empty body
		requestCalls := mockCollector.GetRecordFullRequestCalls()
		require.Len(t, requestCalls, 1)

		recordedRequest := requestCalls[0]
		assert.Equal(t, "GET", recordedRequest.Method)
		assert.Empty(t, recordedRequest.RequestBody, "Request body should be empty for GET request")
	})

	t.Run("LargeRequestBody", func(t *testing.T) {
		// Create test server
		testServer := createTestHTTPSServer(t, "Large body response", map[string]string{})
		defer testServer.Close()

		// Create recording classifier that matches all requests
		recordingClassifier := &config.ClassifierTrue{}

		// Create mock stats collector
		mockCollector := NewMockStatsCollector()

		// Create proxy with recording
		proxy, listener := createProxyWithRecording(t, recordingClassifier, mockCollector)
		defer listener.Close()

		// Start proxy
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			proxy.StartWithListener(listener)
		}()
		defer func() {
			proxy.Stop()
			wg.Wait()
		}()

		// Create HTTP client that uses the proxy
		proxyURL, err := url.Parse(fmt.Sprintf("http://%s", listener.Addr().String()))
		require.NoError(t, err)

		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			Timeout: 10 * time.Second,
		}

		// Create large request body (10KB)
		largeBody := strings.Repeat("This is a large request body for testing recording functionality. ", 150)

		// Send request with large body
		req, err := http.NewRequest("POST", testServer.URL, strings.NewReader(largeBody))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "text/plain")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Wait for recording
		time.Sleep(100 * time.Millisecond)

		// Verify that large request body was recorded
		requestCalls := mockCollector.GetRecordFullRequestCalls()
		require.Len(t, requestCalls, 1)

		recordedRequest := requestCalls[0]
		assert.Equal(t, "POST", recordedRequest.Method)
		assert.Equal(t, largeBody, string(recordedRequest.RequestBody), "Large request body should be recorded completely")
	})

	t.Run("SpecialCharactersInHeaders", func(t *testing.T) {
		// Create test server
		responseHeaders := map[string]string{
			"X-Special-Chars": "ñáéíóú-测试-🚀",
			"X-Unicode":       "Hello, 世界! 🌍",
		}
		testServer := createTestHTTPSServer(t, "Special chars response", responseHeaders)
		defer testServer.Close()

		// Create recording classifier that matches all requests
		recordingClassifier := &config.ClassifierTrue{}

		// Create mock stats collector
		mockCollector := NewMockStatsCollector()

		// Create proxy with recording
		proxy, listener := createProxyWithRecording(t, recordingClassifier, mockCollector)
		defer listener.Close()

		// Start proxy
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			proxy.StartWithListener(listener)
		}()
		defer func() {
			proxy.Stop()
			wg.Wait()
		}()

		// Create HTTP client that uses the proxy
		proxyURL, err := url.Parse(fmt.Sprintf("http://%s", listener.Addr().String()))
		require.NoError(t, err)

		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			Timeout: 10 * time.Second,
		}

		// Send request with special characters in headers
		req, err := http.NewRequest("GET", testServer.URL, nil)
		require.NoError(t, err)
		req.Header.Set("X-Request-Special", "测试-🎯-ñoño")
		req.Header.Set("X-Request-Unicode", "Привет, мир!")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Wait for recording
		time.Sleep(100 * time.Millisecond)

		// Verify that special characters in headers were recorded correctly
		requestCalls := mockCollector.GetRecordFullRequestCalls()
		require.Len(t, requestCalls, 1)

		recordedRequest := requestCalls[0]
		assert.Equal(t, "测试-🎯-ñoño", recordedRequest.RequestHeaders["X-Request-Special"][0])
		assert.Equal(t, "Привет, мир!", recordedRequest.RequestHeaders["X-Request-Unicode"][0])

		// Verify response headers with special characters
		responseCalls := mockCollector.GetRecordFullResponseCalls()
		require.Len(t, responseCalls, 1)

		recordedResponse := responseCalls[0]
		assert.Equal(t, "ñáéíóú-测试-🚀", recordedResponse.ResponseHeaders["X-Special-Chars"][0])
		assert.Equal(t, "Hello, 世界! 🌍", recordedResponse.ResponseHeaders["X-Unicode"][0])
	})
}

// Integration tests with different classifiers

func TestRecordingWithDifferentClassifiers(t *testing.T) {
	// Create test server first to get the actual port
	testServer := createTestHTTPSServer(t, "Test response", map[string]string{})
	defer testServer.Close()

	// Extract port from test server URL
	serverURL, err := url.Parse(testServer.URL)
	require.NoError(t, err)
	_, portStr, err := net.SplitHostPort(serverURL.Host)
	require.NoError(t, err)
	serverPort, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	testCases := []struct {
		name         string
		classifier   config.Classifier
		shouldRecord bool
		description  string
	}{
		{
			name:         "ClassifierTrue",
			classifier:   &config.ClassifierTrue{},
			shouldRecord: true,
			description:  "Should always record",
		},
		{
			name:         "ClassifierFalse",
			classifier:   &config.ClassifierFalse{},
			shouldRecord: false,
			description:  "Should never record",
		},
		{
			name: "DomainClassifier-Match",
			classifier: &config.ClassifierDomain{
				Op:     config.ClassifierOpContains,
				Domain: "127.0.0.1", // Match the test server's IP
			},
			shouldRecord: true,
			description:  "Should record when domain matches",
		},
		{
			name: "DomainClassifier-NoMatch",
			classifier: &config.ClassifierDomain{
				Op:     config.ClassifierOpContains,
				Domain: "example.com", // Won't match 127.0.0.1
			},
			shouldRecord: false,
			description:  "Should not record when domain doesn't match",
		},
		{
			name: "PortClassifier-Match",
			classifier: &config.ClassifierPort{
				Port: serverPort, // Use actual test server port
			},
			shouldRecord: true,
			description:  "Should record when port matches",
		},
		{
			name: "PortClassifier-NoMatch",
			classifier: &config.ClassifierPort{
				Port: 80, // Won't match HTTPS test server port
			},
			shouldRecord: false,
			description:  "Should not record when port doesn't match",
		},
		{
			name: "AndClassifier-BothMatch",
			classifier: &config.ClassifierAnd{
				Classifiers: []config.Classifier{
					&config.ClassifierDomain{
						Op:     config.ClassifierOpContains,
						Domain: "127.0.0.1",
					},
					&config.ClassifierPort{
						Port: serverPort,
					},
				},
			},
			shouldRecord: true,
			description:  "Should record when both AND conditions match",
		},
		{
			name: "AndClassifier-OneMatch",
			classifier: &config.ClassifierAnd{
				Classifiers: []config.Classifier{
					&config.ClassifierDomain{
						Op:     config.ClassifierOpContains,
						Domain: "127.0.0.1", // This will match
					},
					&config.ClassifierPort{
						Port: 80, // This won't match
					},
				},
			},
			shouldRecord: false,
			description:  "Should not record when only one AND condition matches",
		},
		{
			name: "OrClassifier-OneMatch",
			classifier: &config.ClassifierOr{
				Classifiers: []config.Classifier{
					&config.ClassifierDomain{
						Op:     config.ClassifierOpContains,
						Domain: "127.0.0.1", // This will match
					},
					&config.ClassifierPort{
						Port: 80, // This won't match
					},
				},
			},
			shouldRecord: true,
			description:  "Should record when at least one OR condition matches",
		},
		{
			name: "OrClassifier-NoneMatch",
			classifier: &config.ClassifierOr{
				Classifiers: []config.Classifier{
					&config.ClassifierDomain{
						Op:     config.ClassifierOpContains,
						Domain: "example.com", // Won't match
					},
					&config.ClassifierPort{
						Port: 80, // Won't match
					},
				},
			},
			shouldRecord: false,
			description:  "Should not record when no OR conditions match",
		},
		{
			name: "NotClassifier-Invert",
			classifier: &config.ClassifierNot{
				Classifier: &config.ClassifierDomain{
					Op:     config.ClassifierOpContains,
					Domain: "internal", // Won't match 127.0.0.1
				},
			},
			shouldRecord: true,
			description:  "Should record when NOT condition inverts false to true",
		},
		{
			name: "NotClassifier-InvertMatch",
			classifier: &config.ClassifierNot{
				Classifier: &config.ClassifierDomain{
					Op:     config.ClassifierOpContains,
					Domain: "127.0.0.1", // Will match, but NOT inverts to false
				},
			},
			shouldRecord: false,
			description:  "Should not record when NOT condition inverts true to false",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock stats collector
			mockCollector := NewMockStatsCollector()

			// Create proxy with recording
			proxy, listener := createProxyWithRecording(t, tc.classifier, mockCollector)
			defer listener.Close()

			// Start proxy
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				proxy.StartWithListener(listener)
			}()
			defer func() {
				proxy.Stop()
				wg.Wait()
			}()

			// Create HTTP client that uses the proxy
			proxyURL, err := url.Parse(fmt.Sprintf("http://%s", listener.Addr().String()))
			require.NoError(t, err)

			client := &http.Client{
				Transport: &http.Transport{
					Proxy: http.ProxyURL(proxyURL),
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
				Timeout: 10 * time.Second,
			}

			// Use the actual test server URL
			resp, err := client.Get(testServer.URL)
			require.NoError(t, err)
			defer resp.Body.Close()

			// Wait for recording
			time.Sleep(100 * time.Millisecond)

			// Verify recording behavior
			requestCalls := mockCollector.GetRecordFullRequestCalls()
			responseCalls := mockCollector.GetRecordFullResponseCalls()

			if tc.shouldRecord {
				assert.Len(t, requestCalls, 1, tc.description+" - request")
				assert.Len(t, responseCalls, 1, tc.description+" - response")
			} else {
				assert.Len(t, requestCalls, 0, tc.description+" - request")
				assert.Len(t, responseCalls, 0, tc.description+" - response")
			}
		})
	}
}
