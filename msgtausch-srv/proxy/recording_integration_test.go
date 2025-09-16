package proxy

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test that event-stream responses are not fully recorded (streamed without buffering)
func TestRecordingSkippedForEventStream(t *testing.T) {
	// Create an HTTPS server that serves text/event-stream
	sseServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		require.True(t, ok, "expected http.Flusher")

		// Write a couple of events then return
		for i := 0; i < 3; i++ {
			_, _ = io.WriteString(w, fmt.Sprintf("data: event-%d\n\n", i))
			flusher.Flush()
			time.Sleep(10 * time.Millisecond)
		}
	}))
	defer sseServer.Close()

	recordingClassifier := &config.ClassifierTrue{}
	mockCollector := NewMockStatsCollector()

	proxy, listener := createProxyWithRecording(t, recordingClassifier, mockCollector)
	defer listener.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		proxy.StartWithListener(listener)
	}()
	defer func() { proxy.Stop(); wg.Wait() }()

	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", listener.Addr().String()))
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 3 * time.Second,
	}

	// Make a request that initiates an SSE stream
	req, err := http.NewRequest("GET", sseServer.URL+"/events", nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Read a little to ensure stream established
	buf := make([]byte, 64)
	_, _ = resp.Body.Read(buf)

	// Give proxy a moment, then close
	time.Sleep(50 * time.Millisecond)

	// No recording should have occurred for event-stream
	assert.Len(t, mockCollector.GetRecordFullRequestCalls(), 0)
	assert.Len(t, mockCollector.GetRecordFullResponseCalls(), 0)
}

// Test that the recorded request URL is reconstructed with scheme, host, path, and query
func TestRecordedURLConstruction(t *testing.T) {
	// Backend responds simply
	backend := createTestHTTPSServer(t, "ok", map[string]string{})
	defer backend.Close()

	recordingClassifier := &config.ClassifierTrue{}
	mockCollector := NewMockStatsCollector()

	proxy, listener := createProxyWithRecording(t, recordingClassifier, mockCollector)
	defer listener.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); proxy.StartWithListener(listener) }()
	defer func() { proxy.Stop(); wg.Wait() }()

	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", listener.Addr().String()))
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}

	// Request with path and query
	pathAndQuery := "/api/v1/items?limit=10&filter=a%20b"
	req, err := http.NewRequest("GET", backend.URL+pathAndQuery, nil)
	require.NoError(t, err)
	req.Header.Set("User-Agent", "URL-Builder/1.0")

	resp, err := client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	time.Sleep(100 * time.Millisecond)

	calls := mockCollector.GetRecordFullRequestCalls()
	require.Len(t, calls, 1)

	recorded := calls[0]
	// Expect full https URL with host from backend and proper query
	expectedPrefix := "https://"
	assert.True(t, strings.HasPrefix(recorded.URL, expectedPrefix))
	assert.True(t, strings.HasSuffix(recorded.URL, pathAndQuery))
	// Ensure host is present in the middle (rough check)
	assert.Contains(t, recorded.URL, ":") // host:port
}

// Test that multiple sequential requests are recorded individually
func TestMultipleSequentialRecordings(t *testing.T) {
	backend := createTestHTTPSServer(t, "pong", map[string]string{"X-Resp": "1"})
	defer backend.Close()

	recordingClassifier := &config.ClassifierTrue{}
	mockCollector := NewMockStatsCollector()

	proxy, listener := createProxyWithRecording(t, recordingClassifier, mockCollector)
	defer listener.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); proxy.StartWithListener(listener) }()
	defer func() { proxy.Stop(); wg.Wait() }()

	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", listener.Addr().String()))
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}

	// First request
	req1, err := http.NewRequest("POST", backend.URL+"/r1", strings.NewReader("alpha"))
	require.NoError(t, err)
	req1.Header.Set("Content-Type", "text/plain")
	resp1, err := client.Do(req1)
	require.NoError(t, err)
	resp1.Body.Close()

	// Second request (same client, keep-alive)
	req2, err := http.NewRequest("POST", backend.URL+"/r2", strings.NewReader("beta"))
	require.NoError(t, err)
	req2.Header.Set("Content-Type", "text/plain")
	resp2, err := client.Do(req2)
	require.NoError(t, err)
	resp2.Body.Close()

	time.Sleep(150 * time.Millisecond)

	reqCalls := mockCollector.GetRecordFullRequestCalls()
	respCalls := mockCollector.GetRecordFullResponseCalls()

	require.Len(t, reqCalls, 2)
	require.Len(t, respCalls, 2)

	assert.Equal(t, "alpha", string(reqCalls[0].RequestBody))
	assert.Equal(t, "beta", string(reqCalls[1].RequestBody))
}

// Test that a chunked response (non-event-stream) is fully buffered and recorded
func TestRecordingChunkedResponse(t *testing.T) {
	// Backend that writes response in chunks without Content-Length
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		flusher, _ := w.(http.Flusher)
		chunks := []string{"part-1-", "part-2-", "part-3"}
		for _, c := range chunks {
			_, _ = io.WriteString(w, c)
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(5 * time.Millisecond)
		}
	}))
	defer backend.Close()

	recordingClassifier := &config.ClassifierTrue{}
	mockCollector := NewMockStatsCollector()

	proxy, listener := createProxyWithRecording(t, recordingClassifier, mockCollector)
	defer listener.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); proxy.StartWithListener(listener) }()
	defer func() { proxy.Stop(); wg.Wait() }()

	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", listener.Addr().String()))
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   5 * time.Second,
	}

	resp, err := client.Get(backend.URL + "/chunked")
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	time.Sleep(120 * time.Millisecond)

	// Ensure client saw concatenated chunks
	assert.Equal(t, "part-1-part-2-part-3", string(body))

	// Ensure recorder captured full response body
	rec := mockCollector.GetRecordFullResponseCalls()
	require.Len(t, rec, 1)
	assert.Equal(t, "part-1-part-2-part-3", string(rec[0].ResponseBody))
}

// Test that gzip-encoded responses are recorded (compressed); verify by decompressing
func TestRecordingGzipResponse(t *testing.T) {
	payload := strings.Repeat("hello gz ", 50)
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		_, _ = gz.Write([]byte(payload))
		_ = gz.Close()
	}))
	defer backend.Close()

	recordingClassifier := &config.ClassifierTrue{}
	mockCollector := NewMockStatsCollector()
	proxy, listener := createProxyWithRecording(t, recordingClassifier, mockCollector)
	defer listener.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); proxy.StartWithListener(listener) }()
	defer func() { proxy.Stop(); wg.Wait() }()

	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", listener.Addr().String()))
	require.NoError(t, err)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 5 * time.Second}

	resp, err := client.Get(backend.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()

	time.Sleep(120 * time.Millisecond)

	rec := mockCollector.GetRecordFullResponseCalls()
	require.Len(t, rec, 1)

	// Decompress recorded body and compare
	zr, err := gzip.NewReader(bytes.NewReader(rec[0].ResponseBody))
	require.NoError(t, err)
	decompressed, err := io.ReadAll(zr)
	require.NoError(t, err)
	_ = zr.Close()
	assert.Equal(t, payload, string(decompressed))
}

// Test that a redirect followed by final response produces two recordings
func TestRecordingRedirectChain(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("done"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer backend.Close()

	recordingClassifier := &config.ClassifierTrue{}
	mockCollector := NewMockStatsCollector()
	proxy, listener := createProxyWithRecording(t, recordingClassifier, mockCollector)
	defer listener.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); proxy.StartWithListener(listener) }()
	defer func() { proxy.Stop(); wg.Wait() }()

	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", listener.Addr().String()))
	require.NoError(t, err)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 5 * time.Second}

	resp, err := client.Get(backend.URL + "/redirect")
	require.NoError(t, err)
	_ = resp.Body.Close()

	time.Sleep(150 * time.Millisecond)

	reqCalls := mockCollector.GetRecordFullRequestCalls()
	respCalls := mockCollector.GetRecordFullResponseCalls()
	require.Len(t, reqCalls, 2)
	require.Len(t, respCalls, 2)
	assert.Equal(t, http.StatusFound, respCalls[0].StatusCode)
	assert.Equal(t, http.StatusOK, respCalls[1].StatusCode)
}

// Test that exclude-classifier prevents interception and thus no full recording occurs
func TestRecordingExcludedHost(t *testing.T) {
	backend := createTestHTTPSServer(t, "nope", map[string]string{"X-Test": "exclude"})
	defer backend.Close()

	// Build config with exclude classifier matching localhost
	recordingClassifier := &config.ClassifierTrue{}
	mockCollector := NewMockStatsCollector()

	// Create listener on random port
	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	cfg := &config.Config{
		Servers:        []config.ServerConfig{{Type: config.ProxyTypeStandard, ListenAddress: listener.Addr().String(), Enabled: true}},
		TimeoutSeconds: 10,
		Statistics:     config.StatisticsConfig{Enabled: true, Recording: recordingClassifier},
		Interception:   config.InterceptionConfig{Enabled: true, HTTPS: true, InsecureSkipVerify: true, ExcludeClassifier: &config.ClassifierDomain{Op: config.ClassifierOpContains, Domain: "127.0.0.1"}},
	}

	proxy := NewProxy(cfg)
	proxy.Collector = mockCollector

	// Set up HTTPS interceptor
	caCertPEM, caKeyPEM := generateTestCA(t)
	for i := range proxy.servers {
		if cfg.Interception.HTTPS {
			httpsInterceptor, err := NewHTTPSInterceptor(caCertPEM, caKeyPEM, proxy, nil, nil)
			require.NoError(t, err)
			proxy.servers[i].httpsInterceptor = httpsInterceptor
		}
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); proxy.StartWithListener(listener) }()
	defer func() { proxy.Stop(); wg.Wait() }()

	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", listener.Addr().String()))
	require.NoError(t, err)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 5 * time.Second}

	// Send request; exclude classifier should bypass interception
	resp, err := client.Get(backend.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()

	time.Sleep(120 * time.Millisecond)

	// No full recordings should be present
	assert.Len(t, mockCollector.GetRecordFullRequestCalls(), 0)
	assert.Len(t, mockCollector.GetRecordFullResponseCalls(), 0)
}
