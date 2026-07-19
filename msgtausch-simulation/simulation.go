package msgtausch_simulation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"crypto/tls"
	"crypto/x509"

	"github.com/armon/go-socks5"
	msgtauschconfig "github.com/codefionn/msgtausch/msgtausch-srv/config"
	msgtauschlogger "github.com/codefionn/msgtausch/msgtausch-srv/logger"
	msgtauschproxy "github.com/codefionn/msgtausch/msgtausch-srv/proxy"
	"github.com/gorilla/websocket"
)

// SimulationStats contains detailed statistics from a simulation run
type SimulationStats struct {
	Seed                   int64                                  `json:"seed"`
	TotalRequests          int                                    `json:"total_requests"`
	RequestsNotForwarded   int                                    `json:"requests_not_forwarded"`
	ForwardedRequests      int                                    `json:"forwarded_requests"`
	ConfiguredForwards     int                                    `json:"configured_forwards"`
	ForwardsUsed           int                                    `json:"forwards_used"`
	ForwardConnections     map[string]int64                       `json:"forward_connections"`
	HTTPMethodCounts       map[string]int                         `json:"http_method_counts"`
	ProtocolCounts         map[string]int                         `json:"protocol_counts"`
	ValidatedHTTPResponses int64                                  `json:"validated_http_responses"`
	WebSocketMessages      int64                                  `json:"websocket_messages"`
	UnrecoverableErrors    int64                                  `json:"unrecoverable_errors"`
	WebSocketConnections   int64                                  `json:"websocket_connections"`
	ExpectedWebSocketConns int64                                  `json:"expected_websocket_connections"`
	TargetServerStats      []TargetServerStats                    `json:"target_server_stats"`
	ErrorCountsByTarget    map[string]map[SimulationErrorType]int `json:"error_counts_by_target"`
	ProxyChainLength       int                                    `json:"proxy_chain_length"`
	ResponseTimes          []time.Duration                        `json:"-"` // Response times for percentile calculation
	P50                    time.Duration                          `json:"p50_ms"`
	P95                    time.Duration                          `json:"p95_ms"`
	P99                    time.Duration                          `json:"p99_ms"`
	P99_9                  time.Duration                          `json:"p99_9_ms"`
	P99_99                 time.Duration                          `json:"p99_99_ms"`
	MinResponseTime        time.Duration                          `json:"min_response_time_ms"`
	MaxResponseTime        time.Duration                          `json:"max_response_time_ms"`
	AvgResponseTime        time.Duration                          `json:"avg_response_time_ms"`
}

// TargetServerStats contains statistics for a single target server
type TargetServerStats struct {
	URL                string                      `json:"url"`
	RequestCount       int64                       `json:"request_count"`
	WebSocketConnCount int64                       `json:"websocket_conn_count"`
	ErrorCounts        map[SimulationErrorType]int `json:"error_counts"`
}

// DetailedSimulationError enhances standard errors with HTTP response details.
type DetailedSimulationError struct {
	OriginalError  error
	HTTPResponse   *http.Response // Store the actual response
	ProxyErrorCode string         // Extracted from X-Proxy-Error header or HTML body
	// ResponseBody   string         // No longer storing raw body, parse on demand from HTTPResponse.Body
}

func (e *DetailedSimulationError) Error() string {
	if e.ProxyErrorCode != "" {
		return fmt.Sprintf("HTTP Status: %d, Proxy Error Code: %s (Original: %v)", e.HTTPResponse.StatusCode, e.ProxyErrorCode, e.OriginalError)
	}
	if e.HTTPResponse != nil {
		return fmt.Sprintf("HTTP Status: %d (Original: %v)", e.HTTPResponse.StatusCode, e.OriginalError)
	}
	return e.OriginalError.Error()
}

func (e *DetailedSimulationError) Unwrap() error {
	return e.OriginalError
}

// extractProxyErrorCode attempts to find a proxy-specific error code.
// It first checks the X-Proxy-Error header, then tries to parse the HTML body.
func extractProxyErrorCode(resp *http.Response) string {
	if resp == nil {
		return ""
	}

	// Check X-Proxy-Error header first
	if proxyHeaderErr := resp.Header.Get("X-Proxy-Error"); proxyHeaderErr != "" {
		return proxyHeaderErr
	}

	// If not found in header, try parsing HTML body (e.g., for 502 pages)
	// Read the body (make sure to be able to re-read it if necessary, or consume it here)
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		// Cannot read body, so cannot parse
		return ""
	}
	// Restore the body so it can be read again by other parts of the simulation if needed
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	return parseErrorCodeFromHTML(bodyBytes)
}

// parseErrorCodeFromHTML tries to extract an error code (e.g., "E1234")
// from an HTML response body, looking for the pattern:
// <p><span class="error-code">Error Code:</span> ERROR_CODE_HERE</p>
func parseErrorCodeFromHTML(bodyBytes []byte) string {
	bodyStr := string(bodyBytes)
	// Crude parsing, can be improved with regex or a proper HTML parser if needed
	signature := `<p><span class="error-code">Error Code:</span>`
	startIdx := strings.Index(bodyStr, signature)
	if startIdx == -1 {
		// Try another common signature for error pages that might not be 502s
		// but still use a similar format, e.g. internal server errors.
		signatureAlt := `<span class="error-code">`
		startIdxAlt := strings.Index(bodyStr, signatureAlt)
		if startIdxAlt == -1 {
			return ""
		}
		// Check if this alternative signature is for the "Error Code:" field
		potentialCodeStart := startIdxAlt + len(signatureAlt)
		potentialCodeEnd := strings.Index(bodyStr[potentialCodeStart:], `</span>`)
		if potentialCodeEnd != -1 {
			// Look for "Error Code:" text nearby to be more certain
			// This is still heuristic but better than nothing.
			searchRegion := bodyStr[maxInt(0, startIdxAlt-50):minInt(len(bodyStr), startIdxAlt+potentialCodeEnd+50)]
			if strings.Contains(searchRegion, "Error Code:") {
				return strings.TrimSpace(bodyStr[potentialCodeStart : potentialCodeStart+potentialCodeEnd])
			}
		}
		return ""
	}

	startIdx += len(signature)
	endIdx := strings.Index(bodyStr[startIdx:], `</p>`)
	if endIdx == -1 {
		// Fallback if </p> is not found, try to find </span> as a closer delimiter for the code
		endIdx = strings.Index(bodyStr[startIdx:], `</span>`)
		if endIdx == -1 {
			return ""
		}
	}

	return strings.TrimSpace(bodyStr[startIdx : startIdx+endIdx])
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SimulationErrorType represents the type of simulated error.
type SimulationErrorType string

const (
	// ErrorNone indicates no error occurred.
	ErrorNone SimulationErrorType = ""
	// ErrorTCP indicates a TCP-level error.
	ErrorTCP SimulationErrorType = "tcp"
	// ErrorTimeout indicates a timeout occurred.
	ErrorTimeout SimulationErrorType = "timeout"
	// ErrorHTTP400 indicates an HTTP 400 error.
	ErrorHTTP400 SimulationErrorType = "http400"
	// ErrorHTTP501 indicates an HTTP 501 error.
	ErrorHTTP501 SimulationErrorType = "http501"
)

// SimulationTestCase defines a test case for the proxy simulation
type SimulationTestCase struct {
	Seed         int64 `json:"seed"`
	AllowTimeout bool  `json:"allowTimeout"`
	DisableError bool  `json:"disableError,omitempty"`
}

// RandomSimulationTestCase generates a SimulationTestCase with random values based on the given seed.
func RandomSimulationTestCase(seed int64) SimulationTestCase {
	rng := rand.New(rand.NewSource(seed))
	return SimulationTestCase{
		Seed:         rng.Int63(),
		AllowTimeout: rng.Float64() < 0.001,
	}
}

// SimulatedTargetServer defines a server that introduces various latencies and errors
type SimulatedTargetServer struct {
	server             *httptest.Server
	latencyMs          int
	errorRate          float32
	errorCounts        sync.Map           // Thread-safe map to track errors by type
	requestCount       atomic.Int64       // Counter for actual requests received
	allRequestCount    atomic.Int64       // Counter including requests routed through forwards
	websocketUpgrader  websocket.Upgrader // Upgrader for websocket connections
	websocketConnCount atomic.Int64       // Counter for actual websocket connections made
	allWebsocketConns  atomic.Int64       // Counter including connections routed through forwards
	receivedRequestIDs sync.Map           // Debug: track X-Sim-Req IDs received (for diagnosing tally mismatches)
	errorCountsMu      sync.Mutex
}

// SimulatedSocks5Proxy represents a simulated SOCKS5 proxy (mocked for testing).
type SimulatedSocks5Proxy struct {
	Port     int
	Server   *socks5.Server
	Listener net.Listener
	done     chan struct{}
	accepted *atomic.Int64
}

// SimulatedMsgtauschProxy represents a running msgtausch proxy instance for simulation/testing.
type SimulatedMsgtauschProxy struct {
	Port     int
	Seed     int64
	Proxy    *msgtauschproxy.Proxy
	Listener net.Listener
	Config   *msgtauschconfig.Config
	done     chan struct{}
	accepted *atomic.Int64
}

type countingListener struct {
	net.Listener
	accepted *atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return conn, err
}

func (p *SimulatedSocks5Proxy) acceptedConnections() int64 {
	return p.accepted.Load()
}

func (p *SimulatedMsgtauschProxy) acceptedConnections() int64 {
	return p.accepted.Load()
}

// RunSimulation runs a simulation with random requests, proxies, and targets. It validates error accounting.
//
// The seed allows reproduction of problematic runs.
func RunSimulation(seed int64, enableForwards bool) error {
	_, err := runSimulation(seed, enableForwards)
	return err
}

func runSimulation(seed int64, enableForwards bool) (*SimulationStats, error) {
	rng := rand.New(rand.NewSource(seed))
	// 1. Create random forwards (SOCKS5 and msgtausch)
	var socksProxies []*SimulatedSocks5Proxy
	var msgtauschProxies []*SimulatedMsgtauschProxy
	if enableForwards {
		socksProxies = CreateRandomSocks5Proxies(rng.Int63())
		msgtauschProxies = CreateRandomMsgtauschProxies(rng.Int63())
	}
	defer func() {
		for _, p := range socksProxies {
			p.Listener.Close()
			// Wait for server goroutine to finish with timeout
			select {
			case <-p.done:
				// Server finished gracefully
			case <-time.After(2 * time.Second):
				// Timeout waiting for server to finish
				msgtauschlogger.Warn("SOCKS5 server did not shut down gracefully")
			}
		}
	}()
	defer func() {
		for _, p := range msgtauschProxies {
			if err := p.Proxy.Stop(); err != nil {
				log.Printf("Error stopping proxy: %v", err)
			}
			// Wait for server goroutine to finish with timeout
			select {
			case <-p.done:
				// Server finished gracefully
			case <-time.After(2 * time.Second):
				// Timeout waiting for server to finish
				msgtauschlogger.Warn("Msgtausch proxy did not shut down gracefully")
			}
		}
	}()

	// Initialize total counters for websocket connections and requests
	expectedWebsocketConns := make(map[string]int64)
	totalRequests := make(map[string]int)
	mutexTotalRequests := sync.Mutex{}

	// 2. Create random target servers
	nTargets := 2 + rng.Intn(4) + len(socksProxies) + len(msgtauschProxies)
	targets := make([]*SimulatedTargetServer, nTargets)
	for i := range targets {
		targets[i] = NewSimulatedTargetServer(rng.Int63())

		totalRequests[targets[i].server.URL] = 0
		expectedWebsocketConns[targets[i].server.URL] = 0
	}

	defer func() {
		for _, t := range targets {
			t.Close()
		}
	}()

	// 3. Build config forwards
	forwards := make([]msgtauschconfig.Forward, 0)
	var usedForwards = 0
	if enableForwards {
		for i, sp := range socksProxies {
			var fwd msgtauschconfig.Forward = &msgtauschconfig.ForwardSocks5{
				ClassifierData: &msgtauschconfig.ClassifierPort{
					Port: targetServerPort(targets[i]),
				},
				Address: fmt.Sprintf("127.0.0.1:%d", sp.Port),
			}
			forwards = append(forwards, fwd)
			usedForwards++
		}
		for i, mp := range msgtauschProxies {
			targetIdx := len(socksProxies) + i
			var fwd msgtauschconfig.Forward = &msgtauschconfig.ForwardProxy{
				ClassifierData: &msgtauschconfig.ClassifierPort{
					Port: targetServerPort(targets[targetIdx]),
				},
				Address: fmt.Sprintf("127.0.0.1:%d", mp.Port),
			}
			forwards = append(forwards, fwd)
			usedForwards++
		}
	}

	// 4. Create main proxy config
	cfg := &msgtauschconfig.Config{
		Servers: []msgtauschconfig.ServerConfig{
			{
				Type:          msgtauschconfig.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:0", // random port
				Enabled:       true,
			},
		},
		TimeoutSeconds: 60,
		Classifiers:    make(map[string]msgtauschconfig.Classifier),
		Forwards:       forwards,
		// Initialize with nil allowlist/blocklist - this prevents the NewProxy function
		// from trying to compile non-existent classifiers
		Allowlist: nil,
		Blocklist: nil,
	}

	listener, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to start simulation proxy: %w", err)
	}
	urlForProxy, err := url.Parse("http://" + listener.Addr().String())
	if err != nil {
		return nil, err
	}

	defer func() {
		if closeErr := listener.Close(); closeErr != nil {
			msgtauschlogger.Error("Error closing listener: %v", closeErr)
		}
	}()
	proxy := msgtauschproxy.NewProxy(cfg)
	go func() {
		_ = proxy.StartWithListener(listener)
	}()

	// 5. Run random requests
	nRequests := 20 + rng.Intn(50)
	nRequestsNotForwarded := 0
	errCounts := make(map[string]map[SimulationErrorType]int)
	mutexErrCounts := sync.Mutex{}
	// Track response times for percentile calculation
	responseTimes := make([]time.Duration, 0, nRequests)
	mutexResponseTimes := sync.Mutex{}
	// Optionally trust a custom CA for HTTPS targets
	tlsRootCAs, err := x509.SystemCertPool()
	if err != nil {
		tlsRootCAs = x509.NewCertPool()
	}
	if caPEM := os.Getenv("SIM_TLS_CA_CERT_PEM"); caPEM != "" {
		tlsRootCAs.AppendCertsFromPEM([]byte(caPEM))
	}
	for _, target := range targets {
		if cert := target.server.Certificate(); cert != nil {
			tlsRootCAs.AddCert(cert)
		}
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return urlForProxy, nil
			},
			TLSClientConfig:   &tls.Config{RootCAs: tlsRootCAs, InsecureSkipVerify: false},
			DisableKeepAlives: true, // Disable connection reuse to avoid retry issues
		},
	}

	// Create websocket dialer
	wsDialer := websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
		Proxy: func(req *http.Request) (*url.URL, error) {
			return urlForProxy, nil
		},
		TLSClientConfig: &tls.Config{RootCAs: tlsRootCAs, InsecureSkipVerify: false},
	}

	mutexLen := rng.Intn(8) + 4
	mutex := make([]sync.Mutex, mutexLen)
	mutexMap := sync.Mutex{}

	var wg sync.WaitGroup
	wg.Add(nRequests)

	unrecoverableErrorCount := atomic.Int64{}
	httpAttempts := atomic.Int64{}
	httpAccounted := atomic.Int64{}
	validatedHTTPResponses := atomic.Int64{}
	wsAttempts := atomic.Int64{}
	wsMessages := atomic.Int64{}
	inFlight := atomic.Int64{}
	httpMethods := []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodHead,
		http.MethodOptions,
	}
	httpMethodCounts := make(map[string]int, len(httpMethods))
	protocolCounts := make(map[string]int, 4)

	for i := range nRequests {
		initialWait := time.Duration(10+rng.Intn(40)) * time.Millisecond

		targetIdx := rng.Intn(len(targets))
		if i < len(targets) {
			// Guarantee at least one request per target. Forward-enabled runs use
			// this deterministic prefix to exercise every configured route.
			targetIdx = i
		}
		target := targets[targetIdx]
		targetURL := target.URL()

		// Decide whether to use HTTP or WebSocket (20% chance for WebSocket)
		useWebSocket := i == len(httpMethods) || (i > len(httpMethods) && rng.Float64() < 0.2)
		usesForward := targetIdx < len(forwards)
		protocol := "http"
		if strings.HasPrefix(targetURL, "https://") {
			protocol = "https"
		}
		if useWebSocket {
			protocol = "ws"
			if strings.HasPrefix(targetURL, "https://") {
				protocol = "wss"
			}
		}
		protocolCounts[protocol]++

		if !usesForward {
			mutexTotalRequests.Lock()
			totalRequests[targetURL]++
			nRequestsNotForwarded++
			mutexTotalRequests.Unlock()
		}

		mutexMap.Lock()
		mutexTarget := &mutex[rng.Intn(mutexLen)]
		mutexMap.Unlock()
		mutexTarget.Lock()

		tc := RandomSimulationTestCase(rng.Int63())
		if i <= len(httpMethods) {
			// The deterministic feature floor must reach the target so request and
			// response integrity can be checked. Later requests retain random faults.
			tc.DisableError = true
		}
		tcJSON, err := json.Marshal(tc)
		if err != nil {
			msgtauschlogger.Error("Test case could not be converted to JSON")
		}

		setHeader := func(header http.Header) {
			header.Set("X-Sim-Req", fmt.Sprintf("req-%d", i))
			header.Set("X-Sim-Forward", fmt.Sprintf("%t", usesForward))
			header.Set("X-Test-Case", string(tcJSON))
		}

		if useWebSocket {
			wsAttempts.Add(1)
			inFlight.Add(1)
			// Convert http(s):// to ws(s):// for WebSocket
			wsURL := targetURL
			if strings.HasPrefix(wsURL, "https://") {
				wsURL = "wss://" + strings.TrimPrefix(wsURL, "https://")
			} else if strings.HasPrefix(wsURL, "http://") {
				wsURL = "ws://" + strings.TrimPrefix(wsURL, "http://")
			}

			// Increment the expected websocket connection count for this target.
			mutexTotalRequests.Lock()
			expectedWebsocketConns[targetURL]++
			mutexTotalRequests.Unlock()

			go func(wsURL string, usesForward bool, reqIndex int, initialWait time.Duration, mutexTarget *sync.Mutex) {
				time.Sleep(initialWait)

				defer func() {
					mutexTarget.Unlock()
					inFlight.Add(-1)
					msgtauschlogger.Debug("[CLIENT] WS req-%d done (forward=%v)", reqIndex, usesForward)
					wg.Done()
				}()

				msgtauschlogger.Debug("[CLIENT] WS req-%d starting (forward=%v, target=%s)", reqIndex, usesForward, wsURL)

				// Connect to the WebSocket server
				header := http.Header{}
				header.Set("X-Sim-Req", fmt.Sprintf("req-%d", reqIndex))
				header.Set("X-Sim-Forward", fmt.Sprintf("%t", usesForward))
				header.Set("X-Test-Case", string(tcJSON))
				conn, resp, err := wsDialer.Dial(wsURL, header)
				if resp != nil {
					defer func() {
						if closeErr := resp.Body.Close(); closeErr != nil {
							msgtauschlogger.Error("Error closing response body: %v", closeErr)
						}
					}()
				}
				if err != nil {
					msgtauschlogger.Error("Error connecting to WebSocket: %v", err)
					unrecoverableErrorCount.Add(1)
					return
				}
				defer func() {
					if closeErr := conn.Close(); closeErr != nil {
						msgtauschlogger.Error("Error closing connection: %v", closeErr)
					}
				}()

				// Exercise both text and binary frames, and verify multiple messages
				// can travel over the same upgraded connection.
				for messageIndex, messageType := range []int{websocket.TextMessage, websocket.BinaryMessage} {
					message := []byte(fmt.Sprintf("%t-ws-req-%d-message-%d", usesForward, reqIndex, messageIndex))
					if err = conn.WriteMessage(messageType, message); err != nil {
						msgtauschlogger.Error("Error sending WebSocket message: %v", err)
						unrecoverableErrorCount.Add(1)
						return
					}

					responseType, respMsg, readErr := conn.ReadMessage()
					if readErr != nil {
						msgtauschlogger.Error("Error reading WebSocket message: %v", readErr)
						unrecoverableErrorCount.Add(1)
						return
					}

					if responseType != messageType || !bytes.Equal(respMsg, message) {
						msgtauschlogger.Error("WebSocket echo mismatch for request %d: want type %d body %q, got type %d body %q", reqIndex, messageType, message, responseType, respMsg)
						unrecoverableErrorCount.Add(1)
						return
					}
					wsMessages.Add(1)
				}
			}(wsURL, usesForward, i, initialWait, mutexTarget)
		} else {
			httpAttempts.Add(1)
			inFlight.Add(1)
			method := httpMethods[i%len(httpMethods)]
			httpMethodCounts[method]++
			payload := fmt.Sprintf("simulation-payload-%d-%d", seed, i)
			expectedResponse := fmt.Sprintf("simulation-response-%d-%d", seed, i)
			var requestBody io.Reader = http.NoBody
			if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
				requestBody = strings.NewReader(payload)
				expectedResponse = payload
			}
			requestURL := fmt.Sprintf("%s?test_id=%d&seed=%d", targetURL, i, seed)
			req, reqErr := http.NewRequest(method, requestURL, requestBody)
			if reqErr != nil {
				mutexTarget.Unlock()
				wg.Done()
				return nil, fmt.Errorf("create request %d: %w", i, reqErr)
			}
			if method == http.MethodPatch {
				// An unknown content length makes net/http use chunked transfer encoding.
				req.ContentLength = -1
			}
			setHeader(req.Header)
			req.Header.Set("X-Sim-Feature", fmt.Sprintf("feature-%d", i))
			req.Header.Set("X-Sim-Expected-Response", expectedResponse)

			go func(req *http.Request, usesForward bool, targetURL, expectedResponse string, requestIndex int, initialWait time.Duration, mutexTarget *sync.Mutex) {
				time.Sleep(initialWait)

				defer func() {
					mutexTarget.Unlock()
					inFlight.Add(-1)
					msgtauschlogger.Debug("[CLIENT] HTTP req done (forward=%v, target=%s)", usesForward, targetURL)
					wg.Done()
				}()

				msgtauschlogger.Debug("[CLIENT] HTTP req starting (forward=%v, target=%s)", usesForward, targetURL)

				accounted := false
				startTime := time.Now()
				resp, err := client.Do(req)
				elapsed := time.Since(startTime)
				defer func() {
					if resp != nil {
						_ = resp.Body.Close()
					}
				}()

				// Record response time for successful requests (including error responses)
				if err == nil {
					mutexResponseTimes.Lock()
					responseTimes = append(responseTimes, elapsed)
					mutexResponseTimes.Unlock()
				}

				if err != nil {
					var errorType SimulationErrorType
					msgtauschlogger.Error("Error making request: %v", err)
					if errors.Is(err, syscall.ETIMEDOUT) ||
						strings.Contains(err.Error(), "context deadline exceeded") ||
						strings.Contains(err.Error(), "timeout") {
						errorType = ErrorTimeout
					} else {
						// Treat other I/O failures as TCP-level errors (e.g., abrupt close)
						errorType = ErrorTCP
					}

					// Only count detectable errors
					if !isUndetectableError(errorType, usesForward) {
						mutexErrCounts.Lock()
						defer mutexErrCounts.Unlock()
						if _, ok := errCounts[targetURL]; !ok {
							errCounts[targetURL] = make(map[SimulationErrorType]int)
						}
						errCounts[targetURL][errorType]++
					}
					accounted = true
				} else if resp.StatusCode != http.StatusOK {
					body, _ := io.ReadAll(resp.Body)
					msgtauschlogger.Debug("Received non-200 status code in %s: %d (%s)", targetURL, resp.StatusCode, strings.ReplaceAll(string(body), "\n", ""))
					var errorType SimulationErrorType
					switch resp.StatusCode {
					case http.StatusBadRequest:
						errorType = ErrorHTTP400
					case http.StatusNotImplemented:
						errorType = ErrorHTTP501
					case http.StatusBadGateway:
						gatewayErrCode := extractProxyErrorCode(resp)
						if gatewayErrCode == msgtauschproxy.ErrCodeHTTPForwardFailed {
							errorType = ErrorTCP
						} else if gatewayErrCode != "" {
							msgtauschlogger.Error("Unhandled gateway error: %s (%s)", gatewayErrCode, msgtauschproxy.ErrorDescriptions[gatewayErrCode])
							unrecoverableErrorCount.Add(1)
							return
						}
					default:
						msgtauschlogger.Error("Unhandled HTTP status code: %d", resp.StatusCode)
						unrecoverableErrorCount.Add(1)
						return
					}

					// Only count detectable errors
					if !isUndetectableError(errorType, usesForward) {
						mutexErrCounts.Lock()
						defer mutexErrCounts.Unlock()
						if _, ok := errCounts[targetURL]; !ok {
							errCounts[targetURL] = make(map[SimulationErrorType]int)
							errCounts[targetURL][errorType] = 1
						} else {
							errCounts[targetURL][errorType]++
						}
					}
					accounted = true
				} else {
					if validationErr := validateSuccessfulHTTPResponse(resp, req, expectedResponse, requestIndex); validationErr != nil {
						msgtauschlogger.Error("HTTP feature validation failed: %v", validationErr)
						unrecoverableErrorCount.Add(1)
						return
					}
					validatedHTTPResponses.Add(1)
					accounted = true
				}

				if accounted {
					httpAccounted.Add(1)
				}
			}(req, usesForward, targetURL, expectedResponse, i, initialWait, mutexTarget)
		}
	}

	wg.Wait()

	if inFlight.Load() != 0 {
		return nil, fmt.Errorf("in-flight goroutines remaining after wait: %d", inFlight.Load())
	}

	msgtauschlogger.Info("Simulation completed with %d requests (%d forwards used)", nRequests, usedForwards)

	if unrecoverableErrorCount.Load() > 0 {
		return nil, fmt.Errorf("%d unrecoverable errors occurred", unrecoverableErrorCount.Load())
	}

	// Verify websocket connection counts
	for _, t := range targets {
		if t.allWebsocketConns.Load() != expectedWebsocketConns[t.server.URL] {
			return nil, fmt.Errorf("websocket connection count mismatch for %s: expected %d, got %d",
				t.server.URL, expectedWebsocketConns[t.server.URL], t.allWebsocketConns.Load())
		}
	}

	// Log all target request counts after wg.Wait() for debugging
	msgtauschlogger.Info("=== Post-wg.Wait() request counts (nRequestsNotForwarded=%d) ===", nRequestsNotForwarded)
	for _, t := range targets {
		var receivedIDs []string
		t.receivedRequestIDs.Range(func(key, value any) bool {
			receivedIDs = append(receivedIDs, key.(string))
			return true
		})
		sort.Strings(receivedIDs)
		msgtauschlogger.Info("  Target %s: requestCount=%d, expected=%d, receivedIDs=%v",
			t.server.URL, t.getRequestCount(), totalRequests[t.server.URL], receivedIDs)
	}

	// Validate both error counts and request counts
	err = validateRequestCounts(nRequestsNotForwarded, totalRequests, targets)
	if err != nil {
		return nil, err
	}
	err = validateErrorCounts(errCounts, targets, len(forwards))
	if err != nil {
		return nil, err
	}

	msgtauschlogger.Info("=== After validation, before stats collection ===")
	for _, t := range targets {
		msgtauschlogger.Info("  Target %s: requestCount=%d", t.server.URL, t.getRequestCount())
	}

	forwardConnections := map[string]int64{
		"socks5":     0,
		"http-proxy": 0,
	}
	actualForwardsUsed := 0
	for i, socksProxy := range socksProxies {
		connections := socksProxy.acceptedConnections()
		forwardConnections["socks5"] += connections
		if connections == 0 {
			return nil, fmt.Errorf("SOCKS5 forward %d was configured but received no connections", i)
		}
		actualForwardsUsed++
	}
	for i, httpProxy := range msgtauschProxies {
		connections := httpProxy.acceptedConnections()
		forwardConnections["http-proxy"] += connections
		if connections == 0 {
			return nil, fmt.Errorf("HTTP proxy forward %d was configured but received no connections", i)
		}
		actualForwardsUsed++
	}

	simulationStats := &SimulationStats{
		Seed:                   seed,
		TotalRequests:          nRequests,
		RequestsNotForwarded:   nRequestsNotForwarded,
		ForwardedRequests:      nRequests - nRequestsNotForwarded,
		ConfiguredForwards:     usedForwards,
		ForwardsUsed:           actualForwardsUsed,
		ForwardConnections:     forwardConnections,
		HTTPMethodCounts:       httpMethodCounts,
		ProtocolCounts:         protocolCounts,
		ValidatedHTTPResponses: validatedHTTPResponses.Load(),
		WebSocketMessages:      wsMessages.Load(),
		UnrecoverableErrors:    unrecoverableErrorCount.Load(),
		ProxyChainLength:       1,
		ErrorCountsByTarget:    errCounts,
		TargetServerStats:      make([]TargetServerStats, len(targets)),
	}
	if actualForwardsUsed > 0 {
		// A forwarded request traverses the main proxy and one selected upstream.
		simulationStats.ProxyChainLength = 2
	}

	// Collect target server statistics
	var totalWebSockets int64
	var expectedWebSocketTotal int64
	for i, t := range targets {
		simulationStats.TargetServerStats[i] = TargetServerStats{
			URL:                t.server.URL,
			RequestCount:       t.allRequestCount.Load(),
			WebSocketConnCount: t.allWebsocketConns.Load(),
			ErrorCounts:        make(map[SimulationErrorType]int),
		}
		totalWebSockets += t.allWebsocketConns.Load()

		// Collect error counts for this target
		for _, errorType := range []SimulationErrorType{
			ErrorNone, ErrorTCP, ErrorTimeout, ErrorHTTP400, ErrorHTTP501,
		} {
			count := t.getErrorCount(errorType)
			if count > 0 {
				simulationStats.TargetServerStats[i].ErrorCounts[errorType] = count
			}
		}
	}

	for _, count := range expectedWebsocketConns {
		expectedWebSocketTotal += count
	}

	simulationStats.WebSocketConnections = totalWebSockets
	simulationStats.ExpectedWebSocketConns = expectedWebSocketTotal

	// Calculate percentiles from response times
	simulationStats.ResponseTimes = responseTimes
	calculatePercentiles(simulationStats)

	if httpAccounted.Load() != httpAttempts.Load() {
		return simulationStats, fmt.Errorf("http accounting mismatch: attempts %d accounted %d", httpAttempts.Load(), httpAccounted.Load())
	}
	if httpAttempts.Load()+wsAttempts.Load() != int64(nRequests) {
		return simulationStats, fmt.Errorf("request mix mismatch: http %d + ws %d != total %d", httpAttempts.Load(), wsAttempts.Load(), nRequests)
	}

	// Additional invariants on collected stats
	msgtauschlogger.Info("=== Final check (stats collection) ===")
	var sumRequests int64
	for i, tss := range simulationStats.TargetServerStats {
		msgtauschlogger.Info("  Target %s: statsRequestCount=%d, liveRequestCount=%d",
			tss.URL, tss.RequestCount, targets[i].allRequestCount.Load())
		sumRequests += tss.RequestCount
		var sumErrors int
		for _, c := range tss.ErrorCounts {
			sumErrors += c
		}
		if int64(sumErrors) > tss.RequestCount {
			return simulationStats, fmt.Errorf("error/request mismatch for %s: errors %d exceed requests %d", tss.URL, sumErrors, tss.RequestCount)
		}
	}
	if sumRequests != int64(nRequests) {
		return simulationStats, fmt.Errorf("request tally mismatch: targets saw %d requests vs expected %d", sumRequests, nRequests)
	}

	return simulationStats, nil
}

// calculatePercentiles calculates percentile statistics from response times
func calculatePercentiles(stats *SimulationStats) {
	if len(stats.ResponseTimes) == 0 {
		return
	}

	// Sort response times
	sort.Slice(stats.ResponseTimes, func(i, j int) bool {
		return stats.ResponseTimes[i] < stats.ResponseTimes[j]
	})

	n := len(stats.ResponseTimes)

	// Calculate percentiles
	stats.P50 = percentile(stats.ResponseTimes, 50.0)
	stats.P95 = percentile(stats.ResponseTimes, 95.0)
	stats.P99 = percentile(stats.ResponseTimes, 99.0)
	stats.P99_9 = percentile(stats.ResponseTimes, 99.9)
	stats.P99_99 = percentile(stats.ResponseTimes, 99.99)

	// Calculate min, max, avg
	stats.MinResponseTime = stats.ResponseTimes[0]
	stats.MaxResponseTime = stats.ResponseTimes[n-1]

	var sum time.Duration
	for _, rt := range stats.ResponseTimes {
		sum += rt
	}
	stats.AvgResponseTime = sum / time.Duration(n)
}

// percentile calculates the p-th percentile from a sorted slice of durations
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}

	// Use linear interpolation
	index := (p / 100.0) * float64(len(sorted)-1)
	lower := int(index)
	upper := lower + 1

	if upper >= len(sorted) {
		return sorted[len(sorted)-1]
	}

	// Interpolate between lower and upper
	fraction := index - float64(lower)
	lowerVal := float64(sorted[lower])
	upperVal := float64(sorted[upper])
	result := lowerVal + fraction*(upperVal-lowerVal)

	return time.Duration(result)
}

// RunSimulationWithStats runs a simulation and returns detailed statistics along with any error
func RunSimulationWithStats(seed int64, enableForwards bool) (*SimulationStats, error) {
	return runSimulation(seed, enableForwards)
}

func targetServerPort(target *SimulatedTargetServer) int {
	targetURL, err := url.Parse(target.URL())
	if err != nil {
		panic(fmt.Sprintf("invalid simulated target URL %q: %v", target.URL(), err))
	}
	port, err := strconv.Atoi(targetURL.Port())
	if err != nil {
		panic(fmt.Sprintf("invalid simulated target port in %q: %v", target.URL(), err))
	}
	return port
}

func validateSuccessfulHTTPResponse(resp *http.Response, req *http.Request, expectedBody string, requestIndex int) error {
	expectedHeaders := map[string]string{
		"X-Test-Header":    "test-value",
		"X-Request-Method": req.Method,
		"X-Test-ID":        strconv.Itoa(requestIndex),
		"X-Sim-Feature":    req.Header.Get("X-Sim-Feature"),
		"X-Sim-Seed":       req.URL.Query().Get("seed"),
	}
	if req.Method == http.MethodPatch && !strings.Contains(resp.Header.Get("X-Sim-Transfer-Encoding"), "chunked") {
		return fmt.Errorf("request %d PATCH did not arrive with chunked transfer encoding", requestIndex)
	}
	for name, want := range expectedHeaders {
		if got := resp.Header.Get(name); got != want {
			return fmt.Errorf("request %d %s header %s: want %q, got %q", requestIndex, req.Method, name, want, got)
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("request %d %s read response body: %w", requestIndex, req.Method, err)
	}
	if req.Method == http.MethodHead {
		if len(body) != 0 {
			return fmt.Errorf("request %d HEAD returned a body of %d bytes", requestIndex, len(body))
		}
		return nil
	}
	if string(body) != expectedBody {
		return fmt.Errorf("request %d %s body: want %q, got %q", requestIndex, req.Method, expectedBody, body)
	}
	return nil
}

// validateErrorCounts checks that all expected errors were accounted for
func validateErrorCounts(errCounts map[string]map[SimulationErrorType]int, targets []*SimulatedTargetServer, forwardCount int) error {
	// Validate error accounting
	for ti, t := range targets {
		// Iterate through all possible error types
		for _, et := range []SimulationErrorType{ErrorTCP, ErrorTimeout, ErrorHTTP400, ErrorHTTP501} {
			count := t.getErrorCount(et)

			// Skip error types with zero count
			if count == 0 {
				continue
			}

			if isUndetectableError(et, ti < forwardCount) {
				continue
			}
			if _, ok := errCounts[t.server.URL]; !ok {
				errCounts[t.server.URL] = make(map[SimulationErrorType]int)
			}
			if count != errCounts[t.server.URL][et] {
				return fmt.Errorf("error count mismatch for %s on %s: expected %d, got %d", et, t.server.URL, count, errCounts[t.server.URL][et])
			}
		}
	}

	return nil
}

// validateRequestCounts checks that all expected requests were accounted for
func validateRequestCounts(nRequests int, expectedRequests map[string]int, targets []*SimulatedTargetServer) error {
	actualNRequests := 0
	for _, t := range targets {
		expected := expectedRequests[t.server.URL]
		actual := t.getRequestCount()
		actualNRequests += int(actual)

		msgtauschlogger.Debug("Request count for %s: %d actual vs %d expected",
			t.server.URL, actual, expected)

		if actual != int64(expected) {
			msgtauschlogger.Error("Detailed mismatch for %s: server counted %d requests, client expected %d",
				t.server.URL, actual, expected)
			return fmt.Errorf("request count mismatch for %s: expected %d, got %d",
				t.server.URL, expected, actual)
		}
	}

	if actualNRequests != nRequests {
		return fmt.Errorf("request count mismatch: expected %d, got %d", nRequests, actualNRequests)
	}

	return nil
}

// isUndetectableError determines if an error type can be detected through a forward
func isUndetectableError(et SimulationErrorType, usesForward bool) bool {
	if !usesForward {
		return false
	}

	if et == ErrorHTTP400 ||
		et == ErrorHTTP501 {
		return false
	}

	return et == ErrorTCP ||
		et == ErrorTimeout
}

// CreateRandomMsgtauschProxies creates a random number (1-4) of msgtausch proxy servers with random configs and ports.
func CreateRandomMsgtauschProxies(seed int64) []*SimulatedMsgtauschProxy {
	rng := rand.New(rand.NewSource(seed))
	n := 1 + rng.Intn(4) // 1-4 proxies
	proxies := make([]*SimulatedMsgtauschProxy, n)
	for i := range n {
		cfg := &msgtauschconfig.Config{
			Servers: []msgtauschconfig.ServerConfig{
				{
					Type:          msgtauschconfig.ProxyTypeStandard,
					ListenAddress: "127.0.0.1:0",
					Enabled:       true,
				},
			},
			TimeoutSeconds: 10 + rng.Intn(50), // 10-59s
			Classifiers:    make(map[string]msgtauschconfig.Classifier),
			Forwards:       nil, // No forwards for basic simulation
			Allowlist:      nil, // Explicitly set to nil to avoid compilation errors
			Blocklist:      nil, // Explicitly set to nil to avoid compilation errors
		}

		listener, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
		if err != nil {
			msgtauschlogger.Error("Failed to start msgtausch proxy listener on %s: %v", cfg.Servers[0].ListenAddress, err)
			panic(fmt.Sprintf("Failed to start msgtausch proxy listener on %s: %v", cfg.Servers[0].ListenAddress, err))
		}
		port := listener.Addr().(*net.TCPAddr).Port
		cfg.Servers[0].ListenAddress = fmt.Sprintf("127.0.0.1:%d", port)
		proxy := msgtauschproxy.NewProxy(cfg)
		accepted := &atomic.Int64{}
		trackedListener := &countingListener{Listener: listener, accepted: accepted}
		// Create done channel for graceful shutdown
		done := make(chan struct{})

		// Start the proxy in a goroutine with proper cleanup
		go func(p *msgtauschproxy.Proxy, l net.Listener, done chan struct{}) {
			defer close(done)
			err := p.StartWithListener(l)
			if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
				msgtauschlogger.Error("Proxy server exited with error: %v", err)
			}
		}(proxy, trackedListener, done)

		proxies[i] = &SimulatedMsgtauschProxy{
			Port:     port,
			Seed:     rng.Int63(),
			Proxy:    proxy,
			Listener: trackedListener,
			Config:   cfg,
			done:     done,
			accepted: accepted,
		}
	}
	return proxies
}

// CreateRandomSocks5Proxies creates a single simulated SOCKS5 proxy using the provided seed.
func CreateRandomSocks5Proxies(seed int64) []*SimulatedSocks5Proxy {
	rng := rand.New(rand.NewSource(seed))
	n := rng.Intn(3) + 1 // Generate 1-3 proxies
	proxies := make([]*SimulatedSocks5Proxy, n)
	for i := range n {
		addr := "127.0.0.1:0"
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			panic(fmt.Sprintf("Failed to start SOCKS5 listener on %s: %v", addr, err))
		}
		server, err := socks5.New(&socks5.Config{})
		if err != nil {
			if closeErr := listener.Close(); closeErr != nil {
				msgtauschlogger.Error("Error closing listener: %v", closeErr)
			}
			panic(fmt.Sprintf("Failed to create SOCKS5 server: %v", err))
		}
		// Create done channel for graceful shutdown
		done := make(chan struct{})
		accepted := &atomic.Int64{}
		trackedListener := &countingListener{Listener: listener, accepted: accepted}

		// Start the SOCKS5 server in a goroutine with proper cleanup
		go func(s *socks5.Server, l net.Listener, done chan struct{}) {
			defer close(done)
			err := s.Serve(l)
			if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
				msgtauschlogger.Error("SOCKS5 server error: %v", err)
			}
		}(server, trackedListener, done)

		proxies[i] = &SimulatedSocks5Proxy{
			Port:     listener.Addr().(*net.TCPAddr).Port,
			Server:   server,
			Listener: trackedListener,
			done:     done,
			accepted: accepted,
		}
	}
	return proxies
}

// NewSimulatedTargetServer creates a new simulated target server for testing.
func NewSimulatedTargetServer(seed int64) *SimulatedTargetServer {
	rng := rand.New(rand.NewSource(seed))
	sts := &SimulatedTargetServer{
		errorCounts: sync.Map{},
		latencyMs:   rng.Intn(10),
		errorRate:   rng.Float32() * 0.5,
		websocketUpgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				return true // Accept all origins for testing
			},
		},
		websocketConnCount: atomic.Int64{},
		requestCount:       atomic.Int64{},
	}

	// Shared handler for HTTP/HTTPS
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		usesForward := r.Header.Get("X-Sim-Forward") == "true"
		simReqID := r.Header.Get("X-Sim-Req")

		// Check if this is a WebSocket upgrade request
		if websocket.IsWebSocketUpgrade(r) {
			sts.allRequestCount.Add(1)
			sts.allWebsocketConns.Add(1)
			if !usesForward {
				// Increment request counter for each request received
				newCount := sts.requestCount.Add(1)
				sts.receivedRequestIDs.Store(simReqID, true)
				msgtauschlogger.Debug("[TARGET %s] WS request #%d: id=%s forward=%v", sts.server.URL, newCount, simReqID, usesForward)
				// Increment the actual connection counter
				sts.websocketConnCount.Add(1)
			}

			// Handle WebSocket connection
			conn, err := sts.websocketUpgrader.Upgrade(w, r, nil)
			if err != nil {
				msgtauschlogger.Debug("Failed to upgrade WebSocket connection: %v", err)
				return
			}
			defer func() {
				if closeErr := conn.Close(); closeErr != nil {
					msgtauschlogger.Error("Error closing connection: %v", closeErr)
				}
			}()

			// Apply latency
			if sts.latencyMs > 0 {
				time.Sleep(time.Duration(sts.latencyMs) * time.Millisecond)
			}

			// Normal WebSocket echo behavior
			for {
				msgType, msg, err := conn.ReadMessage()
				if err != nil {
					break
				}

				// Echo the message back
				err = conn.WriteMessage(msgType, msg)
				if err != nil {
					break
				}
			}
			return
		}

		// Count ALL requests that reach the server, regardless of what happens next
		sts.allRequestCount.Add(1)
		if !usesForward {
			newCount := sts.requestCount.Add(1)
			sts.receivedRequestIDs.Store(simReqID, true)
			msgtauschlogger.Debug("[TARGET %s] HTTP request #%d: id=%s forward=%v", sts.server.URL, newCount, simReqID, usesForward)
		}

		// Handle regular HTTP request
		// Apply latency
		if sts.latencyMs > 0 {
			time.Sleep(time.Duration(sts.latencyMs) * time.Millisecond)
		}

		tcHeader := r.Header.Get("X-Test-Case")
		var tc SimulationTestCase
		err := json.Unmarshal([]byte(tcHeader), &tc)
		if err != nil {
			msgtauschlogger.Error("Failed to parse test case JSON: %s", tcHeader)
		}

		rng := rand.New(rand.NewSource(tc.Seed))

		// Determine if we should introduce an error
		if !tc.DisableError && rng.Float32() < sts.errorRate {
			// Choose an error type
			errorTypes := []SimulationErrorType{
				ErrorTCP,
				ErrorHTTP400,
				ErrorHTTP501,
			}
			if tc.AllowTimeout {
				errorTypes = append(errorTypes, ErrorTimeout)
			}
			errorType := errorTypes[rng.Intn(len(errorTypes))]
			msgtauschlogger.Debug("Simulating error in %s: %s", sts.server.URL, errorType)

			// Increment error count atomically
			if !usesForward {
				sts.incrementErrorCount(errorType)
			}

			// Simulate the selected error
			switch errorType {
			case ErrorTCP:
				// Abruptly close the connection
				hj, ok := w.(http.Hijacker)
				if !ok {
					msgtauschlogger.Error("Could not create hijacker for tcp connection %s", sts.server.URL)
					http.Error(w, "TCP error simulation not supported", http.StatusInternalServerError)
					return
				}
				conn, _, err := hj.Hijack()
				if err != nil {
					msgtauschlogger.Error("Could not hijack tcp connection %s", sts.server.URL)
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				if closeErr := conn.Close(); closeErr != nil {
					msgtauschlogger.Error("Error closing connection: %v", closeErr)
				}
				return
			case ErrorTimeout:
				// Hijack and close the connection to simulate timeout
				hj, ok := w.(http.Hijacker)
				if !ok {
					msgtauschlogger.Error("Could not create hijacker for timeout simulation %s", sts.server.URL)
					http.Error(w, "Timeout error simulation not supported", http.StatusInternalServerError)
					return
				}
				conn, _, err := hj.Hijack()
				if err != nil {
					msgtauschlogger.Error("Could not hijack connection for timeout %s", sts.server.URL)
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				// Close connection after a short delay to simulate a timeout condition
				go func() {
					time.Sleep(20 * time.Second) // Longer than client timeout
					if closeErr := conn.Close(); closeErr != nil {
						msgtauschlogger.Error("Error closing connection: %v", closeErr)
					}
				}()
				return
			case ErrorHTTP400:
				http.Error(w, "Simulated 400 error", http.StatusBadRequest)
				return
			case ErrorHTTP501:
				http.Error(w, "Simulated 501 error", http.StatusNotImplemented)
				return
			}
		} else {
			// Normal response
			w.Header().Set("X-Test-Header", "test-value")
			w.Header().Set("X-Request-Method", r.Method)
			w.Header().Set("X-Sim-Feature", r.Header.Get("X-Sim-Feature"))
			w.Header().Set("X-Sim-Seed", r.URL.Query().Get("seed"))
			w.Header().Set("X-Sim-Transfer-Encoding", strings.Join(r.TransferEncoding, ","))

			// Extract test case ID from URL if present
			if testIDStr := r.URL.Query().Get("test_id"); testIDStr != "" {
				w.Header().Set("X-Test-ID", testIDStr)
			}

			// Echo request bodies for upload methods and a request-specific token
			// for the remaining methods. The client validates both paths.
			switch r.Method {
			case http.MethodPost, http.MethodPut, http.MethodPatch:
				body, err := io.ReadAll(r.Body)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if _, err := w.Write(body); err != nil {
					log.Printf("Error writing response body: %v", err)
				}
			default:
				if _, err := io.WriteString(w, r.Header.Get("X-Sim-Expected-Response")); err != nil {
					log.Printf("Error writing response: %v", err)
				}
			}
		}
	})

	// Maybe run as HTTPS using provided server certificate
	useTLS := false
	if os.Getenv("SIM_TLS_ENABLE") == "1" {
		// 50% default, overridable via SIM_TLS_PROBABILITY
		prob := 0.5
		if p := os.Getenv("SIM_TLS_PROBABILITY"); p != "" {
			if f, err := strconv.ParseFloat(p, 64); err == nil {
				if f < 0 {
					f = 0
				} else if f > 1 {
					f = 1
				}
				prob = f
			}
		}
		useTLS = rng.Float64() < prob
	}

	if useTLS {
		certPEM := os.Getenv("SIM_TLS_SERVER_CERT_PEM")
		keyPEM := os.Getenv("SIM_TLS_SERVER_KEY_PEM")
		if certPEM != "" && keyPEM != "" {
			server := httptest.NewUnstartedServer(handler)
			pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
			if err == nil {
				server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
				server.StartTLS()
				sts.server = server
				return sts
			}
		}
		// Fallback to Go's built-in TLS server if custom certs missing
		sts.server = httptest.NewTLSServer(handler)
		return sts
	}

	// Plain HTTP server
	sts.server = httptest.NewServer(handler)

	return sts
}

// incrementErrorCount atomically increments the error count for a specific error type
func (s *SimulatedTargetServer) incrementErrorCount(errorType SimulationErrorType) {
	s.errorCountsMu.Lock()
	defer s.errorCountsMu.Unlock()
	value, _ := s.errorCounts.LoadOrStore(errorType, 0)
	count := value.(int)
	s.errorCounts.Store(errorType, count+1)
}

// getErrorCount atomically gets the error count for a specific error type
func (s *SimulatedTargetServer) getErrorCount(errorType SimulationErrorType) int {
	s.errorCountsMu.Lock()
	defer s.errorCountsMu.Unlock()
	value, found := s.errorCounts.Load(errorType)
	if !found {
		return 0
	}
	return value.(int)
}

// getRequestCount returns the total number of requests received by this server
func (s *SimulatedTargetServer) getRequestCount() int64 {
	return s.requestCount.Load()
}

// URL returns the base URL of the simulated target server.
func (s *SimulatedTargetServer) URL() string {
	return s.server.URL
}

// Close shuts down the simulated target server.
func (s *SimulatedTargetServer) Close() {
	s.server.CloseClientConnections()
	s.server.Close()
}
