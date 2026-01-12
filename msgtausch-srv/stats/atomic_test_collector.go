package stats

import (
	"context"
	"sync/atomic"
	"time"
)

// AtomicTestCollector is a lock-free test collector for high-performance testing
type AtomicTestCollector struct {
	// Atomic counters for all statistics
	counters *AtomicCounters

	// Detailed tracking with atomic operations
	connections   atomic.Value // map[int64]*connectionData
	httpRequests  atomic.Value // []httpRequestData
	httpResponses atomic.Value // []httpResponseData
	errors        atomic.Value // []errorData
	security      atomic.Value // []securityEventData

	// Performance tracking
	latencyNanos AtomicInt64Counter
	requestCount AtomicInt64Counter

	// Control flags
	closed AtomicBool
}

// NewAtomicTestCollector creates a new atomic test collector
func NewAtomicTestCollector() *AtomicTestCollector {
	collector := &AtomicTestCollector{
		counters: NewAtomicCounters(),
	}

	// Initialize atomic values
	collector.connections.Store(make(map[int64]*connectionData))
	collector.httpRequests.Store(make([]httpRequestData, 0))
	collector.httpResponses.Store(make([]httpResponseData, 0))
	collector.errors.Store(make([]errorData, 0))
	collector.security.Store(make([]securityEventData, 0))

	return collector
}

// StartConnection records the start of a connection
func (a *AtomicTestCollector) StartConnection(ctx context.Context, clientIP, targetHost string, targetPort int, protocol string) (int64, error) {
	if a.closed.Load() {
		return 0, context.Canceled
	}

	// Generate a simple atomic connection ID
	connectionID := a.counters.TotalConnections.Add(1) + 1000 // Start from 1000 to avoid zero

	// Update counters
	a.counters.ActiveConnections.Add(1)

	// Add to connections map using atomic value
	conns := a.connections.Load().(map[int64]*connectionData)
	newConns := make(map[int64]*connectionData, len(conns)+1)

	// Copy existing connections
	for k, v := range conns {
		newConns[k] = v
	}

	// Add new connection
	newConns[connectionID] = &connectionData{
		connectionUUID: "",
		clientIP:       clientIP,
		targetHost:     targetHost,
		targetPort:     targetPort,
		protocol:       protocol,
		startedAt:      time.Now(),
	}

	a.connections.Store(newConns)

	return connectionID, nil
}

// StartConnectionWithUUID records the start of a connection with a provided UUID
func (a *AtomicTestCollector) StartConnectionWithUUID(ctx context.Context, connectionUUID, clientIP, targetHost string, targetPort int, protocol string) (int64, error) {
	if a.closed.Load() {
		return 0, context.Canceled
	}

	connectionID := a.counters.TotalConnections.Add(1) + 1000
	a.counters.ActiveConnections.Add(1)

	conns := a.connections.Load().(map[int64]*connectionData)
	newConns := make(map[int64]*connectionData, len(conns)+1)

	for k, v := range conns {
		newConns[k] = v
	}

	newConns[connectionID] = &connectionData{
		connectionUUID: connectionUUID,
		clientIP:       clientIP,
		targetHost:     targetHost,
		targetPort:     targetPort,
		protocol:       protocol,
		startedAt:      time.Now(),
	}

	a.connections.Store(newConns)

	return connectionID, nil
}

// EndConnection records the end of a connection
func (a *AtomicTestCollector) EndConnection(ctx context.Context, connectionID, bytesSent, bytesReceived int64, duration time.Duration, closeReason string) error {
	if a.closed.Load() {
		return context.Canceled
	}

	// Update counters
	a.counters.ActiveConnections.Add(-1)
	a.counters.TotalBytesIn.Add(bytesReceived)
	a.counters.TotalBytesOut.Add(bytesSent)

	if closeReason != "normal" {
		a.counters.ConnectionErrors.Add(1)
		a.counters.TotalErrors.Add(1)
	}

	// Remove from connections map
	conns := a.connections.Load().(map[int64]*connectionData)
	if _, exists := conns[connectionID]; exists {
		newConns := make(map[int64]*connectionData, len(conns))
		for k, v := range conns {
			if k != connectionID {
				newConns[k] = v
			}
		}
		a.connections.Store(newConns)
	}

	return nil
}

// RecordHTTPRequest records an HTTP request
func (a *AtomicTestCollector) RecordHTTPRequest(ctx context.Context, connectionID int64, method, url, host, userAgent string, contentLength int64) error {
	if a.closed.Load() {
		return context.Canceled
	}

	// Update counters
	a.counters.TotalRequests.Add(1)
	a.counters.TotalBytesIn.Add(contentLength)

	// Buffer the request
	requests := a.httpRequests.Load().([]httpRequestData)
	newRequests := make([]httpRequestData, len(requests)+1)
	copy(newRequests, requests)

	newRequests[len(requests)] = httpRequestData{
		connectionID:  connectionID,
		method:        method,
		url:           url,
		host:          host,
		userAgent:     userAgent,
		contentLength: contentLength,
		headerSize:    0,
		timestamp:     time.Now(),
	}

	a.httpRequests.Store(newRequests)

	return nil
}

// RecordHTTPResponse records an HTTP response
func (a *AtomicTestCollector) RecordHTTPResponse(ctx context.Context, connectionID int64, statusCode int, contentLength int64) error {
	if a.closed.Load() {
		return context.Canceled
	}

	// Update counters
	a.counters.TotalBytesOut.Add(contentLength)

	if statusCode >= 400 {
		a.counters.HTTPErrors.Add(1)
		a.counters.TotalErrors.Add(1)
	}

	// Buffer the response
	responses := a.httpResponses.Load().([]httpResponseData)
	newResponses := make([]httpResponseData, len(responses)+1)
	copy(newResponses, responses)

	newResponses[len(responses)] = httpResponseData{
		connectionID:  connectionID,
		statusCode:    statusCode,
		contentLength: contentLength,
		headerSize:    0,
		timestamp:     time.Now(),
	}

	a.httpResponses.Store(newResponses)

	return nil
}

// RecordHTTPRequestWithHeaders records an HTTP request including header size
func (a *AtomicTestCollector) RecordHTTPRequestWithHeaders(ctx context.Context, connectionID int64, method, url, host, userAgent string, contentLength, headerSize int64) error {
	if a.closed.Load() {
		return context.Canceled
	}

	// Update counters
	a.counters.TotalRequests.Add(1)
	a.counters.TotalBytesIn.Add(contentLength + headerSize)

	// Buffer the request
	requests := a.httpRequests.Load().([]httpRequestData)
	newRequests := make([]httpRequestData, len(requests)+1)
	copy(newRequests, requests)

	newRequests[len(requests)] = httpRequestData{
		connectionID:  connectionID,
		method:        method,
		url:           url,
		host:          host,
		userAgent:     userAgent,
		contentLength: contentLength,
		headerSize:    headerSize,
		timestamp:     time.Now(),
	}

	a.httpRequests.Store(newRequests)

	return nil
}

// RecordHTTPResponseWithHeaders records an HTTP response including header size
func (a *AtomicTestCollector) RecordHTTPResponseWithHeaders(ctx context.Context, connectionID int64, statusCode int, contentLength, headerSize int64) error {
	if a.closed.Load() {
		return context.Canceled
	}

	// Update counters
	a.counters.TotalBytesOut.Add(contentLength + headerSize)

	if statusCode >= 400 {
		a.counters.HTTPErrors.Add(1)
		a.counters.TotalErrors.Add(1)
	}

	// Buffer the response
	responses := a.httpResponses.Load().([]httpResponseData)
	newResponses := make([]httpResponseData, len(responses)+1)
	copy(newResponses, responses)

	newResponses[len(responses)] = httpResponseData{
		connectionID:  connectionID,
		statusCode:    statusCode,
		contentLength: contentLength,
		headerSize:    headerSize,
		timestamp:     time.Now(),
	}

	a.httpResponses.Store(newResponses)

	return nil
}

// RecordError records an error
func (a *AtomicTestCollector) RecordError(ctx context.Context, connectionID int64, errorType, errorMessage string) error {
	if a.closed.Load() {
		return context.Canceled
	}

	// Update counters
	a.counters.TotalErrors.Add(1)

	// Buffer the error
	errors := a.errors.Load().([]errorData)
	newErrors := make([]errorData, len(errors)+1)
	copy(newErrors, errors)

	newErrors[len(errors)] = errorData{
		connectionID: connectionID,
		errorType:    errorType,
		errorMessage: errorMessage,
		timestamp:    time.Now(),
	}

	a.errors.Store(newErrors)

	return nil
}

// RecordDataTransfer records data transfer
func (a *AtomicTestCollector) RecordDataTransfer(ctx context.Context, connectionID, bytesSent, bytesReceived int64) error {
	if a.closed.Load() {
		return context.Canceled
	}

	// Update counters
	a.counters.TotalBytesIn.Add(bytesReceived)
	a.counters.TotalBytesOut.Add(bytesSent)
	a.counters.DataTransferEvents.Add(1)

	return nil
}

// RecordBlockedRequest records a blocked request
func (a *AtomicTestCollector) RecordBlockedRequest(ctx context.Context, clientIP, targetHost, reason string) error {
	if a.closed.Load() {
		return context.Canceled
	}

	// Update counters
	a.counters.BlockedRequests.Add(1)

	// Buffer the security event
	security := a.security.Load().([]securityEventData)
	newSecurity := make([]securityEventData, len(security)+1)
	copy(newSecurity, security)

	newSecurity[len(security)] = securityEventData{
		clientIP:   clientIP,
		targetHost: targetHost,
		eventType:  "blocked",
		reason:     reason,
		timestamp:  time.Now(),
	}

	a.security.Store(newSecurity)

	return nil
}

// RecordAllowedRequest records an allowed request
func (a *AtomicTestCollector) RecordAllowedRequest(ctx context.Context, clientIP, targetHost string) error {
	if a.closed.Load() {
		return context.Canceled
	}

	// Update counters
	a.counters.AllowedRequests.Add(1)

	// Buffer the security event
	security := a.security.Load().([]securityEventData)
	newSecurity := make([]securityEventData, len(security)+1)
	copy(newSecurity, security)

	newSecurity[len(security)] = securityEventData{
		clientIP:   clientIP,
		targetHost: targetHost,
		eventType:  "allowed",
		timestamp:  time.Now(),
	}

	a.security.Store(newSecurity)

	return nil
}

// RecordLatency records request latency in nanoseconds
func (a *AtomicTestCollector) RecordLatency(nanoseconds int64) {
	a.latencyNanos.Add(nanoseconds)
	a.requestCount.Add(1)
}

// GetOverviewStats returns overview statistics
func (a *AtomicTestCollector) GetOverviewStats(ctx context.Context) (*OverviewStats, error) {
	snapshot := a.counters.Snapshot()

	return &OverviewStats{
		TotalConnections:  snapshot.TotalConnections,
		ActiveConnections: snapshot.ActiveConnections,
		TotalRequests:     snapshot.TotalRequests,
		TotalErrors:       snapshot.TotalErrors,
		BlockedRequests:   snapshot.BlockedRequests,
		AllowedRequests:   snapshot.AllowedRequests,
		TotalBytesIn:      snapshot.TotalBytesIn,
		TotalBytesOut:     snapshot.TotalBytesOut,
		Uptime:            "0s", // Test collector doesn't track uptime
	}, nil
}

// GetAtomicSnapshot returns a snapshot of all atomic counters
func (a *AtomicTestCollector) GetAtomicSnapshot() CounterSnapshot {
	return a.counters.Snapshot()
}

// GetLatencyStats returns latency statistics
func (a *AtomicTestCollector) GetLatencyStats() LatencyStats {
	totalLatency := a.latencyNanos.Load()
	requestCount := a.requestCount.Load()

	if requestCount == 0 {
		return LatencyStats{}
	}

	return LatencyStats{
		AverageNanos: totalLatency / requestCount,
	}
}

// Reset resets all counters and buffered data
func (a *AtomicTestCollector) Reset() {
	// Reset counters
	a.counters.ResetAll()
	a.latencyNanos.Store(0)
	a.requestCount.Store(0)

	// Reset buffered data
	a.connections.Store(make(map[int64]*connectionData))
	a.httpRequests.Store(make([]httpRequestData, 0))
	a.httpResponses.Store(make([]httpResponseData, 0))
	a.errors.Store(make([]errorData, 0))
	a.security.Store(make([]securityEventData, 0))
}

// Stub implementations for other required interface methods
func (a *AtomicTestCollector) RecordFullHTTPRequest(ctx context.Context, connectionID int64, method, url, host, userAgent string,
	requestHeaders map[string][]string, requestBody []byte, timestamp time.Time) error {
	return nil // Not implemented for test collector
}

func (a *AtomicTestCollector) RecordFullHTTPResponse(ctx context.Context, connectionID int64, statusCode int,
	responseHeaders map[string][]string, responseBody []byte, timestamp time.Time) error {
	return nil // Not implemented for test collector
}

func (a *AtomicTestCollector) GetTopDomains(ctx context.Context, limit int) ([]DomainStats, error) {
	return []DomainStats{}, nil // Not implemented for test collector
}

func (a *AtomicTestCollector) GetSecurityEvents(ctx context.Context, limit int) ([]SecurityEventInfo, error) {
	return []SecurityEventInfo{}, nil // Not implemented for test collector
}

func (a *AtomicTestCollector) GetRecentErrors(ctx context.Context, limit int) ([]ErrorSummary, error) {
	return []ErrorSummary{}, nil // Not implemented for test collector
}

func (a *AtomicTestCollector) GetBandwidthStats(ctx context.Context, days int) (*BandwidthStats, error) {
	return &BandwidthStats{}, nil // Not implemented for test collector
}

func (a *AtomicTestCollector) GetSystemStats(ctx context.Context) (*SystemStats, error) {
	return &SystemStats{}, nil // Not implemented for test collector
}

func (a *AtomicTestCollector) HealthCheck(ctx context.Context) error {
	if a.closed.Load() {
		return context.Canceled
	}
	return nil
}

func (a *AtomicTestCollector) Close() error {
	a.closed.Set(true)
	return nil
}
