package stats

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
)

// AtomicBufferedCollector implements Collector with lock-free operations for hot paths
type AtomicBufferedCollector struct {
	underlying Collector
	interval   time.Duration
	flushMu    sync.Mutex

	// Atomic counters for frequently accessed metrics
	counters *AtomicCounters

	// Buffer management with lock-free access patterns
	buffer struct {
		pendingConnections   atomic.Value // map[int64]*connectionData
		completedConnections []completedConnectionData
		httpRequests         []httpRequestData
		httpResponses        []httpResponseData
		errors               []errorData
		dataTransfers        []dataTransferData
		security             []securityEventData
		mu                   sync.RWMutex
		pendingMu            sync.Mutex
		bufferFull           AtomicBool
	}

	stopChan chan struct{}
	doneChan chan struct{}
	wg       sync.WaitGroup
}

// NewAtomicBufferedCollector creates a new atomic buffered collector
func NewAtomicBufferedCollector(underlying Collector) *AtomicBufferedCollector {
	return NewAtomicBufferedCollectorWithInterval(underlying, 5*time.Minute)
}

// NewAtomicBufferedCollectorWithInterval creates an atomic buffered collector with custom interval
func NewAtomicBufferedCollectorWithInterval(underlying Collector, interval time.Duration) *AtomicBufferedCollector {
	if interval == 0 {
		interval = 5 * time.Second
	}

	abc := &AtomicBufferedCollector{
		underlying: underlying,
		interval:   interval,
		counters:   NewAtomicCounters(),
		stopChan:   make(chan struct{}),
		doneChan:   make(chan struct{}),
	}

	// Initialize atomic value for pending connections
	pendingConns := make(map[int64]*connectionData)
	abc.buffer.pendingConnections.Store(pendingConns)

	// Pre-allocate slices with reasonable capacities
	abc.buffer.completedConnections = make([]completedConnectionData, 0, 1000)
	abc.buffer.httpRequests = make([]httpRequestData, 0, 1000)
	abc.buffer.httpResponses = make([]httpResponseData, 0, 1000)
	abc.buffer.errors = make([]errorData, 0, 100)
	abc.buffer.dataTransfers = make([]dataTransferData, 0, 1000)
	abc.buffer.security = make([]securityEventData, 0, 100)

	abc.wg.Add(1)
	go abc.flusher()

	return abc
}

// flusher runs in the background and flushes data every interval
func (a *AtomicBufferedCollector) flusher() {
	defer a.wg.Done()
	defer close(a.doneChan)

	logger.Debug("Starting atomic buffered stats flusher %s", a.interval)

	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.flush()
		case <-a.stopChan:
			a.flush()
			return
		}
	}
}

// StartConnection records the start of a connection with atomic operations
func (a *AtomicBufferedCollector) StartConnection(ctx context.Context, clientIP, targetHost string, targetPort int, protocol string) (int64, error) {
	// Use underlying collector for stable connection ID
	connectionID, err := a.underlying.StartConnection(ctx, clientIP, targetHost, targetPort, protocol)
	if err != nil {
		return 0, err
	}

	// Update atomic counters
	a.counters.TotalConnections.Add(1)
	a.counters.ActiveConnections.Add(1)

	// Serialize copy-on-write map updates. atomic.Value makes publishing a map
	// safe, but a read-copy-store sequence is not atomic by itself.
	a.buffer.pendingMu.Lock()
	defer a.buffer.pendingMu.Unlock()
	pendingConns := a.buffer.pendingConnections.Load().(map[int64]*connectionData)
	newPendingConns := make(map[int64]*connectionData, len(pendingConns)+1)

	// Copy existing connections
	for k, v := range pendingConns {
		newPendingConns[k] = v
	}

	// Add new connection
	newPendingConns[connectionID] = &connectionData{
		connectionUUID: "",
		clientIP:       clientIP,
		targetHost:     targetHost,
		targetPort:     targetPort,
		protocol:       protocol,
		startedAt:      time.Now(),
	}

	a.buffer.pendingConnections.Store(newPendingConns)

	return connectionID, nil
}

// StartConnectionWithUUID records the start of a connection with a provided UUID
func (a *AtomicBufferedCollector) StartConnectionWithUUID(ctx context.Context, connectionUUID, clientIP, targetHost string, targetPort int, protocol string) (int64, error) {
	connectionID, err := a.underlying.StartConnectionWithUUID(ctx, connectionUUID, clientIP, targetHost, targetPort, protocol)
	if err != nil {
		return 0, err
	}

	// Update atomic counters
	a.counters.TotalConnections.Add(1)
	a.counters.ActiveConnections.Add(1)

	a.buffer.pendingMu.Lock()
	defer a.buffer.pendingMu.Unlock()
	pendingConns := a.buffer.pendingConnections.Load().(map[int64]*connectionData)
	newPendingConns := make(map[int64]*connectionData, len(pendingConns)+1)

	// Copy existing connections
	for k, v := range pendingConns {
		newPendingConns[k] = v
	}

	// Add new connection
	newPendingConns[connectionID] = &connectionData{
		connectionUUID: connectionUUID,
		clientIP:       clientIP,
		targetHost:     targetHost,
		targetPort:     targetPort,
		protocol:       protocol,
		startedAt:      time.Now(),
	}

	a.buffer.pendingConnections.Store(newPendingConns)

	return connectionID, nil
}

// EndConnection records the end of a connection with atomic operations
func (a *AtomicBufferedCollector) EndConnection(ctx context.Context, connectionID, bytesSent, bytesReceived int64, duration time.Duration, closeReason string) error {
	// Move from pending to completed with a serialized copy-on-write update.
	a.buffer.pendingMu.Lock()
	pendingConns := a.buffer.pendingConnections.Load().(map[int64]*connectionData)
	conn, exists := pendingConns[connectionID]
	if !exists {
		a.buffer.pendingMu.Unlock()
		return nil
	}
	newPendingConns := make(map[int64]*connectionData, len(pendingConns)-1)
	for k, v := range pendingConns {
		if k != connectionID {
			newPendingConns[k] = v
		}
	}
	a.buffer.pendingConnections.Store(newPendingConns)
	a.buffer.pendingMu.Unlock()

	a.counters.ActiveConnections.Add(-1)
	a.counters.TotalBytesIn.Add(bytesReceived)
	a.counters.TotalBytesOut.Add(bytesSent)
	if closeReason != "normal" {
		a.counters.ConnectionErrors.Add(1)
		a.counters.TotalErrors.Add(1)
	}

	a.buffer.mu.Lock()
	a.buffer.completedConnections = append(a.buffer.completedConnections, completedConnectionData{
		connectionID:   connectionID,
		connectionUUID: conn.connectionUUID,
		clientIP:       conn.clientIP,
		targetHost:     conn.targetHost,
		targetPort:     conn.targetPort,
		protocol:       conn.protocol,
		startedAt:      conn.startedAt,
		endedAt:        time.Now(),
		bytesSent:      bytesSent,
		bytesReceived:  bytesReceived,
		duration:       duration,
		closeReason:    closeReason,
	})
	a.buffer.mu.Unlock()

	return nil
}

// RecordHTTPRequest records an HTTP request with atomic operations
func (a *AtomicBufferedCollector) RecordHTTPRequest(ctx context.Context, connectionID int64, method, url, host, userAgent string, contentLength int64) error {
	// Update atomic counters
	a.counters.TotalRequests.Add(1)
	a.counters.TotalBytesIn.Add(contentLength)

	// Buffer the request details
	a.buffer.mu.Lock()
	a.buffer.httpRequests = append(a.buffer.httpRequests, httpRequestData{
		connectionID:  connectionID,
		method:        method,
		url:           url,
		host:          host,
		userAgent:     userAgent,
		contentLength: contentLength,
		headerSize:    0, // Default to 0 for backward compatibility
		timestamp:     time.Now(),
	})
	a.buffer.mu.Unlock()

	return nil
}

// RecordHTTPResponse records an HTTP response with atomic operations
func (a *AtomicBufferedCollector) RecordHTTPResponse(ctx context.Context, connectionID int64, statusCode int, contentLength int64) error {
	// Update atomic counters
	a.counters.TotalBytesOut.Add(contentLength)

	// Track HTTP errors
	if statusCode >= 400 {
		a.counters.HTTPErrors.Add(1)
		a.counters.TotalErrors.Add(1)
	}

	// Buffer the response details
	a.buffer.mu.Lock()
	a.buffer.httpResponses = append(a.buffer.httpResponses, httpResponseData{
		connectionID:  connectionID,
		statusCode:    statusCode,
		contentLength: contentLength,
		headerSize:    0, // Default to 0 for backward compatibility
		timestamp:     time.Now(),
	})
	a.buffer.mu.Unlock()

	return nil
}

// RecordHTTPRequestWithHeaders records an HTTP request including header size
func (a *AtomicBufferedCollector) RecordHTTPRequestWithHeaders(ctx context.Context, connectionID int64, method, url, host, userAgent string, contentLength, headerSize int64) error {
	// Update atomic counters
	a.counters.TotalRequests.Add(1)
	a.counters.TotalBytesIn.Add(contentLength + headerSize)

	// Buffer the request details
	a.buffer.mu.Lock()
	a.buffer.httpRequests = append(a.buffer.httpRequests, httpRequestData{
		connectionID:  connectionID,
		method:        method,
		url:           url,
		host:          host,
		userAgent:     userAgent,
		contentLength: contentLength,
		headerSize:    headerSize,
		timestamp:     time.Now(),
	})
	a.buffer.mu.Unlock()

	return nil
}

// RecordHTTPResponseWithHeaders records an HTTP response including header size
func (a *AtomicBufferedCollector) RecordHTTPResponseWithHeaders(ctx context.Context, connectionID int64, statusCode int, contentLength, headerSize int64) error {
	// Update atomic counters
	a.counters.TotalBytesOut.Add(contentLength + headerSize)

	// Track HTTP errors
	if statusCode >= 400 {
		a.counters.HTTPErrors.Add(1)
		a.counters.TotalErrors.Add(1)
	}

	// Buffer the response details
	a.buffer.mu.Lock()
	a.buffer.httpResponses = append(a.buffer.httpResponses, httpResponseData{
		connectionID:  connectionID,
		statusCode:    statusCode,
		contentLength: contentLength,
		headerSize:    headerSize,
		timestamp:     time.Now(),
	})
	a.buffer.mu.Unlock()

	return nil
}

// RecordError records an error with atomic operations
func (a *AtomicBufferedCollector) RecordError(ctx context.Context, connectionID int64, errorType, errorMessage string) error {
	// Update atomic counters
	a.counters.TotalErrors.Add(1)

	// Buffer the error details
	a.buffer.mu.Lock()
	a.buffer.errors = append(a.buffer.errors, errorData{
		connectionID: connectionID,
		errorType:    errorType,
		errorMessage: errorMessage,
		timestamp:    time.Now(),
	})
	a.buffer.mu.Unlock()

	return nil
}

// RecordDataTransfer records data transfer with atomic operations
func (a *AtomicBufferedCollector) RecordDataTransfer(ctx context.Context, connectionID, bytesSent, bytesReceived int64) error {
	// Update atomic counters
	a.counters.TotalBytesIn.Add(bytesReceived)
	a.counters.TotalBytesOut.Add(bytesSent)
	a.counters.DataTransferEvents.Add(1)

	// Buffer the data transfer details
	a.buffer.mu.Lock()
	a.buffer.dataTransfers = append(a.buffer.dataTransfers, dataTransferData{
		connectionID:  connectionID,
		bytesSent:     bytesSent,
		bytesReceived: bytesReceived,
		timestamp:     time.Now(),
	})
	a.buffer.mu.Unlock()

	return nil
}

// RecordBlockedRequest records a blocked request with atomic operations
func (a *AtomicBufferedCollector) RecordBlockedRequest(ctx context.Context, clientIP, targetHost, reason string) error {
	// Update atomic counters
	a.counters.BlockedRequests.Add(1)

	// Buffer the security event
	a.buffer.mu.Lock()
	a.buffer.security = append(a.buffer.security, securityEventData{
		clientIP:   clientIP,
		targetHost: targetHost,
		eventType:  "blocked",
		reason:     reason,
		timestamp:  time.Now(),
	})
	a.buffer.mu.Unlock()

	return nil
}

// RecordAllowedRequest records an allowed request with atomic operations
func (a *AtomicBufferedCollector) RecordAllowedRequest(ctx context.Context, clientIP, targetHost string) error {
	// Update atomic counters
	a.counters.AllowedRequests.Add(1)

	// Buffer the security event
	a.buffer.mu.Lock()
	a.buffer.security = append(a.buffer.security, securityEventData{
		clientIP:   clientIP,
		targetHost: targetHost,
		eventType:  "allowed",
		timestamp:  time.Now(),
	})
	a.buffer.mu.Unlock()

	return nil
}

// GetOverviewStats returns overview statistics using atomic counters
func (a *AtomicBufferedCollector) GetOverviewStats(ctx context.Context) (*OverviewStats, error) {
	// Get snapshot of atomic counters
	snapshot := a.counters.Snapshot()

	// Get system stats from underlying collector
	systemStats, err := a.underlying.GetSystemStats(ctx)
	if err != nil {
		return nil, err
	}

	return &OverviewStats{
		TotalConnections:  snapshot.TotalConnections,
		ActiveConnections: snapshot.ActiveConnections,
		TotalRequests:     snapshot.TotalRequests,
		TotalErrors:       snapshot.TotalErrors,
		BlockedRequests:   snapshot.BlockedRequests,
		AllowedRequests:   snapshot.AllowedRequests,
		TotalBytesIn:      snapshot.TotalBytesIn,
		TotalBytesOut:     snapshot.TotalBytesOut,
		Uptime:            time.Duration(systemStats.UptimeSeconds * int64(time.Second)).String(),
	}, nil
}

// Delegate methods to underlying collector for complex operations
func (a *AtomicBufferedCollector) RecordFullHTTPRequest(ctx context.Context, connectionID int64, method, url, host, userAgent string,
	requestHeaders map[string][]string, requestBody []byte, timestamp time.Time) error {
	return a.underlying.RecordFullHTTPRequest(ctx, connectionID, method, url, host, userAgent, requestHeaders, requestBody, timestamp)
}

func (a *AtomicBufferedCollector) RecordFullHTTPResponse(ctx context.Context, connectionID int64, statusCode int,
	responseHeaders map[string][]string, responseBody []byte, timestamp time.Time) error {
	return a.underlying.RecordFullHTTPResponse(ctx, connectionID, statusCode, responseHeaders, responseBody, timestamp)
}

func (a *AtomicBufferedCollector) GetTopDomains(ctx context.Context, limit int) ([]DomainStats, error) {
	return a.underlying.GetTopDomains(ctx, limit)
}

func (a *AtomicBufferedCollector) GetSecurityEvents(ctx context.Context, limit int) ([]SecurityEventInfo, error) {
	return a.underlying.GetSecurityEvents(ctx, limit)
}

func (a *AtomicBufferedCollector) GetRecentErrors(ctx context.Context, limit int) ([]ErrorSummary, error) {
	return a.underlying.GetRecentErrors(ctx, limit)
}

func (a *AtomicBufferedCollector) GetBandwidthStats(ctx context.Context, days int) (*BandwidthStats, error) {
	return a.underlying.GetBandwidthStats(ctx, days)
}

func (a *AtomicBufferedCollector) GetSystemStats(ctx context.Context) (*SystemStats, error) {
	return a.underlying.GetSystemStats(ctx)
}

func (a *AtomicBufferedCollector) HealthCheck(ctx context.Context) error {
	return a.underlying.HealthCheck(ctx)
}

// flush writes all buffered data to the underlying collector
func (a *AtomicBufferedCollector) flush() {
	a.flushMu.Lock()
	defer a.flushMu.Unlock()

	a.buffer.mu.Lock()

	sumStats := len(a.buffer.completedConnections) +
		len(a.buffer.httpRequests) +
		len(a.buffer.httpResponses) +
		len(a.buffer.errors) +
		len(a.buffer.dataTransfers) +
		len(a.buffer.security)

	if sumStats == 0 {
		a.buffer.mu.Unlock()
		return
	}

	completedConnections := a.buffer.completedConnections
	httpRequests := a.buffer.httpRequests
	httpResponses := a.buffer.httpResponses
	errorsToFlush := a.buffer.errors
	dataTransfers := a.buffer.dataTransfers
	securityEvents := a.buffer.security
	a.buffer.completedConnections = make([]completedConnectionData, 0, max(1000, cap(completedConnections)))
	a.buffer.httpRequests = make([]httpRequestData, 0, max(1000, cap(httpRequests)))
	a.buffer.httpResponses = make([]httpResponseData, 0, max(1000, cap(httpResponses)))
	a.buffer.errors = make([]errorData, 0, max(100, cap(errorsToFlush)))
	a.buffer.dataTransfers = make([]dataTransferData, 0, max(1000, cap(dataTransfers)))
	a.buffer.security = make([]securityEventData, 0, max(100, cap(securityEvents)))
	a.buffer.mu.Unlock()

	logger.Debug("Flushing atomic buffered stats data %d", sumStats)

	ctx := context.Background()

	// Process HTTP requests
	for _, req := range httpRequests {
		if req.headerSize > 0 {
			if err := a.underlying.RecordHTTPRequestWithHeaders(ctx, req.connectionID, req.method, req.url, req.host, req.userAgent, req.contentLength, req.headerSize); err != nil {
				_ = err
			}
		} else {
			if err := a.underlying.RecordHTTPRequest(ctx, req.connectionID, req.method, req.url, req.host, req.userAgent, req.contentLength); err != nil {
				_ = err
			}
		}
	}

	// Process HTTP responses
	for _, resp := range httpResponses {
		if resp.headerSize > 0 {
			if err := a.underlying.RecordHTTPResponseWithHeaders(ctx, resp.connectionID, resp.statusCode, resp.contentLength, resp.headerSize); err != nil {
				_ = err
			}
		} else {
			if err := a.underlying.RecordHTTPResponse(ctx, resp.connectionID, resp.statusCode, resp.contentLength); err != nil {
				_ = err
			}
		}
	}

	// Process other buffered data (errors, data transfers, security events)
	for _, errData := range errorsToFlush {
		if err := a.underlying.RecordError(ctx, errData.connectionID, errData.errorType, errData.errorMessage); err != nil {
			_ = err
		}
	}

	for _, dt := range dataTransfers {
		if err := a.underlying.RecordDataTransfer(ctx, dt.connectionID, dt.bytesSent, dt.bytesReceived); err != nil {
			_ = err
		}
	}

	for _, event := range securityEvents {
		if event.eventType == "blocked" {
			if err := a.underlying.RecordBlockedRequest(ctx, event.clientIP, event.targetHost, event.reason); err != nil {
				_ = err
			}
		} else {
			if err := a.underlying.RecordAllowedRequest(ctx, event.clientIP, event.targetHost); err != nil {
				_ = err
			}
		}
	}

	// Final totals overwrite previously flushed deltas, avoiding double counts.
	for i := range completedConnections {
		conn := &completedConnections[i]
		if err := a.underlying.EndConnection(ctx, conn.connectionID, conn.bytesSent, conn.bytesReceived, conn.duration, conn.closeReason); err != nil {
			logger.Error("Failed to flush completed connection %d: %v", conn.connectionID, err)
		}
	}
}

// Close stops the flusher and writes any remaining data
func (a *AtomicBufferedCollector) Close() error {
	close(a.stopChan)
	a.wg.Wait()
	return a.underlying.Close()
}

// ForceFlush immediately flushes all buffered data
func (a *AtomicBufferedCollector) ForceFlush() {
	a.flush()
}

// GetAtomicCounters returns a snapshot of the atomic counters
func (a *AtomicBufferedCollector) GetAtomicCounters() CounterSnapshot {
	return a.counters.Snapshot()
}
