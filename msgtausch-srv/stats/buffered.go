package stats

import (
	"context"
	"sync"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
)

// BufferedCollector implements Collector with 5-minute batching
type BufferedCollector struct {
	underlying Collector
	interval   time.Duration

	buffer struct {
		pendingConnections   map[int64]*connectionData
		completedConnections []completedConnectionData
		httpRequests         []httpRequestData
		httpResponses        []httpResponseData
		errors               []errorData
		dataTransfers        []dataTransferData
		security             []securityEventData
		mu                   sync.RWMutex
	}

	stopChan chan struct{}
	doneChan chan struct{}
	wg       sync.WaitGroup
}

type connectionData struct {
	clientIP   string
	targetHost string
	targetPort int
	protocol   string
	startedAt  time.Time
}

type completedConnectionData struct {
	connectionID  int64
	clientIP      string
	targetHost    string
	targetPort    int
	protocol      string
	startedAt     time.Time
	endedAt       time.Time
	bytesSent     int64
	bytesReceived int64
	duration      time.Duration
	closeReason   string
}

type httpRequestData struct {
	connectionID  int64
	method        string
	url           string
	host          string
	userAgent     string
	contentLength int64
	headerSize    int64
	timestamp     time.Time
}

type httpResponseData struct {
	connectionID  int64
	statusCode    int
	contentLength int64
	headerSize    int64
	timestamp     time.Time
}

type errorData struct {
	connectionID int64
	errorType    string
	errorMessage string
	timestamp    time.Time
}

type dataTransferData struct {
	connectionID  int64
	bytesSent     int64
	bytesReceived int64
	timestamp     time.Time
}

type securityEventData struct {
	clientIP   string
	targetHost string
	eventType  string
	reason     string
	timestamp  time.Time
}

// NewBufferedCollector creates a new buffered collector with 5-minute batching
func NewBufferedCollector(underlying Collector) *BufferedCollector {
	return NewBufferedCollectorWithInterval(underlying, 5*time.Minute)
}

// NewBufferedCollectorWithInterval creates a buffered collector with custom interval
func NewBufferedCollectorWithInterval(underlying Collector, interval time.Duration) *BufferedCollector {
	if interval == 0 {
		interval = 5 * time.Second
	}

	bc := &BufferedCollector{
		underlying: underlying,
		interval:   interval,
		stopChan:   make(chan struct{}),
		doneChan:   make(chan struct{}),
	}

	bc.buffer.pendingConnections = make(map[int64]*connectionData)
	bc.buffer.completedConnections = make([]completedConnectionData, 0, 1000)
	bc.buffer.httpRequests = make([]httpRequestData, 0, 1000)
	bc.buffer.httpResponses = make([]httpResponseData, 0, 1000)
	bc.buffer.errors = make([]errorData, 0, 100)
	bc.buffer.dataTransfers = make([]dataTransferData, 0, 1000)
	bc.buffer.security = make([]securityEventData, 0, 100)

	bc.wg.Add(1)
	go bc.flusher()

	return bc
}

// flusher runs in the background and flushes data every 5 minutes
func (b *BufferedCollector) flusher() {
	defer b.wg.Done()
	defer close(b.doneChan)

	logger.Debug("Starting buffered stats flusher %s", b.interval)

	ticker := time.NewTicker(b.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			b.flush()
		case <-b.stopChan:
			b.flush()
			return
		}
	}
}

// StartConnection records the start of a connection
func (b *BufferedCollector) StartConnection(ctx context.Context, clientIP, targetHost string, targetPort int, protocol string) (int64, error) {
	// For buffered collector, we need to use the underlying collector to get proper IDs
	// but we'll buffer the actual write
	connectionID, err := b.underlying.StartConnection(ctx, clientIP, targetHost, targetPort, protocol)
	if err != nil {
		return 0, err
	}

	b.buffer.mu.Lock()
	defer b.buffer.mu.Unlock()

	b.buffer.pendingConnections[connectionID] = &connectionData{
		clientIP:   clientIP,
		targetHost: targetHost,
		targetPort: targetPort,
		protocol:   protocol,
		startedAt:  time.Now(),
	}

	return connectionID, nil
}

// EndConnection records the end of a connection
func (b *BufferedCollector) EndConnection(ctx context.Context, connectionID, bytesSent, bytesReceived int64, duration time.Duration, closeReason string) error {
	b.buffer.mu.Lock()
	defer b.buffer.mu.Unlock()

	if conn, exists := b.buffer.pendingConnections[connectionID]; exists {
		b.buffer.completedConnections = append(b.buffer.completedConnections, completedConnectionData{
			connectionID:  connectionID,
			clientIP:      conn.clientIP,
			targetHost:    conn.targetHost,
			targetPort:    conn.targetPort,
			protocol:      conn.protocol,
			startedAt:     conn.startedAt,
			endedAt:       time.Now(),
			bytesSent:     bytesSent,
			bytesReceived: bytesReceived,
			duration:      duration,
			closeReason:   closeReason,
		})
		delete(b.buffer.pendingConnections, connectionID)
	}

	return nil
}

// RecordHTTPRequest records an HTTP request
func (b *BufferedCollector) RecordHTTPRequest(ctx context.Context, connectionID int64, method, url, host, userAgent string, contentLength int64) error {
	b.buffer.mu.Lock()
	defer b.buffer.mu.Unlock()

	b.buffer.httpRequests = append(b.buffer.httpRequests, httpRequestData{
		connectionID:  connectionID,
		method:        method,
		url:           url,
		host:          host,
		userAgent:     userAgent,
		contentLength: contentLength,
		headerSize:    0, // Default to 0 for backward compatibility
		timestamp:     time.Now(),
	})

	return nil
}

// RecordHTTPResponse records an HTTP response
func (b *BufferedCollector) RecordHTTPResponse(ctx context.Context, connectionID int64, statusCode int, contentLength int64) error {
	b.buffer.mu.Lock()
	defer b.buffer.mu.Unlock()

	b.buffer.httpResponses = append(b.buffer.httpResponses, httpResponseData{
		connectionID:  connectionID,
		statusCode:    statusCode,
		contentLength: contentLength,
		headerSize:    0, // Default to 0 for backward compatibility
		timestamp:     time.Now(),
	})

	return nil
}

// RecordHTTPRequestWithHeaders records an HTTP request including header size
func (b *BufferedCollector) RecordHTTPRequestWithHeaders(ctx context.Context, connectionID int64, method, url, host, userAgent string, contentLength, headerSize int64) error {
	b.buffer.mu.Lock()
	defer b.buffer.mu.Unlock()

	b.buffer.httpRequests = append(b.buffer.httpRequests, httpRequestData{
		connectionID:  connectionID,
		method:        method,
		url:           url,
		host:          host,
		userAgent:     userAgent,
		contentLength: contentLength,
		headerSize:    headerSize,
		timestamp:     time.Now(),
	})

	return nil
}

// RecordHTTPResponseWithHeaders records an HTTP response including header size
func (b *BufferedCollector) RecordHTTPResponseWithHeaders(ctx context.Context, connectionID int64, statusCode int, contentLength, headerSize int64) error {
	b.buffer.mu.Lock()
	defer b.buffer.mu.Unlock()

	b.buffer.httpResponses = append(b.buffer.httpResponses, httpResponseData{
		connectionID:  connectionID,
		statusCode:    statusCode,
		contentLength: contentLength,
		headerSize:    headerSize,
		timestamp:     time.Now(),
	})

	return nil
}

// RecordError records an error
func (b *BufferedCollector) RecordError(ctx context.Context, connectionID int64, errorType, errorMessage string) error {
	b.buffer.mu.Lock()
	defer b.buffer.mu.Unlock()

	b.buffer.errors = append(b.buffer.errors, errorData{
		connectionID: connectionID,
		errorType:    errorType,
		errorMessage: errorMessage,
		timestamp:    time.Now(),
	})

	return nil
}

// RecordDataTransfer records data transfer
func (b *BufferedCollector) RecordDataTransfer(ctx context.Context, connectionID, bytesSent, bytesReceived int64) error {
	b.buffer.mu.Lock()
	defer b.buffer.mu.Unlock()

	b.buffer.dataTransfers = append(b.buffer.dataTransfers, dataTransferData{
		connectionID:  connectionID,
		bytesSent:     bytesSent,
		bytesReceived: bytesReceived,
		timestamp:     time.Now(),
	})

	return nil
}

// RecordBlockedRequest records a blocked request
func (b *BufferedCollector) RecordBlockedRequest(ctx context.Context, clientIP, targetHost, reason string) error {
	b.buffer.mu.Lock()
	defer b.buffer.mu.Unlock()

	b.buffer.security = append(b.buffer.security, securityEventData{
		clientIP:   clientIP,
		targetHost: targetHost,
		eventType:  "blocked",
		reason:     reason,
		timestamp:  time.Now(),
	})

	return nil
}

// RecordAllowedRequest records an allowed request
func (b *BufferedCollector) RecordAllowedRequest(ctx context.Context, clientIP, targetHost string) error {
	b.buffer.mu.Lock()
	defer b.buffer.mu.Unlock()

	b.buffer.security = append(b.buffer.security, securityEventData{
		clientIP:   clientIP,
		targetHost: targetHost,
		eventType:  "allowed",
		timestamp:  time.Now(),
	})

	return nil
}

// RecordConnectionDuration records connection duration
func (b *BufferedCollector) RecordConnectionDuration(ctx context.Context, connectionID int64, duration time.Duration) error {
	// Handled in EndConnection
	return nil
}

// HealthCheck checks if the underlying collector is healthy
func (b *BufferedCollector) HealthCheck(ctx context.Context) error {
	return b.underlying.HealthCheck(ctx)
}

// flush writes all buffered data to the underlying collector
func (b *BufferedCollector) flush() {
	b.buffer.mu.Lock()
	defer b.buffer.mu.Unlock()

	sumStats := len(b.buffer.pendingConnections) +
		len(b.buffer.completedConnections) +
		len(b.buffer.httpRequests) +
		len(b.buffer.httpResponses) +
		len(b.buffer.errors) +
		len(b.buffer.dataTransfers) +
		len(b.buffer.security)

	if sumStats == 0 {
		return
	}

	logger.Debug("Flushing stats data %d", sumStats)

	ctx := context.Background()

	// Process completed connections
	for i := range b.buffer.completedConnections {
		conn := &b.buffer.completedConnections[i]
		if err := b.underlying.EndConnection(ctx, conn.connectionID, conn.bytesSent, conn.bytesReceived, conn.duration, conn.closeReason); err != nil {
			// Log error but continue processing other items
			_ = err
		}
	}

	// Process HTTP requests
	for _, req := range b.buffer.httpRequests {
		// Use the new method with headers if headerSize is provided, otherwise fall back to the old method
		if req.headerSize > 0 {
			if err := b.underlying.RecordHTTPRequestWithHeaders(ctx, req.connectionID, req.method, req.url, req.host, req.userAgent, req.contentLength, req.headerSize); err != nil {
				_ = err
			}
		} else {
			if err := b.underlying.RecordHTTPRequest(ctx, req.connectionID, req.method, req.url, req.host, req.userAgent, req.contentLength); err != nil {
				_ = err
			}
		}
	}

	// Process HTTP responses
	for _, resp := range b.buffer.httpResponses {
		// Use the new method with headers if headerSize is provided, otherwise fall back to the old method
		if resp.headerSize > 0 {
			if err := b.underlying.RecordHTTPResponseWithHeaders(ctx, resp.connectionID, resp.statusCode, resp.contentLength, resp.headerSize); err != nil {
				_ = err
			}
		} else {
			if err := b.underlying.RecordHTTPResponse(ctx, resp.connectionID, resp.statusCode, resp.contentLength); err != nil {
				_ = err
			}
		}
	}

	// Process errors
	for _, errData := range b.buffer.errors {
		if err := b.underlying.RecordError(ctx, errData.connectionID, errData.errorType, errData.errorMessage); err != nil {
			_ = err
		}
	}

	// Process data transfers
	for _, dt := range b.buffer.dataTransfers {
		if err := b.underlying.RecordDataTransfer(ctx, dt.connectionID, dt.bytesSent, dt.bytesReceived); err != nil {
			_ = err
		}
	}

	// Process security events
	for _, event := range b.buffer.security {
		if event.eventType == "blocked" {
			if err := b.underlying.RecordBlockedRequest(ctx, event.clientIP, event.targetHost, event.reason); err != nil {
				_ = err
			}
		} else {
			if err := b.underlying.RecordAllowedRequest(ctx, event.clientIP, event.targetHost); err != nil {
				_ = err
			}
		}
	}

	// Clear buffers
	b.buffer.pendingConnections = make(map[int64]*connectionData)
	b.buffer.completedConnections = b.buffer.completedConnections[:0]
	b.buffer.httpRequests = b.buffer.httpRequests[:0]
	b.buffer.httpResponses = b.buffer.httpResponses[:0]
	b.buffer.errors = b.buffer.errors[:0]
	b.buffer.dataTransfers = b.buffer.dataTransfers[:0]
	b.buffer.security = b.buffer.security[:0]
}

// Close stops the flusher and writes any remaining data
func (b *BufferedCollector) Close() error {
	close(b.stopChan)
	b.wg.Wait()
	return b.underlying.Close()
}

// GetOverviewStats delegates to underlying collector
func (b *BufferedCollector) GetOverviewStats(ctx context.Context) (*OverviewStats, error) {
	return b.underlying.GetOverviewStats(ctx)
}

// GetTopDomains delegates to underlying collector
func (b *BufferedCollector) GetTopDomains(ctx context.Context, limit int) ([]DomainStats, error) {
	return b.underlying.GetTopDomains(ctx, limit)
}

// GetSecurityEvents delegates to underlying collector
func (b *BufferedCollector) GetSecurityEvents(ctx context.Context, limit int) ([]SecurityEventInfo, error) {
	return b.underlying.GetSecurityEvents(ctx, limit)
}

// GetRecentErrors delegates to underlying collector
func (b *BufferedCollector) GetRecentErrors(ctx context.Context, limit int) ([]ErrorSummary, error) {
	return b.underlying.GetRecentErrors(ctx, limit)
}

// GetBandwidthStats delegates to underlying collector
func (b *BufferedCollector) GetBandwidthStats(ctx context.Context, days int) (*BandwidthStats, error) {
	return b.underlying.GetBandwidthStats(ctx, days)
}

// ForceFlush immediately flushes all buffered data
func (b *BufferedCollector) ForceFlush() {
	b.flush()
}
