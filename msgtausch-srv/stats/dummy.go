package stats

import (
	"context"
	"time"
)

// DummyCollector is a no-op implementation of Collector
// It does nothing and is used when statistics collection is disabled
type DummyCollector struct{}

// NewDummyCollector creates a new dummy collector
func NewDummyCollector() *DummyCollector {
	return &DummyCollector{}
}

// StartConnection records the start of a connection (no-op)
func (d *DummyCollector) StartConnection(ctx context.Context, clientIP, targetHost string, targetPort int, protocol string) (int64, error) {
	return 0, nil
}

// EndConnection records the end of a connection (no-op)
func (d *DummyCollector) EndConnection(ctx context.Context, connectionID, bytesSent, bytesReceived int64, duration time.Duration, closeReason string) error {
	return nil
}

// RecordHTTPRequest records an HTTP request (no-op)
func (d *DummyCollector) RecordHTTPRequest(ctx context.Context, connectionID int64, method, url, host, userAgent string, contentLength int64) error {
	return nil
}

// RecordHTTPResponse records an HTTP response (no-op)
func (d *DummyCollector) RecordHTTPResponse(ctx context.Context, connectionID int64, statusCode int, contentLength int64) error {
	return nil
}

// RecordHTTPRequestWithHeaders records an HTTP request with header size (no-op)
func (d *DummyCollector) RecordHTTPRequestWithHeaders(ctx context.Context, connectionID int64, method, url, host, userAgent string, contentLength, headerSize int64) error {
	return nil
}

// RecordHTTPResponseWithHeaders records an HTTP response with header size (no-op)
func (d *DummyCollector) RecordHTTPResponseWithHeaders(ctx context.Context, connectionID int64, statusCode int, contentLength, headerSize int64) error {
	return nil
}

// RecordError records an error (no-op)
func (d *DummyCollector) RecordError(ctx context.Context, connectionID int64, errorType, errorMessage string) error {
	return nil
}

// RecordDataTransfer records data transfer (no-op)
func (d *DummyCollector) RecordDataTransfer(ctx context.Context, connectionID, bytesSent, bytesReceived int64) error {
	return nil
}

// RecordBlockedRequest records a blocked request (no-op)
func (d *DummyCollector) RecordBlockedRequest(ctx context.Context, clientIP, targetHost, reason string) error {
	return nil
}

// RecordAllowedRequest records an allowed request (no-op)
func (d *DummyCollector) RecordAllowedRequest(ctx context.Context, clientIP, targetHost string) error {
	return nil
}

// HealthCheck always returns healthy for dummy collector
func (d *DummyCollector) HealthCheck(ctx context.Context) error {
	return nil
}

// GetOverviewStats returns empty stats for dummy collector
func (d *DummyCollector) GetOverviewStats(ctx context.Context) (*OverviewStats, error) {
	return &OverviewStats{}, nil
}

// GetTopDomains returns empty domain stats for dummy collector
func (d *DummyCollector) GetTopDomains(ctx context.Context, limit int) ([]DomainStats, error) {
	return []DomainStats{}, nil
}

// GetSecurityEvents returns empty security events for dummy collector
func (d *DummyCollector) GetSecurityEvents(ctx context.Context, limit int) ([]SecurityEventInfo, error) {
	return []SecurityEventInfo{}, nil
}

// GetRecentErrors returns empty error summaries for dummy collector
func (d *DummyCollector) GetRecentErrors(ctx context.Context, limit int) ([]ErrorSummary, error) {
	return []ErrorSummary{}, nil
}

// GetBandwidthStats returns empty bandwidth stats for dummy collector
func (d *DummyCollector) GetBandwidthStats(ctx context.Context, days int) (*BandwidthStats, error) {
	return &BandwidthStats{Daily: []DailyBandwidth{}, Total: 0}, nil
}

// Close does nothing for dummy collector
func (d *DummyCollector) Close() error {
	return nil
}
