package stats

import (
	"context"
	"time"
)

// Collector defines the interface for collecting proxy statistics
type Collector interface {
	// Connection tracking
	StartConnection(ctx context.Context, clientIP, targetHost string, targetPort int, protocol string) (int64, error)
	StartConnectionWithUUID(ctx context.Context, connectionUUID, clientIP, targetHost string, targetPort int, protocol string) (int64, error)
	EndConnection(ctx context.Context, connectionID int64, bytesSent, bytesReceived int64, duration time.Duration, closeReason string) error

	// Request/Response tracking
	RecordHTTPRequest(ctx context.Context, connectionID int64, method, url, host, userAgent string, contentLength int64) error
	RecordHTTPResponse(ctx context.Context, connectionID int64, statusCode int, contentLength int64) error

	// Extended Request/Response tracking with header sizes
	RecordHTTPRequestWithHeaders(ctx context.Context, connectionID int64, method, url, host, userAgent string, contentLength, headerSize int64) error
	RecordHTTPResponseWithHeaders(ctx context.Context, connectionID int64, statusCode int, contentLength, headerSize int64) error

	// Error tracking
	RecordError(ctx context.Context, connectionID int64, errorType, errorMessage string) error

	// Bandwidth tracking
	RecordDataTransfer(ctx context.Context, connectionID int64, bytesSent, bytesReceived int64) error

	// Security events
	RecordBlockedRequest(ctx context.Context, clientIP, targetHost, reason string) error
	RecordAllowedRequest(ctx context.Context, clientIP, targetHost string) error

	// Request/Response recording (for matched traffic)
	RecordFullHTTPRequest(ctx context.Context, connectionID int64, method, url, host, userAgent string,
		requestHeaders map[string][]string, requestBody []byte, timestamp time.Time) error
	RecordFullHTTPResponse(ctx context.Context, connectionID int64, statusCode int,
		responseHeaders map[string][]string, responseBody []byte, timestamp time.Time) error

	// Dashboard queries
	GetOverviewStats(ctx context.Context) (*OverviewStats, error)
	GetTopDomains(ctx context.Context, limit int) ([]DomainStats, error)
	GetSecurityEvents(ctx context.Context, limit int) ([]SecurityEventInfo, error)
	GetRecentErrors(ctx context.Context, limit int) ([]ErrorSummary, error)
	GetBandwidthStats(ctx context.Context, days int) (*BandwidthStats, error)
	GetSystemStats(ctx context.Context) (*SystemStats, error)

	// Health check
	HealthCheck(ctx context.Context) error

	// Close cleans up resources
	Close() error
}

// StreamingRecorder is an optional extension that allows streaming request bodies
// into persistent storage without buffering the entire payload in memory.
// Implementations should create a parent request record first, then accept
// incremental body parts linked to that record.
type StreamingRecorder interface {
	// BeginRecordedHTTPRequest creates a recorded_http_requests row without body
	// and returns its ID for subsequent body part appends.
	BeginRecordedHTTPRequest(ctx context.Context, connectionID int64, method, url, host, userAgent string,
		requestHeaders map[string][]string, timestamp time.Time) (requestID int64, err error)

	// AppendRecordedHTTPRequestBodyPart stores a body chunk for the given request record.
	// Implementations may also update the parent request_body_size atomically.
	AppendRecordedHTTPRequestBodyPart(ctx context.Context, requestID int64, seqNo int64, data []byte, timestamp time.Time) error

	// FinishRecordedHTTPRequest finalizes any bookkeeping for the recorded request.
	// Implementations may compute/validate total size, update timestamps, etc.
	FinishRecordedHTTPRequest(ctx context.Context, requestID int64) error

	// Response streaming
	BeginRecordedHTTPResponse(ctx context.Context, connectionID int64, statusCode int,
		responseHeaders map[string][]string, timestamp time.Time) (responseID int64, err error)
	AppendRecordedHTTPResponseBodyPart(ctx context.Context, responseID int64, seqNo int64, data []byte, timestamp time.Time) error
	FinishRecordedHTTPResponse(ctx context.Context, responseID int64) error
}

// ConnectionInfo holds information about a connection
type ConnectionInfo struct {
	ID            int64
	UUID          string
	ClientIP      string
	TargetHost    string
	TargetPort    int
	Protocol      string
	StartedAt     time.Time
	EndedAt       *time.Time
	BytesSent     int64
	BytesReceived int64
	Duration      time.Duration
	CloseReason   string
}

// HTTPRequestInfo holds information about an HTTP request
type HTTPRequestInfo struct {
	ConnectionID  int64
	Method        string
	URL           string
	Host          string
	UserAgent     string
	ContentLength int64
	HeaderSize    int64
	Timestamp     time.Time
}

// HTTPResponseInfo holds information about an HTTP response
type HTTPResponseInfo struct {
	ConnectionID  int64
	StatusCode    int
	ContentLength int64
	HeaderSize    int64
	Timestamp     time.Time
}

// ErrorInfo holds information about an error
type ErrorInfo struct {
	ConnectionID int64
	ErrorType    string
	ErrorMessage string
	Timestamp    time.Time
}

// SecurityEvent holds information about security events
type SecurityEvent struct {
	ClientIP   string
	TargetHost string
	EventType  string // "blocked" or "allowed"
	Reason     string
	Timestamp  time.Time
}

// Dashboard query result types

// OverviewStats provides high-level statistics
type OverviewStats struct {
	TotalConnections  int64  `json:"total_connections"`
	ActiveConnections int64  `json:"active_connections"`
	TotalRequests     int64  `json:"total_requests"`
	TotalErrors       int64  `json:"total_errors"`
	BlockedRequests   int64  `json:"blocked_requests"`
	AllowedRequests   int64  `json:"allowed_requests"`
	TotalBytesIn      int64  `json:"total_bytes_in"`
	TotalBytesOut     int64  `json:"total_bytes_out"`
	Uptime            string `json:"uptime"`
}

// DomainStats represents statistics for a domain
type DomainStats struct {
	Domain       string    `json:"domain"`
	RequestCount int64     `json:"request_count"`
	TotalBytes   int64     `json:"total_bytes"`
	LastAccess   time.Time `json:"last_access"`
}

// SecurityEventInfo represents a security event for dashboard
type SecurityEventInfo struct {
	ID         int64     `json:"id"`
	ClientIP   string    `json:"client_ip"`
	TargetHost string    `json:"target_host"`
	EventType  string    `json:"event_type"`
	Reason     string    `json:"reason"`
	Timestamp  time.Time `json:"timestamp"`
}

// ErrorSummary represents error statistics
type ErrorSummary struct {
	ErrorType    string    `json:"error_type"`
	Count        int64     `json:"count"`
	LastMessage  string    `json:"last_message"`
	LastOccurred time.Time `json:"last_occurred"`
}

// BandwidthStats provides bandwidth usage data
type BandwidthStats struct {
	Daily []DailyBandwidth `json:"daily"`
	Total int64            `json:"total"`
}

// DailyBandwidth represents daily bandwidth usage
type DailyBandwidth struct {
	Date         string `json:"date"`
	BytesIn      int64  `json:"bytes_in"`
	BytesOut     int64  `json:"bytes_out"`
	RequestCount int64  `json:"request_count"`
}

// SystemStats provides system hardware and performance information
type SystemStats struct {
	CurrentConnections int64   `json:"current_connections"`
	CPUUsagePercent    float64 `json:"cpu_usage_percent"`
	MemoryUsedBytes    int64   `json:"memory_used_bytes"`
	MemoryTotalBytes   int64   `json:"memory_total_bytes"`
	MemoryUsagePercent float64 `json:"memory_usage_percent"`
	CPUCount           int     `json:"cpu_count"`
	OSInfo             string  `json:"os_info"`
	Architecture       string  `json:"architecture"`
	UptimeSeconds      int64   `json:"uptime_seconds"`
}

// RecordedHTTPRequest holds full HTTP request data for recording
type RecordedHTTPRequest struct {
	ID              int64               `json:"id"`
	ConnectionID    int64               `json:"connection_id"`
	Method          string              `json:"method"`
	URL             string              `json:"url"`
	Host            string              `json:"host"`
	UserAgent       string              `json:"user_agent"`
	RequestHeaders  map[string][]string `json:"request_headers"`
	RequestBody     []byte              `json:"request_body"`
	RequestBodySize int64               `json:"request_body_size"`
	Timestamp       time.Time           `json:"timestamp"`
}

// RecordedHTTPResponse holds full HTTP response data for recording
type RecordedHTTPResponse struct {
	ID               int64               `json:"id"`
	ConnectionID     int64               `json:"connection_id"`
	StatusCode       int                 `json:"status_code"`
	ResponseHeaders  map[string][]string `json:"response_headers"`
	ResponseBody     []byte              `json:"response_body"`
	ResponseBodySize int64               `json:"response_body_size"`
	Timestamp        time.Time           `json:"timestamp"`
}
