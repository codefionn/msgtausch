package stats

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
	_ "github.com/mattn/go-sqlite3"
)

// SQLiteCollector implements Collector using SQLite as the backend
type SQLiteCollector struct {
	db *sql.DB
}

// NewSQLiteCollector creates a new SQLite-based statistics collector
func NewSQLiteCollector(dbPath string) (*SQLiteCollector, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to connect to SQLite database: %w", err)
	}

	// Enable WAL mode for better concurrency
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("failed to set WAL mode: %w", err)
	}

	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	collector := &SQLiteCollector{db: db}
	if err := collector.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	logger.Debug("Intialized stats collector sqlite")

	return collector, nil
}

// initSchema creates the necessary tables if they don't exist
func (s *SQLiteCollector) initSchema() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS connections (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			client_ip TEXT NOT NULL,
			target_host TEXT NOT NULL,
			target_port INTEGER NOT NULL,
			protocol TEXT NOT NULL,
			started_at DATETIME NOT NULL,
			ended_at DATETIME,
			bytes_sent INTEGER DEFAULT 0,
			bytes_received INTEGER DEFAULT 0,
			duration_ms INTEGER,
			close_reason TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_connections_client_ip ON connections(client_ip)`,
		`CREATE INDEX IF NOT EXISTS idx_connections_target_host ON connections(target_host)`,
		`CREATE INDEX IF NOT EXISTS idx_connections_started_at ON connections(started_at)`,

		`CREATE TABLE IF NOT EXISTS http_requests (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			connection_id INTEGER NOT NULL,
			method TEXT NOT NULL,
			url TEXT NOT NULL,
			host TEXT NOT NULL,
			user_agent TEXT,
			content_length INTEGER DEFAULT 0,
			timestamp DATETIME NOT NULL,
			FOREIGN KEY (connection_id) REFERENCES connections(id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_http_requests_connection_id ON http_requests(connection_id)`,
		`CREATE INDEX IF NOT EXISTS idx_http_requests_timestamp ON http_requests(timestamp)`,

		`CREATE TABLE IF NOT EXISTS http_responses (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			connection_id INTEGER NOT NULL,
			status_code INTEGER NOT NULL,
			content_length INTEGER DEFAULT 0,
			timestamp DATETIME NOT NULL,
			FOREIGN KEY (connection_id) REFERENCES connections(id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_http_responses_connection_id ON http_responses(connection_id)`,

		`CREATE TABLE IF NOT EXISTS errors (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			connection_id INTEGER,
			error_type TEXT NOT NULL,
			error_message TEXT NOT NULL,
			timestamp DATETIME NOT NULL,
			FOREIGN KEY (connection_id) REFERENCES connections(id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_errors_timestamp ON errors(timestamp)`,

		`CREATE TABLE IF NOT EXISTS security_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			client_ip TEXT NOT NULL,
			target_host TEXT NOT NULL,
			event_type TEXT NOT NULL,
			reason TEXT,
			timestamp DATETIME NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_security_events_client_ip ON security_events(client_ip)`,
		`CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp)`,

		`CREATE TABLE IF NOT EXISTS data_transfers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			connection_id INTEGER NOT NULL,
			bytes_sent INTEGER DEFAULT 0,
			bytes_received INTEGER DEFAULT 0,
			timestamp DATETIME NOT NULL,
			FOREIGN KEY (connection_id) REFERENCES connections(id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_data_transfers_connection_id ON data_transfers(connection_id)`,
	}

	for _, query := range queries {
		if _, err := s.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute schema query: %w", err)
		}
	}

	return nil
}

// StartConnection records the start of a connection
func (s *SQLiteCollector) StartConnection(ctx context.Context, clientIP, targetHost string, targetPort int, protocol string) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO connections (client_ip, target_host, target_port, protocol, started_at)
		 VALUES (?, ?, ?, ?, ?)`,
		clientIP, targetHost, targetPort, protocol, time.Now())
	if err != nil {
		return 0, fmt.Errorf("failed to record connection start: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get connection ID: %w", err)
	}

	return id, nil
}

// EndConnection records the end of a connection
func (s *SQLiteCollector) EndConnection(ctx context.Context, connectionID, bytesSent, bytesReceived int64, duration time.Duration, closeReason string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE connections
		 SET ended_at = ?, bytes_sent = ?, bytes_received = ?, duration_ms = ?, close_reason = ?
		 WHERE id = ?`,
		time.Now(), bytesSent, bytesReceived, duration.Milliseconds(), closeReason, connectionID)
	if err != nil {
		return fmt.Errorf("failed to record connection end: %w", err)
	}
	return nil
}

// RecordHTTPRequest records an HTTP request
func (s *SQLiteCollector) RecordHTTPRequest(ctx context.Context, connectionID int64, method, url, host, userAgent string, contentLength int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO http_requests (connection_id, method, url, host, user_agent, content_length, timestamp)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		connectionID, method, url, host, userAgent, contentLength, time.Now())
	if err != nil {
		return fmt.Errorf("failed to record HTTP request: %w", err)
	}
	return nil
}

// RecordHTTPResponse records an HTTP response
func (s *SQLiteCollector) RecordHTTPResponse(ctx context.Context, connectionID int64, statusCode int, contentLength int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO http_responses (connection_id, status_code, content_length, timestamp)
		 VALUES (?, ?, ?, ?)`,
		connectionID, statusCode, contentLength, time.Now())
	if err != nil {
		return fmt.Errorf("failed to record HTTP response: %w", err)
	}
	return nil
}

// RecordHTTPRequestWithHeaders records an HTTP request including header size
func (s *SQLiteCollector) RecordHTTPRequestWithHeaders(ctx context.Context, connectionID int64, method, url, host, userAgent string, contentLength, headerSize int64) error {
	// First, try to add header_size column if it doesn't exist (migration)
	_, _ = s.db.ExecContext(ctx, `ALTER TABLE http_requests ADD COLUMN header_size INTEGER DEFAULT 0`)

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO http_requests (connection_id, method, url, host, user_agent, content_length, header_size, timestamp)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		connectionID, method, url, host, userAgent, contentLength, headerSize, time.Now())
	if err != nil {
		return fmt.Errorf("failed to record HTTP request with headers: %w", err)
	}
	return nil
}

// RecordHTTPResponseWithHeaders records an HTTP response including header size
func (s *SQLiteCollector) RecordHTTPResponseWithHeaders(ctx context.Context, connectionID int64, statusCode int, contentLength, headerSize int64) error {
	// First, try to add header_size column if it doesn't exist (migration)
	_, _ = s.db.ExecContext(ctx, `ALTER TABLE http_responses ADD COLUMN header_size INTEGER DEFAULT 0`)

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO http_responses (connection_id, status_code, content_length, header_size, timestamp)
		 VALUES (?, ?, ?, ?, ?)`,
		connectionID, statusCode, contentLength, headerSize, time.Now())
	if err != nil {
		return fmt.Errorf("failed to record HTTP response with headers: %w", err)
	}
	return nil
}

// RecordError records an error
func (s *SQLiteCollector) RecordError(ctx context.Context, connectionID int64, errorType, errorMessage string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO errors (connection_id, error_type, error_message, timestamp)
		 VALUES (?, ?, ?, ?)`,
		connectionID, errorType, errorMessage, time.Now())
	if err != nil {
		return fmt.Errorf("failed to record error: %w", err)
	}
	return nil
}

// RecordDataTransfer records data transfer
func (s *SQLiteCollector) RecordDataTransfer(ctx context.Context, connectionID, bytesSent, bytesReceived int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE connections
		 SET bytes_sent = bytes_sent + ?, bytes_received = bytes_received + ?
		 WHERE id = ?`,
		bytesSent, bytesReceived, connectionID)
	if err != nil {
		return fmt.Errorf("failed to record data transfer: %w", err)
	}
	return nil
}

// RecordBlockedRequest records a blocked request
func (s *SQLiteCollector) RecordBlockedRequest(ctx context.Context, clientIP, targetHost, reason string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO security_events (client_ip, target_host, event_type, reason, timestamp)
		 VALUES (?, ?, 'blocked', ?, ?)`,
		clientIP, targetHost, reason, time.Now())
	if err != nil {
		return fmt.Errorf("failed to record blocked request: %w", err)
	}
	return nil
}

// RecordAllowedRequest records an allowed request
func (s *SQLiteCollector) RecordAllowedRequest(ctx context.Context, clientIP, targetHost string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO security_events (client_ip, target_host, event_type, timestamp)
		 VALUES (?, ?, 'allowed', ?)`,
		clientIP, targetHost, time.Now())
	if err != nil {
		return fmt.Errorf("failed to record allowed request: %w", err)
	}
	return nil
}

// RecordConnectionDuration records connection duration
func (s *SQLiteCollector) RecordConnectionDuration(ctx context.Context, connectionID int64, duration time.Duration) error {
	// This is handled in EndConnection
	return nil
}

// HealthCheck checks if the database connection is healthy
func (s *SQLiteCollector) HealthCheck(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// GetOverviewStats returns overview statistics
func (s *SQLiteCollector) GetOverviewStats(ctx context.Context) (*OverviewStats, error) {
	stats := &OverviewStats{}

	// Total connections
	query := "SELECT COUNT(*) FROM connections"
	err := s.db.QueryRowContext(ctx, query).Scan(&stats.TotalConnections)
	if err != nil {
		return nil, fmt.Errorf("failed to get total connections: %w", err)
	}

	// Active connections
	query = "SELECT COUNT(*) FROM connections WHERE ended_at IS NULL"
	err = s.db.QueryRowContext(ctx, query).Scan(&stats.ActiveConnections)
	if err != nil {
		return nil, fmt.Errorf("failed to get active connections: %w", err)
	}

	// Total requests
	query = "SELECT COUNT(*) FROM http_requests"
	err = s.db.QueryRowContext(ctx, query).Scan(&stats.TotalRequests)
	if err != nil {
		return nil, fmt.Errorf("failed to get total requests: %w", err)
	}

	// Total errors
	query = "SELECT COUNT(*) FROM errors"
	err = s.db.QueryRowContext(ctx, query).Scan(&stats.TotalErrors)
	if err != nil {
		return nil, fmt.Errorf("failed to get total errors: %w", err)
	}

	// Blocked/Allowed requests
	query = `SELECT
		COALESCE(SUM(CASE WHEN event_type = 'blocked' THEN 1 ELSE 0 END), 0) as blocked,
		COALESCE(SUM(CASE WHEN event_type = 'allowed' THEN 1 ELSE 0 END), 0) as allowed
		FROM security_events`
	err = s.db.QueryRowContext(ctx, query).Scan(&stats.BlockedRequests, &stats.AllowedRequests)
	if err != nil {
		return nil, fmt.Errorf("failed to get security stats: %w", err)
	}

	// Total bytes
	query = "SELECT COALESCE(SUM(bytes_sent), 0), COALESCE(SUM(bytes_received), 0) FROM connections"
	err = s.db.QueryRowContext(ctx, query).Scan(&stats.TotalBytesOut, &stats.TotalBytesIn)
	if err != nil {
		return nil, fmt.Errorf("failed to get total bytes: %w", err)
	}

	// Calculate uptime from first connection
	query = "SELECT MIN(started_at) FROM connections"
	var firstConnection time.Time
	err = s.db.QueryRowContext(ctx, query).Scan(&firstConnection)
	if err != nil {
		stats.Uptime = "No connections yet"
	} else {
		stats.Uptime = time.Since(firstConnection).String()
	}

	return stats, nil
}

// GetTopDomains returns top domains by request count
func (s *SQLiteCollector) GetTopDomains(ctx context.Context, limit int) (domains []DomainStats, err error) {
	query := `
		SELECT target_host, COUNT(*) as request_count,
		       SUM(bytes_sent + bytes_received) as total_bytes,
		       datetime(MAX(started_at)) as last_access
		FROM connections
		GROUP BY target_host
		ORDER BY request_count DESC
		LIMIT ?
	`

	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get top domains: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("failed to close rows: %w", closeErr)
		}
	}()

	for rows.Next() {
		var domain DomainStats
		var lastAccessStr string
		if err := rows.Scan(&domain.Domain, &domain.RequestCount, &domain.TotalBytes, &lastAccessStr); err != nil {
			return nil, fmt.Errorf("failed to scan domain row: %w", err)
		}

		// Parse the timestamp string into time.Time
		if lastAccessStr != "" {
			// Try multiple timestamp formats that SQLite might use
			formats := []string{
				"2006-01-02 15:04:05.999999999-07:00",
				"2006-01-02 15:04:05",
				"2006-01-02T15:04:05Z",
				"2006-01-02T15:04:05.999999999Z",
				time.RFC3339,
				time.RFC3339Nano,
			}

			var err error
			for _, format := range formats {
				if domain.LastAccess, err = time.Parse(format, lastAccessStr); err == nil {
					break
				}
			}

			if err != nil {
				// If all parsing fails, use current time as fallback
				domain.LastAccess = time.Now()
			}
		}

		domains = append(domains, domain)
	}

	return domains, nil
}

// GetSecurityEvents returns recent security events
func (s *SQLiteCollector) GetSecurityEvents(ctx context.Context, limit int) (events []SecurityEventInfo, err error) {
	query := `
		SELECT rowid, client_ip, target_host, event_type, reason, timestamp
		FROM security_events
		ORDER BY timestamp DESC
		LIMIT ?
	`

	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get security events: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("failed to close rows: %w", closeErr)
		}
	}()

	for rows.Next() {
		var event SecurityEventInfo
		var reason sql.NullString
		var timestampStr string
		if err := rows.Scan(&event.ID, &event.ClientIP, &event.TargetHost, &event.EventType, &reason, &timestampStr); err != nil {
			return nil, fmt.Errorf("failed to scan security event row: %w", err)
		}

		// Handle nullable reason field
		if reason.Valid {
			event.Reason = reason.String
		} else {
			event.Reason = ""
		}

		// Parse timestamp
		if timestampStr != "" {
			formats := []string{
				"2006-01-02 15:04:05.999999999-07:00",
				"2006-01-02 15:04:05",
				"2006-01-02T15:04:05Z",
				"2006-01-02T15:04:05.999999999Z",
				time.RFC3339,
				time.RFC3339Nano,
			}

			var err error
			for _, format := range formats {
				if event.Timestamp, err = time.Parse(format, timestampStr); err == nil {
					break
				}
			}

			if err != nil {
				event.Timestamp = time.Now()
			}
		}

		events = append(events, event)
	}

	return events, nil
}

// GetRecentErrors returns recent error summaries
func (s *SQLiteCollector) GetRecentErrors(ctx context.Context, limit int) (errorSummaries []ErrorSummary, err error) {
	query := `
		SELECT error_type, COUNT(*) as count,
		       MAX(error_message) as last_message,
		       MAX(timestamp) as last_occurred
		FROM errors
		GROUP BY error_type
		ORDER BY count DESC
		LIMIT ?
	`

	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent errors: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("failed to close rows: %w", closeErr)
		}
	}()

	for rows.Next() {
		var summary ErrorSummary
		var lastOccurredStr string
		if err := rows.Scan(&summary.ErrorType, &summary.Count, &summary.LastMessage, &lastOccurredStr); err != nil {
			return nil, fmt.Errorf("failed to scan error summary row: %w", err)
		}

		// Parse timestamp
		if lastOccurredStr != "" {
			formats := []string{
				"2006-01-02 15:04:05.999999999-07:00",
				"2006-01-02 15:04:05",
				"2006-01-02T15:04:05Z",
				"2006-01-02T15:04:05.999999999Z",
				time.RFC3339,
				time.RFC3339Nano,
			}

			var err error
			for _, format := range formats {
				if summary.LastOccurred, err = time.Parse(format, lastOccurredStr); err == nil {
					break
				}
			}

			if err != nil {
				summary.LastOccurred = time.Now()
			}
		}

		errorSummaries = append(errorSummaries, summary)
	}

	return errorSummaries, nil
}

// GetBandwidthStats returns bandwidth statistics for the last N days
func (s *SQLiteCollector) GetBandwidthStats(ctx context.Context, days int) (stats *BandwidthStats, err error) {
	query := `
		SELECT DATE(started_at) as date,
		       SUM(bytes_received) as bytes_in,
		       SUM(bytes_sent) as bytes_out,
		       COUNT(*) as request_count
		FROM connections
		WHERE started_at >= datetime('now', '-' || ? || ' days')
		GROUP BY DATE(started_at)
		ORDER BY date ASC
	`

	rows, err := s.db.QueryContext(ctx, query, days)
	if err != nil {
		return nil, fmt.Errorf("failed to get bandwidth stats: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("failed to close rows: %w", closeErr)
		}
	}()

	stats = &BandwidthStats{
		Daily: []DailyBandwidth{},
		Total: 0,
	}

	for rows.Next() {
		var daily DailyBandwidth
		if err := rows.Scan(&daily.Date, &daily.BytesIn, &daily.BytesOut, &daily.RequestCount); err != nil {
			return nil, fmt.Errorf("failed to scan bandwidth stats row: %w", err)
		}
		stats.Daily = append(stats.Daily, daily)
		stats.Total += daily.BytesIn + daily.BytesOut
	}

	return stats, nil
}

// GetSystemStats returns system statistics
func (s *SQLiteCollector) GetSystemStats(ctx context.Context) (*SystemStats, error) {
	systemCollector := NewSystemStatsCollector(s)
	return systemCollector.CollectSystemStats(ctx)
}

// GetActiveConnectionCount returns the number of active connections
func (s *SQLiteCollector) GetActiveConnectionCount() int64 {
	query := `SELECT COUNT(*) FROM connections WHERE ended_at IS NULL`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var count int64
	err := s.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		logger.Debug("Failed to get active connection count: %v", err)
		return 0
	}

	return count
}

// Close closes the database connection
func (s *SQLiteCollector) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
