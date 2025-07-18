package stats

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
	_ "github.com/lib/pq"
)

// PostgreSQLCollector implements Collector using PostgreSQL
type PostgreSQLCollector struct {
	db *sql.DB
}

// NewPostgreSQLCollector creates a new PostgreSQL-based stats collector
func NewPostgreSQLCollector(connectionString string) (*PostgreSQLCollector, error) {
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to open PostgreSQL database: %w", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL database: %w", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	collector := &PostgreSQLCollector{db: db}
	if err := collector.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	logger.Debug("Initialized stats collector postgresql")

	return collector, nil
}

// initSchema creates the necessary tables if they don't exist
func (p *PostgreSQLCollector) initSchema() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS connections (
			id SERIAL PRIMARY KEY,
			client_ip INET NOT NULL,
			target_host TEXT NOT NULL,
			target_port INTEGER NOT NULL,
			protocol TEXT NOT NULL,
			started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			ended_at TIMESTAMP WITH TIME ZONE,
			bytes_sent BIGINT DEFAULT 0,
			bytes_received BIGINT DEFAULT 0,
			duration_ms INTEGER,
			close_reason TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_connections_client_ip ON connections(client_ip)`,
		`CREATE INDEX IF NOT EXISTS idx_connections_target_host ON connections(target_host)`,
		`CREATE INDEX IF NOT EXISTS idx_connections_started_at ON connections(started_at)`,

		`CREATE TABLE IF NOT EXISTS http_requests (
			id SERIAL PRIMARY KEY,
			connection_id INTEGER NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
			method TEXT NOT NULL,
			url TEXT NOT NULL,
			host TEXT NOT NULL,
			user_agent TEXT,
			content_length BIGINT DEFAULT 0,
			timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_http_requests_connection_id ON http_requests(connection_id)`,
		`CREATE INDEX IF NOT EXISTS idx_http_requests_timestamp ON http_requests(timestamp)`,

		`CREATE TABLE IF NOT EXISTS http_responses (
			id SERIAL PRIMARY KEY,
			connection_id INTEGER NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
			request_id INTEGER REFERENCES http_requests(id) ON DELETE CASCADE,
			status_code INTEGER NOT NULL,
			content_length BIGINT DEFAULT 0,
			timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_http_responses_connection_id ON http_responses(connection_id)`,

		`CREATE TABLE IF NOT EXISTS errors (
			id SERIAL PRIMARY KEY,
			connection_id INTEGER REFERENCES connections(id) ON DELETE CASCADE,
			error_type TEXT NOT NULL,
			error_message TEXT NOT NULL,
			timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_errors_timestamp ON errors(timestamp)`,

		`CREATE TABLE IF NOT EXISTS security_events (
			id SERIAL PRIMARY KEY,
			client_ip INET NOT NULL,
			target_host TEXT NOT NULL,
			event_type TEXT NOT NULL,
			reason TEXT,
			timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_security_events_client_ip ON security_events(client_ip)`,
		`CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp)`,

		`CREATE TABLE IF NOT EXISTS data_transfers (
			id SERIAL PRIMARY KEY,
			connection_id INTEGER NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
			bytes_sent BIGINT DEFAULT 0,
			bytes_received BIGINT DEFAULT 0,
			timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_data_transfers_connection_id ON data_transfers(connection_id)`,
	}

	for _, query := range queries {
		if _, err := p.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute schema query: %w", err)
		}
	}

	return nil
}

// StartConnection records the start of a connection
func (p *PostgreSQLCollector) StartConnection(ctx context.Context, clientIP, targetHost string, targetPort int, protocol string) (int64, error) {
	var id int64
	err := p.db.QueryRowContext(ctx,
		`INSERT INTO connections (client_ip, target_host, target_port, protocol)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		clientIP, targetHost, targetPort, protocol).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("failed to record connection start: %w", err)
	}
	return id, nil
}

// EndConnection records the end of a connection
func (p *PostgreSQLCollector) EndConnection(ctx context.Context, connectionID, bytesSent, bytesReceived int64, duration time.Duration, closeReason string) error {
	_, err := p.db.ExecContext(ctx,
		`UPDATE connections
		 SET ended_at = NOW(), bytes_sent = $1, bytes_received = $2, duration_ms = $3, close_reason = $4
		 WHERE id = $5`,
		bytesSent, bytesReceived, duration.Milliseconds(), closeReason, connectionID)
	if err != nil {
		return fmt.Errorf("failed to record connection end: %w", err)
	}
	return nil
}

// RecordHTTPRequest records an HTTP request
func (p *PostgreSQLCollector) RecordHTTPRequest(ctx context.Context, connectionID int64, method, url, host, userAgent string, contentLength int64) error {
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO http_requests (connection_id, method, url, host, user_agent, content_length)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		connectionID, method, url, host, userAgent, contentLength)
	if err != nil {
		return fmt.Errorf("failed to record HTTP request: %w", err)
	}
	return nil
}

// RecordHTTPResponse records an HTTP response
func (p *PostgreSQLCollector) RecordHTTPResponse(ctx context.Context, connectionID int64, statusCode int, contentLength int64) error {
	// Get the latest request for this connection
	var requestID int64
	err := p.db.QueryRowContext(ctx,
		`SELECT id FROM http_requests WHERE connection_id = $1 ORDER BY timestamp DESC LIMIT 1`,
		connectionID).Scan(&requestID)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to get request ID: %w", err)
	}

	_, err = p.db.ExecContext(ctx,
		`INSERT INTO http_responses (connection_id, request_id, status_code, content_length)
		 VALUES ($1, $2, $3, $4)`,
		connectionID, requestID, statusCode, contentLength)
	if err != nil {
		return fmt.Errorf("failed to record HTTP response: %w", err)
	}
	return nil
}

// RecordHTTPRequestWithHeaders records an HTTP request including header size
func (p *PostgreSQLCollector) RecordHTTPRequestWithHeaders(ctx context.Context, connectionID int64, method, url, host, userAgent string, contentLength, headerSize int64) error {
	// First, try to add header_size column if it doesn't exist (migration)
	_, _ = p.db.ExecContext(ctx, `ALTER TABLE http_requests ADD COLUMN header_size INTEGER DEFAULT 0`)

	_, err := p.db.ExecContext(ctx,
		`INSERT INTO http_requests (connection_id, method, url, host, user_agent, content_length, header_size)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		connectionID, method, url, host, userAgent, contentLength, headerSize)
	if err != nil {
		return fmt.Errorf("failed to record HTTP request with headers: %w", err)
	}
	return nil
}

// RecordHTTPResponseWithHeaders records an HTTP response including header size
func (p *PostgreSQLCollector) RecordHTTPResponseWithHeaders(ctx context.Context, connectionID int64, statusCode int, contentLength, headerSize int64) error {
	// First, try to add header_size column if it doesn't exist (migration)
	_, _ = p.db.ExecContext(ctx, `ALTER TABLE http_responses ADD COLUMN header_size INTEGER DEFAULT 0`)

	// Get the latest request for this connection
	var requestID int64
	err := p.db.QueryRowContext(ctx,
		`SELECT id FROM http_requests WHERE connection_id = $1 ORDER BY timestamp DESC LIMIT 1`,
		connectionID).Scan(&requestID)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to get request ID: %w", err)
	}

	_, err = p.db.ExecContext(ctx,
		`INSERT INTO http_responses (connection_id, request_id, status_code, content_length, header_size)
		 VALUES ($1, $2, $3, $4, $5)`,
		connectionID, requestID, statusCode, contentLength, headerSize)
	if err != nil {
		return fmt.Errorf("failed to record HTTP response with headers: %w", err)
	}
	return nil
}

// RecordError records an error
func (p *PostgreSQLCollector) RecordError(ctx context.Context, connectionID int64, errorType, errorMessage string) error {
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO errors (connection_id, error_type, error_message)
		 VALUES ($1, $2, $3)`,
		connectionID, errorType, errorMessage)
	if err != nil {
		return fmt.Errorf("failed to record error: %w", err)
	}
	return nil
}

// RecordDataTransfer records data transfer
func (p *PostgreSQLCollector) RecordDataTransfer(ctx context.Context, connectionID, bytesSent, bytesReceived int64) error {
	_, err := p.db.ExecContext(ctx,
		`UPDATE connections
		 SET bytes_sent = bytes_sent + $1, bytes_received = bytes_received + $2
		 WHERE id = $3`,
		bytesSent, bytesReceived, connectionID)
	if err != nil {
		return fmt.Errorf("failed to record data transfer: %w", err)
	}
	return nil
}

// RecordBlockedRequest records a blocked request
func (p *PostgreSQLCollector) RecordBlockedRequest(ctx context.Context, clientIP, targetHost, reason string) error {
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO security_events (client_ip, target_host, event_type, reason)
		 VALUES ($1, $2, 'blocked', $3)`,
		clientIP, targetHost, reason)
	if err != nil {
		return fmt.Errorf("failed to record blocked request: %w", err)
	}
	return nil
}

// RecordAllowedRequest records an allowed request
func (p *PostgreSQLCollector) RecordAllowedRequest(ctx context.Context, clientIP, targetHost string) error {
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO security_events (client_ip, target_host, event_type)
		 VALUES ($1, $2, 'allowed')`,
		clientIP, targetHost)
	if err != nil {
		return fmt.Errorf("failed to record allowed request: %w", err)
	}
	return nil
}

// RecordConnectionDuration records connection duration
func (p *PostgreSQLCollector) RecordConnectionDuration(ctx context.Context, connectionID int64, duration time.Duration) error {
	_, err := p.db.ExecContext(ctx,
		`UPDATE connections SET duration_ms = $1 WHERE id = $2`,
		duration.Milliseconds(), connectionID)
	if err != nil {
		return fmt.Errorf("failed to record connection duration: %w", err)
	}
	return nil
}

// HealthCheck checks if the database connection is healthy
func (p *PostgreSQLCollector) HealthCheck(ctx context.Context) error {
	return p.db.PingContext(ctx)
}

// GetOverviewStats returns overview statistics
func (p *PostgreSQLCollector) GetOverviewStats(ctx context.Context) (*OverviewStats, error) {
	stats := &OverviewStats{}

	// Total connections
	query := "SELECT COUNT(*) FROM connections"
	err := p.db.QueryRowContext(ctx, query).Scan(&stats.TotalConnections)
	if err != nil {
		return nil, fmt.Errorf("failed to get total connections: %w", err)
	}

	// Active connections
	query = "SELECT COUNT(*) FROM connections WHERE ended_at IS NULL"
	err = p.db.QueryRowContext(ctx, query).Scan(&stats.ActiveConnections)
	if err != nil {
		return nil, fmt.Errorf("failed to get active connections: %w", err)
	}

	// Total requests
	query = "SELECT COUNT(*) FROM http_requests"
	err = p.db.QueryRowContext(ctx, query).Scan(&stats.TotalRequests)
	if err != nil {
		return nil, fmt.Errorf("failed to get total requests: %w", err)
	}

	// Total errors
	query = "SELECT COUNT(*) FROM errors"
	err = p.db.QueryRowContext(ctx, query).Scan(&stats.TotalErrors)
	if err != nil {
		return nil, fmt.Errorf("failed to get total errors: %w", err)
	}

	// Blocked/Allowed requests
	query = `SELECT
		COALESCE(SUM(CASE WHEN event_type = 'blocked' THEN 1 ELSE 0 END), 0) as blocked,
		COALESCE(SUM(CASE WHEN event_type = 'allowed' THEN 1 ELSE 0 END), 0) as allowed
		FROM security_events`
	err = p.db.QueryRowContext(ctx, query).Scan(&stats.BlockedRequests, &stats.AllowedRequests)
	if err != nil {
		return nil, fmt.Errorf("failed to get security stats: %w", err)
	}

	// Total bytes
	query = "SELECT COALESCE(SUM(bytes_sent), 0), COALESCE(SUM(bytes_received), 0) FROM connections"
	err = p.db.QueryRowContext(ctx, query).Scan(&stats.TotalBytesOut, &stats.TotalBytesIn)
	if err != nil {
		return nil, fmt.Errorf("failed to get total bytes: %w", err)
	}

	// Calculate uptime from first connection
	query = "SELECT MIN(started_at) FROM connections"
	var firstConnection time.Time
	err = p.db.QueryRowContext(ctx, query).Scan(&firstConnection)
	if err != nil {
		stats.Uptime = "No connections yet"
	} else {
		stats.Uptime = time.Since(firstConnection).String()
	}

	return stats, nil
}

// GetTopDomains returns top domains by request count
func (p *PostgreSQLCollector) GetTopDomains(ctx context.Context, limit int) (domains []DomainStats, err error) {
	query := `
		SELECT target_host, COUNT(*) as request_count,
		       SUM(bytes_sent + bytes_received) as total_bytes,
		       MAX(started_at) as last_access
		FROM connections
		GROUP BY target_host
		ORDER BY request_count DESC
		LIMIT $1
	`

	rows, err := p.db.QueryContext(ctx, query, limit)
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
			// Try multiple timestamp formats that PostgreSQL might use
			formats := []string{
				"2006-01-02 15:04:05.999999999-07:00",
				"2006-01-02 15:04:05-07:00",
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
func (p *PostgreSQLCollector) GetSecurityEvents(ctx context.Context, limit int) (events []SecurityEventInfo, err error) {
	query := `
		SELECT id, client_ip, target_host, event_type, reason, timestamp
		FROM security_events
		ORDER BY timestamp DESC
		LIMIT $1
	`

	rows, err := p.db.QueryContext(ctx, query, limit)
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
				"2006-01-02 15:04:05-07:00",
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
func (p *PostgreSQLCollector) GetRecentErrors(ctx context.Context, limit int) (errorSummaries []ErrorSummary, err error) {
	query := `
		SELECT error_type, COUNT(*) as count,
		       MAX(error_message) as last_message,
		       MAX(timestamp) as last_occurred
		FROM errors
		GROUP BY error_type
		ORDER BY count DESC
		LIMIT $1
	`

	rows, err := p.db.QueryContext(ctx, query, limit)
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
				"2006-01-02 15:04:05-07:00",
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
func (p *PostgreSQLCollector) GetBandwidthStats(ctx context.Context, days int) (stats *BandwidthStats, err error) {
	query := `
		SELECT DATE(started_at) as date,
		       SUM(bytes_received) as bytes_in,
		       SUM(bytes_sent) as bytes_out,
		       COUNT(*) as request_count
		FROM connections
		WHERE started_at >= NOW() - INTERVAL '%d days'
		GROUP BY DATE(started_at)
		ORDER BY date ASC
	`

	rows, err := p.db.QueryContext(ctx, fmt.Sprintf(query, days))
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

// Close closes the database connection
func (p *PostgreSQLCollector) Close() error {
	if p.db != nil {
		return p.db.Close()
	}
	return nil
}
