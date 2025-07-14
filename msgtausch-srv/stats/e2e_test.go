package stats

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEndToEndStatisticsFlow(t *testing.T) {
	// Create temporary database file
	dbPath := "test_e2e_stats.db"
	defer os.Remove(dbPath)

	// Test configuration
	cfg := config.StatisticsConfig{
		Enabled:       true,
		Backend:       "sqlite",
		SQLitePath:    dbPath,
		BufferSize:    100,
		FlushInterval: 1, // 1 second for testing
	}

	// Create factory and collector
	factory := NewCollectorFactory()
	collector, err := factory.CreateCollector(cfg)
	require.NoError(t, err)
	defer collector.Close()

	// Test buffered collector specifically
	bufferedCollector, ok := collector.(*BufferedCollector)
	require.True(t, ok, "Expected BufferedCollector")

	ctx := context.Background()

	// Test 1: Basic connection lifecycle
	t.Run("ConnectionLifecycle", func(t *testing.T) {
		connID, err := collector.StartConnection(ctx, "192.168.1.100", "example.com", 80, "http")
		require.NoError(t, err)
		assert.Greater(t, connID, int64(0))

		// Record HTTP request
		err = collector.RecordHTTPRequest(ctx, connID, "GET", "/api/data", "example.com", "Mozilla/5.0", 0)
		require.NoError(t, err)

		// Record HTTP response
		err = collector.RecordHTTPResponse(ctx, connID, 200, 1024)
		require.NoError(t, err)

		// Record data transfer
		err = collector.RecordDataTransfer(ctx, connID, 512, 1024)
		require.NoError(t, err)

		// End connection
		err = collector.EndConnection(ctx, connID, 512, 1024, 2*time.Second, "normal")
		require.NoError(t, err)
	})

	// Test 2: Security events
	t.Run("SecurityEvents", func(t *testing.T) {
		// Blocked request
		err = collector.RecordBlockedRequest(ctx, "192.168.1.101", "malicious.com", "blocklist")
		require.NoError(t, err)

		// Allowed request
		err = collector.RecordAllowedRequest(ctx, "192.168.1.102", "safe-site.com")
		require.NoError(t, err)
	})

	// Test 3: Error recording
	t.Run("ErrorRecording", func(t *testing.T) {
		connID, err := collector.StartConnection(ctx, "192.168.1.103", "timeout.com", 443, "https")
		require.NoError(t, err)

		err = collector.RecordError(ctx, connID, "timeout", "connection timeout after 30s")
		require.NoError(t, err)

		err = collector.EndConnection(ctx, connID, 0, 0, 30*time.Second, "timeout")
		require.NoError(t, err)
	})

	// Force flush to ensure all data is written
	bufferedCollector.ForceFlush()

	// Test 4: Verify data persistence
	t.Run("DataPersistence", func(t *testing.T) {
		db, err := sql.Open("sqlite3", dbPath)
		require.NoError(t, err)
		defer db.Close()

		// Verify connections
		var connCount int
		err = db.QueryRow("SELECT COUNT(*) FROM connections").Scan(&connCount)
		require.NoError(t, err)
		assert.Equal(t, 2, connCount, "Expected 2 connections (one completed, one with timeout)")

		// Verify HTTP requests
		var requestCount int
		err = db.QueryRow("SELECT COUNT(*) FROM http_requests").Scan(&requestCount)
		require.NoError(t, err)
		assert.Equal(t, 1, requestCount, "Expected 1 HTTP request")

		// Verify HTTP responses
		var responseCount int
		err = db.QueryRow("SELECT COUNT(*) FROM http_responses").Scan(&responseCount)
		require.NoError(t, err)
		assert.Equal(t, 1, responseCount, "Expected 1 HTTP response")

		// Verify security events
		var securityCount int
		err = db.QueryRow("SELECT COUNT(*) FROM security_events").Scan(&securityCount)
		require.NoError(t, err)
		assert.Equal(t, 2, securityCount, "Expected 2 security events")

		// Verify errors
		var errorCount int
		err = db.QueryRow("SELECT COUNT(*) FROM errors").Scan(&errorCount)
		require.NoError(t, err)
		assert.Equal(t, 1, errorCount, "Expected 1 error")

		// Verify connection details
		var clientIP, targetHost, protocol, closeReason string
		var bytesSent, bytesReceived int64
		err = db.QueryRow(`
			SELECT client_ip, target_host, protocol, bytes_sent, bytes_received, close_reason
			FROM connections WHERE client_ip = '192.168.1.100'
		`).Scan(&clientIP, &targetHost, &protocol, &bytesSent, &bytesReceived, &closeReason)
		require.NoError(t, err)
		assert.Equal(t, "192.168.1.100", clientIP)
		assert.Equal(t, "example.com", targetHost)
		assert.Equal(t, "http", protocol)
		assert.Equal(t, int64(1024), bytesSent)
		assert.Equal(t, int64(2048), bytesReceived)
		assert.Equal(t, "normal", closeReason)

		// Verify security events details
		var eventType, reason string
		err = db.QueryRow(`
			SELECT event_type, reason FROM security_events
			WHERE client_ip = '192.168.1.101'
		`).Scan(&eventType, &reason)
		require.NoError(t, err)
		assert.Equal(t, "blocked", eventType)
		assert.Equal(t, "blocklist", reason)
	})
}

func TestBufferedCollectorGracefulShutdown(t *testing.T) {
	dbPath := "test_shutdown_stats.db"
	defer os.Remove(dbPath)

	cfg := config.StatisticsConfig{
		Enabled:       true,
		Backend:       "sqlite",
		SQLitePath:    dbPath,
		FlushInterval: 300, // 5 minutes, but we'll close before flush
	}

	factory := NewCollectorFactory()
	collector, err := factory.CreateCollector(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	// Record some data
	connID, _ := collector.StartConnection(ctx, "192.168.1.200", "test.com", 80, "http")
	collector.RecordHTTPRequest(ctx, connID, "POST", "/data", "test.com", "test-agent", 100)
	collector.RecordAllowedRequest(ctx, "192.168.1.200", "test.com")

	// Close should trigger final flush
	err = collector.Close()
	require.NoError(t, err)

	// Verify data was flushed on close
	db, err := sql.Open("sqlite3", dbPath)
	require.NoError(t, err)
	defer db.Close()

	var connCount, securityCount int
	db.QueryRow("SELECT COUNT(*) FROM connections").Scan(&connCount)
	db.QueryRow("SELECT COUNT(*) FROM security_events").Scan(&securityCount)

	assert.Equal(t, 1, connCount)
	assert.Equal(t, 1, securityCount)
}

func TestConfigurationVariations(t *testing.T) {
	tests := []struct {
		name   string
		config config.StatisticsConfig
	}{
		{
			name: "disabled",
			config: config.StatisticsConfig{
				Enabled: false,
			},
		},
		{
			name: "sqlite_custom_path",
			config: config.StatisticsConfig{
				Enabled:    true,
				Backend:    "sqlite",
				SQLitePath: "custom_stats.db",
			},
		},
		{
			name: "dummy_backend",
			config: config.StatisticsConfig{
				Enabled: true,
				Backend: "dummy",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.config.SQLitePath != "" {
				defer os.Remove(tt.config.SQLitePath)
			}

			factory := NewCollectorFactory()
			collector, err := factory.CreateCollector(tt.config)
			require.NoError(t, err)

			ctx := context.Background()
			_, err = collector.StartConnection(ctx, "test", "test.com", 80, "http")
			require.NoError(t, err)

			err = collector.Close()
			require.NoError(t, err)
		})
	}
}

func TestHealthCheck(t *testing.T) {
	tests := []struct {
		name   string
		config config.StatisticsConfig
	}{
		{
			name: "dummy_healthy",
			config: config.StatisticsConfig{
				Enabled: false,
			},
		},
		{
			name: "sqlite_healthy",
			config: config.StatisticsConfig{
				Enabled:    true,
				Backend:    "sqlite",
				SQLitePath: "test_health.db",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.config.SQLitePath != "" {
				defer os.Remove(tt.config.SQLitePath)
			}

			factory := NewCollectorFactory()
			collector, err := factory.CreateCollector(tt.config)
			require.NoError(t, err)
			defer collector.Close()

			ctx := context.Background()
			err = collector.HealthCheck(ctx)
			require.NoError(t, err)
		})
	}
}

func TestConcurrentOperations(t *testing.T) {
	dbPath := "test_concurrent.db"
	defer os.Remove(dbPath)

	cfg := config.StatisticsConfig{
		Enabled:       true,
		Backend:       "sqlite",
		SQLitePath:    dbPath,
		FlushInterval: 1,
	}

	factory := NewCollectorFactory()
	collector, err := factory.CreateCollector(cfg)
	require.NoError(t, err)
	defer collector.Close()

	ctx := context.Background()
	const numGoroutines = 10
	const operationsPerGoroutine = 100

	done := make(chan bool)
	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			for j := 0; j < operationsPerGoroutine; j++ {
				connID := int64(goroutineID*1000 + j)
				collector.StartConnection(ctx, fmt.Sprintf("client-%d", goroutineID),
					fmt.Sprintf("site-%d.com", j), 80, "http")
				collector.RecordHTTPRequest(ctx, connID, "GET", "/",
					fmt.Sprintf("site-%d.com", j), "agent", 0)
				collector.RecordAllowedRequest(ctx,
					fmt.Sprintf("client-%d", goroutineID), fmt.Sprintf("site-%d.com", j))
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Force flush and verify
	if bc, ok := collector.(*BufferedCollector); ok {
		bc.ForceFlush()
	}

	db, err := sql.Open("sqlite3", dbPath)
	require.NoError(t, err)
	defer db.Close()

	var totalConnections int
	err = db.QueryRow("SELECT COUNT(*) FROM connections").Scan(&totalConnections)
	require.NoError(t, err)
	assert.Equal(t, numGoroutines*operationsPerGoroutine, totalConnections)
}
