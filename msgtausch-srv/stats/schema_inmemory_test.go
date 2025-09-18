package stats

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "github.com/mattn/go-sqlite3"
)

// TestInMemoryDatabaseInitialization tests full database initialization with in-memory SQLite
func TestInMemoryDatabaseInitialization(t *testing.T) {
	t.Run("CleanInitialization", func(t *testing.T) {
		// Test clean database initialization from scratch
		db := setupInMemoryDB(t)
		defer db.Close()

		// Initialize schema
		initializer := NewSchemaInitializer(db, "sqlite3")
		err := initializer.ValidateAndInitialize()
		require.NoError(t, err)

		// Verify all expected tables exist
		expectedTables := []string{
			"connections", "http_requests", "http_responses", "http_request_bodies",
			"http_response_bodies", "blocked_requests", "allowed_requests",
			"connection_errors", "errors", "security_events", "data_transfers",
			"recorded_http_requests", "recorded_http_responses",
			"recorded_http_request_body_parts", "recorded_http_response_body_parts",
		}

		for _, table := range expectedTables {
			assertTableExists(t, db, table)
		}

		// Verify schema validation passes
		schema := GetExpectedSchema()
		validator := NewSchemaValidator(db, schema, "sqlite3")
		result, err := validator.ValidateSchema()
		require.NoError(t, err)
		assert.True(t, result.Valid, "Schema validation should pass for clean initialization")
	})

	t.Run("SchemaValidationDetails", func(t *testing.T) {
		// Test detailed schema validation
		db := setupInMemoryDB(t)
		defer db.Close()

		// Initialize schema
		initializer := NewSchemaInitializer(db, "sqlite3")
		err := initializer.ValidateAndInitialize()
		require.NoError(t, err)

		// Test specific table structures
		t.Run("ConnectionsTable", func(t *testing.T) {
			columns := getTableColumns(t, db, "connections")
			expectedColumns := []string{
				"id", "connection_uuid", "client_ip", "target_host", "target_port",
				"protocol", "started_at", "ended_at", "bytes_sent", "bytes_received",
				"duration_ms", "close_reason",
			}

			for _, expected := range expectedColumns {
				assert.Contains(t, columns, expected, "connections table should have column %s", expected)
			}
		})

		t.Run("HttpRequestsTable", func(t *testing.T) {
			columns := getTableColumns(t, db, "http_requests")
			expectedColumns := []string{
				"id", "connection_id", "method", "url", "host", "user_agent",
				"content_length", "header_size", "timestamp",
			}

			for _, expected := range expectedColumns {
				assert.Contains(t, columns, expected, "http_requests table should have column %s", expected)
			}
		})

		t.Run("ErrorsTable", func(t *testing.T) {
			columns := getTableColumns(t, db, "errors")
			expectedColumns := []string{"id", "connection_id", "error_type", "error_message", "timestamp"}

			for _, expected := range expectedColumns {
				assert.Contains(t, columns, expected, "errors table should have column %s", expected)
			}
		})
	})
}

// TestDatabaseMigrationUpgrade tests database migration and upgrade scenarios
func TestDatabaseMigrationUpgrade(t *testing.T) {
	t.Run("MissingConnectionUUIDColumn", func(t *testing.T) {
		// Test migration when connection_uuid column is missing
		db := setupInMemoryDB(t)
		defer db.Close()

		// Create connections table without connection_uuid column (simulating old schema)
		_, err := db.Exec(`
			CREATE TABLE connections (
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
			)
		`)
		require.NoError(t, err)

		// Add some other expected tables to make the migration more realistic
		_, err = db.Exec(`
			CREATE TABLE http_requests (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				connection_id INTEGER NOT NULL,
				method TEXT NOT NULL,
				url TEXT NOT NULL,
				host TEXT NOT NULL,
				user_agent TEXT,
				content_length BIGINT DEFAULT 0,
				header_size BIGINT DEFAULT 0,
				timestamp DATETIME NOT NULL,
				FOREIGN KEY (connection_id) REFERENCES connections(id)
			)
		`)
		require.NoError(t, err)

		// Verify connection_uuid column doesn't exist initially
		columns := getTableColumns(t, db, "connections")
		assert.NotContains(t, columns, "connection_uuid", "connection_uuid should not exist before migration")

		// Run schema initialization (should migrate)
		initializer := NewSchemaInitializer(db, "sqlite3")
		err = initializer.ValidateAndInitialize()
		require.NoError(t, err)

		// Verify connection_uuid column was added
		columns = getTableColumns(t, db, "connections")
		assert.Contains(t, columns, "connection_uuid", "connection_uuid should exist after migration")

		// Verify all expected tables now exist
		expectedTables := []string{
			"connections", "http_requests", "http_responses", "errors", "security_events",
		}
		for _, table := range expectedTables {
			assertTableExists(t, db, table)
		}
	})

	t.Run("MissingTables", func(t *testing.T) {
		// Test migration when multiple tables are missing
		db := setupInMemoryDB(t)
		defer db.Close()

		// Create only a basic connections table
		_, err := db.Exec(`
			CREATE TABLE connections (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				connection_uuid TEXT,
				client_ip TEXT NOT NULL,
				target_host TEXT NOT NULL,
				target_port INTEGER NOT NULL,
				protocol TEXT NOT NULL,
				started_at DATETIME NOT NULL
			)
		`)
		require.NoError(t, err)

		// Verify only connections table exists
		assertTableExists(t, db, "connections")
		assertTableNotExists(t, db, "http_requests")
		assertTableNotExists(t, db, "errors")
		assertTableNotExists(t, db, "security_events")

		// Run schema initialization (should create missing tables)
		initializer := NewSchemaInitializer(db, "sqlite3")
		err = initializer.ValidateAndInitialize()
		require.NoError(t, err)

		// Verify all tables now exist
		expectedTables := []string{
			"connections", "http_requests", "http_responses", "errors", "security_events",
			"data_transfers", "recorded_http_requests", "recorded_http_responses",
		}
		for _, table := range expectedTables {
			assertTableExists(t, db, table)
		}
	})

	t.Run("TypeMismatchDetection", func(t *testing.T) {
		// Test detection of type mismatches
		db := setupInMemoryDB(t)
		defer db.Close()

		// Create http_requests table with wrong content_length type
		_, err := db.Exec(`
			CREATE TABLE connections (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				connection_uuid TEXT,
				client_ip TEXT NOT NULL,
				target_host TEXT NOT NULL,
				target_port INTEGER NOT NULL,
				protocol TEXT NOT NULL,
				started_at DATETIME NOT NULL
			)
		`)
		require.NoError(t, err)

		_, err = db.Exec(`
			CREATE TABLE http_requests (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				connection_id INTEGER NOT NULL,
				method TEXT NOT NULL,
				url TEXT NOT NULL,
				host TEXT NOT NULL,
				user_agent TEXT,
				content_length TEXT NOT NULL, -- Wrong type! Should be BIGINT
				timestamp DATETIME NOT NULL
			)
		`)
		require.NoError(t, err)

		// Run schema validation (should detect type mismatch)
		schema := GetExpectedSchema()
		validator := NewSchemaValidator(db, schema, "sqlite3")
		result, err := validator.ValidateSchema()
		require.NoError(t, err)

		// Should detect the type mismatch
		assert.False(t, result.Valid, "Schema validation should fail due to type mismatch")
		assert.NotEmpty(t, result.TypeMismatches, "Should detect type mismatches")

		// Find the specific type mismatch
		found := false
		for _, mismatch := range result.TypeMismatches {
			if mismatch.Table == "http_requests" && mismatch.Column == "content_length" {
				assert.Equal(t, ColumnTypeBigint, mismatch.Expected)
				assert.Equal(t, "TEXT", mismatch.Actual)
				found = true
				break
			}
		}
		assert.True(t, found, "Should detect content_length type mismatch")
	})
}

// TestSchemaValidationReporting tests schema validation reporting functionality
func TestSchemaValidationReporting(t *testing.T) {
	t.Run("ValidSchemaReport", func(t *testing.T) {
		db := setupInMemoryDB(t)
		defer db.Close()

		// Initialize complete schema
		initializer := NewSchemaInitializer(db, "sqlite3")
		err := initializer.ValidateAndInitialize()
		require.NoError(t, err)

		// Validate and generate report
		schema := GetExpectedSchema()
		validator := NewSchemaValidator(db, schema, "sqlite3")
		result, err := validator.ValidateSchema()
		require.NoError(t, err)

		report := result.GenerateReport()
		assert.Contains(t, report, "✅ Database schema validation PASSED")
		assert.Contains(t, report, "All tables, columns, and indexes match the expected schema")
	})

	t.Run("InvalidSchemaReport", func(t *testing.T) {
		db := setupInMemoryDB(t)
		defer db.Close()

		// Create incomplete schema
		_, err := db.Exec(`
			CREATE TABLE connections (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				client_ip TEXT NOT NULL,
				target_host TEXT NOT NULL
				-- Missing many columns
			)
		`)
		require.NoError(t, err)

		// Validate and generate report
		schema := GetExpectedSchema()
		validator := NewSchemaValidator(db, schema, "sqlite3")
		result, err := validator.ValidateSchema()
		require.NoError(t, err)

		report := result.GenerateReport()
		assert.Contains(t, report, "❌ Database schema validation FAILED")
		assert.Contains(t, report, "Missing Tables:")
		assert.Contains(t, report, "Missing Columns:")
		assert.Contains(t, report, "Missing Indexes:")

		// Should list specific missing items
		assert.Contains(t, report, "http_requests")
		assert.Contains(t, report, "connection_uuid")
	})
}

// TestInMemoryCollectorIntegration tests full integration with SQLiteCollector
func TestInMemoryCollectorIntegration(t *testing.T) {
	t.Run("CollectorInitialization", func(t *testing.T) {
		// Test that SQLiteCollector can initialize with in-memory database
		collector, err := NewSQLiteCollector(":memory:")
		require.NoError(t, err)
		defer collector.Close()

		// Test basic operations
		ctx := context.Background()

		// Start a connection
		connID, err := collector.StartConnectionWithUUID(ctx, "test-uuid-1", "127.0.0.1", "example.com", 80, "http")
		require.NoError(t, err)
		assert.Greater(t, connID, int64(0))

		// Record HTTP request
		err = collector.RecordHTTPRequest(ctx, connID, "GET", "http://example.com/", "example.com", "Mozilla/5.0", 0)
		require.NoError(t, err)

		// Record HTTP response
		err = collector.RecordHTTPResponse(ctx, connID, 200, 1024)
		require.NoError(t, err)

		// End connection
		err = collector.EndConnection(ctx, connID, 1024, 2048, 500*time.Millisecond, "normal")
		require.NoError(t, err)

		// Verify data was recorded
		stats, err := collector.GetOverviewStats(ctx)
		require.NoError(t, err)
		assert.Equal(t, int64(1), stats.TotalConnections)
		assert.Equal(t, int64(1), stats.TotalRequests)
	})

	t.Run("CollectorErrorHandling", func(t *testing.T) {
		collector, err := NewSQLiteCollector(":memory:")
		require.NoError(t, err)
		defer collector.Close()

		ctx := context.Background()

		// Test error recording
		connID, err := collector.StartConnection(ctx, "127.0.0.1", "example.com", 80, "http")
		require.NoError(t, err)

		err = collector.RecordError(ctx, connID, "connection_timeout", "Connection timed out after 30s")
		require.NoError(t, err)

		// Verify error was recorded
		stats, err := collector.GetOverviewStats(ctx)
		require.NoError(t, err)
		assert.Equal(t, int64(1), stats.TotalErrors)
	})
}

// TestConcurrentSchemaOperations tests concurrent access to schema operations
func TestConcurrentSchemaOperations(t *testing.T) {
	t.Run("ConcurrentValidation", func(t *testing.T) {
		// Use individual databases for each goroutine to avoid SQLite concurrency issues
		schema := GetExpectedSchema()
		const numGoroutines = 5

		results := make(chan bool, numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func() {
				// Each goroutine gets its own in-memory database
				db := setupInMemoryDB(t)
				defer db.Close()

				// Initialize schema
				initializer := NewSchemaInitializer(db, "sqlite3")
				err := initializer.ValidateAndInitialize()
				if err != nil {
					results <- false
					return
				}

				// Validate schema
				validator := NewSchemaValidator(db, schema, "sqlite3")
				result, err := validator.ValidateSchema()
				results <- err == nil && result.Valid
			}()
		}

		// All validations should succeed
		for i := 0; i < numGoroutines; i++ {
			assert.True(t, <-results, "Concurrent validation should succeed")
		}
	})
}

// Helper functions

func setupInMemoryDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)

	// Enable foreign keys and WAL mode for realistic testing
	_, err = db.Exec("PRAGMA foreign_keys=ON")
	require.NoError(t, err)

	_, err = db.Exec("PRAGMA journal_mode=WAL")
	require.NoError(t, err)

	return db
}

func assertTableExists(t *testing.T, db *sql.DB, tableName string) {
	var name string
	err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", tableName).Scan(&name)
	assert.NoError(t, err, "Table %s should exist", tableName)
	assert.Equal(t, tableName, name)
}

func assertTableNotExists(t *testing.T, db *sql.DB, tableName string) {
	var name string
	err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", tableName).Scan(&name)
	assert.Equal(t, sql.ErrNoRows, err, "Table %s should not exist", tableName)
}

func getTableColumns(t *testing.T, db *sql.DB, tableName string) []string {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
	require.NoError(t, err)
	defer rows.Close()

	var columns []string
	for rows.Next() {
		var cid int
		var name, dataType string
		var notNull int
		var defaultValue interface{}
		var pk int

		err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk)
		require.NoError(t, err)
		columns = append(columns, name)
	}

	return columns
}