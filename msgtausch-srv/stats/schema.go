package stats

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
)

// ColumnType represents the type of a database column
type ColumnType string

const (
	ColumnTypeSerial    ColumnType = "SERIAL"    // PostgreSQL auto-increment
	ColumnTypeInt       ColumnType = "INT"       // Generic integer type
	ColumnTypeInteger   ColumnType = "INTEGER"   // SQLite/PostgreSQL integer
	ColumnTypeText      ColumnType = "TEXT"      // Text/VARCHAR
	ColumnTypeBigint    ColumnType = "BIGINT"    // Large integers
	ColumnTypeTimestamp ColumnType = "TIMESTAMP" // Timestamp with timezone
	ColumnTypeDateTime  ColumnType = "DATETIME"  // SQLite datetime
	ColumnTypeBytea     ColumnType = "BYTEA"     // PostgreSQL binary data
	ColumnTypeBlob      ColumnType = "BLOB"      // SQLite binary data
	ColumnTypeInet      ColumnType = "INET"      // PostgreSQL IP address
	ColumnTypeJsonb     ColumnType = "JSONB"     // PostgreSQL JSON binary
)

// ColumnDefinition defines a database column
type ColumnDefinition struct {
	Name          string
	Type          ColumnType
	NotNull       bool
	PrimaryKey    bool
	AutoIncrement bool
	DefaultValue  *string
	References    *ForeignKey
}

// ForeignKey defines a foreign key relationship
type ForeignKey struct {
	Table    string
	Column   string
	OnDelete string // CASCADE, SET NULL, etc.
}

// IndexDefinition defines a database index
type IndexDefinition struct {
	Name    string
	Table   string
	Columns []string
	Unique  bool
}

// TableDefinition defines a complete database table
type TableDefinition struct {
	Name    string
	Columns []ColumnDefinition
	Indexes []IndexDefinition
}

// DatabaseSchema defines the complete database schema
type DatabaseSchema struct {
	Tables  []TableDefinition
	Indexes []IndexDefinition
	Version string
}

// SchemaValidator validates database schemas and detects inconsistencies
type SchemaValidator struct {
	db     *sql.DB
	schema *DatabaseSchema
	driver string // "sqlite3" or "postgres"
}

// NewSchemaValidator creates a new schema validator
func NewSchemaValidator(db *sql.DB, schema *DatabaseSchema, driver string) *SchemaValidator {
	return &SchemaValidator{
		db:     db,
		schema: schema,
		driver: driver,
	}
}

// ValidationResult contains the results of schema validation
type ValidationResult struct {
	Valid            bool
	MissingTables    []string
	MissingColumns   []TableColumnMismatch
	MissingIndexes   []string
	ExtraColumns     []TableColumnMismatch
	TypeMismatches   []ColumnTypeMismatch
	ConstraintIssues []ConstraintIssue
	Errors           []error
}

// TableColumnMismatch represents a missing or extra column
type TableColumnMismatch struct {
	Table  string
	Column string
	Issue  string
}

// ColumnTypeMismatch represents a column type mismatch
type ColumnTypeMismatch struct {
	Table    string
	Column   string
	Expected ColumnType
	Actual   string
}

// ConstraintIssue represents a constraint problem
type ConstraintIssue struct {
	Table      string
	Column     string
	Constraint string
	Issue      string
}

// GetExpectedSchema returns the expected database schema
func GetExpectedSchema() *DatabaseSchema {
	return &DatabaseSchema{
		Version: "1.0.0",
		Tables: []TableDefinition{
			{
				Name: "connections",
				Columns: []ColumnDefinition{
					{Name: "id", Type: ColumnTypeSerial, PrimaryKey: true, AutoIncrement: true, NotNull: true},
					{Name: "connection_uuid", Type: ColumnTypeText, NotNull: false},
					{Name: "client_ip", Type: ColumnTypeText, NotNull: true}, // Changed to TEXT for consistency
					{Name: "target_host", Type: ColumnTypeText, NotNull: true},
					{Name: "target_port", Type: ColumnTypeInteger, NotNull: true},
					{Name: "protocol", Type: ColumnTypeText, NotNull: true},
					{Name: "started_at", Type: ColumnTypeTimestamp, NotNull: true},
					{Name: "ended_at", Type: ColumnTypeTimestamp, NotNull: false},
					{Name: "bytes_sent", Type: ColumnTypeBigint, NotNull: false, DefaultValue: stringPtr("0")},
					{Name: "bytes_received", Type: ColumnTypeBigint, NotNull: false, DefaultValue: stringPtr("0")},
					{Name: "duration_ms", Type: ColumnTypeInteger, NotNull: false},
					{Name: "close_reason", Type: ColumnTypeText, NotNull: false},
				},
				Indexes: []IndexDefinition{
					{Name: "idx_connections_client_ip", Table: "connections", Columns: []string{"client_ip"}},
					{Name: "idx_connections_target_host", Table: "connections", Columns: []string{"target_host"}},
					{Name: "idx_connections_started_at", Table: "connections", Columns: []string{"started_at"}},
					{Name: "idx_connections_uuid", Table: "connections", Columns: []string{"connection_uuid"}},
				},
			},
			{
				Name: "http_requests",
				Columns: []ColumnDefinition{
					{Name: "id", Type: ColumnTypeSerial, PrimaryKey: true, AutoIncrement: true, NotNull: true},
					{Name: "connection_id", Type: ColumnTypeInteger, NotNull: true, References: &ForeignKey{Table: "connections", Column: "id", OnDelete: "CASCADE"}},
					{Name: "method", Type: ColumnTypeText, NotNull: true},
					{Name: "url", Type: ColumnTypeText, NotNull: true},
					{Name: "host", Type: ColumnTypeText, NotNull: true},
					{Name: "user_agent", Type: ColumnTypeText, NotNull: false},
					{Name: "content_length", Type: ColumnTypeBigint, NotNull: false, DefaultValue: stringPtr("0")},
					{Name: "header_size", Type: ColumnTypeBigint, NotNull: false, DefaultValue: stringPtr("0")},
					{Name: "timestamp", Type: ColumnTypeTimestamp, NotNull: true},
				},
				Indexes: []IndexDefinition{
					{Name: "idx_http_requests_connection_id", Table: "http_requests", Columns: []string{"connection_id"}},
					{Name: "idx_http_requests_timestamp", Table: "http_requests", Columns: []string{"timestamp"}},
				},
			},
			{
				Name: "http_responses",
				Columns: []ColumnDefinition{
					{Name: "id", Type: ColumnTypeSerial, PrimaryKey: true, AutoIncrement: true, NotNull: true},
					{Name: "connection_id", Type: ColumnTypeInteger, NotNull: true, References: &ForeignKey{Table: "connections", Column: "id", OnDelete: "CASCADE"}},
					{Name: "request_id", Type: ColumnTypeInteger, NotNull: false, References: &ForeignKey{Table: "http_requests", Column: "id", OnDelete: "CASCADE"}},
					{Name: "status_code", Type: ColumnTypeInteger, NotNull: true},
					{Name: "content_length", Type: ColumnTypeBigint, NotNull: false, DefaultValue: stringPtr("0")},
					{Name: "header_size", Type: ColumnTypeBigint, NotNull: false, DefaultValue: stringPtr("0")},
					{Name: "timestamp", Type: ColumnTypeTimestamp, NotNull: true},
				},
				Indexes: []IndexDefinition{
					{Name: "idx_http_responses_connection_id", Table: "http_responses", Columns: []string{"connection_id"}},
					{Name: "idx_http_responses_timestamp", Table: "http_responses", Columns: []string{"timestamp"}},
				},
			},
			{
				Name: "http_request_bodies",
				Columns: []ColumnDefinition{
					{Name: "id", Type: ColumnTypeSerial, PrimaryKey: true, AutoIncrement: true, NotNull: true},
					{Name: "request_id", Type: ColumnTypeInteger, NotNull: true, References: &ForeignKey{Table: "http_requests", Column: "id", OnDelete: "CASCADE"}},
					{Name: "sequence_number", Type: ColumnTypeInteger, NotNull: true},
					{Name: "data", Type: ColumnTypeBytea, NotNull: true}, // Will be BLOB for SQLite
					{Name: "timestamp", Type: ColumnTypeTimestamp, NotNull: true},
				},
				Indexes: []IndexDefinition{
					{Name: "idx_http_request_bodies_request_id", Table: "http_request_bodies", Columns: []string{"request_id"}},
				},
			},
			{
				Name: "http_response_bodies",
				Columns: []ColumnDefinition{
					{Name: "id", Type: ColumnTypeSerial, PrimaryKey: true, AutoIncrement: true, NotNull: true},
					{Name: "response_id", Type: ColumnTypeInteger, NotNull: true, References: &ForeignKey{Table: "http_responses", Column: "id", OnDelete: "CASCADE"}},
					{Name: "sequence_number", Type: ColumnTypeInteger, NotNull: true},
					{Name: "data", Type: ColumnTypeBytea, NotNull: true}, // Will be BLOB for SQLite
					{Name: "timestamp", Type: ColumnTypeTimestamp, NotNull: true},
				},
				Indexes: []IndexDefinition{
					{Name: "idx_http_response_bodies_response_id", Table: "http_response_bodies", Columns: []string{"response_id"}},
				},
			},
			{
				Name: "blocked_requests",
				Columns: []ColumnDefinition{
					{Name: "id", Type: ColumnTypeSerial, PrimaryKey: true, AutoIncrement: true, NotNull: true},
					{Name: "client_ip", Type: ColumnTypeText, NotNull: true},
					{Name: "target_host", Type: ColumnTypeText, NotNull: true},
					{Name: "reason", Type: ColumnTypeText, NotNull: true},
					{Name: "timestamp", Type: ColumnTypeTimestamp, NotNull: true},
				},
				Indexes: []IndexDefinition{
					{Name: "idx_blocked_requests_timestamp", Table: "blocked_requests", Columns: []string{"timestamp"}},
					{Name: "idx_blocked_requests_client_ip", Table: "blocked_requests", Columns: []string{"client_ip"}},
				},
			},
			{
				Name: "allowed_requests",
				Columns: []ColumnDefinition{
					{Name: "id", Type: ColumnTypeSerial, PrimaryKey: true, AutoIncrement: true, NotNull: true},
					{Name: "client_ip", Type: ColumnTypeText, NotNull: true},
					{Name: "target_host", Type: ColumnTypeText, NotNull: true},
					{Name: "timestamp", Type: ColumnTypeTimestamp, NotNull: true},
				},
				Indexes: []IndexDefinition{
					{Name: "idx_allowed_requests_timestamp", Table: "allowed_requests", Columns: []string{"timestamp"}},
				},
			},
			{
				Name: "connection_errors",
				Columns: []ColumnDefinition{
					{Name: "id", Type: ColumnTypeSerial, PrimaryKey: true, AutoIncrement: true, NotNull: true},
					{Name: "connection_id", Type: ColumnTypeInteger, NotNull: false, References: &ForeignKey{Table: "connections", Column: "id", OnDelete: "SET NULL"}},
					{Name: "error_code", Type: ColumnTypeText, NotNull: true},
					{Name: "error_message", Type: ColumnTypeText, NotNull: true},
					{Name: "timestamp", Type: ColumnTypeTimestamp, NotNull: true},
				},
				Indexes: []IndexDefinition{
					{Name: "idx_connection_errors_timestamp", Table: "connection_errors", Columns: []string{"timestamp"}},
					{Name: "idx_connection_errors_connection_id", Table: "connection_errors", Columns: []string{"connection_id"}},
				},
			},
			{
				Name: "errors",
				Columns: []ColumnDefinition{
					{Name: "id", Type: ColumnTypeSerial, PrimaryKey: true, AutoIncrement: true, NotNull: true},
					{Name: "connection_id", Type: ColumnTypeInteger, NotNull: true},
					{Name: "error_type", Type: ColumnTypeText, NotNull: true},
					{Name: "error_message", Type: ColumnTypeText, NotNull: true},
					{Name: "timestamp", Type: ColumnTypeTimestamp, NotNull: true, DefaultValue: stringPtr("CURRENT_TIMESTAMP")},
				},
				Indexes: []IndexDefinition{
					{Name: "idx_errors_timestamp", Table: "errors", Columns: []string{"timestamp"}},
				},
			},
			{
				Name: "security_events",
				Columns: []ColumnDefinition{
					{Name: "id", Type: ColumnTypeSerial, PrimaryKey: true, AutoIncrement: true, NotNull: true},
					{Name: "client_ip", Type: ColumnTypeText, NotNull: true},
					{Name: "target_host", Type: ColumnTypeText, NotNull: true},
					{Name: "event_type", Type: ColumnTypeText, NotNull: true},
					{Name: "reason", Type: ColumnTypeText},
					{Name: "timestamp", Type: ColumnTypeTimestamp, NotNull: true, DefaultValue: stringPtr("CURRENT_TIMESTAMP")},
				},
				Indexes: []IndexDefinition{
					{Name: "idx_security_events_client_ip", Table: "security_events", Columns: []string{"client_ip"}},
					{Name: "idx_security_events_timestamp", Table: "security_events", Columns: []string{"timestamp"}},
				},
			},
			{
				Name: "data_transfers",
				Columns: []ColumnDefinition{
					{Name: "id", Type: ColumnTypeSerial, PrimaryKey: true, AutoIncrement: true, NotNull: true},
					{Name: "connection_id", Type: ColumnTypeInteger, NotNull: true, References: &ForeignKey{Table: "connections", Column: "id", OnDelete: "CASCADE"}},
					{Name: "bytes_sent", Type: ColumnTypeBigint, NotNull: false, DefaultValue: stringPtr("0")},
					{Name: "bytes_received", Type: ColumnTypeBigint, NotNull: false, DefaultValue: stringPtr("0")},
					{Name: "timestamp", Type: ColumnTypeTimestamp, NotNull: true, DefaultValue: stringPtr("CURRENT_TIMESTAMP")},
				},
				Indexes: []IndexDefinition{
					{Name: "idx_data_transfers_connection_id", Table: "data_transfers", Columns: []string{"connection_id"}},
				},
			},
			{
				Name: "recorded_http_requests",
				Columns: []ColumnDefinition{
					{Name: "id", Type: ColumnTypeSerial, PrimaryKey: true, AutoIncrement: true, NotNull: true},
					{Name: "connection_id", Type: ColumnTypeInteger, NotNull: true, References: &ForeignKey{Table: "connections", Column: "id", OnDelete: "CASCADE"}},
					{Name: "method", Type: ColumnTypeText, NotNull: true},
					{Name: "url", Type: ColumnTypeText, NotNull: true},
					{Name: "host", Type: ColumnTypeText, NotNull: true},
					{Name: "user_agent", Type: ColumnTypeText},
					{Name: "request_headers", Type: ColumnTypeText}, // JSON encoded headers
					{Name: "request_body", Type: ColumnTypeBytea},
					{Name: "request_body_size", Type: ColumnTypeInteger, NotNull: false, DefaultValue: stringPtr("0")},
					{Name: "timestamp", Type: ColumnTypeTimestamp, NotNull: true, DefaultValue: stringPtr("CURRENT_TIMESTAMP")},
				},
				Indexes: []IndexDefinition{
					{Name: "idx_recorded_http_requests_connection_id", Table: "recorded_http_requests", Columns: []string{"connection_id"}},
					{Name: "idx_recorded_http_requests_timestamp", Table: "recorded_http_requests", Columns: []string{"timestamp"}},
				},
			},
			{
				Name: "recorded_http_responses",
				Columns: []ColumnDefinition{
					{Name: "id", Type: ColumnTypeSerial, PrimaryKey: true, AutoIncrement: true, NotNull: true},
					{Name: "connection_id", Type: ColumnTypeInteger, NotNull: true, References: &ForeignKey{Table: "connections", Column: "id", OnDelete: "CASCADE"}},
					{Name: "status_code", Type: ColumnTypeInteger, NotNull: true},
					{Name: "response_headers", Type: ColumnTypeText}, // JSON encoded headers
					{Name: "response_body", Type: ColumnTypeBytea},
					{Name: "response_body_size", Type: ColumnTypeInteger, NotNull: false, DefaultValue: stringPtr("0")},
					{Name: "timestamp", Type: ColumnTypeTimestamp, NotNull: true, DefaultValue: stringPtr("CURRENT_TIMESTAMP")},
				},
				Indexes: []IndexDefinition{
					{Name: "idx_recorded_http_responses_connection_id", Table: "recorded_http_responses", Columns: []string{"connection_id"}},
					{Name: "idx_recorded_http_responses_timestamp", Table: "recorded_http_responses", Columns: []string{"timestamp"}},
				},
			},
			{
				Name: "recorded_http_request_body_parts",
				Columns: []ColumnDefinition{
					{Name: "id", Type: ColumnTypeSerial, PrimaryKey: true, AutoIncrement: true, NotNull: true},
					{Name: "request_id", Type: ColumnTypeInteger, NotNull: true, References: &ForeignKey{Table: "recorded_http_requests", Column: "id", OnDelete: "CASCADE"}},
					{Name: "seq_no", Type: ColumnTypeInteger, NotNull: true},
					{Name: "data", Type: ColumnTypeBytea},
					{Name: "part_size", Type: ColumnTypeInteger, NotNull: false, DefaultValue: stringPtr("0")},
					{Name: "timestamp", Type: ColumnTypeTimestamp, NotNull: true, DefaultValue: stringPtr("CURRENT_TIMESTAMP")},
				},
				Indexes: []IndexDefinition{
					{Name: "idx_req_body_parts_request_id", Table: "recorded_http_request_body_parts", Columns: []string{"request_id"}},
					{Name: "idx_req_body_parts_req_seq", Table: "recorded_http_request_body_parts", Columns: []string{"request_id", "seq_no"}},
				},
			},
			{
				Name: "recorded_http_response_body_parts",
				Columns: []ColumnDefinition{
					{Name: "id", Type: ColumnTypeSerial, PrimaryKey: true, AutoIncrement: true, NotNull: true},
					{Name: "response_id", Type: ColumnTypeInteger, NotNull: true, References: &ForeignKey{Table: "recorded_http_responses", Column: "id", OnDelete: "CASCADE"}},
					{Name: "seq_no", Type: ColumnTypeInteger, NotNull: true},
					{Name: "data", Type: ColumnTypeBytea},
					{Name: "part_size", Type: ColumnTypeInteger, NotNull: false, DefaultValue: stringPtr("0")},
					{Name: "timestamp", Type: ColumnTypeTimestamp, NotNull: true, DefaultValue: stringPtr("CURRENT_TIMESTAMP")},
				},
				Indexes: []IndexDefinition{
					{Name: "idx_resp_body_parts_response_id", Table: "recorded_http_response_body_parts", Columns: []string{"response_id"}},
					{Name: "idx_resp_body_parts_resp_seq", Table: "recorded_http_response_body_parts", Columns: []string{"response_id", "seq_no"}},
				},
			},
		},
	}
}

// ValidateSchema validates the current database schema against the expected schema
func (sv *SchemaValidator) ValidateSchema() (*ValidationResult, error) {
	result := &ValidationResult{
		Valid:            true,
		MissingTables:    []string{},
		MissingColumns:   []TableColumnMismatch{},
		MissingIndexes:   []string{},
		ExtraColumns:     []TableColumnMismatch{},
		TypeMismatches:   []ColumnTypeMismatch{},
		ConstraintIssues: []ConstraintIssue{},
		Errors:           []error{},
	}

	// Check tables and columns
	for _, expectedTable := range sv.schema.Tables {
		exists, err := sv.tableExists(expectedTable.Name)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("error checking table %s: %w", expectedTable.Name, err))
			result.Valid = false
			continue
		}

		if !exists {
			result.MissingTables = append(result.MissingTables, expectedTable.Name)
			result.Valid = false
			continue
		}

		// Check columns for this table
		if err := sv.validateTableColumns(expectedTable, result); err != nil {
			result.Errors = append(result.Errors, err)
			result.Valid = false
		}

		// Check indexes for this table
		if err := sv.validateTableIndexes(expectedTable, result); err != nil {
			result.Errors = append(result.Errors, err)
			result.Valid = false
		}
	}

	return result, nil
}

// tableExists checks if a table exists in the database
func (sv *SchemaValidator) tableExists(tableName string) (bool, error) {
	var query string
	switch sv.driver {
	case "sqlite3":
		query = `SELECT name FROM sqlite_master WHERE type='table' AND name=?`
	case "postgres":
		query = `SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename=$1`
	default:
		return false, fmt.Errorf("unsupported driver: %s", sv.driver)
	}

	var name string
	err := sv.db.QueryRow(query, tableName).Scan(&name)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// validateTableColumns validates all columns in a table
func (sv *SchemaValidator) validateTableColumns(table TableDefinition, result *ValidationResult) error {
	actualColumns, err := sv.getTableColumns(table.Name)
	if err != nil {
		return fmt.Errorf("failed to get columns for table %s: %w", table.Name, err)
	}

	// Create maps for easier comparison
	expectedCols := make(map[string]ColumnDefinition)
	for _, col := range table.Columns {
		expectedCols[col.Name] = col
	}

	actualColNames := make(map[string]bool)
	for _, col := range actualColumns {
		actualColNames[col.Name] = true
	}

	// Check for missing columns
	for _, expectedCol := range table.Columns {
		if !actualColNames[expectedCol.Name] {
			result.MissingColumns = append(result.MissingColumns, TableColumnMismatch{
				Table:  table.Name,
				Column: expectedCol.Name,
				Issue:  "missing column",
			})
			result.Valid = false
		}
	}

	// Check for extra columns and type mismatches
	for _, actualCol := range actualColumns {
		if expectedCol, exists := expectedCols[actualCol.Name]; exists {
			// Check type compatibility
			if !sv.isTypeCompatible(expectedCol.Type, actualCol.Type, actualCol.TypeDetails) {
				result.TypeMismatches = append(result.TypeMismatches, ColumnTypeMismatch{
					Table:    table.Name,
					Column:   actualCol.Name,
					Expected: expectedCol.Type,
					Actual:   actualCol.TypeDetails,
				})
				result.Valid = false
			}
		} else {
			result.ExtraColumns = append(result.ExtraColumns, TableColumnMismatch{
				Table:  table.Name,
				Column: actualCol.Name,
				Issue:  "unexpected column",
			})
		}
	}

	return nil
}

// ActualColumn represents a column as it exists in the database
type ActualColumn struct {
	Name         string
	Type         ColumnType
	TypeDetails  string
	NotNull      bool
	DefaultValue *string
}

// getTableColumns gets the actual columns from the database
func (sv *SchemaValidator) getTableColumns(tableName string) ([]ActualColumn, error) {
	var columns []ActualColumn

	switch sv.driver {
	case "sqlite3":
		query := fmt.Sprintf("PRAGMA table_info(%s)", tableName)
		rows, err := sv.db.Query(query)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		for rows.Next() {
			var cid int
			var name, dataType string
			var notNull int
			var defaultValue interface{}
			var pk int

			err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk)
			if err != nil {
				return nil, err
			}

			var defVal *string
			if defaultValue != nil {
				str := fmt.Sprintf("%v", defaultValue)
				defVal = &str
			}

			columns = append(columns, ActualColumn{
				Name:         name,
				Type:         sv.mapSQLiteType(dataType),
				TypeDetails:  dataType,
				NotNull:      notNull == 1,
				DefaultValue: defVal,
			})
		}

	case "postgres":
		query := `
			SELECT column_name, data_type, is_nullable, column_default
			FROM information_schema.columns
			WHERE table_name = $1 AND table_schema = 'public'
			ORDER BY ordinal_position`

		rows, err := sv.db.Query(query, tableName)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		for rows.Next() {
			var name, dataType, nullable string
			var defaultValue sql.NullString

			err := rows.Scan(&name, &dataType, &nullable, &defaultValue)
			if err != nil {
				return nil, err
			}

			var defVal *string
			if defaultValue.Valid {
				defVal = &defaultValue.String
			}

			columns = append(columns, ActualColumn{
				Name:         name,
				Type:         sv.mapPostgresType(dataType),
				TypeDetails:  dataType,
				NotNull:      nullable == "NO",
				DefaultValue: defVal,
			})
		}

	default:
		return nil, fmt.Errorf("unsupported driver: %s", sv.driver)
	}

	return columns, nil
}

// validateTableIndexes validates indexes for a table
func (sv *SchemaValidator) validateTableIndexes(table TableDefinition, result *ValidationResult) error {
	actualIndexes, err := sv.getTableIndexes(table.Name)
	if err != nil {
		return fmt.Errorf("failed to get indexes for table %s: %w", table.Name, err)
	}

	actualIndexNames := make(map[string]bool)
	for _, idx := range actualIndexes {
		actualIndexNames[idx] = true
	}

	// Check for missing indexes
	for _, expectedIdx := range table.Indexes {
		if !actualIndexNames[expectedIdx.Name] {
			result.MissingIndexes = append(result.MissingIndexes, expectedIdx.Name)
			result.Valid = false
		}
	}

	return nil
}

// getTableIndexes gets the actual indexes from the database
func (sv *SchemaValidator) getTableIndexes(tableName string) ([]string, error) {
	var indexes []string

	switch sv.driver {
	case "sqlite3":
		query := fmt.Sprintf("PRAGMA index_list(%s)", tableName)
		rows, err := sv.db.Query(query)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		for rows.Next() {
			var seq int
			var name string
			var unique int
			var origin string
			var partial int

			err := rows.Scan(&seq, &name, &unique, &origin, &partial)
			if err != nil {
				return nil, err
			}

			// Skip automatically created indexes for PRIMARY KEY
			if !strings.HasPrefix(name, "sqlite_autoindex_") {
				indexes = append(indexes, name)
			}
		}

	case "postgres":
		query := `
			SELECT indexname
			FROM pg_indexes
			WHERE tablename = $1 AND schemaname = 'public'`

		rows, err := sv.db.Query(query, tableName)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		for rows.Next() {
			var name string
			err := rows.Scan(&name)
			if err != nil {
				return nil, err
			}

			// Skip primary key indexes
			if !strings.HasSuffix(name, "_pkey") {
				indexes = append(indexes, name)
			}
		}

	default:
		return nil, fmt.Errorf("unsupported driver: %s", sv.driver)
	}

	return indexes, nil
}

// isTypeCompatible checks if two column types are compatible
func (sv *SchemaValidator) isTypeCompatible(expected, actual ColumnType, actualDetails string) bool {
	// Direct match
	if expected == actual {
		return true
	}

	// Handle driver-specific type mappings
	switch sv.driver {
	case "sqlite3":
		return sv.isSQLiteTypeCompatible(expected, actualDetails)
	case "postgres":
		return sv.isPostgresTypeCompatible(expected, actualDetails)
	}

	return false
}

// mapSQLiteType maps SQLite types to our ColumnType enum
func (sv *SchemaValidator) mapSQLiteType(sqliteType string) ColumnType {
	upper := strings.ToUpper(sqliteType)
	switch {
	case strings.Contains(upper, "INTEGER"):
		return ColumnTypeInteger
	case strings.Contains(upper, "TEXT"):
		return ColumnTypeText
	case strings.Contains(upper, "DATETIME"):
		return ColumnTypeDateTime
	case strings.Contains(upper, "BLOB"):
		return ColumnTypeBlob
	default:
		return ColumnType(sqliteType)
	}
}

// mapPostgresType maps PostgreSQL types to our ColumnType enum
func (sv *SchemaValidator) mapPostgresType(pgType string) ColumnType {
	switch pgType {
	case "integer":
		return ColumnTypeInteger
	case "bigint":
		return ColumnTypeBigint
	case "text", "character varying":
		return ColumnTypeText
	case "timestamp with time zone", "timestamp without time zone":
		return ColumnTypeTimestamp
	case "bytea":
		return ColumnTypeBytea
	case "inet":
		return ColumnTypeInet
	case "jsonb":
		return ColumnTypeJsonb
	default:
		return ColumnType(pgType)
	}
}

// isSQLiteTypeCompatible checks SQLite type compatibility
func (sv *SchemaValidator) isSQLiteTypeCompatible(expected ColumnType, actualDetails string) bool {
	upper := strings.ToUpper(actualDetails)

	switch expected {
	case ColumnTypeSerial, ColumnTypeInteger:
		return strings.Contains(upper, "INTEGER")
	case ColumnTypeText:
		return strings.Contains(upper, "TEXT")
	case ColumnTypeBigint:
		return strings.Contains(upper, "INTEGER") || strings.Contains(upper, "BIGINT")
	case ColumnTypeDateTime, ColumnTypeTimestamp:
		return strings.Contains(upper, "DATETIME") || strings.Contains(upper, "TEXT")
	case ColumnTypeBlob, ColumnTypeBytea:
		return strings.Contains(upper, "BLOB")
	}

	return false
}

// isPostgresTypeCompatible checks PostgreSQL type compatibility
func (sv *SchemaValidator) isPostgresTypeCompatible(expected ColumnType, actualDetails string) bool {
	switch expected {
	case ColumnTypeSerial:
		return actualDetails == "integer" || actualDetails == "serial"
	case ColumnTypeInteger:
		return actualDetails == "integer"
	case ColumnTypeInt:
		return actualDetails == "integer"
	case ColumnTypeBigint:
		return actualDetails == "bigint" || actualDetails == "integer" // PostgreSQL integer can be used for expected bigint
	case ColumnTypeText:
		return actualDetails == "text" ||
			strings.HasPrefix(actualDetails, "character varying") ||
			actualDetails == "inet" || // INET is compatible with TEXT for IP addresses
			actualDetails == "jsonb" // JSONB is compatible with TEXT for JSON data
	case ColumnTypeTimestamp:
		return strings.Contains(actualDetails, "timestamp")
	case ColumnTypeBytea:
		return actualDetails == "bytea"
	case ColumnTypeInet:
		return actualDetails == "inet" || actualDetails == "text" // INET or TEXT both work for IP addresses
	case ColumnTypeJsonb:
		return actualDetails == "jsonb" || actualDetails == "text" // JSONB or TEXT both work for JSON
	}

	return false
}

// GenerateReport generates a human-readable validation report
func (result *ValidationResult) GenerateReport() string {
	var report strings.Builder

	if result.Valid {
		report.WriteString("✅ Database schema validation PASSED\n")
		report.WriteString("All tables, columns, and indexes match the expected schema.\n")
		return report.String()
	}

	report.WriteString("❌ Database schema validation FAILED\n\n")

	if len(result.MissingTables) > 0 {
		report.WriteString("Missing Tables:\n")
		for _, table := range result.MissingTables {
			report.WriteString(fmt.Sprintf("  - %s\n", table))
		}
		report.WriteString("\n")
	}

	if len(result.MissingColumns) > 0 {
		report.WriteString("Missing Columns:\n")
		for _, col := range result.MissingColumns {
			report.WriteString(fmt.Sprintf("  - Table '%s' missing column '%s': %s\n", col.Table, col.Column, col.Issue))
		}
		report.WriteString("\n")
	}

	if len(result.TypeMismatches) > 0 {
		report.WriteString("Type Mismatches:\n")
		for _, mismatch := range result.TypeMismatches {
			report.WriteString(fmt.Sprintf("  - Table '%s' column '%s': expected %s, got %s\n",
				mismatch.Table, mismatch.Column, mismatch.Expected, mismatch.Actual))
		}
		report.WriteString("\n")
	}

	if len(result.MissingIndexes) > 0 {
		report.WriteString("Missing Indexes:\n")
		sort.Strings(result.MissingIndexes)
		for _, idx := range result.MissingIndexes {
			report.WriteString(fmt.Sprintf("  - %s\n", idx))
		}
		report.WriteString("\n")
	}

	if len(result.ExtraColumns) > 0 {
		report.WriteString("Extra Columns:\n")
		for _, col := range result.ExtraColumns {
			report.WriteString(fmt.Sprintf("  - Table '%s' has unexpected column '%s': %s\n", col.Table, col.Column, col.Issue))
		}
		report.WriteString("\n")
	}

	if len(result.ConstraintIssues) > 0 {
		report.WriteString("Constraint Issues:\n")
		for _, issue := range result.ConstraintIssues {
			report.WriteString(fmt.Sprintf("  - Table '%s' column '%s' constraint '%s': %s\n",
				issue.Table, issue.Column, issue.Constraint, issue.Issue))
		}
		report.WriteString("\n")
	}

	if len(result.Errors) > 0 {
		report.WriteString("Validation Errors:\n")
		for _, err := range result.Errors {
			report.WriteString(fmt.Sprintf("  - %v\n", err))
		}
	}

	return report.String()
}

// Helper function to create string pointer
func stringPtr(s string) *string {
	return &s
}
