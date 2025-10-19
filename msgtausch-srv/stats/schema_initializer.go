package stats

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
)

// SchemaInitializer handles database schema initialization and migration
type SchemaInitializer struct {
	db     *sql.DB
	driver string
	schema *DatabaseSchema
}

// NewSchemaInitializer creates a new schema initializer
func NewSchemaInitializer(db *sql.DB, driver string) *SchemaInitializer {
	return &SchemaInitializer{
		db:     db,
		driver: driver,
		schema: GetExpectedSchema(),
	}
}

// InitializeSchema initializes the database schema
func (si *SchemaInitializer) InitializeSchema() error {
	logger.Info("Initializing database schema (driver: %s)", si.driver)

	// First, try to create all tables
	for _, table := range si.schema.Tables {
		if err := si.createTable(table); err != nil {
			return fmt.Errorf("failed to create table %s: %w", table.Name, err)
		}
	}

	// Then create indexes
	for _, table := range si.schema.Tables {
		for _, index := range table.Indexes {
			if err := si.createIndex(index); err != nil {
				return fmt.Errorf("failed to create index %s: %w", index.Name, err)
			}
		}
	}

	// Finally, validate the schema
	validator := NewSchemaValidator(si.db, si.schema, si.driver)
	result, err := validator.ValidateSchema()
	if err != nil {
		return fmt.Errorf("schema validation failed: %w", err)
	}

	if !result.Valid {
		logger.Warn("Schema validation found issues:\n%s", result.GenerateReport())

		// Try to fix the issues
		if err := si.fixSchemaIssues(result); err != nil {
			return fmt.Errorf("failed to fix schema issues: %w", err)
		}

		// Re-validate after fixes
		result, err = validator.ValidateSchema()
		if err != nil {
			return fmt.Errorf("schema re-validation failed: %w", err)
		}

		if !result.Valid {
			return fmt.Errorf("schema issues could not be fixed:\n%s", result.GenerateReport())
		}
	}

	logger.Info("Database schema initialization completed successfully")
	return nil
}

// createTable creates a single table
func (si *SchemaInitializer) createTable(table TableDefinition) error {
	exists, err := si.tableExists(table.Name)
	if err != nil {
		return fmt.Errorf("failed to check if table %s exists: %w", table.Name, err)
	}

	if exists {
		logger.Debug("Table %s already exists, checking for missing columns", table.Name)
		return si.ensureTableColumns(table)
	}

	query := si.generateCreateTableSQL(table)
	logger.Debug("Creating table %s with SQL: %s", table.Name, query)

	_, err = si.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to execute CREATE TABLE for %s: %w", table.Name, err)
	}

	logger.Info("Created table: %s", table.Name)
	return nil
}

// ensureTableColumns ensures all expected columns exist in a table
func (si *SchemaInitializer) ensureTableColumns(table TableDefinition) error {
	validator := NewSchemaValidator(si.db, si.schema, si.driver)
	actualColumns, err := validator.getTableColumns(table.Name)
	if err != nil {
		return fmt.Errorf("failed to get columns for table %s: %w", table.Name, err)
	}

	actualColNames := make(map[string]bool)
	for _, col := range actualColumns {
		actualColNames[col.Name] = true
	}

	// Add missing columns
	for _, expectedCol := range table.Columns {
		if !actualColNames[expectedCol.Name] {
			if err := si.addColumn(table.Name, expectedCol); err != nil {
				return fmt.Errorf("failed to add column %s to table %s: %w", expectedCol.Name, table.Name, err)
			}
		}
	}

	return nil
}

// addColumn adds a missing column to a table
func (si *SchemaInitializer) addColumn(tableName string, column ColumnDefinition) error {
	query := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s", tableName, si.generateColumnSQL(column))
	logger.Info("Adding missing column %s to table %s", column.Name, tableName)
	logger.Debug("ALTER TABLE SQL: %s", query)

	_, err := si.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to add column %s: %w", column.Name, err)
	}

	return nil
}

// createIndex creates a single index
func (si *SchemaInitializer) createIndex(index IndexDefinition) error {
	exists, err := si.indexExists(index.Name)
	if err != nil {
		return fmt.Errorf("failed to check if index %s exists: %w", index.Name, err)
	}

	if exists {
		logger.Debug("Index %s already exists", index.Name)
		return nil
	}

	query := si.generateCreateIndexSQL(index)
	logger.Debug("Creating index %s with SQL: %s", index.Name, query)

	_, err = si.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create index %s: %w", index.Name, err)
	}

	logger.Debug("Created index: %s", index.Name)
	return nil
}

// generateCreateTableSQL generates CREATE TABLE SQL for the specific driver
func (si *SchemaInitializer) generateCreateTableSQL(table TableDefinition) string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (\n", table.Name))

	columnDefs := make([]string, 0, len(table.Columns))
	for _, column := range table.Columns {
		columnDefs = append(columnDefs, "  "+si.generateColumnSQL(column))
	}

	builder.WriteString(strings.Join(columnDefs, ",\n"))
	builder.WriteString("\n)")

	return builder.String()
}

// generateColumnSQL generates column definition SQL
func (si *SchemaInitializer) generateColumnSQL(column ColumnDefinition) string {
	var parts []string
	parts = append(parts, column.Name)

	// Handle type conversion for specific drivers
	columnType := si.convertColumnType(column.Type, column.AutoIncrement, column.PrimaryKey)
	parts = append(parts, string(columnType))

	// Handle constraints
	if column.PrimaryKey && si.driver == "sqlite3" && column.AutoIncrement {
		parts = append(parts, "PRIMARY KEY AUTOINCREMENT")
	} else if column.PrimaryKey && si.driver == "postgres" {
		parts = append(parts, "PRIMARY KEY")
	}

	if column.NotNull && !column.PrimaryKey {
		parts = append(parts, "NOT NULL")
	}

	if column.DefaultValue != nil {
		parts = append(parts, fmt.Sprintf("DEFAULT %s", *column.DefaultValue))
	}

	// Handle foreign keys (PostgreSQL style)
	if column.References != nil && si.driver == "postgres" {
		ref := fmt.Sprintf("REFERENCES %s(%s)", column.References.Table, column.References.Column)
		if column.References.OnDelete != "" {
			ref += fmt.Sprintf(" ON DELETE %s", column.References.OnDelete)
		}
		parts = append(parts, ref)
	}

	return strings.Join(parts, " ")
}

// convertColumnType converts our ColumnType to database-specific types
func (si *SchemaInitializer) convertColumnType(colType ColumnType, autoIncrement, primaryKey bool) ColumnType {
	switch si.driver {
	case "sqlite3":
		switch colType {
		case ColumnTypeSerial:
			if autoIncrement && primaryKey {
				return ColumnTypeInteger
			}
			return ColumnTypeInteger
		case ColumnTypeTimestamp:
			return ColumnTypeDateTime
		case ColumnTypeBytea:
			return ColumnTypeBlob
		case ColumnTypeInet:
			return ColumnTypeText
		}
	case "postgres":
		switch colType {
		case ColumnTypeSerial:
			return ColumnTypeSerial
		case ColumnTypeDateTime:
			return "TIMESTAMP WITH TIME ZONE"
		case ColumnTypeBlob:
			return ColumnTypeBytea
		case ColumnTypeText:
			// For PostgreSQL, we can use specific types
			return ColumnTypeText
		}
	}

	return colType
}

// generateCreateIndexSQL generates CREATE INDEX SQL
func (si *SchemaInitializer) generateCreateIndexSQL(index IndexDefinition) string {
	unique := ""
	if index.Unique {
		unique = "UNIQUE "
	}

	columns := strings.Join(index.Columns, ", ")
	return fmt.Sprintf("CREATE %sINDEX IF NOT EXISTS %s ON %s(%s)",
		unique, index.Name, index.Table, columns)
}

// tableExists checks if a table exists
func (si *SchemaInitializer) tableExists(tableName string) (bool, error) {
	var query string
	switch si.driver {
	case "sqlite3":
		query = `SELECT name FROM sqlite_master WHERE type='table' AND name=?`
	case "postgres":
		query = `SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename=$1`
	default:
		return false, fmt.Errorf("unsupported driver: %s", si.driver)
	}

	var name string
	err := si.db.QueryRow(query, tableName).Scan(&name)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

// indexExists checks if an index exists
func (si *SchemaInitializer) indexExists(indexName string) (bool, error) {
	var query string
	switch si.driver {
	case "sqlite3":
		query = `SELECT name FROM sqlite_master WHERE type='index' AND name=?`
	case "postgres":
		query = `SELECT indexname FROM pg_indexes WHERE indexname=$1 AND schemaname='public'`
	default:
		return false, fmt.Errorf("unsupported driver: %s", si.driver)
	}

	var name string
	err := si.db.QueryRow(query, indexName).Scan(&name)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

// fixSchemaIssues attempts to fix common schema issues
func (si *SchemaInitializer) fixSchemaIssues(result *ValidationResult) error {
	logger.Info("Attempting to fix %d schema issues",
		len(result.MissingTables)+len(result.MissingColumns)+len(result.MissingIndexes))

	// Create missing tables
	for _, tableName := range result.MissingTables {
		for _, table := range si.schema.Tables {
			if table.Name == tableName {
				logger.Info("Creating missing table: %s", tableName)
				if err := si.createTable(table); err != nil {
					return fmt.Errorf("failed to create missing table %s: %w", tableName, err)
				}
				break
			}
		}
	}

	// Add missing columns
	for _, missingCol := range result.MissingColumns {
		for _, table := range si.schema.Tables {
			if table.Name == missingCol.Table {
				for _, column := range table.Columns {
					if column.Name == missingCol.Column {
						logger.Info("Adding missing column %s to table %s", missingCol.Column, missingCol.Table)
						if err := si.addColumn(missingCol.Table, column); err != nil {
							return fmt.Errorf("failed to add missing column %s.%s: %w",
								missingCol.Table, missingCol.Column, err)
						}
						break
					}
				}
				break
			}
		}
	}

	// Create missing indexes
	for _, indexName := range result.MissingIndexes {
		for _, table := range si.schema.Tables {
			for _, index := range table.Indexes {
				if index.Name == indexName {
					logger.Info("Creating missing index: %s", indexName)
					if err := si.createIndex(index); err != nil {
						return fmt.Errorf("failed to create missing index %s: %w", indexName, err)
					}
					break
				}
			}
		}
	}

	return nil
}

// ValidateAndInitialize performs complete schema initialization with validation
func (si *SchemaInitializer) ValidateAndInitialize() error {
	logger.Info("Starting schema validation and initialization")

	// First attempt to initialize
	if err := si.InitializeSchema(); err != nil {
		logger.Error("Schema initialization failed: %v", err)
		return err
	}

	// Perform final validation
	validator := NewSchemaValidator(si.db, si.schema, si.driver)
	result, err := validator.ValidateSchema()
	if err != nil {
		return fmt.Errorf("final schema validation failed: %w", err)
	}

	// Log the validation report
	report := result.GenerateReport()
	if result.Valid {
		logger.Info("Schema validation successful:\n%s", report)
	} else {
		logger.Error("Schema validation failed:\n%s", report)
		return fmt.Errorf("schema validation failed after initialization")
	}

	return nil
}
