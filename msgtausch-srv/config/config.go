package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"
)

// ProxyType defines the type of proxy server
type ProxyType string

// Available proxy types
const (
	ProxyTypeStandard ProxyType = "standard" // Regular proxy server
	ProxyTypeHTTP     ProxyType = "http"     // HTTP intercepting proxy
	ProxyTypeHTTPS    ProxyType = "https"    // HTTPS intercepting proxy
	ProxyTypeQUIC     ProxyType = "quic"     // QUIC/HTTP3 intercepting proxy
)

// InterceptionConfig defines settings for HTTP/HTTPS traffic interception
type InterceptionConfig struct {
	Enabled   bool   // Whether interception is enabled
	HTTP      bool   // Whether to intercept HTTP traffic
	HTTPS     bool   // Whether to intercept HTTPS traffic
	CAFile    string // Path to CA certificate file (for HTTPS/QUIC interceptor)
	CAKeyFile string // Path to CA private key file (for HTTPS/QUIC interceptor)
}

// PortalConfig defines settings for the admin portal
type PortalConfig struct {
	Username string `json:"username"` // Optional username for portal authentication
	Password string `json:"password"` // Optional password for portal authentication
}

// ServerConfig defines configuration for a single proxy server instance
type ServerConfig struct {
	Type                 ProxyType // Type of proxy server (standard, http, https)
	ListenAddress        string    // Address to listen on (e.g., 127.0.0.1:8080)
	Enabled              bool      // Whether this server is enabled
	InterceptorName      string    // Identifier for this interceptor (optional)
	MaxConnections       int       // Maximum connections for this server instance
	ConnectionsPerClient int       // Maximum connections per client IP
}

// Config represents the main configuration structure for the proxy server.
type Config struct {
	Servers                  []ServerConfig // List of proxy server configurations
	TimeoutSeconds           int            // Global timeout for all connections
	MaxConcurrentConnections int            // Global max concurrent connections
	Classifiers              map[string]Classifier
	Forwards                 []Forward
	Allowlist                Classifier         // Optional host allowlist using classifier
	Blocklist                Classifier         // Optional host blocklist using classifier
	Interception             InterceptionConfig // Global settings for traffic interception
	Statistics               StatisticsConfig   // Statistics collection configuration
	Portal                   PortalConfig       // Portal authentication configuration
}

// ForwardType defines the type of forwarding rule.
type ForwardType int

const (
	// ForwardTypeDefaultNetwork represents the default network forwarding type.
	ForwardTypeDefaultNetwork ForwardType = iota
	// ForwardTypeSocks5 represents SOCKS5 proxy forwarding.
	ForwardTypeSocks5
	// ForwardTypeProxy represents HTTP proxy forwarding.
	ForwardTypeProxy
)

// Forward defines the interface for forwarding configurations.
type Forward interface {
	Type() ForwardType
	Classifier() Classifier
}

// ForwardDefaultNetwork represents default network forwarding configuration.
type ForwardDefaultNetwork struct {
	ClassifierData Classifier
	ForceIPv4      bool
}

// Type returns the forwarding type for this configuration.
func (c *ForwardDefaultNetwork) Type() ForwardType {
	return ForwardTypeDefaultNetwork
}

// Classifier returns the classifier for this forwarding rule.
func (c *ForwardDefaultNetwork) Classifier() Classifier {
	if c.ClassifierData == nil {
		// Provide a default classifier if none specified
		return &ClassifierTrue{}
	}
	return c.ClassifierData
}

// ForwardSocks5 represents SOCKS5 proxy forwarding configuration.
type ForwardSocks5 struct {
	ClassifierData Classifier
	Address        string
	Username       *string
	Password       *string
	ForceIPv4      bool
}

// Type returns the forwarding type for this configuration.
func (c *ForwardSocks5) Type() ForwardType {
	return ForwardTypeSocks5
}

// Classifier returns the classifier for this forwarding rule.
func (c *ForwardSocks5) Classifier() Classifier {
	if c.ClassifierData == nil {
		// Provide a default classifier if none specified
		return &ClassifierTrue{}
	}
	return c.ClassifierData
}

// ForwardProxy represents HTTP proxy forwarding configuration.
type ForwardProxy struct {
	ClassifierData Classifier
	Address        string
	Username       *string
	Password       *string
	ForceIPv4      bool
}

// Type returns the forwarding type for this configuration.
func (c *ForwardProxy) Type() ForwardType {
	return ForwardTypeProxy
}

// Classifier returns the classifier for this forwarding rule.
func (c *ForwardProxy) Classifier() Classifier {
	if c.ClassifierData == nil {
		// Provide a default classifier if none specified
		return &ClassifierTrue{}
	}
	return c.ClassifierData
}

// LoadConfig loads configuration from the specified file path.
func LoadConfig(configPath string) (*Config, error) {
	// Default configuration with a standard proxy server
	cfg := &Config{
		Servers: []ServerConfig{
			{
				Type:                 ProxyTypeStandard,
				ListenAddress:        "127.0.0.1:8080",
				Enabled:              true,
				MaxConnections:       100,
				ConnectionsPerClient: 10,
			},
		},
		TimeoutSeconds:           30,
		MaxConcurrentConnections: 100,
	}

	// If config file exists, load it first
	if configPath != "" {
		var err error

		ext := filepath.Ext(configPath)
		switch strings.ToLower(ext) {
		case ".json":
			err = loadJSONConfig(configPath, cfg)
		case ".hcl":
			err = loadHCLConfig(configPath, cfg)
		default:
			return nil, fmt.Errorf("unsupported config file format: %s", ext)
		}

		if err != nil {
			return nil, err
		}
	}

	// Apply environment variables (these override config file values)
	loadConfigFromEnv(cfg)

	return cfg, nil
}

// StatisticsConfig holds configuration for statistics collection
type StatisticsConfig struct {
	Enabled       bool   `json:"enabled" hcl:"enabled"`
	Backend       string `json:"backend" hcl:"backend"`               // "sqlite", "postgres", or "dummy"
	SQLitePath    string `json:"sqlite_path" hcl:"sqlite_path"`       // Path to SQLite database file
	PostgresDSN   string `json:"postgres_dsn" hcl:"postgres_dsn"`     // PostgreSQL connection string
	BufferSize    int    `json:"buffer_size" hcl:"buffer_size"`       // Buffer size for batch operations
	FlushInterval int    `json:"flush_interval" hcl:"flush_interval"` // Flush interval in seconds
}

// validateConfigKeys checks for common key mistakes like using underscores instead of hyphens
func validateConfigKeys(data map[string]any) error {
	// Define mapping of incorrect underscore keys to correct hyphenated keys
	keyMappings := map[string]string{
		"listen_address":             "listen-address",
		"timeout_seconds":            "timeout-seconds",
		"max_concurrent_connections": "max-concurrent-connections",
		"max_connections":            "max-connections",
		"connections_per_client":     "connections-per-client",
		"interceptor_name":           "interceptor-name",
		"force_ipv4":                 "force-ipv4",
		"default_network":            "default-network",
		"domains_file":               "domains-file",
	}

	// Check top-level keys
	for key := range data {
		if correctKey, exists := keyMappings[key]; exists {
			return fmt.Errorf("invalid config key '%s': use '%s' instead (hyphens, not underscores)", key, correctKey)
		}
	}

	// Check server configuration keys
	if servers, ok := data["servers"].([]any); ok {
		for i, serverData := range servers {
			if serverMap, ok := serverData.(map[string]any); ok {
				for key := range serverMap {
					if correctKey, exists := keyMappings[key]; exists {
						return fmt.Errorf("invalid server config key '%s' at index %d: use '%s' instead (hyphens, not underscores)", key, i, correctKey)
					}
				}
			}
		}
	}

	// Check forwards configuration keys
	if forwards, ok := data["forwards"].([]any); ok {
		for i, forwardData := range forwards {
			if forwardMap, ok := forwardData.(map[string]any); ok {
				for key := range forwardMap {
					if correctKey, exists := keyMappings[key]; exists {
						return fmt.Errorf("invalid forward config key '%s' at index %d: use '%s' instead (hyphens, not underscores)", key, i, correctKey)
					}
				}
			}
		}
	}

	// Check classifier keys recursively
	if classifiers, ok := data["classifiers"].(map[string]any); ok {
		for name, classifierData := range classifiers {
			if classifierMap, ok := classifierData.(map[string]any); ok {
				if err := validateClassifierKeys(classifierMap, fmt.Sprintf("classifier '%s'", name)); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// validateClassifierKeys recursively validates classifier configuration keys
func validateClassifierKeys(classifierMap map[string]any, context string) error {
	keyMappings := map[string]string{
		"domains_file": "domains-file",
		"not_equal":    "not-equal",
		"not_contains": "not-contains",
	}

	for key := range classifierMap {
		if correctKey, exists := keyMappings[key]; exists {
			return fmt.Errorf("invalid %s key '%s': use '%s' instead (hyphens, not underscores)", context, key, correctKey)
		}
	}

	// Recursively check nested classifiers
	if classifiers, ok := classifierMap["classifiers"].([]any); ok {
		for i, nestedClassifier := range classifiers {
			if nestedMap, ok := nestedClassifier.(map[string]any); ok {
				if err := validateClassifierKeys(nestedMap, fmt.Sprintf("%s nested classifier at index %d", context, i)); err != nil {
					return err
				}
			}
		}
	}

	if classifier, ok := classifierMap["classifier"].(map[string]any); ok {
		if err := validateClassifierKeys(classifier, fmt.Sprintf("%s nested classifier", context)); err != nil {
			return err
		}
	}

	return nil
}

func loadJSONConfig(configPath string, cfg *Config) error {
	cleanPath := filepath.Clean(configPath)
	if !filepath.IsAbs(cleanPath) {
		absPath, err := filepath.Abs(cleanPath)
		if err != nil {
			return fmt.Errorf("invalid config file path: %w", err)
		}
		cleanPath = absPath
	}
	file, err := os.Open(cleanPath)
	if err != nil {
		return fmt.Errorf("failed to open config file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			logger.Error("Error closing config file: %v", closeErr)
		}
	}()

	// First, decode into a map to handle the hyphenated keys
	var data map[string]any
	err = json.NewDecoder(file).Decode(&data)
	if err != nil {
		return fmt.Errorf("failed to decode JSON config: %w", err)
	}

	// Validate config keys and provide helpful error messages for underscore usage
	if err := validateConfigKeys(data); err != nil {
		return err
	}

	// Use the same parsing logic as HCL by manually mapping values from the map to Config struct
	return parseConfigData(data, cfg)
}

func loadHCLConfig(configPath string, cfg *Config) error {
	cleanPath := filepath.Clean(configPath)
	if !filepath.IsAbs(cleanPath) {
		absPath, err := filepath.Abs(cleanPath)
		if err != nil {
			return fmt.Errorf("invalid config file path: %w", err)
		}
		cleanPath = absPath
	}

	// Parse HCL file
	parser := hclparse.NewParser()
	file, diags := parser.ParseHCLFile(cleanPath)
	if diags.HasErrors() {
		return fmt.Errorf("failed to parse HCL config: %s", diags.Error())
	}

	// Create evaluation context
	evalCtx := &hcl.EvalContext{}

	// Get all attributes (we'll accept any attributes dynamically)
	attrs, diags := file.Body.JustAttributes()
	if diags.HasErrors() {
		return fmt.Errorf("failed to decode HCL config: %s", diags.Error())
	}

	// Convert HCL attributes to a map[string]any
	data := make(map[string]any)
	for name, attr := range attrs {
		val, diags := attr.Expr.Value(evalCtx)
		if diags.HasErrors() {
			return fmt.Errorf("failed to evaluate HCL attribute %s: %s", name, diags.Error())
		}

		// Convert cty.Value to Go types
		goVal, err := convertCtyValueToGo(val)
		if err != nil {
			return fmt.Errorf("failed to convert HCL value for %s: %w", name, err)
		}
		data[name] = goVal
	}

	// Validate config keys and provide helpful error messages for underscore usage
	if err := validateConfigKeys(data); err != nil {
		return err
	}

	// Use the same parsing logic as JSON by manually mapping values from the map to Config struct
	return parseConfigData(data, cfg)
}

// convertCtyValueToGo converts a cty.Value to a Go value (map[string]any, []any, etc.)
func convertCtyValueToGo(val cty.Value) (any, error) {
	if val.IsNull() {
		return nil, nil
	}

	switch {
	case val.Type() == cty.String:
		return val.AsString(), nil
	case val.Type() == cty.Number:
		f, _ := val.AsBigFloat().Float64()
		// Try to convert to int if it's a whole number
		if f == float64(int64(f)) {
			return int64(f), nil
		}
		return f, nil
	case val.Type() == cty.Bool:
		return val.True(), nil
	case val.Type().IsListType() || val.Type().IsTupleType():
		var result []any
		for it := val.ElementIterator(); it.Next(); {
			_, elem := it.Element()
			converted, err := convertCtyValueToGo(elem)
			if err != nil {
				return nil, err
			}
			result = append(result, converted)
		}
		return result, nil
	case val.Type().IsMapType() || val.Type().IsObjectType():
		result := make(map[string]any)
		for it := val.ElementIterator(); it.Next(); {
			key, elem := it.Element()
			keyStr := key.AsString()
			converted, err := convertCtyValueToGo(elem)
			if err != nil {
				return nil, err
			}
			result[keyStr] = converted
		}
		return result, nil
	default:
		// Fallback: try to convert using gocty
		var result any
		err := gocty.FromCtyValue(val, &result)
		return result, err
	}
}

func parseConfigData(data map[string]any, cfg *Config) error {
	// Handle servers configuration
	if val, exists := data["servers"]; exists {
		serverList, ok := val.([]any)
		if !ok {
			return fmt.Errorf("servers must be an array")
		}

		// Clear default servers if specified in config
		cfg.Servers = []ServerConfig{}

		for i, serverData := range serverList {
			serverMap, ok := serverData.(map[string]any)
			if !ok {
				return fmt.Errorf("server configuration at index %d must be an object", i)
			}

			server := ServerConfig{
				Type:                 ProxyTypeStandard,
				Enabled:              true,
				MaxConnections:       100,
				ConnectionsPerClient: 10,
			}

			// Parse server type
			if typeVal, exists := serverMap["type"]; exists {
				ptr, err := parseValue[string](typeVal)
				if err != nil {
					return fmt.Errorf("server type at index %d must be a string: %w", i, err)
				}
				serverType := ProxyType(*ptr)

				// Validate that the proxy type is one of the supported types
				validType := false
				switch serverType {
				case ProxyTypeStandard, ProxyTypeHTTP, ProxyTypeHTTPS, ProxyTypeQUIC:
					validType = true
				}

				if !validType {
					return fmt.Errorf("invalid proxy type at index %d: %s", i, *ptr)
				}

				server.Type = serverType
			}

			// Parse listen address
			if addrVal, exists := serverMap["listen-address"]; exists {
				ptr, err := parseValue[string](addrVal)
				if err != nil {
					return fmt.Errorf("listen-address at index %d must be a string: %w", i, err)
				}
				server.ListenAddress = *ptr
			}

			// Parse enabled
			if enabledVal, exists := serverMap["enabled"]; exists {
				ptr, err := parseValue[bool](enabledVal)
				if err != nil {
					return fmt.Errorf("enabled at index %d must be a boolean: %w", i, err)
				}
				server.Enabled = *ptr
			}

			// Parse interceptor name
			if nameVal, exists := serverMap["interceptor-name"]; exists {
				ptr, err := parseValue[string](nameVal)
				if err != nil {
					return fmt.Errorf("interceptor-name at index %d must be a string: %w", i, err)
				}
				server.InterceptorName = *ptr
			}

			// Parse max connections
			if maxConnsVal, exists := serverMap["max-connections"]; exists {
				ptr, err := parseValue[int](maxConnsVal)
				if err != nil {
					return fmt.Errorf("max-connections at index %d must be an integer: %w", i, err)
				}
				server.MaxConnections = *ptr
			}

			// Parse connections per client
			if clientConnsVal, exists := serverMap["connections-per-client"]; exists {
				ptr, err := parseValue[int](clientConnsVal)
				if err != nil {
					return fmt.Errorf("connections-per-client at index %d must be an integer: %w", i, err)
				}
				server.ConnectionsPerClient = *ptr
			}

			cfg.Servers = append(cfg.Servers, server)
		}
	}

	// For backward compatibility: if listen-address is specified but no servers,
	// create a standard server with that address
	if val, exists := data["listen-address"]; exists && len(cfg.Servers) == 0 {
		ptr, err := parseValue[string](val)
		if err != nil {
			if strings.Contains(err.Error(), "secret") {
				return err
			}
			return fmt.Errorf("listen-address must be a string")
		}
		// Create a standard proxy server with the specified address
		cfg.Servers = []ServerConfig{
			{
				Type:                 ProxyTypeStandard,
				ListenAddress:        *ptr,
				Enabled:              true,
				MaxConnections:       100,
				ConnectionsPerClient: 10,
			},
		}
	}

	if val, exists := data["timeout-seconds"]; exists {
		ptr, err := parseValue[int](val)
		if err != nil {
			if strings.Contains(err.Error(), "secret") {
				return err
			}
			return fmt.Errorf("timeout-seconds must be a number")
		}
		cfg.TimeoutSeconds = *ptr
	}

	if val, exists := data["max-concurrent-connections"]; exists {
		ptr, err := parseValue[int](val)
		if err != nil {
			if strings.Contains(err.Error(), "secret") {
				return err
			}
			return fmt.Errorf("max-concurrent-connections must be a number")
		}
		cfg.MaxConcurrentConnections = *ptr
	}

	// Clear existing classifiers
	cfg.Classifiers = make(map[string]Classifier)

	if classifiers, ok := data["classifiers"].(map[string]any); ok && classifiers != nil {
		for key, classifier := range classifiers {
			// Assuming classifier is a map[string]interface{}
			classifierMap, ok := classifier.(map[string]any)
			if !ok {
				return fmt.Errorf("invalid classifier format")
			}

			newClassifier, err := parseClassifier(classifierMap)
			if err != nil {
				return err
			}

			// Add the new classifier to the config cfg.Classifiers[key] = newClassifier
			cfg.Classifiers[key] = newClassifier
		}
	}

	// Parse forwards if present
	if forwards, ok := data["forwards"].([]any); ok && forwards != nil {
		// Clear existing forwards
		cfg.Forwards = nil

		for _, forward := range forwards {
			forwardMap, ok := forward.(map[string]any)
			if !ok {
				return fmt.Errorf("invalid forward format")
			}

			forwardType, ok := forwardMap["type"].(string)
			if !ok {
				return fmt.Errorf("missing forward type")
			}

			// Parse classifier if present (common to all forward types)
			var classifier Classifier
			if classifierData, ok := forwardMap["classifier"].(map[string]any); ok {
				var err error
				classifier, err = parseClassifier(classifierData)
				if err != nil {
					return fmt.Errorf("failed to parse classifier for %s forward: %w", forwardType, err)
				}
			}

			var newForward Forward

			switch forwardType {
			case "default-network":
				networkForward := &ForwardDefaultNetwork{
					ClassifierData: classifier,
				}
				if forceIPv4, err := parseValue[bool](forwardMap["force-ipv4"]); err == nil {
					networkForward.ForceIPv4 = *forceIPv4
				}
				newForward = networkForward

			case "socks5":
				socks5Forward := &ForwardSocks5{
					ClassifierData: classifier,
				}
				if address, err := parseValue[string](forwardMap["address"]); err == nil {
					socks5Forward.Address = *address
				} else {
					return fmt.Errorf("socks5 forward requires address field")
				}

				if username, err := parseValue[string](forwardMap["username"]); err == nil {
					socks5Forward.Username = username
				}

				if password, err := parseValue[string](forwardMap["password"]); err == nil {
					socks5Forward.Password = password
				}

				if forceIPv4, err := parseValue[bool](forwardMap["force-ipv4"]); err == nil {
					socks5Forward.ForceIPv4 = *forceIPv4
				}

				newForward = socks5Forward

			case "proxy":
				proxyForward := &ForwardProxy{
					ClassifierData: classifier,
				}
				if address, err := parseValue[string](forwardMap["address"]); err == nil {
					proxyForward.Address = *address
				} else {
					return fmt.Errorf("proxy forward requires address field")
				}

				if username, err := parseValue[string](forwardMap["username"]); err == nil {
					proxyForward.Username = username
				}

				if password, err := parseValue[string](forwardMap["password"]); err == nil {
					proxyForward.Password = password
				}

				if forceIPv4, err := parseValue[bool](forwardMap["force-ipv4"]); err == nil {
					proxyForward.ForceIPv4 = *forceIPv4
				}

				newForward = proxyForward

			default:
				return fmt.Errorf("unsupported forward type: %s", forwardType)
			}

			cfg.Forwards = append(cfg.Forwards, newForward)
		}
	}

	// Handle portal configuration
	if val, exists := data["portal"]; exists {
		portalMap, ok := val.(map[string]any)
		if !ok {
			return fmt.Errorf("portal configuration must be an object")
		}

		// Parse username
		if usernameVal, exists := portalMap["username"]; exists {
			if username, err := parseValue[string](usernameVal); err == nil {
				cfg.Portal.Username = *username
			} else {
				return fmt.Errorf("portal username must be a string: %w", err)
			}
		}

		// Parse password
		if passwordVal, exists := portalMap["password"]; exists {
			if password, err := parseValue[string](passwordVal); err == nil {
				cfg.Portal.Password = *password
			} else {
				return fmt.Errorf("portal password must be a string: %w", err)
			}
		}
	}

	// Handle statistics configuration
	if val, exists := data["statistics"]; exists {
		statsMap, ok := val.(map[string]any)
		if !ok {
			return fmt.Errorf("statistics configuration must be an object")
		}

		// Parse enabled
		if enabledVal, exists := statsMap["enabled"]; exists {
			if enabled, err := parseValue[bool](enabledVal); err == nil {
				cfg.Statistics.Enabled = *enabled
			} else {
				return fmt.Errorf("statistics enabled must be a boolean: %w", err)
			}
		}

		// Parse backend
		if backendVal, exists := statsMap["backend"]; exists {
			if backend, err := parseValue[string](backendVal); err == nil {
				cfg.Statistics.Backend = *backend
			} else {
				return fmt.Errorf("statistics backend must be a string: %w", err)
			}
		}

		// Parse sqlite_path
		if sqlitePathVal, exists := statsMap["sqlite_path"]; exists {
			if sqlitePath, err := parseValue[string](sqlitePathVal); err == nil {
				cfg.Statistics.SQLitePath = *sqlitePath
			} else {
				return fmt.Errorf("statistics sqlite_path must be a string: %w", err)
			}
		}

		// Parse postgres_dsn
		if postgresDsnVal, exists := statsMap["postgres_dsn"]; exists {
			if postgresDsn, err := parseValue[string](postgresDsnVal); err == nil {
				cfg.Statistics.PostgresDSN = *postgresDsn
			} else {
				return fmt.Errorf("statistics postgres_dsn must be a string: %w", err)
			}
		}

		// Parse buffer_size
		if bufferSizeVal, exists := statsMap["buffer_size"]; exists {
			if bufferSize, err := parseValue[int](bufferSizeVal); err == nil {
				cfg.Statistics.BufferSize = *bufferSize
			} else {
				return fmt.Errorf("statistics buffer_size must be an integer: %w", err)
			}
		}

		// Parse flush_interval
		if flushIntervalVal, exists := statsMap["flush_interval"]; exists {
			if flushInterval, err := parseValue[int](flushIntervalVal); err == nil {
				cfg.Statistics.FlushInterval = *flushInterval
			} else {
				return fmt.Errorf("statistics flush_interval must be an integer: %w", err)
			}
		}
	}

	return nil
}

func parseValue[T any](value any) (*T, error) {
	var zero T
	tType := reflect.TypeOf(zero)
	ptr := reflect.New(tType)
	elem := ptr.Elem()

	// Secret-case: retrieve env var
	if m, ok := value.(map[string]any); ok {
		if key, ok := m["_secret"].(string); ok {
			res := os.Getenv(key)
			if res == "" {
				return nil, fmt.Errorf("secret %s not set", key)
			}
			value = res
		}
	}

	switch v := value.(type) {
	case float64:
		// JSON number
		switch elem.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			elem.SetInt(int64(v))
		case reflect.Float32, reflect.Float64:
			elem.SetFloat(v)
		default:
			return nil, fmt.Errorf("expected %T, got JSON number", zero)
		}
	case int64:
		// HCL number (integer)
		switch elem.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			elem.SetInt(v)
		case reflect.Float32, reflect.Float64:
			elem.SetFloat(float64(v))
		default:
			return nil, fmt.Errorf("expected %T, got int64", zero)
		}
	case int:
		// Go number
		switch elem.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			elem.SetInt(int64(v))
		case reflect.Float32, reflect.Float64:
			elem.SetFloat(float64(v))
		default:
			return nil, fmt.Errorf("expected %T, got int", zero)
		}
	case string:
		switch elem.Kind() {
		case reflect.String:
			elem.SetString(v)
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			i, err := strconv.ParseInt(v, 10, elem.Type().Bits())
			if err != nil {
				return nil, fmt.Errorf("failed to parse int: %w", err)
			}
			elem.SetInt(i)
		case reflect.Float32, reflect.Float64:
			f, err := strconv.ParseFloat(v, elem.Type().Bits())
			if err != nil {
				return nil, fmt.Errorf("failed to parse float: %w", err)
			}
			elem.SetFloat(f)
		case reflect.Bool:
			b, err := strconv.ParseBool(v)
			if err != nil {
				return nil, fmt.Errorf("failed to parse bool: %w", err)
			}
			elem.SetBool(b)
		default:
			return nil, fmt.Errorf("expected %T, got string", zero)
		}
	case bool:
		if elem.Kind() == reflect.Bool {
			elem.SetBool(v)
		} else {
			return nil, fmt.Errorf("expected %T, got bool", zero)
		}
	default:
		// direct-case: cast
		if rv, ok := value.(T); ok {
			return &rv, nil
		}
		return nil, fmt.Errorf("expected %T, got %T", zero, value)
	}
	return ptr.Interface().(*T), nil
}

func parseClassifier(classifierMap map[string]any) (Classifier, error) {
	// Create a new classifier based on the type
	var newClassifier Classifier
	classifierType, ok := classifierMap["type"].(string)
	if !ok {
		return nil, fmt.Errorf("missing classifier type")
	}

	switch classifierType {
	case "and":
		newClassifier = &ClassifierAnd{}
		if classifiers, ok := classifierMap["classifiers"].([]any); ok && classifiers != nil {
			for _, classifier := range classifiers {
				class, err := parseClassifier(classifier.(map[string]any))
				if err != nil {
					return nil, err
				}
				newClassifier.(*ClassifierAnd).Classifiers = append(newClassifier.(*ClassifierAnd).Classifiers, class)
			}
		}
	case "or":
		newClassifier = &ClassifierOr{}
		if classifiers, ok := classifierMap["classifiers"].([]any); ok && classifiers != nil {
			for _, classifier := range classifiers {
				class, err := parseClassifier(classifier.(map[string]any))
				if err != nil {
					return nil, err
				}
				newClassifier.(*ClassifierOr).Classifiers = append(newClassifier.(*ClassifierOr).Classifiers, class)
			}
		}
	case "not":
		newClassifier = &ClassifierNot{}
		if classifier, ok := classifierMap["classifier"].(map[string]any); ok {
			class, err := parseClassifier(classifier)
			if err != nil {
				return nil, err
			}
			newClassifier.(*ClassifierNot).Classifier = class
		}
	case "domain":
		domainClassifier := &ClassifierDomain{}

		// Set the domain
		if domain, ok := classifierMap["domain"].(string); ok {
			domainClassifier.Domain = domain
		}

		// Set the operation
		if op, ok := classifierMap["op"].(string); ok {
			domainClassifier.Op = parseClassifierOp(op)
		}

		newClassifier = domainClassifier
	case "ip":
		ipClassifier := &ClassifierIP{}

		// Set the IP address
		if ip, ok := classifierMap["ip"].(string); ok {
			ipClassifier.IP = ip
		}

		newClassifier = ipClassifier
	case "network":
		networkClassifier := &ClassifierNetwork{}

		// Set the CIDR
		if cidr, ok := classifierMap["cidr"].(string); ok {
			networkClassifier.CIDR = cidr
		}

		newClassifier = networkClassifier
	case "port":
		portClassifier := &ClassifierPort{}
		switch port := classifierMap["port"].(type) {
		case float64:
			portClassifier.Port = int(port)
		case int64:
			portClassifier.Port = int(port)
		case int:
			portClassifier.Port = port
		}
		newClassifier = portClassifier
	case "ref":
		refClassifier := &ClassifierRef{}
		if id, ok := classifierMap["id"].(string); ok {
			refClassifier.Id = id
		}
		newClassifier = refClassifier
	case "true":
		newClassifier = &ClassifierTrue{}
	case "false":
		newClassifier = &ClassifierFalse{}
	case "domains-file":
		filePath, ok := classifierMap["file"].(string)
		if !ok || filePath == "" {
			return nil, fmt.Errorf("domains-file classifier requires a 'file' field")
		}
		clf := &ClassifierDomainsFile{FilePath: filePath}
		newClassifier = clf
	case "domains_file":
		return nil, fmt.Errorf("invalid classifier type 'domains_file': use 'domains-file' instead (hyphens, not underscores)")
	default:
		return nil, fmt.Errorf("unsupported classifier type: %s", classifierType)
	}

	return newClassifier, nil
}

func parseClassifierOp(op string) ClassifierOp {
	switch op {
	case "equal":
		return ClassifierOpEqual
	case "not-equal":
		return ClassifierOpNotEqual
	case "is":
		return ClassifierOpIs
	case "contains":
		return ClassifierOpContains
	case "not-contains":
		return ClassifierOpNotContains
	default:
		return ClassifierOpEqual
	}
}

func loadConfigFromEnv(cfg *Config) {
	// Handle global timeout setting
	if timeoutStr := os.Getenv("MSGTAUSCH_TIMEOUTSECONDS"); timeoutStr != "" {
		if timeout, err := strconv.Atoi(timeoutStr); err == nil {
			cfg.TimeoutSeconds = timeout
		} else {
			// Handle error: maybe log a warning?
			fmt.Fprintf(os.Stderr, "Warning: Invalid format for MSGTAUSCH_TIMEOUTSECONDS: %s\n", timeoutStr)
		}
	}

	// Handle global max connections setting
	if maxConnStr := os.Getenv("MSGTAUSCH_MAXCONCURRENTCONNECTIONS"); maxConnStr != "" {
		if maxConn, err := strconv.Atoi(maxConnStr); err == nil {
			cfg.MaxConcurrentConnections = maxConn
		} else {
			// Handle error: maybe log a warning?
			fmt.Fprintf(os.Stderr, "Warning: Invalid format for MSGTAUSCH_MAXCONCURRENTCONNECTIONS: %s\n", maxConnStr)
		}
	}

	// Handle global interception enabled setting
	if interceptEnabled := os.Getenv("MSGTAUSCH_INTERCEPT"); interceptEnabled != "" {
		cfg.Interception.Enabled = strings.EqualFold(interceptEnabled, "true") || interceptEnabled == "1"
	}

	// Handle global HTTP interception setting
	if interceptHTTP := os.Getenv("MSGTAUSCH_INTERCEPTHTTP"); interceptHTTP != "" {
		cfg.Interception.HTTP = strings.EqualFold(interceptHTTP, "true") || interceptHTTP == "1"
	}

	// Handle global HTTPS interception setting
	if interceptHTTPS := os.Getenv("MSGTAUSCH_INTERCEPTHTTPS"); interceptHTTPS != "" {
		cfg.Interception.HTTPS = strings.EqualFold(interceptHTTPS, "true") || interceptHTTPS == "1"
	}

	// Handle global CA certificate file setting
	if caFile := os.Getenv("MSGTAUSCH_CAFILE"); caFile != "" {
		cfg.Interception.CAFile = caFile
	}

	// Handle global CA key file setting
	if caKeyFile := os.Getenv("MSGTAUSCH_CAKEYFILE"); caKeyFile != "" {
		cfg.Interception.CAKeyFile = caKeyFile
	}

	// Handle portal configuration from environment variables
	if portalUsername := os.Getenv("MSGTAUSCH_PORTAL_USERNAME"); portalUsername != "" {
		cfg.Portal.Username = portalUsername
	}

	if portalPassword := os.Getenv("MSGTAUSCH_PORTAL_PASSWORD"); portalPassword != "" {
		cfg.Portal.Password = portalPassword
	}

	// For backward compatibility: if MSGTAUSCH_LISTENADDRESS is specified but no servers,
	// create a standard server with that address
	if addr := os.Getenv("MSGTAUSCH_LISTENADDRESS"); addr != "" {
		// Check if we already have servers configured
		if len(cfg.Servers) == 0 {
			// Create a standard proxy server with the address from env var
			cfg.Servers = []ServerConfig{
				{
					Type:                 ProxyTypeStandard,
					ListenAddress:        addr,
					Enabled:              true,
					MaxConnections:       100,
					ConnectionsPerClient: 10,
				},
			}
		} else {
			// Update the first server's address
			cfg.Servers[0].ListenAddress = addr
		}
	}

	// Handle server-specific environment variables
	// Example format: MSGTAUSCH_SERVER_0_LISTENADDRESS=127.0.0.1:8080
	// Example format: MSGTAUSCH_SERVER_0_TYPE=https
	for i := 0; ; i++ {
		prefix := fmt.Sprintf("MSGTAUSCH_SERVER_%d_", i)
		addrVar := prefix + "LISTENADDRESS"
		typeVar := prefix + "TYPE"
		enabledVar := prefix + "ENABLED"
		caFileVar := prefix + "CAFILE"
		caKeyFileVar := prefix + "CAKEYFILE"
		maxConnsVar := prefix + "MAXCONNECTIONS"
		clientConnsVar := prefix + "CONNECTIONSPCLIENT"

		// Check if this server config exists by looking for the address
		addr := os.Getenv(addrVar)
		if addr == "" {
			// No more server configurations
			break
		}

		// Create a new server config or use existing if available
		var server ServerConfig
		if i < len(cfg.Servers) {
			// Update existing server config
			server = cfg.Servers[i]
		} else {
			// Create new server config with defaults
			server = ServerConfig{
				Type:                 ProxyTypeStandard,
				Enabled:              true,
				MaxConnections:       100,
				ConnectionsPerClient: 10,
			}
		}

		// Set the server address
		server.ListenAddress = addr

		// Set the server type if specified
		if typeStr := os.Getenv(typeVar); typeStr != "" {
			server.Type = ProxyType(typeStr)
		}

		// Set enabled status if specified
		if enabledStr := os.Getenv(enabledVar); enabledStr != "" {
			if enabled, err := strconv.ParseBool(enabledStr); err == nil {
				server.Enabled = enabled
			} else {
				fmt.Fprintf(os.Stderr, "Warning: Invalid format for %s: %s\n", enabledVar, enabledStr)
			}
		}

		// Set global CA file if specified via server-specific env var and global is not set
		if caFile := os.Getenv(caFileVar); caFile != "" && cfg.Interception.CAFile == "" {
			cfg.Interception.CAFile = caFile
		}

		// Set global CA key file if specified via server-specific env var and global is not set
		if caKeyFile := os.Getenv(caKeyFileVar); caKeyFile != "" && cfg.Interception.CAKeyFile == "" {
			cfg.Interception.CAKeyFile = caKeyFile
		}

		// Set max connections if specified
		if maxConnsStr := os.Getenv(maxConnsVar); maxConnsStr != "" {
			if maxConns, err := strconv.Atoi(maxConnsStr); err == nil {
				server.MaxConnections = maxConns
			} else {
				fmt.Fprintf(os.Stderr, "Warning: Invalid format for %s: %s\n", maxConnsVar, maxConnsStr)
			}
		}

		// Set client connections if specified
		if clientConnsStr := os.Getenv(clientConnsVar); clientConnsStr != "" {
			if clientConns, err := strconv.Atoi(clientConnsStr); err == nil {
				server.ConnectionsPerClient = clientConns
			} else {
				fmt.Fprintf(os.Stderr, "Warning: Invalid format for %s: %s\n", clientConnsVar, clientConnsStr)
			}
		}

		// Update or add the server config
		if i < len(cfg.Servers) {
			cfg.Servers[i] = server
		} else {
			cfg.Servers = append(cfg.Servers, server)
		}
	}
}
