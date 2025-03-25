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

	// Apply environment variables
	loadConfigFromEnv(cfg)

	// If config file exists, load it
	if configPath != "" {
		var err error

		ext := filepath.Ext(configPath)
		switch strings.ToLower(ext) {
		case ".json":
			err = loadJSONConfig(configPath, cfg)
		default:
			return nil, fmt.Errorf("unsupported config file format: %s", ext)
		}

		if err != nil {
			return nil, err
		}
	}

	return cfg, nil
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

	// Manually map the values from the map to the Config struct
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

				newForward = proxyForward

			default:
				return fmt.Errorf("unsupported forward type: %s", forwardType)
			}

			cfg.Forwards = append(cfg.Forwards, newForward)
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
		if port, ok := classifierMap["port"].(float64); ok {
			portClassifier.Port = int(port)
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
