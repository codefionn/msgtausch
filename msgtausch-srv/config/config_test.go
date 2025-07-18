package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Helper function to create a temporary config file
func createTempConfigFile(t *testing.T, dir, filename, content string) string {
	t.Helper()
	tempFilePath := filepath.Join(dir, filename)
	err := os.WriteFile(tempFilePath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to create temp config file %s: %v", tempFilePath, err)
	}
	return tempFilePath
}

func TestLoadConfigJSON(t *testing.T) {
	// --- Test Case: Domains File Classifier ---
	domainsFile := createTempConfigFile(t, t.TempDir(), "domains.txt", "example.com\nfoo.org\nbar.net\n")
	domainsClassifierJSON := `{
		"classifiers": {
			"domains": {
				"type": "domains-file",
				"file": "` + domainsFile + `"
			}
		}
	}`
	domainsClassifierPath := createTempConfigFile(t, t.TempDir(), "domains_classifier.json", domainsClassifierJSON)
	cfgDomains, err := LoadConfig(domainsClassifierPath)
	if err != nil {
		t.Fatalf("Failed to load config with domains-file classifier: %v", err)
	}
	cDomains, ok := cfgDomains.Classifiers["domains"].(*ClassifierDomainsFile)
	if !ok {
		t.Fatalf("Expected *ClassifierDomainsFile, got %T", cfgDomains.Classifiers["domains"])
	}
	if cDomains.FilePath != domainsFile {
		t.Errorf("Expected file path %q, got %q", domainsFile, cDomains.FilePath)
	}

	// --- Test Case: Port Classifier ---
	portClassifierJSON := `{
		"servers": [
			{
				"type": "standard",
				"listen-address": "localhost:8000",
				"enabled": true
			}
		],
		"timeout-seconds": 60,
		"max-concurrent-connections": 200,
		"classifiers": {
			"port1": {
				"type": "port",
				"port": 443
			}
		}
	}`
	portClassifierPath := createTempConfigFile(t, t.TempDir(), "port_classifier.json", portClassifierJSON)
	cfg, err := LoadConfig(portClassifierPath)
	if err != nil {
		t.Fatalf("Failed to load config with port classifier: %v", err)
	}
	c, ok := cfg.Classifiers["port1"].(*ClassifierPort)
	if !ok {
		t.Fatalf("Expected *ClassifierPort, got %T", cfg.Classifiers["port1"])
	}
	if c.Port != 443 {
		t.Errorf("Expected port 443, got %d", c.Port)
	}

	testDir := t.TempDir() // Create a temporary directory for test files

	// --- Test Case: True/False Classifiers ---
	trueFalseClassifierJSON := `{
		"classifiers": {
			"always_true": { "type": "true" },
			"always_false": { "type": "false" }
		}
	}`
	trueFalseClassifierPath := createTempConfigFile(t, testDir, "true_false_classifier.json", trueFalseClassifierJSON)
	cfg, err = LoadConfig(trueFalseClassifierPath)
	if err != nil {
		t.Fatalf("Failed to load config with true/false classifiers: %v", err)
	}
	if _, ok := cfg.Classifiers["always_true"].(*ClassifierTrue); !ok {
		t.Errorf("Expected *ClassifierTrue, got %T", cfg.Classifiers["always_true"])
	}
	if _, ok := cfg.Classifiers["always_false"].(*ClassifierFalse); !ok {
		t.Errorf("Expected *ClassifierFalse, got %T", cfg.Classifiers["always_false"])
	}

	// --- Test Case 1: Valid JSON with IP and Network classifiers ---
	validJSONWithIPClassifiersContent := `{
		"servers": [
			{
				"type": "standard",
				"listen-address": "localhost:8000",
				"enabled": true
			}
		],
		"timeout-seconds": 60,
		"max-concurrent-connections": 200,
		"classifiers": {
			"ip1": {
				"type": "ip",
				"ip": "192.168.1.1"
			},
			"net1": {
				"type": "network",
				"cidr": "10.0.0.0/8"
			}
		}
	}`
	validJSONWithIPClassifiersPath := createTempConfigFile(t, testDir, "valid_ip_classifiers.json", validJSONWithIPClassifiersContent)

	// --- Test Case 2: Malformed JSON ---
	malformedJSONContent := `{ "listen-address": "localhost:8000", ` // Missing closing brace
	malformedJSONPath := createTempConfigFile(t, testDir, "malformed.json", malformedJSONContent)

	// --- Test Case 3: Invalid type for numeric field ---
	invalidTypeJSONContent := `{ "timeout-seconds": "not a number" }`
	invalidTypeJSONPath := createTempConfigFile(t, testDir, "invalid_type.json", invalidTypeJSONContent)

	// --- Test Case 4: Non-existent file ---
	nonExistentPath := filepath.Join(testDir, "nonexistent.json")

	// --- Test Case 5: Invalid Classifier Structure ---
	invalidClassifierJSONContent := `{ "classifiers": { "bad": { "type": "unknown" } } }`
	invalidClassifierJSONPath := createTempConfigFile(t, testDir, "invalid_classifier.json", invalidClassifierJSONContent)

	// --- Test Case 6: Invalid Forward Structure ---
	invalidForwardJSONContent := `{ "forwards": [ { "classifier": "any", "forward": { "type": "unknown" } } ] }`
	invalidForwardJSONPath := createTempConfigFile(t, testDir, "invalid_forward.json", invalidForwardJSONContent)

	testCases := []struct {
		name        string
		configPath  string
		wantErr     bool
		expectedCfg *Config // Only check for non-error cases
	}{
		{
			name:       "Valid JSON with IP and Network classifiers",
			configPath: validJSONWithIPClassifiersPath,
			wantErr:    false,
			expectedCfg: &Config{
				Servers: []ServerConfig{
					{
						Type:                 ProxyTypeStandard,
						ListenAddress:        "localhost:8000",
						Enabled:              true,
						MaxConnections:       100,
						ConnectionsPerClient: 10,
					},
				},
				TimeoutSeconds:           60,
				MaxConcurrentConnections: 200,
				Classifiers: map[string]Classifier{
					"ip1": &ClassifierIP{
						IP: "192.168.1.1",
					},
					"net1": &ClassifierNetwork{
						CIDR: "10.0.0.0/8",
					},
				},
			},
		},
		{
			name:       "Non-existent file",
			configPath: nonExistentPath,
			wantErr:    true,
		},
		{
			name:       "Malformed JSON",
			configPath: malformedJSONPath,
			wantErr:    true,
		},
		{
			name:       "Invalid type",
			configPath: invalidTypeJSONPath,
			wantErr:    true,
		},
		{
			name:       "Invalid Classifier JSON",
			configPath: invalidClassifierJSONPath,
			wantErr:    true,
		},
		{
			name:       "Invalid Forward JSON",
			configPath: invalidForwardJSONPath,
			wantErr:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadConfig(tc.configPath)

			if (err != nil) != tc.wantErr {
				t.Fatalf("LoadConfig() error = %v, wantErr %v", err, tc.wantErr)
			}

			if !tc.wantErr && !reflect.DeepEqual(cfg, tc.expectedCfg) {
				// Use a more detailed comparison if needed, especially for nested structs/maps
				t.Errorf("Loaded config mismatch:\nExpected: %+v\nGot:      %+v", tc.expectedCfg, cfg)
				// Add detailed diff if necessary
			}
		})
	}
}

func TestClassifierTrueFalse_Type(t *testing.T) {
	if (&ClassifierTrue{}).Type() != ClassifierTypeTrue {
		t.Errorf("ClassifierTrue.Type() = %v, want %v", (&ClassifierTrue{}).Type(), ClassifierTypeTrue)
	}
	if (&ClassifierFalse{}).Type() != ClassifierTypeFalse {
		t.Errorf("ClassifierFalse.Type() = %v, want %v", (&ClassifierFalse{}).Type(), ClassifierTypeFalse)
	}
}

func TestParseClassifier_TrueFalse(t *testing.T) {
	cases := []struct {
		name         string
		input        map[string]any
		expectedType ClassifierType
	}{
		{"true classifier", map[string]any{"type": "true"}, ClassifierTypeTrue},
		{"false classifier", map[string]any{"type": "false"}, ClassifierTypeFalse},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cl, err := parseClassifier(c.input)
			if err != nil {
				t.Fatalf("parseClassifier error: %v", err)
			}
			if cl.Type() != c.expectedType {
				t.Errorf("got type %v, want %v", cl.Type(), c.expectedType)
			}
		})
	}
}

func TestLoadConfigUnsupportedFormat(t *testing.T) {
	testDir := t.TempDir()
	unsupportedPath := createTempConfigFile(t, testDir, "config.yaml", "listen-address: localhost:7070")

	_, err := LoadConfig(unsupportedPath)
	if err == nil {
		t.Fatal("LoadConfig() expected an error for unsupported format, but got nil")
	}

	expectedErrorMsg := "unsupported config file format: .yaml"
	if err.Error() != expectedErrorMsg {
		t.Errorf("LoadConfig() error message mismatch:\nExpected: %s\nGot:      %s", expectedErrorMsg, err.Error())
	}
}

func TestLoadConfigJSON_Secrets(t *testing.T) {
	dir := t.TempDir()
	// Set environment variables for secrets
	os.Setenv("ADDR_SECRET", "127.0.0.1:9000")
	defer os.Unsetenv("ADDR_SECRET")
	os.Setenv("TIMEOUT_SECRET", "45")
	defer os.Unsetenv("TIMEOUT_SECRET")
	os.Setenv("MAXCONN_SECRET", "150")
	defer os.Unsetenv("MAXCONN_SECRET")

	secretJSON := `{
    "servers": [{
        "type": "standard",
        "listen-address": {"_secret":"ADDR_SECRET"},
        "enabled": true
    }],
    "timeout-seconds": {"_secret":"TIMEOUT_SECRET"},
    "max-concurrent-connections": {"_secret":"MAXCONN_SECRET"}
}`
	path := createTempConfigFile(t, dir, "secret_config.json", secretJSON)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig with secret config failed: %v", err)
	}
	if len(cfg.Servers) != 1 || cfg.Servers[0].ListenAddress != "127.0.0.1:9000" {
		t.Errorf("Expected server ListenAddress 127.0.0.1:9000, got %v", cfg.Servers)
	}
	if cfg.TimeoutSeconds != 45 {
		t.Errorf("Expected TimeoutSeconds 45, got %d", cfg.TimeoutSeconds)
	}
	if cfg.MaxConcurrentConnections != 150 {
		t.Errorf("Expected MaxConcurrentConnections 150, got %d", cfg.MaxConcurrentConnections)
	}
}

func TestLoadConfigJSON_SecretMissing(t *testing.T) {
	dir := t.TempDir()
	missingJSON := `{"servers": [{"type": "standard", "listen-address": {"_secret":"MISSING_SECRET"}, "enabled": true}]}`
	path := createTempConfigFile(t, dir, "missing_secret.json", missingJSON)

	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "secret MISSING_SECRET not set") {
		t.Fatalf("Expected secret not set error, got %v", err)
	}
}

func TestLoadConfigJSON_ForwardClassifiers(t *testing.T) {
	testDir := t.TempDir()

	// Test cases for different forward types with classifiers
	testCases := []struct {
		name        string
		jsonContent string
		wantErr     bool
		validate    func(t *testing.T, cfg *Config)
	}{
		{
			name: "Default network forward with domain classifier",
			jsonContent: `{
				"forwards": [
					{
						"type": "default-network",
						"classifier": {
							"type": "domain",
							"domain": "example.com",
							"op": "equal"
						}
					}
				]
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if len(cfg.Forwards) != 1 {
					t.Fatalf("Expected 1 forward, got %d", len(cfg.Forwards))
				}

				forward := cfg.Forwards[0].(*ForwardDefaultNetwork)
				classifier := forward.Classifier().(*ClassifierDomain)

				if classifier.Domain != "example.com" {
					t.Errorf("Expected domain 'example.com', got '%s'", classifier.Domain)
				}
				if classifier.Op != ClassifierOpEqual {
					t.Errorf("Expected ClassifierOpEqual, got %v", classifier.Op)
				}
			},
		},
		{
			name: "SOCKS5 forward with IP classifier",
			jsonContent: `{
				"forwards": [
					{
						"type": "socks5",
						"address": "proxy.example.com:1080",
						"classifier": {
							"type": "ip",
							"ip": "192.168.1.1"
						}
					}
				]
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if len(cfg.Forwards) != 1 {
					t.Fatalf("Expected 1 forward, got %d", len(cfg.Forwards))
				}

				forward := cfg.Forwards[0].(*ForwardSocks5)
				if forward.Address != "proxy.example.com:1080" {
					t.Errorf("Expected address 'proxy.example.com:1080', got '%s'", forward.Address)
				}

				classifier := forward.Classifier().(*ClassifierIP)
				if classifier.IP != "192.168.1.1" {
					t.Errorf("Expected IP '192.168.1.1', got '%s'", classifier.IP)
				}
			},
		},
		{
			name: "Proxy forward with network classifier",
			jsonContent: `{
				"forwards": [
					{
						"type": "proxy",
						"address": "proxy.corp.com:8080",
						"username": "user1",
						"password": "pass123",
						"classifier": {
							"type": "network",
							"cidr": "10.0.0.0/8"
						}
					}
				]
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if len(cfg.Forwards) != 1 {
					t.Fatalf("Expected 1 forward, got %d", len(cfg.Forwards))
				}

				forward := cfg.Forwards[0].(*ForwardProxy)
				if forward.Address != "proxy.corp.com:8080" {
					t.Errorf("Expected address 'proxy.corp.com:8080', got '%s'", forward.Address)
				}
				if forward.Username == nil || *forward.Username != "user1" {
					t.Errorf("Expected username 'user1', got %v", forward.Username)
				}
				if forward.Password == nil || *forward.Password != "pass123" {
					t.Errorf("Expected password 'pass123', got %v", forward.Password)
				}

				classifier := forward.Classifier().(*ClassifierNetwork)
				if classifier.CIDR != "10.0.0.0/8" {
					t.Errorf("Expected CIDR '10.0.0.0/8', got '%s'", classifier.CIDR)
				}
			},
		},
		{
			name: "Forward with port classifier",
			jsonContent: `{
				"forwards": [
					{
						"type": "default-network",
						"classifier": {
							"type": "port",
							"port": 443
						}
					}
				]
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if len(cfg.Forwards) != 1 {
					t.Fatalf("Expected 1 forward, got %d", len(cfg.Forwards))
				}

				forward := cfg.Forwards[0].(*ForwardDefaultNetwork)
				classifier := forward.Classifier().(*ClassifierPort)

				if classifier.Port != 443 {
					t.Errorf("Expected port 443, got %d", classifier.Port)
				}
			},
		},
		{
			name: "Forward with true classifier",
			jsonContent: `{
				"forwards": [
					{
						"type": "socks5",
						"address": "fallback.proxy.com:1080",
						"classifier": {
							"type": "true"
						}
					}
				]
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if len(cfg.Forwards) != 1 {
					t.Fatalf("Expected 1 forward, got %d", len(cfg.Forwards))
				}

				forward := cfg.Forwards[0].(*ForwardSocks5)
				if forward.Address != "fallback.proxy.com:1080" {
					t.Errorf("Expected address 'fallback.proxy.com:1080', got '%s'", forward.Address)
				}

				if _, ok := forward.Classifier().(*ClassifierTrue); !ok {
					t.Errorf("Expected ClassifierTrue, got %T", forward.Classifier())
				}
			},
		},
		{
			name: "Forward with AND classifier",
			jsonContent: `{
				"forwards": [
					{
						"type": "default-network",
						"classifier": {
							"type": "and",
							"classifiers": [
								{
									"type": "domain",
									"domain": "example.com",
									"op": "contains"
								},
								{
									"type": "port",
									"port": 80
								}
							]
						}
					}
				]
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if len(cfg.Forwards) != 1 {
					t.Fatalf("Expected 1 forward, got %d", len(cfg.Forwards))
				}

				forward := cfg.Forwards[0].(*ForwardDefaultNetwork)
				andClassifier := forward.Classifier().(*ClassifierAnd)

				if len(andClassifier.Classifiers) != 2 {
					t.Fatalf("Expected 2 classifiers in AND, got %d", len(andClassifier.Classifiers))
				}

				domainClassifier, ok := andClassifier.Classifiers[0].(*ClassifierDomain)
				if !ok {
					t.Errorf("Expected first classifier to be ClassifierDomain, got %T", andClassifier.Classifiers[0])
				} else {
					if domainClassifier.Domain != "example.com" {
						t.Errorf("Expected domain 'example.com', got '%s'", domainClassifier.Domain)
					}
					if domainClassifier.Op != ClassifierOpContains {
						t.Errorf("Expected ClassifierOpContains, got %v", domainClassifier.Op)
					}
				}

				portClassifier, ok := andClassifier.Classifiers[1].(*ClassifierPort)
				if !ok {
					t.Errorf("Expected second classifier to be ClassifierPort, got %T", andClassifier.Classifiers[1])
				} else if portClassifier.Port != 80 {
					t.Errorf("Expected port 80, got %d", portClassifier.Port)
				}
			},
		},
		{
			name: "Forward without classifier (should use default)",
			jsonContent: `{
				"forwards": [
					{
						"type": "default-network"
					}
				]
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if len(cfg.Forwards) != 1 {
					t.Fatalf("Expected 1 forward, got %d", len(cfg.Forwards))
				}

				forward := cfg.Forwards[0].(*ForwardDefaultNetwork)
				if _, ok := forward.Classifier().(*ClassifierTrue); !ok {
					t.Errorf("Expected default ClassifierTrue when no classifier specified, got %T", forward.Classifier())
				}
			},
		},
		{
			name: "Forward with invalid classifier type",
			jsonContent: `{
				"forwards": [
					{
						"type": "default-network",
						"classifier": {
							"type": "invalid-type"
						}
					}
				]
			}`,
			wantErr: true,
		},
		{
			name: "SOCKS5 forward missing address but with classifier",
			jsonContent: `{
				"forwards": [
					{
						"type": "socks5",
						"classifier": {
							"type": "true"
						}
					}
				]
			}`,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configPath := createTempConfigFile(t, testDir, tc.name+".json", tc.jsonContent)

			cfg, err := LoadConfig(configPath)

			if (err != nil) != tc.wantErr {
				t.Fatalf("LoadConfig() error = %v, wantErr %v", err, tc.wantErr)
			}

			if !tc.wantErr && tc.validate != nil {
				tc.validate(t, cfg)
			}
		})
	}
}

func TestParseClassifier_OrClassifier(t *testing.T) {
	testCases := []struct {
		name        string
		input       map[string]any
		expectError bool
		validate    func(t *testing.T, classifier Classifier)
	}{
		{
			name: "OR classifier with domain and port sub-classifiers",
			input: map[string]any{
				"type": "or",
				"classifiers": []any{
					map[string]any{
						"type":   "domain",
						"domain": "example.com",
						"op":     "equal",
					},
					map[string]any{
						"type": "port",
						"port": float64(443),
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, classifier Classifier) {
				orClassifier, ok := classifier.(*ClassifierOr)
				if !ok {
					t.Fatalf("Expected *ClassifierOr, got %T", classifier)
				}
				if len(orClassifier.Classifiers) != 2 {
					t.Fatalf("Expected 2 sub-classifiers, got %d", len(orClassifier.Classifiers))
				}

				// Check first sub-classifier (domain)
				domainClassifier, ok := orClassifier.Classifiers[0].(*ClassifierDomain)
				if !ok {
					t.Errorf("Expected first sub-classifier to be *ClassifierDomain, got %T", orClassifier.Classifiers[0])
				} else {
					if domainClassifier.Domain != "example.com" {
						t.Errorf("Expected domain 'example.com', got '%s'", domainClassifier.Domain)
					}
					if domainClassifier.Op != ClassifierOpEqual {
						t.Errorf("Expected ClassifierOpEqual, got %v", domainClassifier.Op)
					}
				}

				// Check second sub-classifier (port)
				portClassifier, ok := orClassifier.Classifiers[1].(*ClassifierPort)
				if !ok {
					t.Errorf("Expected second sub-classifier to be *ClassifierPort, got %T", orClassifier.Classifiers[1])
				} else if portClassifier.Port != 443 {
					t.Errorf("Expected port 443, got %d", portClassifier.Port)
				}
			},
		},
		{
			name: "OR classifier with IP and network sub-classifiers",
			input: map[string]any{
				"type": "or",
				"classifiers": []any{
					map[string]any{
						"type": "ip",
						"ip":   "192.168.1.1",
					},
					map[string]any{
						"type": "network",
						"cidr": "10.0.0.0/8",
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, classifier Classifier) {
				orClassifier, ok := classifier.(*ClassifierOr)
				if !ok {
					t.Fatalf("Expected *ClassifierOr, got %T", classifier)
				}
				if len(orClassifier.Classifiers) != 2 {
					t.Fatalf("Expected 2 sub-classifiers, got %d", len(orClassifier.Classifiers))
				}

				// Check first sub-classifier (IP)
				ipClassifier, ok := orClassifier.Classifiers[0].(*ClassifierIP)
				if !ok {
					t.Errorf("Expected first sub-classifier to be *ClassifierIP, got %T", orClassifier.Classifiers[0])
				} else if ipClassifier.IP != "192.168.1.1" {
					t.Errorf("Expected IP '192.168.1.1', got '%s'", ipClassifier.IP)
				}

				// Check second sub-classifier (network)
				networkClassifier, ok := orClassifier.Classifiers[1].(*ClassifierNetwork)
				if !ok {
					t.Errorf("Expected second sub-classifier to be *ClassifierNetwork, got %T", orClassifier.Classifiers[1])
				} else if networkClassifier.CIDR != "10.0.0.0/8" {
					t.Errorf("Expected CIDR '10.0.0.0/8', got '%s'", networkClassifier.CIDR)
				}
			},
		},
		{
			name: "OR classifier with single true sub-classifier",
			input: map[string]any{
				"type": "or",
				"classifiers": []any{
					map[string]any{"type": "true"},
				},
			},
			expectError: false,
			validate: func(t *testing.T, classifier Classifier) {
				orClassifier, ok := classifier.(*ClassifierOr)
				if !ok {
					t.Fatalf("Expected *ClassifierOr, got %T", classifier)
				}
				if len(orClassifier.Classifiers) != 1 {
					t.Fatalf("Expected 1 sub-classifier, got %d", len(orClassifier.Classifiers))
				}

				if _, ok := orClassifier.Classifiers[0].(*ClassifierTrue); !ok {
					t.Errorf("Expected sub-classifier to be *ClassifierTrue, got %T", orClassifier.Classifiers[0])
				}
			},
		},
		{
			name: "OR classifier with empty sub-classifiers",
			input: map[string]any{
				"type":        "or",
				"classifiers": []any{},
			},
			expectError: false,
			validate: func(t *testing.T, classifier Classifier) {
				orClassifier, ok := classifier.(*ClassifierOr)
				if !ok {
					t.Fatalf("Expected *ClassifierOr, got %T", classifier)
				}
				if len(orClassifier.Classifiers) != 0 {
					t.Fatalf("Expected 0 sub-classifiers, got %d", len(orClassifier.Classifiers))
				}
			},
		},
		{
			name: "OR classifier without classifiers field",
			input: map[string]any{
				"type": "or",
			},
			expectError: false,
			validate: func(t *testing.T, classifier Classifier) {
				orClassifier, ok := classifier.(*ClassifierOr)
				if !ok {
					t.Fatalf("Expected *ClassifierOr, got %T", classifier)
				}
				if orClassifier.Classifiers != nil {
					t.Fatalf("Expected nil sub-classifiers slice, got %v", orClassifier.Classifiers)
				}
			},
		},
		{
			name: "OR classifier with invalid sub-classifier",
			input: map[string]any{
				"type": "or",
				"classifiers": []any{
					map[string]any{"type": "invalid-type"},
				},
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			classifier, err := parseClassifier(tc.input)

			if (err != nil) != tc.expectError {
				t.Fatalf("parseClassifier() error = %v, expectError %v", err, tc.expectError)
			}

			if !tc.expectError && tc.validate != nil {
				tc.validate(t, classifier)
			}
		})
	}
}

func TestParseClassifier_NotClassifier(t *testing.T) {
	testCases := []struct {
		name        string
		input       map[string]any
		expectError bool
		validate    func(t *testing.T, classifier Classifier)
	}{
		{
			name: "NOT classifier with domain sub-classifier",
			input: map[string]any{
				"type": "not",
				"classifier": map[string]any{
					"type":   "domain",
					"domain": "example.com",
					"op":     "equal",
				},
			},
			expectError: false,
			validate: func(t *testing.T, classifier Classifier) {
				notClassifier, ok := classifier.(*ClassifierNot)
				if !ok {
					t.Fatalf("Expected *ClassifierNot, got %T", classifier)
				}

				domainClassifier, ok := notClassifier.Classifier.(*ClassifierDomain)
				if !ok {
					t.Fatalf("Expected sub-classifier to be *ClassifierDomain, got %T", notClassifier.Classifier)
				}
				if domainClassifier.Domain != "example.com" {
					t.Errorf("Expected domain 'example.com', got '%s'", domainClassifier.Domain)
				}
				if domainClassifier.Op != ClassifierOpEqual {
					t.Errorf("Expected ClassifierOpEqual, got %v", domainClassifier.Op)
				}
			},
		},
		{
			name: "NOT classifier with port sub-classifier",
			input: map[string]any{
				"type": "not",
				"classifier": map[string]any{
					"type": "port",
					"port": float64(80),
				},
			},
			expectError: false,
			validate: func(t *testing.T, classifier Classifier) {
				notClassifier, ok := classifier.(*ClassifierNot)
				if !ok {
					t.Fatalf("Expected *ClassifierNot, got %T", classifier)
				}

				portClassifier, ok := notClassifier.Classifier.(*ClassifierPort)
				if !ok {
					t.Fatalf("Expected sub-classifier to be *ClassifierPort, got %T", notClassifier.Classifier)
				}
				if portClassifier.Port != 80 {
					t.Errorf("Expected port 80, got %d", portClassifier.Port)
				}
			},
		},
		{
			name: "NOT classifier with true sub-classifier",
			input: map[string]any{
				"type": "not",
				"classifier": map[string]any{
					"type": "true",
				},
			},
			expectError: false,
			validate: func(t *testing.T, classifier Classifier) {
				notClassifier, ok := classifier.(*ClassifierNot)
				if !ok {
					t.Fatalf("Expected *ClassifierNot, got %T", classifier)
				}

				if _, ok := notClassifier.Classifier.(*ClassifierTrue); !ok {
					t.Errorf("Expected sub-classifier to be *ClassifierTrue, got %T", notClassifier.Classifier)
				}
			},
		},
		{
			name: "NOT classifier without classifier field",
			input: map[string]any{
				"type": "not",
			},
			expectError: false,
			validate: func(t *testing.T, classifier Classifier) {
				notClassifier, ok := classifier.(*ClassifierNot)
				if !ok {
					t.Fatalf("Expected *ClassifierNot, got %T", classifier)
				}
				if notClassifier.Classifier != nil {
					t.Fatalf("Expected nil sub-classifier, got %v", notClassifier.Classifier)
				}
			},
		},
		{
			name: "NOT classifier with invalid sub-classifier",
			input: map[string]any{
				"type": "not",
				"classifier": map[string]any{
					"type": "invalid-type",
				},
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			classifier, err := parseClassifier(tc.input)

			if (err != nil) != tc.expectError {
				t.Fatalf("parseClassifier() error = %v, expectError %v", err, tc.expectError)
			}

			if !tc.expectError && tc.validate != nil {
				tc.validate(t, classifier)
			}
		})
	}
}

func TestParseClassifier_NestedClassifiers(t *testing.T) {
	testCases := []struct {
		name        string
		input       map[string]any
		expectError bool
		validate    func(t *testing.T, classifier Classifier)
	}{
		{
			name: "OR classifier containing AND classifier",
			input: map[string]any{
				"type": "or",
				"classifiers": []any{
					map[string]any{
						"type": "and",
						"classifiers": []any{
							map[string]any{
								"type":   "domain",
								"domain": "example.com",
								"op":     "equal",
							},
							map[string]any{
								"type": "port",
								"port": float64(443),
							},
						},
					},
					map[string]any{
						"type": "ip",
						"ip":   "192.168.1.1",
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, classifier Classifier) {
				orClassifier, ok := classifier.(*ClassifierOr)
				if !ok {
					t.Fatalf("Expected *ClassifierOr, got %T", classifier)
				}
				if len(orClassifier.Classifiers) != 2 {
					t.Fatalf("Expected 2 sub-classifiers, got %d", len(orClassifier.Classifiers))
				}

				// Check first sub-classifier (AND)
				andClassifier, ok := orClassifier.Classifiers[0].(*ClassifierAnd)
				if !ok {
					t.Fatalf("Expected first sub-classifier to be *ClassifierAnd, got %T", orClassifier.Classifiers[0])
				}
				if len(andClassifier.Classifiers) != 2 {
					t.Fatalf("Expected AND classifier to have 2 sub-classifiers, got %d", len(andClassifier.Classifiers))
				}

				// Check second sub-classifier (IP)
				ipClassifier, ok := orClassifier.Classifiers[1].(*ClassifierIP)
				if !ok {
					t.Fatalf("Expected second sub-classifier to be *ClassifierIP, got %T", orClassifier.Classifiers[1])
				}
				if ipClassifier.IP != "192.168.1.1" {
					t.Errorf("Expected IP '192.168.1.1', got '%s'", ipClassifier.IP)
				}
			},
		},
		{
			name: "NOT classifier containing OR classifier",
			input: map[string]any{
				"type": "not",
				"classifier": map[string]any{
					"type": "or",
					"classifiers": []any{
						map[string]any{
							"type": "port",
							"port": float64(80),
						},
						map[string]any{
							"type": "port",
							"port": float64(8080),
						},
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, classifier Classifier) {
				notClassifier, ok := classifier.(*ClassifierNot)
				if !ok {
					t.Fatalf("Expected *ClassifierNot, got %T", classifier)
				}

				orClassifier, ok := notClassifier.Classifier.(*ClassifierOr)
				if !ok {
					t.Fatalf("Expected sub-classifier to be *ClassifierOr, got %T", notClassifier.Classifier)
				}
				if len(orClassifier.Classifiers) != 2 {
					t.Fatalf("Expected OR classifier to have 2 sub-classifiers, got %d", len(orClassifier.Classifiers))
				}
			},
		},
		{
			name: "AND classifier containing NOT classifier",
			input: map[string]any{
				"type": "and",
				"classifiers": []any{
					map[string]any{
						"type":   "domain",
						"domain": "example.com",
						"op":     "contains",
					},
					map[string]any{
						"type": "not",
						"classifier": map[string]any{
							"type": "port",
							"port": float64(443),
						},
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, classifier Classifier) {
				andClassifier, ok := classifier.(*ClassifierAnd)
				if !ok {
					t.Fatalf("Expected *ClassifierAnd, got %T", classifier)
				}
				if len(andClassifier.Classifiers) != 2 {
					t.Fatalf("Expected 2 sub-classifiers, got %d", len(andClassifier.Classifiers))
				}

				// Check first sub-classifier (domain)
				domainClassifier, ok := andClassifier.Classifiers[0].(*ClassifierDomain)
				if !ok {
					t.Fatalf("Expected first sub-classifier to be *ClassifierDomain, got %T", andClassifier.Classifiers[0])
				}
				if domainClassifier.Domain != "example.com" {
					t.Errorf("Expected domain 'example.com', got '%s'", domainClassifier.Domain)
				}

				// Check second sub-classifier (NOT)
				notClassifier, ok := andClassifier.Classifiers[1].(*ClassifierNot)
				if !ok {
					t.Fatalf("Expected second sub-classifier to be *ClassifierNot, got %T", andClassifier.Classifiers[1])
				}

				// Check NOT's sub-classifier (port)
				portClassifier, ok := notClassifier.Classifier.(*ClassifierPort)
				if !ok {
					t.Fatalf("Expected NOT's sub-classifier to be *ClassifierPort, got %T", notClassifier.Classifier)
				}
				if portClassifier.Port != 443 {
					t.Errorf("Expected port 443, got %d", portClassifier.Port)
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			classifier, err := parseClassifier(tc.input)

			if (err != nil) != tc.expectError {
				t.Fatalf("parseClassifier() error = %v, expectError %v", err, tc.expectError)
			}

			if !tc.expectError && tc.validate != nil {
				tc.validate(t, classifier)
			}
		})
	}
}

func TestLoadConfigHCL(t *testing.T) {
	// --- Test Case: HCL Basic Configuration ---
	basicHCLContent := `
servers = [
  {
    type = "standard"
    listen-address = "localhost:8000"
    enabled = true
  }
]
timeout-seconds = 60
max-concurrent-connections = 200
classifiers = {
  port1 = {
    type = "port"
    port = 443
  }
}
`
	testDir := t.TempDir()
	basicHCLPath := createTempConfigFile(t, testDir, "basic.hcl", basicHCLContent)
	cfg, err := LoadConfig(basicHCLPath)
	if err != nil {
		t.Fatalf("Failed to load basic HCL config: %v", err)
	}

	// Verify server configuration
	if len(cfg.Servers) != 1 {
		t.Fatalf("Expected 1 server, got %d", len(cfg.Servers))
	}
	server := cfg.Servers[0]
	if server.Type != ProxyTypeStandard {
		t.Errorf("Expected server type standard, got %s", server.Type)
	}
	if server.ListenAddress != "localhost:8000" {
		t.Errorf("Expected listen address localhost:8000, got %s", server.ListenAddress)
	}
	if !server.Enabled {
		t.Errorf("Expected server to be enabled")
	}

	// Verify global settings
	if cfg.TimeoutSeconds != 60 {
		t.Errorf("Expected timeout 60, got %d", cfg.TimeoutSeconds)
	}
	if cfg.MaxConcurrentConnections != 200 {
		t.Errorf("Expected max connections 200, got %d", cfg.MaxConcurrentConnections)
	}

	// Verify classifier
	c, ok := cfg.Classifiers["port1"].(*ClassifierPort)
	if !ok {
		t.Fatalf("Expected *ClassifierPort, got %T", cfg.Classifiers["port1"])
	}
	if c.Port != 443 {
		t.Errorf("Expected port 443, got %d", c.Port)
	}

	// --- Test Case: HCL Complex Configuration with Forwards ---
	complexHCLContent := `
servers = [
  {
    type = "https"
    listen-address = "localhost:8443"
    enabled = true
    interceptor-name = "ssl-interceptor"
    max-connections = 150
    connections-per-client = 20
  },
  {
    type = "http"
    listen-address = "localhost:8080"
    enabled = true
  }
]

timeout-seconds = 45
max-concurrent-connections = 300

classifiers = {
  internal_net = {
    type = "network"
    cidr = "192.168.0.0/16"
  }
  
  external_domains = {
    type = "domain"
    domain = "external.com"
    op = "contains"
  }
  
  always_true = {
    type = "true"
  }
  
  combined_rule = {
    type = "and"
    classifiers = [
      {
        type = "domain"
        domain = "example.com"
        op = "equal"
      },
      {
        type = "port"
        port = 443
      }
    ]
  }
}

forwards = [
  {
    type = "socks5"
    address = "proxy.internal.com:1080"
    username = "proxyuser"
    password = "proxypass"
    force-ipv4 = true
    classifier = {
      type = "ref"
      id = "internal_net"
    }
  },
  {
    type = "proxy"
    address = "corp-proxy.example.com:8080"
    classifier = {
      type = "domain"
      domain = "corporate.com"
      op = "contains"
    }
  },
  {
    type = "default-network"
    force-ipv4 = false
    classifier = {
      type = "true"
    }
  }
]
`
	complexHCLPath := createTempConfigFile(t, testDir, "complex.hcl", complexHCLContent)
	complexCfg, err := LoadConfig(complexHCLPath)
	if err != nil {
		t.Fatalf("Failed to load complex HCL config: %v", err)
	}

	// Verify servers
	if len(complexCfg.Servers) != 2 {
		t.Fatalf("Expected 2 servers, got %d", len(complexCfg.Servers))
	}

	httpsServer := complexCfg.Servers[0]
	if httpsServer.Type != ProxyTypeHTTPS {
		t.Errorf("Expected first server type https, got %s", httpsServer.Type)
	}
	if httpsServer.InterceptorName != "ssl-interceptor" {
		t.Errorf("Expected interceptor name ssl-interceptor, got %s", httpsServer.InterceptorName)
	}
	if httpsServer.MaxConnections != 150 {
		t.Errorf("Expected max connections 150, got %d", httpsServer.MaxConnections)
	}

	// Verify classifiers
	if len(complexCfg.Classifiers) != 4 {
		t.Fatalf("Expected 4 classifiers, got %d", len(complexCfg.Classifiers))
	}

	// Test network classifier
	netClassifier, ok := complexCfg.Classifiers["internal_net"].(*ClassifierNetwork)
	if !ok {
		t.Fatalf("Expected *ClassifierNetwork, got %T", complexCfg.Classifiers["internal_net"])
	}
	if netClassifier.CIDR != "192.168.0.0/16" {
		t.Errorf("Expected CIDR 192.168.0.0/16, got %s", netClassifier.CIDR)
	}

	// Test AND classifier
	andClassifier, ok := complexCfg.Classifiers["combined_rule"].(*ClassifierAnd)
	if !ok {
		t.Fatalf("Expected *ClassifierAnd, got %T", complexCfg.Classifiers["combined_rule"])
	}
	if len(andClassifier.Classifiers) != 2 {
		t.Fatalf("Expected 2 sub-classifiers in AND, got %d", len(andClassifier.Classifiers))
	}

	// Verify forwards
	if len(complexCfg.Forwards) != 3 {
		t.Fatalf("Expected 3 forwards, got %d", len(complexCfg.Forwards))
	}

	// Test SOCKS5 forward
	socks5Forward := complexCfg.Forwards[0].(*ForwardSocks5)
	if socks5Forward.Address != "proxy.internal.com:1080" {
		t.Errorf("Expected SOCKS5 address proxy.internal.com:1080, got %s", socks5Forward.Address)
	}
	if socks5Forward.Username == nil || *socks5Forward.Username != "proxyuser" {
		t.Errorf("Expected SOCKS5 username proxyuser, got %v", socks5Forward.Username)
	}
	if !socks5Forward.ForceIPv4 {
		t.Errorf("Expected SOCKS5 ForceIPv4 to be true")
	}

	// Test ref classifier in SOCKS5 forward
	refClassifier, ok := socks5Forward.Classifier().(*ClassifierRef)
	if !ok {
		t.Fatalf("Expected *ClassifierRef in SOCKS5 forward, got %T", socks5Forward.Classifier())
	}
	if refClassifier.Id != "internal_net" {
		t.Errorf("Expected ref ID internal_net, got %s", refClassifier.Id)
	}
}

func TestLoadConfigHCL_ErrorCases(t *testing.T) {
	testDir := t.TempDir()

	testCases := []struct {
		name        string
		hclContent  string
		expectedErr string
	}{
		{
			name: "Invalid HCL syntax",
			hclContent: `
servers = [
  {
    type = "standard
    listen-address = "localhost:8000"
  }
]`,
			expectedErr: "failed to parse HCL config",
		},
		{
			name: "Invalid proxy type",
			hclContent: `
servers = [
  {
    type = "invalid-type"
    listen-address = "localhost:8000"
  }
]`,
			expectedErr: "invalid proxy type",
		},
		{
			name: "Missing SOCKS5 address",
			hclContent: `
forwards = [
  {
    type = "socks5"
    username = "user"
  }
]`,
			expectedErr: "socks5 forward requires address field",
		},
		{
			name: "Invalid classifier type",
			hclContent: `
classifiers = {
  test = {
    type = "unknown-type"
  }
}`,
			expectedErr: "unsupported classifier type",
		},
		{
			name: "Underscore key validation",
			hclContent: `
timeout_seconds = 30
`,
			expectedErr: "invalid config key 'timeout_seconds': use 'timeout-seconds' instead",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hclPath := createTempConfigFile(t, testDir, tc.name+".hcl", tc.hclContent)
			_, err := LoadConfig(hclPath)
			if err == nil {
				t.Fatalf("Expected error but got none")
			}
			if !strings.Contains(err.Error(), tc.expectedErr) {
				t.Errorf("Expected error to contain '%s', got '%s'", tc.expectedErr, err.Error())
			}
		})
	}
}

func TestLoadConfigHCL_Secrets(t *testing.T) {
	testDir := t.TempDir()

	// Set environment variables for secrets
	os.Setenv("HCL_ADDR_SECRET", "127.0.0.1:9000")
	defer os.Unsetenv("HCL_ADDR_SECRET")
	os.Setenv("HCL_TIMEOUT_SECRET", "45")
	defer os.Unsetenv("HCL_TIMEOUT_SECRET")
	os.Setenv("HCL_USERNAME_SECRET", "hcluser")
	defer os.Unsetenv("HCL_USERNAME_SECRET")

	secretHCLContent := `
servers = [
  {
    type = "standard"
    listen-address = {
      _secret = "HCL_ADDR_SECRET"
    }
    enabled = true
  }
]
timeout-seconds = {
  _secret = "HCL_TIMEOUT_SECRET"
}
forwards = [
  {
    type = "socks5"
    address = "proxy.example.com:1080"
    username = {
      _secret = "HCL_USERNAME_SECRET"
    }
  }
]
`
	secretHCLPath := createTempConfigFile(t, testDir, "secret.hcl", secretHCLContent)
	cfg, err := LoadConfig(secretHCLPath)
	if err != nil {
		t.Fatalf("Failed to load HCL config with secrets: %v", err)
	}

	// Verify secret values were resolved
	if len(cfg.Servers) != 1 || cfg.Servers[0].ListenAddress != "127.0.0.1:9000" {
		t.Errorf("Expected server address 127.0.0.1:9000, got %v", cfg.Servers[0].ListenAddress)
	}
	if cfg.TimeoutSeconds != 45 {
		t.Errorf("Expected timeout 45, got %d", cfg.TimeoutSeconds)
	}

	if len(cfg.Forwards) != 1 {
		t.Fatalf("Expected 1 forward, got %d", len(cfg.Forwards))
	}
	socks5Forward := cfg.Forwards[0].(*ForwardSocks5)
	if socks5Forward.Username == nil || *socks5Forward.Username != "hcluser" {
		t.Errorf("Expected username hcluser, got %v", socks5Forward.Username)
	}
}

func TestLoadConfigHCL_vs_JSON_Equivalence(t *testing.T) {
	testDir := t.TempDir()

	// Define equivalent configurations in JSON and HCL
	jsonContent := `{
		"servers": [
			{
				"type": "standard",
				"listen-address": "localhost:8000",
				"enabled": true,
				"max-connections": 100,
				"connections-per-client": 10
			}
		],
		"timeout-seconds": 30,
		"max-concurrent-connections": 150,
		"classifiers": {
			"test_domain": {
				"type": "domain",
				"domain": "example.com",
				"op": "equal"
			},
			"test_port": {
				"type": "port",
				"port": 443
			}
		},
		"forwards": [
			{
				"type": "socks5",
				"address": "proxy.example.com:1080",
				"username": "testuser",
				"classifier": {
					"type": "ref",
					"id": "test_domain"
				}
			}
		]
	}`

	hclContent := `
servers = [
  {
    type = "standard"
    listen-address = "localhost:8000"
    enabled = true
    max-connections = 100
    connections-per-client = 10
  }
]

timeout-seconds = 30
max-concurrent-connections = 150

classifiers = {
  test_domain = {
    type = "domain"
    domain = "example.com"
    op = "equal"
  }
  test_port = {
    type = "port"
    port = 443
  }
}

forwards = [
  {
    type = "socks5"
    address = "proxy.example.com:1080"
    username = "testuser"
    classifier = {
      type = "ref"
      id = "test_domain"
    }
  }
]
`

	jsonPath := createTempConfigFile(t, testDir, "equiv.json", jsonContent)
	hclPath := createTempConfigFile(t, testDir, "equiv.hcl", hclContent)

	jsonCfg, err := LoadConfig(jsonPath)
	if err != nil {
		t.Fatalf("Failed to load JSON config: %v", err)
	}

	hclCfg, err := LoadConfig(hclPath)
	if err != nil {
		t.Fatalf("Failed to load HCL config: %v", err)
	}

	// Compare basic settings
	if jsonCfg.TimeoutSeconds != hclCfg.TimeoutSeconds {
		t.Errorf("TimeoutSeconds mismatch: JSON=%d, HCL=%d", jsonCfg.TimeoutSeconds, hclCfg.TimeoutSeconds)
	}
	if jsonCfg.MaxConcurrentConnections != hclCfg.MaxConcurrentConnections {
		t.Errorf("MaxConcurrentConnections mismatch: JSON=%d, HCL=%d", jsonCfg.MaxConcurrentConnections, hclCfg.MaxConcurrentConnections)
	}

	// Compare servers
	if len(jsonCfg.Servers) != len(hclCfg.Servers) {
		t.Fatalf("Server count mismatch: JSON=%d, HCL=%d", len(jsonCfg.Servers), len(hclCfg.Servers))
	}
	jsonServer := jsonCfg.Servers[0]
	hclServer := hclCfg.Servers[0]
	if jsonServer.Type != hclServer.Type || jsonServer.ListenAddress != hclServer.ListenAddress {
		t.Errorf("Server config mismatch: JSON={Type: %s, Addr: %s}, HCL={Type: %s, Addr: %s}",
			jsonServer.Type, jsonServer.ListenAddress, hclServer.Type, hclServer.ListenAddress)
	}

	// Compare classifiers count
	if len(jsonCfg.Classifiers) != len(hclCfg.Classifiers) {
		t.Fatalf("Classifier count mismatch: JSON=%d, HCL=%d", len(jsonCfg.Classifiers), len(hclCfg.Classifiers))
	}

	// Compare domain classifier
	jsonDomain := jsonCfg.Classifiers["test_domain"].(*ClassifierDomain)
	hclDomain := hclCfg.Classifiers["test_domain"].(*ClassifierDomain)
	if jsonDomain.Domain != hclDomain.Domain || jsonDomain.Op != hclDomain.Op {
		t.Errorf("Domain classifier mismatch: JSON={Domain: %s, Op: %v}, HCL={Domain: %s, Op: %v}",
			jsonDomain.Domain, jsonDomain.Op, hclDomain.Domain, hclDomain.Op)
	}

	// Compare forwards
	if len(jsonCfg.Forwards) != len(hclCfg.Forwards) {
		t.Fatalf("Forward count mismatch: JSON=%d, HCL=%d", len(jsonCfg.Forwards), len(hclCfg.Forwards))
	}
	jsonForward := jsonCfg.Forwards[0].(*ForwardSocks5)
	hclForward := hclCfg.Forwards[0].(*ForwardSocks5)
	if jsonForward.Address != hclForward.Address {
		t.Errorf("Forward address mismatch: JSON=%s, HCL=%s", jsonForward.Address, hclForward.Address)
	}
	if (jsonForward.Username == nil) != (hclForward.Username == nil) ||
		(jsonForward.Username != nil && *jsonForward.Username != *hclForward.Username) {
		t.Errorf("Forward username mismatch: JSON=%v, HCL=%v", jsonForward.Username, hclForward.Username)
	}
}

func TestParseConfigData(t *testing.T) {
	// Test the shared parseConfigData function directly
	testCases := []struct {
		name        string
		data        map[string]any
		expectError bool
		validate    func(t *testing.T, cfg *Config)
	}{
		{
			name:        "Empty data",
			data:        map[string]any{},
			expectError: false,
			validate: func(t *testing.T, cfg *Config) {
				// Should keep default values
				if len(cfg.Servers) == 0 {
					t.Errorf("Expected default server, got none")
				}
			},
		},
		{
			name: "Invalid server array",
			data: map[string]any{
				"servers": "not-an-array",
			},
			expectError: true,
		},
		{
			name: "Valid minimal config",
			data: map[string]any{
				"timeout-seconds": float64(45),
				"classifiers": map[string]any{
					"test": map[string]any{
						"type": "true",
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.TimeoutSeconds != 45 {
					t.Errorf("Expected timeout 45, got %d", cfg.TimeoutSeconds)
				}
				if len(cfg.Classifiers) != 1 {
					t.Errorf("Expected 1 classifier, got %d", len(cfg.Classifiers))
				}
				if _, ok := cfg.Classifiers["test"].(*ClassifierTrue); !ok {
					t.Errorf("Expected ClassifierTrue, got %T", cfg.Classifiers["test"])
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Start with default config
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

			err := parseConfigData(tc.data, cfg)

			if (err != nil) != tc.expectError {
				t.Fatalf("parseConfigData() error = %v, expectError %v", err, tc.expectError)
			}

			if !tc.expectError && tc.validate != nil {
				tc.validate(t, cfg)
			}
		})
	}
}

func TestValidateConfigKeys_UnderscoreDetection(t *testing.T) {
	testDir := t.TempDir()

	testCases := []struct {
		name          string
		jsonContent   string
		expectedError string
		shouldError   bool
	}{
		{
			name: "Top-level underscore keys",
			jsonContent: `{
				"listen_address": "localhost:8080",
				"timeout_seconds": 30,
				"max_concurrent_connections": 100
			}`,
			expectedError: "invalid config key",
			shouldError:   true,
		},
		{
			name: "Server config underscore keys",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen_address": "localhost:8080",
						"max_connections": 50,
						"connections_per_client": 5
					}
				]
			}`,
			expectedError: "invalid server config key",
			shouldError:   true,
		},
		{
			name: "Forward config underscore keys",
			jsonContent: `{
				"forwards": [
					{
						"type": "socks5",
						"address": "proxy.example.com:1080",
						"force_ipv4": true
					}
				]
			}`,
			expectedError: "invalid forward config key 'force_ipv4' at index 0: use 'force-ipv4' instead (hyphens, not underscores)",
			shouldError:   true,
		},
		{
			name: "Classifier config underscore keys",
			jsonContent: `{
				"classifiers": {
					"test": {
						"type": "domains-file",
						"file": "/tmp/domains.txt"
					}
				}
			}`,
			expectedError: "invalid classifier 'test' key 'domains_file': use 'domains-file' instead (hyphens, not underscores)",
			shouldError:   false, // This should work since domains-file is correct
		},
		{
			name: "Classifier with underscore type name",
			jsonContent: `{
				"classifiers": {
					"test": {
						"type": "domains_file",
						"file": "/tmp/domains.txt"
					}
				}
			}`,
			expectedError: "invalid classifier type 'domains_file': use 'domains-file' instead (hyphens, not underscores)",
			shouldError:   true,
		},
		{
			name: "Nested domain classifier with underscore operation value",
			jsonContent: `{
				"classifiers": {
					"test": {
						"type": "domain",
						"domain": "example.com",
						"op": "not-equal"
					}
				}
			}`,
			expectedError: "",
			shouldError:   false, // This should work since it's using correct key names and hyphenated values
		},
		{
			name: "NOT classifier with underscore type in nested classifier",
			jsonContent: `{
				"classifiers": {
					"negated": {
						"type": "not",
						"classifier": {
							"type": "domains_file",
							"file": "/tmp/test.txt"
						}
					}
				}
			}`,
			expectedError: "invalid classifier type 'domains_file': use 'domains-file' instead (hyphens, not underscores)",
			shouldError:   true,
		},
		{
			name: "Valid config with correct hyphenated keys",
			jsonContent: `{
				"listen-address": "localhost:8080",
				"timeout-seconds": 30,
				"max-concurrent-connections": 100,
				"servers": [
					{
						"type": "standard",
						"listen-address": "localhost:8080",
						"max-connections": 50,
						"connections-per-client": 5
					}
				],
				"forwards": [
					{
						"type": "default-network",
						"force-ipv4": true
					}
				],
				"classifiers": {
					"test": {
						"type": "domains-file",
						"file": "/tmp/domains.txt"
					}
				}
			}`,
			shouldError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configPath := createTempConfigFile(t, testDir, tc.name+".json", tc.jsonContent)

			_, err := LoadConfig(configPath)

			if tc.shouldError {
				if err == nil {
					t.Fatalf("Expected error but got none")
				}
				if !strings.Contains(err.Error(), tc.expectedError) {
					t.Errorf("Expected error to contain '%s', but got '%s'", tc.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

// TestPortalConfiguration tests the portal configuration parsing
func TestPortalConfiguration(t *testing.T) {
	testDir := t.TempDir()

	testCases := []struct {
		name        string
		jsonContent string
		wantErr     bool
		validate    func(t *testing.T, cfg *Config)
	}{
		{
			name: "Portal with username and password",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": "admin",
					"password": "secure-password"
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Portal.Username != "admin" {
					t.Errorf("Expected portal username 'admin', got '%s'", cfg.Portal.Username)
				}
				if cfg.Portal.Password != "secure-password" {
					t.Errorf("Expected portal password 'secure-password', got '%s'", cfg.Portal.Password)
				}
			},
		},
		{
			name: "Portal with empty username and password",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": "",
					"password": ""
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Portal.Username != "" {
					t.Errorf("Expected empty portal username, got '%s'", cfg.Portal.Username)
				}
				if cfg.Portal.Password != "" {
					t.Errorf("Expected empty portal password, got '%s'", cfg.Portal.Password)
				}
			},
		},
		{
			name: "Portal with only username",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": "admin"
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Portal.Username != "admin" {
					t.Errorf("Expected portal username 'admin', got '%s'", cfg.Portal.Username)
				}
				if cfg.Portal.Password != "" {
					t.Errorf("Expected empty portal password, got '%s'", cfg.Portal.Password)
				}
			},
		},
		{
			name: "Portal with only password",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"password": "secure-password"
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Portal.Username != "" {
					t.Errorf("Expected empty portal username, got '%s'", cfg.Portal.Username)
				}
				if cfg.Portal.Password != "secure-password" {
					t.Errorf("Expected portal password 'secure-password', got '%s'", cfg.Portal.Password)
				}
			},
		},
		{
			name: "No portal configuration",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				]
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Portal.Username != "" {
					t.Errorf("Expected empty portal username, got '%s'", cfg.Portal.Username)
				}
				if cfg.Portal.Password != "" {
					t.Errorf("Expected empty portal password, got '%s'", cfg.Portal.Password)
				}
			},
		},
		{
			name: "Portal with special characters in credentials",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": "admin@example.com",
					"password": "P@ssw0rd!#$%"
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Portal.Username != "admin@example.com" {
					t.Errorf("Expected portal username 'admin@example.com', got '%s'", cfg.Portal.Username)
				}
				if cfg.Portal.Password != "P@ssw0rd!#$%" {
					t.Errorf("Expected portal password 'P@ssw0rd!#$%%', got '%s'", cfg.Portal.Password)
				}
			},
		},
		{
			name: "Portal with unicode characters",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": "用户名",
					"password": "密码123"
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Portal.Username != "用户名" {
					t.Errorf("Expected portal username '用户名', got '%s'", cfg.Portal.Username)
				}
				if cfg.Portal.Password != "密码123" {
					t.Errorf("Expected portal password '密码123', got '%s'", cfg.Portal.Password)
				}
			},
		},
		{
			name: "Portal with long credentials",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": "very-long-username-that-might-be-used-in-enterprise-environments-with-domain-names",
					"password": "very-long-password-with-multiple-requirements-including-uppercase-lowercase-numbers-and-special-characters-123456789!@#$%^&*()"
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				expectedUsername := "very-long-username-that-might-be-used-in-enterprise-environments-with-domain-names"
				expectedPassword := "very-long-password-with-multiple-requirements-including-uppercase-lowercase-numbers-and-special-characters-123456789!@#$%^&*()"

				if cfg.Portal.Username != expectedUsername {
					t.Errorf("Expected portal username '%s', got '%s'", expectedUsername, cfg.Portal.Username)
				}
				if cfg.Portal.Password != expectedPassword {
					t.Errorf("Expected portal password '%s', got '%s'", expectedPassword, cfg.Portal.Password)
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configPath := createTempConfigFile(t, testDir, tc.name+".json", tc.jsonContent)

			cfg, err := LoadConfig(configPath)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error but got: %v", err)
				}
				if tc.validate != nil {
					tc.validate(t, cfg)
				}
			}
		})
	}
}

// TestPortalConfigurationWithExamples tests the portal configuration with actual example files
func TestPortalConfigurationWithExamples(t *testing.T) {
	testCases := []struct {
		name         string
		configFile   string
		expectAuth   bool
		expectedUser string
	}{
		{
			name:         "Standard config with authentication",
			configFile:   "../../examples/config.json",
			expectAuth:   true,
			expectedUser: "admin",
		},
		{
			name:         "IPv4 forcing config with authentication",
			configFile:   "../../examples/config-with-ipv4-forcing.json",
			expectAuth:   true,
			expectedUser: "admin",
		},
		{
			name:         "Minimal config with authentication",
			configFile:   "../../examples/config-portal-minimal.json",
			expectAuth:   true,
			expectedUser: "admin",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadConfig(tc.configFile)
			if err != nil {
				t.Fatalf("Failed to load config file %s: %v", tc.configFile, err)
			}

			if tc.expectAuth {
				if cfg.Portal.Username == "" {
					t.Errorf("Expected non-empty portal username, got empty string")
				}
				if cfg.Portal.Password == "" {
					t.Errorf("Expected non-empty portal password, got empty string")
				}
				if cfg.Portal.Username != tc.expectedUser {
					t.Errorf("Expected portal username '%s', got '%s'", tc.expectedUser, cfg.Portal.Username)
				}
			} else {
				if cfg.Portal.Username != "" {
					t.Errorf("Expected empty portal username, got '%s'", cfg.Portal.Username)
				}
				if cfg.Portal.Password != "" {
					t.Errorf("Expected empty portal password, got '%s'", cfg.Portal.Password)
				}
			}
		})
	}
}

// TestPortalConfigurationEdgeCases tests edge cases and error conditions
func TestPortalConfigurationEdgeCases(t *testing.T) {
	testDir := t.TempDir()

	testCases := []struct {
		name        string
		jsonContent string
		wantErr     bool
		errorMsg    string
	}{
		{
			name: "Portal with null values",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": null,
					"password": null
				}
			}`,
			wantErr: true, // JSON null should cause an error
		},
		{
			name: "Portal with non-string username",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": 123,
					"password": "password"
				}
			}`,
			wantErr:  true,
			errorMsg: "portal username must be a string",
		},
		{
			name: "Portal with non-string password",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": "admin",
					"password": 123
				}
			}`,
			wantErr:  true,
			errorMsg: "portal password must be a string",
		},
		{
			name: "Portal with boolean values",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": true,
					"password": false
				}
			}`,
			wantErr:  true,
			errorMsg: "portal username must be a string",
		},
		{
			name: "Portal with extra fields",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": "admin",
					"password": "password",
					"extra_field": "ignored"
				}
			}`,
			wantErr: false, // Extra fields should be ignored
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configPath := createTempConfigFile(t, testDir, tc.name+".json", tc.jsonContent)

			cfg, err := LoadConfig(configPath)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("Expected error but got none")
				}
				if tc.errorMsg != "" && !strings.Contains(err.Error(), tc.errorMsg) {
					t.Errorf("Expected error to contain '%s', but got '%s'", tc.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error but got: %v", err)
				}
				// For successful cases, verify the config is valid
				if cfg == nil {
					t.Fatalf("Expected valid config but got nil")
				}
			}
		})
	}
}

// TestPortalConfigurationEnvironmentVariables tests portal configuration via environment variables
func TestPortalConfigurationEnvironmentVariables(t *testing.T) {
	testCases := []struct {
		name         string
		envUsername  string
		envPassword  string
		expectAuth   bool
		expectedUser string
		expectedPass string
	}{
		{
			name:         "Portal with both env vars set",
			envUsername:  "env-admin",
			envPassword:  "env-password",
			expectAuth:   true,
			expectedUser: "env-admin",
			expectedPass: "env-password",
		},
		{
			name:         "Portal with only username env var",
			envUsername:  "env-user",
			envPassword:  "",
			expectAuth:   false,
			expectedUser: "env-user",
			expectedPass: "",
		},
		{
			name:         "Portal with only password env var",
			envUsername:  "",
			envPassword:  "env-secret",
			expectAuth:   false,
			expectedUser: "",
			expectedPass: "env-secret",
		},
		{
			name:         "Portal with no env vars",
			envUsername:  "",
			envPassword:  "",
			expectAuth:   false,
			expectedUser: "",
			expectedPass: "",
		},
		{
			name:         "Portal with special characters in env vars",
			envUsername:  "admin@company.com",
			envPassword:  "P@ssw0rd!#$%^&*()",
			expectAuth:   true,
			expectedUser: "admin@company.com",
			expectedPass: "P@ssw0rd!#$%^&*()",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Clear any existing environment variables
			os.Unsetenv("MSGTAUSCH_PORTAL_USERNAME")
			os.Unsetenv("MSGTAUSCH_PORTAL_PASSWORD")

			// Set test environment variables
			if tc.envUsername != "" {
				os.Setenv("MSGTAUSCH_PORTAL_USERNAME", tc.envUsername)
				defer os.Unsetenv("MSGTAUSCH_PORTAL_USERNAME")
			}
			if tc.envPassword != "" {
				os.Setenv("MSGTAUSCH_PORTAL_PASSWORD", tc.envPassword)
				defer os.Unsetenv("MSGTAUSCH_PORTAL_PASSWORD")
			}

			// Load config without any config file (environment variables only)
			cfg, err := LoadConfig("")
			if err != nil {
				t.Fatalf("Failed to load config with environment variables: %v", err)
			}

			// Verify portal configuration
			if cfg.Portal.Username != tc.expectedUser {
				t.Errorf("Expected portal username '%s', got '%s'", tc.expectedUser, cfg.Portal.Username)
			}
			if cfg.Portal.Password != tc.expectedPass {
				t.Errorf("Expected portal password '%s', got '%s'", tc.expectedPass, cfg.Portal.Password)
			}

			// Additional validation for complete authentication setup
			if tc.expectAuth {
				if cfg.Portal.Username == "" || cfg.Portal.Password == "" {
					t.Errorf("Expected both username and password to be set for authentication, got username='%s', password='%s'",
						cfg.Portal.Username, cfg.Portal.Password)
				}
			}
		})
	}
}

// TestPortalConfigurationMixed tests portal configuration with both config file and environment variables
func TestPortalConfigurationMixed(t *testing.T) {
	testDir := t.TempDir()

	testCases := []struct {
		name         string
		jsonContent  string
		envUsername  string
		envPassword  string
		expectedUser string
		expectedPass string
		description  string
	}{
		{
			name: "Config file overridden by environment variables",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": "config-admin",
					"password": "config-password"
				}
			}`,
			envUsername:  "env-admin",
			envPassword:  "env-password",
			expectedUser: "env-admin",
			expectedPass: "env-password",
			description:  "Environment variables should override config file values",
		},
		{
			name: "Config file with partial env override (username only)",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": "config-admin",
					"password": "config-password"
				}
			}`,
			envUsername:  "env-admin",
			envPassword:  "",
			expectedUser: "env-admin",
			expectedPass: "config-password",
			description:  "Environment username should override config, password should remain from config",
		},
		{
			name: "Config file with partial env override (password only)",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": "config-admin",
					"password": "config-password"
				}
			}`,
			envUsername:  "",
			envPassword:  "env-password",
			expectedUser: "config-admin",
			expectedPass: "env-password",
			description:  "Environment password should override config, username should remain from config",
		},
		{
			name: "Environment variables with no portal in config",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				]
			}`,
			envUsername:  "env-only-admin",
			envPassword:  "env-only-password",
			expectedUser: "env-only-admin",
			expectedPass: "env-only-password",
			description:  "Environment variables should work when no portal config in file",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Clear any existing environment variables
			os.Unsetenv("MSGTAUSCH_PORTAL_USERNAME")
			os.Unsetenv("MSGTAUSCH_PORTAL_PASSWORD")

			// Set test environment variables
			if tc.envUsername != "" {
				os.Setenv("MSGTAUSCH_PORTAL_USERNAME", tc.envUsername)
				defer os.Unsetenv("MSGTAUSCH_PORTAL_USERNAME")
			}
			if tc.envPassword != "" {
				os.Setenv("MSGTAUSCH_PORTAL_PASSWORD", tc.envPassword)
				defer os.Unsetenv("MSGTAUSCH_PORTAL_PASSWORD")
			}

			// Create config file
			configPath := createTempConfigFile(t, testDir, tc.name+".json", tc.jsonContent)

			// Load config
			cfg, err := LoadConfig(configPath)
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}

			// Verify portal configuration
			if cfg.Portal.Username != tc.expectedUser {
				t.Errorf("Expected portal username '%s', got '%s'. %s",
					tc.expectedUser, cfg.Portal.Username, tc.description)
			}
			if cfg.Portal.Password != tc.expectedPass {
				t.Errorf("Expected portal password '%s', got '%s'. %s",
					tc.expectedPass, cfg.Portal.Password, tc.description)
			}
		})
	}
}

// TestStatisticsConfigurationExtended tests additional statistics configuration scenarios
func TestStatisticsConfigurationExtended(t *testing.T) {
	testDir := t.TempDir()

	testCases := []struct {
		name        string
		jsonContent string
		wantErr     bool
		validate    func(t *testing.T, cfg *Config)
	}{
		{
			name: "SQLite statistics configuration",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"statistics": {
					"enabled": true,
					"backend": "sqlite",
					"sqlite-path": "/tmp/stats.db",
					"buffer-size": 500,
					"flush-interval": 10
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if !cfg.Statistics.Enabled {
					t.Errorf("Expected statistics enabled to be true")
				}
				if cfg.Statistics.Backend != "sqlite" {
					t.Errorf("Expected backend 'sqlite', got '%s'", cfg.Statistics.Backend)
				}
				if cfg.Statistics.SQLitePath != "/tmp/stats.db" {
					t.Errorf("Expected SQLite path '/tmp/stats.db', got '%s'", cfg.Statistics.SQLitePath)
				}
				if cfg.Statistics.BufferSize != 500 {
					t.Errorf("Expected buffer size 500, got %d", cfg.Statistics.BufferSize)
				}
				if cfg.Statistics.FlushInterval != 10 {
					t.Errorf("Expected flush interval 10, got %d", cfg.Statistics.FlushInterval)
				}
			},
		},
		{
			name: "PostgreSQL statistics configuration",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"statistics": {
					"enabled": true,
					"backend": "postgres",
					"postgres-dsn": "postgres://user:pass@localhost:5432/db",
					"buffer-size": 1000,
					"flush-interval": 5
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if !cfg.Statistics.Enabled {
					t.Errorf("Expected statistics enabled to be true")
				}
				if cfg.Statistics.Backend != "postgres" {
					t.Errorf("Expected backend 'postgres', got '%s'", cfg.Statistics.Backend)
				}
				if cfg.Statistics.PostgresDSN != "postgres://user:pass@localhost:5432/db" {
					t.Errorf("Expected PostgreSQL DSN 'postgres://user:pass@localhost:5432/db', got '%s'", cfg.Statistics.PostgresDSN)
				}
				if cfg.Statistics.BufferSize != 1000 {
					t.Errorf("Expected buffer size 1000, got %d", cfg.Statistics.BufferSize)
				}
				if cfg.Statistics.FlushInterval != 5 {
					t.Errorf("Expected flush interval 5, got %d", cfg.Statistics.FlushInterval)
				}
			},
		},
		{
			name: "Disabled statistics configuration",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"statistics": {
					"enabled": false
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Statistics.Enabled {
					t.Errorf("Expected statistics enabled to be false")
				}
			},
		},
		{
			name: "Statistics with underscore buffer_size key",
			jsonContent: `{
				"statistics": {
					"enabled": true,
					"backend": "sqlite",
					"buffer_size": 1000
				}
			}`,
			wantErr: true,
		},
		{
			name: "Statistics with underscore flush_interval key",
			jsonContent: `{
				"statistics": {
					"enabled": true,
					"backend": "sqlite",
					"flush_interval": 10
				}
			}`,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configPath := createTempConfigFile(t, testDir, tc.name+".json", tc.jsonContent)

			cfg, err := LoadConfig(configPath)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error but got: %v", err)
				}
				if tc.validate != nil {
					tc.validate(t, cfg)
				}
			}
		})
	}
}

// TestForwardTypeConstants tests the ForwardType constants and methods
func TestForwardTypeConstants(t *testing.T) {
	testCases := []struct {
		name         string
		forwardType  ForwardType
		expectedType ForwardType
	}{
		{"DefaultNetwork", ForwardTypeDefaultNetwork, 0},
		{"Socks5", ForwardTypeSocks5, 1},
		{"Proxy", ForwardTypeProxy, 2},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.forwardType != tc.expectedType {
				t.Errorf("Expected ForwardType %d, got %d", tc.expectedType, tc.forwardType)
			}
		})
	}
}

// TestForwardMethods tests the methods of different Forward implementations
func TestForwardMethods(t *testing.T) {
	// Helper function to create string pointers
	stringPtr := func(s string) *string { return &s }

	testCases := []struct {
		name             string
		forward          Forward
		expectedType     ForwardType
		expectClassifier bool
	}{
		{
			name: "ForwardDefaultNetwork with classifier",
			forward: &ForwardDefaultNetwork{
				ClassifierData: &ClassifierTrue{},
				ForceIPv4:      true,
			},
			expectedType:     ForwardTypeDefaultNetwork,
			expectClassifier: true,
		},
		{
			name: "ForwardDefaultNetwork without classifier",
			forward: &ForwardDefaultNetwork{
				ClassifierData: nil,
				ForceIPv4:      false,
			},
			expectedType:     ForwardTypeDefaultNetwork,
			expectClassifier: true, // Should return default ClassifierTrue
		},
		{
			name: "ForwardSocks5 with classifier",
			forward: &ForwardSocks5{
				ClassifierData: &ClassifierDomain{Domain: "example.com"},
				Address:        "proxy.example.com:1080",
				Username:       stringPtr("user"),
				Password:       stringPtr("pass"),
				ForceIPv4:      true,
			},
			expectedType:     ForwardTypeSocks5,
			expectClassifier: true,
		},
		{
			name: "ForwardSocks5 without classifier",
			forward: &ForwardSocks5{
				ClassifierData: nil,
				Address:        "proxy.example.com:1080",
			},
			expectedType:     ForwardTypeSocks5,
			expectClassifier: true, // Should return default ClassifierTrue
		},
		{
			name: "ForwardProxy with classifier",
			forward: &ForwardProxy{
				ClassifierData: &ClassifierNetwork{CIDR: "10.0.0.0/8"},
				Address:        "proxy.corp.com:8080",
				Username:       stringPtr("admin"),
				Password:       stringPtr("secret"),
				ForceIPv4:      false,
			},
			expectedType:     ForwardTypeProxy,
			expectClassifier: true,
		},
		{
			name: "ForwardProxy without classifier",
			forward: &ForwardProxy{
				ClassifierData: nil,
				Address:        "proxy.corp.com:8080",
			},
			expectedType:     ForwardTypeProxy,
			expectClassifier: true, // Should return default ClassifierTrue
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test Type() method
			if tc.forward.Type() != tc.expectedType {
				t.Errorf("Expected Type() to return %d, got %d", tc.expectedType, tc.forward.Type())
			}

			// Test Classifier() method
			classifier := tc.forward.Classifier()
			if tc.expectClassifier {
				if classifier == nil {
					t.Errorf("Expected Classifier() to return non-nil classifier")
				}
				// When no classifier is set, should return ClassifierTrue as default
				if tc.forward.Classifier() == nil {
					t.Errorf("Expected default ClassifierTrue when no classifier set")
				}
			}
		})
	}
}
