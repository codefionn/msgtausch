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
