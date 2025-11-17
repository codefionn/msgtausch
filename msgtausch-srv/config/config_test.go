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
					},
				},
				TimeoutSeconds:           60,
				MaxIdleConns:             2048,
				MaxIdleConnsPerHost:      256,
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
					},
				},
				TimeoutSeconds:           30,
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
