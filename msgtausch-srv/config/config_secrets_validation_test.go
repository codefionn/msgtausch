package config

import (
	"os"
	"strings"
	"testing"
)

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
	secretHCLPath := createTempConfigFileLocal(t, testDir, "secret.hcl", secretHCLContent)
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
			configPath := createTempConfigFileLocal(t, testDir, tc.name+".json", tc.jsonContent)

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
			configPath := createTempConfigFileLocal(t, testDir, tc.name+".json", tc.jsonContent)

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
