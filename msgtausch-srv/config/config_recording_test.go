package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStatisticsConfigWithRecording(t *testing.T) {
	tests := []struct {
		name     string
		jsonData string
		wantErr  bool
		validate func(t *testing.T, cfg *Config)
	}{
		{
			name: "statistics with record classifier",
			jsonData: `{
				"servers": [
					{
						"type": "http",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"statistics": {
					"enabled": true,
					"backend": "sqlite",
					"sqlite-path": "test.db",
					"recording": {
						"type": "record",
						"classifier": {
							"type": "domain",
							"op": "contains",
							"domain": "example"
						}
					}
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.Statistics.Enabled)
				assert.Equal(t, "sqlite", cfg.Statistics.Backend)
				assert.Equal(t, "test.db", cfg.Statistics.SQLitePath)

				require.NotNil(t, cfg.Statistics.Recording)
				assert.Equal(t, ClassifierTypeRecord, cfg.Statistics.Recording.Type())

				recordClassifier, ok := cfg.Statistics.Recording.(*ClassifierRecord)
				require.True(t, ok)
				require.NotNil(t, recordClassifier.Classifier)

				domainClassifier, ok := recordClassifier.Classifier.(*ClassifierDomain)
				require.True(t, ok)
				assert.Equal(t, ClassifierOpContains, domainClassifier.Op)
				assert.Equal(t, "example", domainClassifier.Domain)
			},
		},
		{
			name: "statistics with complex record classifier",
			jsonData: `{
				"servers": [
					{
						"type": "http",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"statistics": {
					"enabled": true,
					"backend": "postgres",
					"postgres-dsn": "postgres://user:pass@localhost/db",
					"recording": {
						"type": "record",
						"classifier": {
							"type": "and",
							"classifiers": [
								{
									"type": "domain",
									"op": "contains",
									"domain": "api"
								},
								{
									"type": "port",
									"port": 443
								}
							]
						}
					}
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.Statistics.Enabled)
				assert.Equal(t, "postgres", cfg.Statistics.Backend)
				assert.Equal(t, "postgres://user:pass@localhost/db", cfg.Statistics.PostgresDSN)

				require.NotNil(t, cfg.Statistics.Recording)
				recordClassifier, ok := cfg.Statistics.Recording.(*ClassifierRecord)
				require.True(t, ok)

				andClassifier, ok := recordClassifier.Classifier.(*ClassifierAnd)
				require.True(t, ok)
				assert.Len(t, andClassifier.Classifiers, 2)
			},
		},
		{
			name: "statistics without recording classifier",
			jsonData: `{
				"servers": [
					{
						"type": "http",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"statistics": {
					"enabled": true,
					"backend": "sqlite",
					"sqlite-path": "test.db"
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.Statistics.Enabled)
				assert.Nil(t, cfg.Statistics.Recording)
			},
		},
		{
			name: "statistics with invalid recording classifier",
			jsonData: `{
				"servers": [
					{
						"type": "http",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"statistics": {
					"enabled": true,
					"backend": "sqlite",
					"sqlite-path": "test.db",
					"recording": {
						"type": "record"
					}
				}
			}`,
			wantErr:  true,
			validate: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := createTempConfigFile(t, t.TempDir(), "test_config.json", tt.jsonData)
			cfg, err := LoadConfig(path)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, cfg)

			if tt.validate != nil {
				tt.validate(t, cfg)
			}
		})
	}
}

func TestParseRecordingClassifierFromJSON(t *testing.T) {
	// Test direct parsing of recording classifier from JSON
	jsonData := `{
		"servers": [
			{
				"type": "http",
				"listen-address": "127.0.0.1:8080",
				"enabled": true
			}
		],
		"statistics": {
			"enabled": true,
			"backend": "sqlite",
			"sqlite-path": "test.db",
			"recording": {
				"type": "record",
				"classifier": {
					"type": "or",
					"classifiers": [
						{
							"type": "domain",
							"op": "equal",
							"domain": "test.com"
						},
						{
							"type": "network",
							"cidr": "192.168.1.0/24"
						}
					]
				}
			}
		}
	}`

	path := createTempConfigFile(t, t.TempDir(), "test_record_classifier.json", jsonData)
	cfg, err := LoadConfig(path)
	require.NoError(t, err)

	// Extract the recording classifier from the parsed config
	require.NotNil(t, cfg.Statistics.Recording)
	classifier := cfg.Statistics.Recording

	recordClassifier, ok := classifier.(*ClassifierRecord)
	require.True(t, ok)

	orClassifier, ok := recordClassifier.Classifier.(*ClassifierOr)
	require.True(t, ok)
	assert.Len(t, orClassifier.Classifiers, 2)

	// Check first classifier (domain)
	domainClassifier, ok := orClassifier.Classifiers[0].(*ClassifierDomain)
	require.True(t, ok)
	assert.Equal(t, ClassifierOpEqual, domainClassifier.Op)
	assert.Equal(t, "test.com", domainClassifier.Domain)

	// Check second classifier (network)
	networkClassifier, ok := orClassifier.Classifiers[1].(*ClassifierNetwork)
	require.True(t, ok)
	assert.Equal(t, "192.168.1.0/24", networkClassifier.CIDR)
}

func TestFullConfigWithRecordingExample(t *testing.T) {
	// Test a complete configuration example similar to what would be used in practice
	jsonData := `{
		"servers": [
			{
				"type": "http",
				"listen-address": "127.0.0.1:8080",
				"enabled": true
			}
		],
		"statistics": {
			"enabled": true,
			"backend": "sqlite",
			"sqlite-path": "recording.db",
			"buffer-size": 1000,
			"flush-interval": 10,
			"recording": {
				"type": "record",
				"classifier": {
					"type": "or",
					"classifiers": [
						{
							"type": "domain",
							"op": "contains",
							"domain": "api"
						},
						{
							"type": "domain",
							"op": "contains",
							"domain": "sensitive"
						}
					]
				}
			}
		},
		"interception": {
			"enabled": true,
			"http": true,
			"https": false
		},
		"classifiers": {
			"test-classifier": {
				"type": "domain",
				"op": "equal",
				"domain": "test.example.com"
			}
		}
	}`

	path := createTempConfigFile(t, t.TempDir(), "full_config.json", jsonData)
	cfg, err := LoadConfig(path)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Validate servers
	require.Len(t, cfg.Servers, 1)
	assert.Equal(t, ProxyTypeHTTP, cfg.Servers[0].Type)
	assert.Equal(t, "127.0.0.1:8080", cfg.Servers[0].ListenAddress)
	assert.True(t, cfg.Servers[0].Enabled)

	// Validate statistics
	assert.True(t, cfg.Statistics.Enabled)
	assert.Equal(t, "sqlite", cfg.Statistics.Backend)
	assert.Equal(t, "recording.db", cfg.Statistics.SQLitePath)
	assert.Equal(t, 1000, cfg.Statistics.BufferSize)
	assert.Equal(t, 10, cfg.Statistics.FlushInterval)

	// Validate recording classifier
	require.NotNil(t, cfg.Statistics.Recording)
	recordClassifier, ok := cfg.Statistics.Recording.(*ClassifierRecord)
	require.True(t, ok)

	orClassifier, ok := recordClassifier.Classifier.(*ClassifierOr)
	require.True(t, ok)
	assert.Len(t, orClassifier.Classifiers, 2)

	// Check both domain classifiers
	for i, expectedDomain := range []string{"api", "sensitive"} {
		domainClassifier, ok := orClassifier.Classifiers[i].(*ClassifierDomain)
		require.True(t, ok, "Classifier %d should be domain classifier", i)
		assert.Equal(t, ClassifierOpContains, domainClassifier.Op)
		assert.Equal(t, expectedDomain, domainClassifier.Domain)
	}

	// Validate interception
	assert.True(t, cfg.Interception.Enabled)
	assert.True(t, cfg.Interception.HTTP)
	assert.False(t, cfg.Interception.HTTPS)

	// Validate regular classifiers are still working
	require.NotNil(t, cfg.Classifiers)
	testClassifier, exists := cfg.Classifiers["test-classifier"]
	require.True(t, exists)
	domainClassifier, ok := testClassifier.(*ClassifierDomain)
	require.True(t, ok)
	assert.Equal(t, "test.example.com", domainClassifier.Domain)
}

func TestRecordingClassifierValidation(t *testing.T) {
	// Test that record classifier validation works correctly
	tests := []struct {
		name        string
		jsonData    string
		expectError bool
		errorSubstr string
	}{
		{
			name: "missing classifier field",
			jsonData: `{
				"servers": [{"type": "http", "listen-address": "127.0.0.1:8080", "enabled": true}],
				"statistics": {
					"enabled": true,
					"backend": "sqlite",
					"recording": {
						"type": "record"
					}
				}
			}`,
			expectError: true,
			errorSubstr: "requires a 'classifier' field",
		},
		{
			name: "invalid nested classifier",
			jsonData: `{
				"servers": [{"type": "http", "listen-address": "127.0.0.1:8080", "enabled": true}],
				"statistics": {
					"enabled": true,
					"backend": "sqlite",
					"recording": {
						"type": "record",
						"classifier": {
							"type": "nonexistent"
						}
					}
				}
			}`,
			expectError: true,
			errorSubstr: "unsupported classifier type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := createTempConfigFile(t, t.TempDir(), "validation_test.json", tt.jsonData)
			_, err := LoadConfig(path)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorSubstr != "" {
					assert.Contains(t, err.Error(), tt.errorSubstr)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}
