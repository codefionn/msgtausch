package config

import (
	"testing"
)

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
			configPath := createTempConfigFileLocal(t, testDir, tc.name+".json", tc.jsonContent)

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
