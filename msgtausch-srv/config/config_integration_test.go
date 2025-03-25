package config

import (
	"os"
	"path/filepath"
	"testing"
)

// Helper function to create a temporary config file
func createTempConfigFileLocal(t *testing.T, dir, filename, content string) string {
	t.Helper()
	tempFilePath := filepath.Join(dir, filename)
	err := os.WriteFile(tempFilePath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to create temp config file %s: %v", tempFilePath, err)
	}
	return tempFilePath
}

func TestLoadConfig_OrClassifierWithDomainsFile(t *testing.T) {
	testDir := t.TempDir()

	// Create a domains file
	domainsFile := createTempConfigFileLocal(t, testDir, "test-domains.txt", "blocked.com\nevil.org\nmalware.net\n")

	// Test config with OR classifier containing domains-file classifier (the original issue)
	configJSON := `{
		"forwards": [
			{
				"type": "socks5",
				"address": "proxy1.example.com:1080",
				"classifier": {
					"type": "or",
					"classifiers": [
						{
							"type": "domains-file",
							"file": "` + domainsFile + `"
						},
						{
							"type": "port",
							"port": 443
						}
					]
				}
			},
			{
				"type": "default-network",
				"classifier": {
					"type": "true"
				}
			}
		]
	}`

	configPath := createTempConfigFileLocal(t, testDir, "or_domains_config.json", configJSON)

	// Load and validate config
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig() failed: %v", err)
	}

	if len(cfg.Forwards) != 2 {
		t.Fatalf("Expected 2 forwards, got %d", len(cfg.Forwards))
	}

	// Check first forward (SOCKS5 with OR classifier)
	socks5Forward, ok := cfg.Forwards[0].(*ForwardSocks5)
	if !ok {
		t.Fatalf("Expected first forward to be *ForwardSocks5, got %T", cfg.Forwards[0])
	}

	if socks5Forward.Address != "proxy1.example.com:1080" {
		t.Errorf("Expected SOCKS5 address 'proxy1.example.com:1080', got '%s'", socks5Forward.Address)
	}

	// Check OR classifier
	orClassifier, ok := socks5Forward.Classifier().(*ClassifierOr)
	if !ok {
		t.Fatalf("Expected classifier to be *ClassifierOr, got %T", socks5Forward.Classifier())
	}

	if len(orClassifier.Classifiers) != 2 {
		t.Fatalf("Expected OR classifier to have 2 sub-classifiers, got %d", len(orClassifier.Classifiers))
	}

	// Check domains-file sub-classifier
	domainsFileClassifier, ok := orClassifier.Classifiers[0].(*ClassifierDomainsFile)
	if !ok {
		t.Fatalf("Expected first sub-classifier to be *ClassifierDomainsFile, got %T", orClassifier.Classifiers[0])
	}

	if domainsFileClassifier.FilePath != domainsFile {
		t.Errorf("Expected domains file path '%s', got '%s'", domainsFile, domainsFileClassifier.FilePath)
	}

	// Check port sub-classifier
	portClassifier, ok := orClassifier.Classifiers[1].(*ClassifierPort)
	if !ok {
		t.Fatalf("Expected second sub-classifier to be *ClassifierPort, got %T", orClassifier.Classifiers[1])
	}

	if portClassifier.Port != 443 {
		t.Errorf("Expected port 443, got %d", portClassifier.Port)
	}

	// Check second forward (default network with true classifier)
	defaultNetworkForward, ok := cfg.Forwards[1].(*ForwardDefaultNetwork)
	if !ok {
		t.Fatalf("Expected second forward to be *ForwardDefaultNetwork, got %T", cfg.Forwards[1])
	}

	if _, ok := defaultNetworkForward.Classifier().(*ClassifierTrue); !ok {
		t.Errorf("Expected second forward classifier to be *ClassifierTrue, got %T", defaultNetworkForward.Classifier())
	}
}

func TestLoadConfig_NestedOrAndNotClassifiers(t *testing.T) {
	testDir := t.TempDir()

	// Test complex nested classifier configuration
	configJSON := `{
		"classifiers": {
			"complex_rule": {
				"type": "and",
				"classifiers": [
					{
						"type": "or",
						"classifiers": [
							{
								"type": "domain",
								"domain": "internal.company.com",
								"op": "contains"
							},
							{
								"type": "network",
								"cidr": "192.168.0.0/16"
							}
						]
					},
					{
						"type": "not",
						"classifier": {
							"type": "port",
							"port": 22
						}
					}
				]
			}
		}
	}`

	configPath := createTempConfigFileLocal(t, testDir, "nested_config.json", configJSON)

	// Load and validate config
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig() failed: %v", err)
	}

	// Check the complex nested classifier
	complexClassifier, exists := cfg.Classifiers["complex_rule"]
	if !exists {
		t.Fatalf("Expected 'complex_rule' classifier to exist")
	}

	// Should be an AND classifier at the top level
	andClassifier, ok := complexClassifier.(*ClassifierAnd)
	if !ok {
		t.Fatalf("Expected top-level classifier to be *ClassifierAnd, got %T", complexClassifier)
	}

	if len(andClassifier.Classifiers) != 2 {
		t.Fatalf("Expected AND classifier to have 2 sub-classifiers, got %d", len(andClassifier.Classifiers))
	}

	// First sub-classifier should be OR
	orClassifier, ok := andClassifier.Classifiers[0].(*ClassifierOr)
	if !ok {
		t.Fatalf("Expected first AND sub-classifier to be *ClassifierOr, got %T", andClassifier.Classifiers[0])
	}

	if len(orClassifier.Classifiers) != 2 {
		t.Fatalf("Expected OR classifier to have 2 sub-classifiers, got %d", len(orClassifier.Classifiers))
	}

	// Check OR's domain sub-classifier
	domainClassifier, ok := orClassifier.Classifiers[0].(*ClassifierDomain)
	if !ok {
		t.Fatalf("Expected OR's first sub-classifier to be *ClassifierDomain, got %T", orClassifier.Classifiers[0])
	}

	if domainClassifier.Domain != "internal.company.com" {
		t.Errorf("Expected domain 'internal.company.com', got '%s'", domainClassifier.Domain)
	}

	if domainClassifier.Op != ClassifierOpContains {
		t.Errorf("Expected ClassifierOpContains, got %v", domainClassifier.Op)
	}

	// Check OR's network sub-classifier
	networkClassifier, ok := orClassifier.Classifiers[1].(*ClassifierNetwork)
	if !ok {
		t.Fatalf("Expected OR's second sub-classifier to be *ClassifierNetwork, got %T", orClassifier.Classifiers[1])
	}

	if networkClassifier.CIDR != "192.168.0.0/16" {
		t.Errorf("Expected CIDR '192.168.0.0/16', got '%s'", networkClassifier.CIDR)
	}

	// Second sub-classifier should be NOT
	notClassifier, ok := andClassifier.Classifiers[1].(*ClassifierNot)
	if !ok {
		t.Fatalf("Expected second AND sub-classifier to be *ClassifierNot, got %T", andClassifier.Classifiers[1])
	}

	// Check NOT's port sub-classifier
	portClassifier, ok := notClassifier.Classifier.(*ClassifierPort)
	if !ok {
		t.Fatalf("Expected NOT's sub-classifier to be *ClassifierPort, got %T", notClassifier.Classifier)
	}

	if portClassifier.Port != 22 {
		t.Errorf("Expected port 22, got %d", portClassifier.Port)
	}
}
