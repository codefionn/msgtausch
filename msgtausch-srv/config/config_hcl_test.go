package config

import (
	"strings"
	"testing"
)

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
	basicHCLPath := createTempConfigFileLocal(t, testDir, "basic.hcl", basicHCLContent)
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
	complexHCLPath := createTempConfigFileLocal(t, testDir, "complex.hcl", complexHCLContent)
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
			hclPath := createTempConfigFileLocal(t, testDir, tc.name+".hcl", tc.hclContent)
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

	jsonPath := createTempConfigFileLocal(t, testDir, "equiv.json", jsonContent)
	hclPath := createTempConfigFileLocal(t, testDir, "equiv.hcl", hclContent)

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
