package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDNSConfig_Unmarshal(t *testing.T) {
	// Test JSON parsing of DNS configuration
	jsonConfig := `{
		"dns": {
			"enabled": true,
			"servers": [
				{
					"address": "8.8.8.8:53",
					"type": "udp",
					"timeout-seconds": 10
				},
				{
					"address": "1.1.1.1:853",
					"type": "dot",
					"timeout-seconds": 15
				}
			]
		}
	}`

	tempDir := t.TempDir()
	tempFilePath := filepath.Join(tempDir, "config.json")
	err := os.WriteFile(tempFilePath, []byte(jsonConfig), 0644)
	if err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}

	cfg, err := LoadConfig(tempFilePath)
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	if !cfg.DNS.Enabled {
		t.Error("Expected DNS enabled to be true")
	}

	if len(cfg.DNS.Servers) != 2 {
		t.Fatalf("Expected 2 DNS servers, got %d", len(cfg.DNS.Servers))
	}

	if cfg.DNS.Servers[0].Address != "8.8.8.8:53" {
		t.Errorf("Expected first DNS server address to be 8.8.8.8:53, got %s", cfg.DNS.Servers[0].Address)
	}

	if cfg.DNS.Servers[0].Type != DNSTypeUDP {
		t.Errorf("Expected first DNS server type to be udp, got %s", cfg.DNS.Servers[0].Type)
	}

	if cfg.DNS.Servers[1].Type != DNSTypeDoT {
		t.Errorf("Expected second DNS server type to be dot, got %s", cfg.DNS.Servers[1].Type)
	}

	if cfg.DNS.Servers[1].TimeoutSeconds != 15 {
		t.Errorf("Expected second DNS server timeout to be 15, got %d", cfg.DNS.Servers[1].TimeoutSeconds)
	}
}

func TestDNSConfig_Default(t *testing.T) {
	// Test that DNS is disabled by default
	tempDir := t.TempDir()
	tempFilePath := filepath.Join(tempDir, "config.json")
	err := os.WriteFile(tempFilePath, []byte("{}"), 0644)
	if err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}

	cfg, err := LoadConfig(tempFilePath)
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	if cfg.DNS.Enabled {
		t.Error("Expected DNS to be disabled by default")
	}

	if len(cfg.DNS.Servers) != 0 {
		t.Errorf("Expected no DNS servers by default, got %d", len(cfg.DNS.Servers))
	}
}

func TestDNSTypeValidation(t *testing.T) {
	// Test invalid DNS type
	invalidJSON := `{
		"dns": {
			"enabled": true,
			"servers": [
				{
					"address": "8.8.8.8:53",
					"type": "invalid"
				}
			]
		}
	}`

	tempDir := t.TempDir()
	tempFilePath := filepath.Join(tempDir, "config.json")
	err := os.WriteFile(tempFilePath, []byte(invalidJSON), 0644)
	if err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}

	_, err = LoadConfig(tempFilePath)
	if err == nil {
		t.Error("Expected error for invalid DNS type, got nil")
	}
}

func TestDNSConfig_Environment(t *testing.T) {
	// Test that DNS config can be loaded from environment variables
	// This is a basic test - actual environment variable testing would require
	// setting environment variables before running the test
	cfg := &Config{}
	cfg.DNS = DefaultDNSConfig()

	// DefaultDNSConfig should have Enabled=false (disabled by default)
	if cfg.DNS.Enabled {
		t.Error("DefaultDNSConfig should have Enabled=false (disabled by default), got true")
	}

	// DefaultDNSConfig should have some default servers configured for reference
	if len(cfg.DNS.Servers) == 0 {
		t.Error("DefaultDNSConfig should have default servers configured")
	}
}

func TestDNSConfig_IPv6(t *testing.T) {
	// Test JSON parsing of DNS configuration with IPv6 addresses
	jsonConfig := `{
		"dns": {
			"enabled": true,
			"servers": [
				{
					"address": "[2001:4860:4860::8888]:53",
					"type": "udp",
					"timeout-seconds": 10
				},
				{
					"address": "[2606:4700:4700::1111]:853",
					"type": "dot",
					"timeout-seconds": 15
				},
				{
					"address": "[::1]:53",
					"type": "tcp",
					"timeout-seconds": 5
				}
			]
		}
	}`

	tempDir := t.TempDir()
	tempFilePath := filepath.Join(tempDir, "config.json")
	err := os.WriteFile(tempFilePath, []byte(jsonConfig), 0644)
	if err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}

	cfg, err := LoadConfig(tempFilePath)
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	if !cfg.DNS.Enabled {
		t.Error("Expected DNS enabled to be true")
	}

	if len(cfg.DNS.Servers) != 3 {
		t.Fatalf("Expected 3 DNS servers, got %d", len(cfg.DNS.Servers))
	}

	// Test Google IPv6 DNS
	if cfg.DNS.Servers[0].Address != "[2001:4860:4860::8888]:53" {
		t.Errorf("Expected first DNS server address to be [2001:4860:4860::8888]:53, got %s", cfg.DNS.Servers[0].Address)
	}
	if cfg.DNS.Servers[0].Type != DNSTypeUDP {
		t.Errorf("Expected first DNS server type to be udp, got %s", cfg.DNS.Servers[0].Type)
	}

	// Test Cloudflare IPv6 DNS
	if cfg.DNS.Servers[1].Address != "[2606:4700:4700::1111]:853" {
		t.Errorf("Expected second DNS server address to be [2606:4700:4700::1111]:853, got %s", cfg.DNS.Servers[1].Address)
	}
	if cfg.DNS.Servers[1].Type != DNSTypeDoT {
		t.Errorf("Expected second DNS server type to be dot, got %s", cfg.DNS.Servers[1].Type)
	}

	// Test localhost IPv6
	if cfg.DNS.Servers[2].Address != "[::1]:53" {
		t.Errorf("Expected third DNS server address to be [::1]:53, got %s", cfg.DNS.Servers[2].Address)
	}
	if cfg.DNS.Servers[2].Type != DNSTypeTCP {
		t.Errorf("Expected third DNS server type to be tcp, got %s", cfg.DNS.Servers[2].Type)
	}
}

func TestDNSConfig_TLSHost(t *testing.T) {
	// Test JSON parsing of DNS configuration with TLS host for SNI
	jsonConfig := `{
		"dns": {
			"enabled": true,
			"servers": [
				{
					"address": "9.9.9.9:853",
					"type": "dot",
					"timeout-seconds": 10,
					"tls-host": "dns.quad9.net"
				},
				{
					"address": "1.1.1.1:853",
					"type": "dot",
					"timeout-seconds": 15,
					"tls-host": "cloudflare-dns.com"
				},
				{
					"address": "8.8.8.8:53",
					"type": "udp",
					"timeout-seconds": 5
				}
			]
		}
	}`

	tempDir := t.TempDir()
	tempFilePath := filepath.Join(tempDir, "config.json")
	err := os.WriteFile(tempFilePath, []byte(jsonConfig), 0644)
	if err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}

	cfg, err := LoadConfig(tempFilePath)
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	if !cfg.DNS.Enabled {
		t.Error("Expected DNS enabled to be true")
	}

	if len(cfg.DNS.Servers) != 3 {
		t.Fatalf("Expected 3 DNS servers, got %d", len(cfg.DNS.Servers))
	}

	// Test Quad9 DoT with custom TLS host
	if cfg.DNS.Servers[0].Address != "9.9.9.9:853" {
		t.Errorf("Expected first DNS server address to be 9.9.9.9:853, got %s", cfg.DNS.Servers[0].Address)
	}
	if cfg.DNS.Servers[0].Type != DNSTypeDoT {
		t.Errorf("Expected first DNS server type to be dot, got %s", cfg.DNS.Servers[0].Type)
	}
	if cfg.DNS.Servers[0].TLSHost != "dns.quad9.net" {
		t.Errorf("Expected first DNS server TLSHost to be dns.quad9.net, got %s", cfg.DNS.Servers[0].TLSHost)
	}

	// Test Cloudflare DoT with custom TLS host
	if cfg.DNS.Servers[1].Address != "1.1.1.1:853" {
		t.Errorf("Expected second DNS server address to be 1.1.1.1:853, got %s", cfg.DNS.Servers[1].Address)
	}
	if cfg.DNS.Servers[1].Type != DNSTypeDoT {
		t.Errorf("Expected second DNS server type to be dot, got %s", cfg.DNS.Servers[1].Type)
	}
	if cfg.DNS.Servers[1].TLSHost != "cloudflare-dns.com" {
		t.Errorf("Expected second DNS server TLSHost to be cloudflare-dns.com, got %s", cfg.DNS.Servers[1].TLSHost)
	}

	// Test UDP server without TLS host (should be empty)
	if cfg.DNS.Servers[2].Address != "8.8.8.8:53" {
		t.Errorf("Expected third DNS server address to be 8.8.8.8:53, got %s", cfg.DNS.Servers[2].Address)
	}
	if cfg.DNS.Servers[2].Type != DNSTypeUDP {
		t.Errorf("Expected third DNS server type to be udp, got %s", cfg.DNS.Servers[2].Type)
	}
	if cfg.DNS.Servers[2].TLSHost != "" {
		t.Errorf("Expected third DNS server TLSHost to be empty, got %s", cfg.DNS.Servers[2].TLSHost)
	}
}
