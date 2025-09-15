package proxy

import (
	"testing"
)

// This file contains shared test utilities and imports for proxy tests
// The actual test functions have been split into focused test files:
// - proxy_basic_test.go: Basic HTTP/HTTPS proxy functionality
// - proxy_socks5_test.go: SOCKS5 forwarding tests
// - proxy_interception_test.go: HTTP/HTTPS interception functionality
// - proxy_classifier_test.go: Host filtering and traffic classification
// - proxy_connection_test.go: Connection management and keep-alive tests

// Test placeholder to ensure this file is valid
func TestProxyPackage(t *testing.T) {
	// This test ensures the proxy package compiles correctly
	if testing.Short() {
		t.Skip("Skipping proxy package test in short mode")
	}
}
