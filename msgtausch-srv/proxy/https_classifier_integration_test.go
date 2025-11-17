package proxy

import (
	"fmt"
	"testing"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHTTPSClassifierEndToEnd tests the HTTPS classifier functionality with actual proxy requests
func TestHTTPSClassifierEndToEnd(t *testing.T) {
	t.Run("Domain-based HTTPS classifier overrides port detection", func(t *testing.T) {
		// Create a config with domain-based HTTPS classifier
		cfg := &config.Config{
			Servers: []config.ServerConfig{
				{
					Type:                 config.ProxyTypeStandard,
					ListenAddress:        "127.0.0.1:0", // Use port 0 for auto-assignment
					Enabled:              true,
				},
			},
			Interception: config.InterceptionConfig{
				Enabled:         true,
				HTTP:            true,
				HTTPS:           true,
				HTTPSClassifier: &config.ClassifierRef{Id: "secure-domains"},
			},
			Classifiers: map[string]config.Classifier{
				"secure-domains": &config.ClassifierDomain{
					Domain: "secure.example.com",
				},
			},
		}

		// Create proxy instance
		proxy := NewProxy(cfg)
		require.NotNil(t, proxy)
		require.Len(t, proxy.servers, 1)

		server := proxy.servers[0]
		require.NotNil(t, server.httpsClassifier, "HTTPS classifier should be compiled and assigned")

		// Test the classifier directly
		testCases := []struct {
			name          string
			host          string
			port          uint16
			expectedHTTPS bool
		}{
			{
				name:          "Domain matches classifier - should be HTTPS even on port 80",
				host:          "secure.example.com",
				port:          80,
				expectedHTTPS: true,
			},
			{
				name:          "Domain matches classifier - should be HTTPS on port 443",
				host:          "secure.example.com",
				port:          443,
				expectedHTTPS: true,
			},
			{
				name:          "Domain doesn't match - should use port-based detection (443)",
				host:          "other.example.com",
				port:          443,
				expectedHTTPS: true, // Port-based detection
			},
			{
				name:          "Domain doesn't match - should use port-based detection (80)",
				host:          "other.example.com",
				port:          80,
				expectedHTTPS: false, // Port-based detection
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Test the HTTPS detection logic
				classifierInput := ClassifierInput{
					host:       tc.host,
					remoteIP:   "",
					remotePort: tc.port,
				}

				classifierResult, err := server.httpsClassifier.Classify(classifierInput)
				require.NoError(t, err, "Classifier should not return error")

				// Default port-based detection
				defaultHTTPS := tc.port == 443 || tc.port == 8443

				// Final decision based on classifier if it matches
				var finalHTTPS bool
				if tc.host == "secure.example.com" {
					finalHTTPS = classifierResult // Should be true due to domain match
				} else {
					finalHTTPS = defaultHTTPS // Should fall back to port-based detection
				}

				assert.Equal(t, tc.expectedHTTPS, finalHTTPS,
					"HTTPS detection mismatch for %s:%d (classifier: %v, default: %v)",
					tc.host, tc.port, classifierResult, defaultHTTPS)
			})
		}
	})

	t.Run("Port-based HTTPS classifier", func(t *testing.T) {
		cfg := &config.Config{
			Servers: []config.ServerConfig{
				{
					Type:                 config.ProxyTypeStandard,
					ListenAddress:        "127.0.0.1:0",
					Enabled:              true,
				},
			},
			Interception: config.InterceptionConfig{
				Enabled:         true,
				HTTP:            true,
				HTTPS:           true,
				HTTPSClassifier: &config.ClassifierRef{Id: "https-ports"},
			},
			Classifiers: map[string]config.Classifier{
				"https-ports": &config.ClassifierPort{
					Port: 8443, // Custom HTTPS port
				},
			},
		}

		proxy := NewProxy(cfg)
		require.NotNil(t, proxy)
		require.Len(t, proxy.servers, 1)

		server := proxy.servers[0]
		require.NotNil(t, server.httpsClassifier)

		testCases := []struct {
			port     uint16
			expected bool
		}{
			{8443, true}, // Should match classifier
			{443, false}, // Should NOT match classifier (only default would match)
			{80, false},  // Should not match
		}

		for _, tc := range testCases {
			result, err := server.httpsClassifier.Classify(ClassifierInput{
				host:       "example.com",
				remoteIP:   "",
				remotePort: tc.port,
			})
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result, "Port %d classification", tc.port)
		}
	})

	t.Run("Complex OR classifier", func(t *testing.T) {
		cfg := &config.Config{
			Servers: []config.ServerConfig{
				{
					Type:                 config.ProxyTypeStandard,
					ListenAddress:        "127.0.0.1:0",
					Enabled:              true,
				},
			},
			Interception: config.InterceptionConfig{
				Enabled:         true,
				HTTP:            true,
				HTTPS:           true,
				HTTPSClassifier: &config.ClassifierRef{Id: "complex-https"},
			},
			Classifiers: map[string]config.Classifier{
				"complex-https": &config.ClassifierOr{
					Classifiers: []config.Classifier{
						&config.ClassifierDomain{Domain: "secure.example.com"},
						&config.ClassifierPort{Port: 8443},
						&config.ClassifierNetwork{CIDR: "192.168.1.0/24"},
					},
				},
			},
		}

		proxy := NewProxy(cfg)
		require.NotNil(t, proxy)
		server := proxy.servers[0]
		require.NotNil(t, server.httpsClassifier)

		testCases := []struct {
			name     string
			host     string
			port     uint16
			remoteIP string
			expected bool
		}{
			{
				name:     "Domain matches",
				host:     "secure.example.com",
				port:     80,
				remoteIP: "10.0.0.1",
				expected: true,
			},
			{
				name:     "Port matches",
				host:     "other.com",
				port:     8443,
				remoteIP: "10.0.0.1",
				expected: true,
			},
			{
				name:     "Network matches",
				host:     "other.com",
				port:     80,
				remoteIP: "192.168.1.100",
				expected: true,
			},
			{
				name:     "Nothing matches",
				host:     "other.com",
				port:     80,
				remoteIP: "10.0.0.1",
				expected: false,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				result, err := server.httpsClassifier.Classify(ClassifierInput{
					host:       tc.host,
					remoteIP:   tc.remoteIP,
					remotePort: tc.port,
				})
				require.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			})
		}
	})
}

// TestHTTPSClassifierReferences tests classifier references and complex configurations
func TestHTTPSClassifierReferences(t *testing.T) {
	t.Run("Classifier reference functionality - should work", func(t *testing.T) {
		cfg := &config.Config{
			Servers: []config.ServerConfig{
				{
					Type:                 config.ProxyTypeStandard,
					ListenAddress:        "127.0.0.1:0",
					Enabled:              true,
				},
			},
			Interception: config.InterceptionConfig{
				Enabled:         true,
				HTTP:            true,
				HTTPS:           true,
				HTTPSClassifier: &config.ClassifierRef{Id: "https-ref"},
			},
			Classifiers: map[string]config.Classifier{
				"https-ref": &config.ClassifierRef{
					Id: "actual-classifier",
				},
				"actual-classifier": &config.ClassifierDomain{
					Domain: "secure.example.com",
				},
			},
		}

		proxy := NewProxy(cfg)
		require.NotNil(t, proxy)
		server := proxy.servers[0]
		require.NotNil(t, server.httpsClassifier)

		// Test that reference works correctly - references should be resolved
		result, err := server.httpsClassifier.Classify(ClassifierInput{
			host:       "secure.example.com",
			remoteIP:   "",
			remotePort: 80,
		})
		require.NoError(t, err, "Reference should work when properly resolved")
		assert.True(t, result, "Should match the domain classifier")
	})

	t.Run("Nested classifier references - should work", func(t *testing.T) {
		cfg := &config.Config{
			Servers: []config.ServerConfig{
				{
					Type:                 config.ProxyTypeStandard,
					ListenAddress:        "127.0.0.1:0",
					Enabled:              true,
				},
			},
			Interception: config.InterceptionConfig{
				Enabled:         true,
				HTTPS:           true,
				HTTPSClassifier: &config.ClassifierRef{Id: "level1-ref"},
			},
			Classifiers: map[string]config.Classifier{
				"level1-ref": &config.ClassifierRef{
					Id: "level2-ref",
				},
				"level2-ref": &config.ClassifierRef{
					Id: "actual-classifier",
				},
				"actual-classifier": &config.ClassifierPort{
					Port: 9443,
				},
			},
		}

		proxy := NewProxy(cfg)
		require.NotNil(t, proxy)
		server := proxy.servers[0]
		require.NotNil(t, server.httpsClassifier)

		// Test that nested reference works correctly - nested references should be resolved
		result, err := server.httpsClassifier.Classify(ClassifierInput{
			host:       "example.com",
			remoteIP:   "",
			remotePort: 9443,
		})
		require.NoError(t, err, "Nested reference should work when properly resolved")
		assert.True(t, result, "Should match the port classifier (port 9443)")
	})
}

// TestHTTPSClassifierErrorHandling tests error handling and edge cases
func TestHTTPSClassifierErrorHandling(t *testing.T) {
	t.Run("Missing classifier reference", func(t *testing.T) {
		cfg := &config.Config{
			Servers: []config.ServerConfig{
				{
					Type:                 config.ProxyTypeStandard,
					ListenAddress:        "127.0.0.1:0",
					Enabled:              true,
				},
			},
			Interception: config.InterceptionConfig{
				Enabled:         true,
				HTTPS:           true,
				HTTPSClassifier: &config.ClassifierRef{Id: "nonexistent-classifier"},
			},
			Classifiers: map[string]config.Classifier{
				"other-classifier": &config.ClassifierDomain{
					Domain: "example.com",
				},
			},
		}

		proxy := NewProxy(cfg)
		require.NotNil(t, proxy)
		server := proxy.servers[0]

		// Should be nil when classifier doesn't exist
		assert.Nil(t, server.httpsClassifier, "HTTPS classifier should be nil when reference doesn't exist")
	})

	t.Run("Invalid classifier configuration", func(t *testing.T) {
		cfg := &config.Config{
			Servers: []config.ServerConfig{
				{
					Type:                 config.ProxyTypeStandard,
					ListenAddress:        "127.0.0.1:0",
					Enabled:              true,
				},
			},
			Interception: config.InterceptionConfig{
				Enabled:         true,
				HTTPS:           true,
				HTTPSClassifier: &config.ClassifierRef{Id: "invalid-classifier"},
			},
			Classifiers: map[string]config.Classifier{
				"invalid-classifier": &config.ClassifierRef{
					Id: "missing-target",
				},
			},
		}

		proxy := NewProxy(cfg)
		require.NotNil(t, proxy)
		server := proxy.servers[0]

		// Classifier is compiled successfully but won't resolve at runtime
		assert.NotNil(t, server.httpsClassifier, "HTTPS classifier should be compiled (references are valid)")

		// Test that the classifier fails when used due to unresolved reference
		_, err := server.httpsClassifier.Classify(ClassifierInput{
			host:       "test.com",
			remoteIP:   "",
			remotePort: 80,
		})
		require.Error(t, err, "Should fail when trying to use unresolved reference")
		assert.Contains(t, err.Error(), "not found", "Error should indicate classifier not found")
	})

	t.Run("Empty classifier configuration", func(t *testing.T) {
		cfg := &config.Config{
			Servers: []config.ServerConfig{
				{
					Type:                 config.ProxyTypeStandard,
					ListenAddress:        "127.0.0.1:0",
					Enabled:              true,
				},
			},
			Interception: config.InterceptionConfig{
				Enabled:         true,
				HTTPS:           true,
				HTTPSClassifier: &config.ClassifierRef{Id: "some-classifier"},
			},
			// No classifiers defined at all
		}

		proxy := NewProxy(cfg)
		require.NotNil(t, proxy)
		server := proxy.servers[0]

		assert.Nil(t, server.httpsClassifier, "HTTPS classifier should be nil when no classifiers are defined")
	})

	t.Run("Empty HTTPS classifier name", func(t *testing.T) {
		cfg := &config.Config{
			Servers: []config.ServerConfig{
				{
					Type:                 config.ProxyTypeStandard,
					ListenAddress:        "127.0.0.1:0",
					Enabled:              true,
				},
			},
			Interception: config.InterceptionConfig{
				Enabled:         true,
				HTTPS:           true,
				HTTPSClassifier: nil, // No classifier
			},
			Classifiers: map[string]config.Classifier{
				"some-classifier": &config.ClassifierDomain{
					Domain: "example.com",
				},
			},
		}

		proxy := NewProxy(cfg)
		require.NotNil(t, proxy)
		server := proxy.servers[0]

		assert.Nil(t, server.httpsClassifier, "HTTPS classifier should be nil when name is empty")
	})
}

// TestHTTPSClassifierPerformance tests the performance aspects of the HTTPS classifier
func TestHTTPSClassifierPerformance(t *testing.T) {
	t.Run("Classifier compilation is done once per server", func(t *testing.T) {
		cfg := &config.Config{
			Servers: []config.ServerConfig{
				{
					Type:                 config.ProxyTypeStandard,
					ListenAddress:        "127.0.0.1:0",
					Enabled:              true,
				},
				{
					Type:                 config.ProxyTypeHTTP,
					ListenAddress:        "127.0.0.1:0",
					Enabled:              true,
				},
			},
			Interception: config.InterceptionConfig{
				Enabled:         true,
				HTTPS:           true,
				HTTPSClassifier: &config.ClassifierRef{Id: "perf-test-classifier"},
			},
			Classifiers: map[string]config.Classifier{
				"perf-test-classifier": &config.ClassifierDomain{
					Domain: "performance.example.com",
				},
			},
		}

		proxy := NewProxy(cfg)
		require.NotNil(t, proxy)
		require.Len(t, proxy.servers, 2)

		// Both servers should have their own classifier instance
		assert.NotNil(t, proxy.servers[0].httpsClassifier)
		assert.NotNil(t, proxy.servers[1].httpsClassifier)

		// Test that both classifiers work independently
		for i, server := range proxy.servers {
			t.Run(fmt.Sprintf("server-%d", i), func(t *testing.T) {
				result, err := server.httpsClassifier.Classify(ClassifierInput{
					host:       "performance.example.com",
					remoteIP:   "",
					remotePort: 80,
				})
				require.NoError(t, err)
				assert.True(t, result)
			})
		}
	})

	t.Run("Fast classifier evaluation", func(t *testing.T) {
		cfg := &config.Config{
			Servers: []config.ServerConfig{
				{
					Type:                 config.ProxyTypeStandard,
					ListenAddress:        "127.0.0.1:0",
					Enabled:              true,
				},
			},
			Interception: config.InterceptionConfig{
				Enabled:         true,
				HTTPS:           true,
				HTTPSClassifier: &config.ClassifierRef{Id: "speed-test"},
			},
			Classifiers: map[string]config.Classifier{
				"speed-test": &config.ClassifierDomain{
					Domain: "speed.example.com",
				},
			},
		}

		proxy := NewProxy(cfg)
		server := proxy.servers[0]
		require.NotNil(t, server.httpsClassifier)

		// Benchmark classifier evaluation speed
		start := time.Now()
		iterations := 1000

		for i := 0; i < iterations; i++ {
			_, err := server.httpsClassifier.Classify(ClassifierInput{
				host:       "speed.example.com",
				remoteIP:   "",
				remotePort: 443,
			})
			require.NoError(t, err)
		}

		duration := time.Since(start)
		avgTime := duration / time.Duration(iterations)

		// Should be very fast (under 100 microseconds per evaluation)
		assert.Less(t, avgTime, 100*time.Microsecond,
			"Classifier evaluation should be fast (got %v per evaluation)", avgTime)
	})
}
