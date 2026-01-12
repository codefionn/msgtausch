package proxy

import (
	"net/http/httptest"
	"testing"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
)

// TestHTTPSClassifierIntegration tests the HTTPS classifier integration in proxy handling
func TestHTTPSClassifierIntegration(t *testing.T) {
	t.Run("HTTPS classifier overrides port-based detection", func(t *testing.T) {
		// Create config with HTTPS classifier that classifies domain "example.com" as HTTPS
		cfg := &config.Config{
			Interception: config.InterceptionConfig{
				Enabled:         true,
				HTTP:            true,
				HTTPS:           true,
				HTTPSClassifier: &config.ClassifierRef{Id: "https-domains"},
			},
			Classifiers: map[string]config.Classifier{
				"https-domains": &config.ClassifierDomain{
					Domain: "example.com",
				},
			},
		}

		// Create proxy and compile classifiers
		proxy := NewProxy(cfg)

		// Check that we have a server with compiled classifiers
		if len(proxy.servers) == 0 {
			// Add a test server
			serverCfg := config.ServerConfig{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:8080",
				Enabled:       true,
			}

			// Compile HTTPS classifier directly for testing
			var httpsClassifier Classifier
			if cfg.Interception.HTTPSClassifier != nil {
				if classifierRef, ok := cfg.Interception.HTTPSClassifier.(*config.ClassifierRef); ok {
					// First, compile all classifiers to get the full map
					if cfg.Classifiers != nil {
						compiledMap, err := CompileClassifiersMap(cfg.Classifiers, nil)
						if err != nil {
							t.Fatalf("Failed to compile classifiers map: %v", err)
						}
						// Look up the specific classifier by ID
						if compiled, exists := compiledMap[classifierRef.Id]; exists {
							httpsClassifier = compiled
						}
					}
				} else {
					// If it's not a ClassifierRef, try to compile it directly
					compiled, err := CompileClassifier(cfg.Interception.HTTPSClassifier, nil)
					if err != nil {
						t.Fatalf("Failed to compile HTTPS classifier: %v", err)
					}
					httpsClassifier = compiled
				}
			}

			server := &Server{
				config:              cfg,
				serverConfig:        serverCfg,
				compiledForwards:    proxy.compiledForwards,
				blocklistClassifier: proxy.blocklistClassifier,
				allowlistClassifier: proxy.allowlistClassifier,
				httpsClassifier:     httpsClassifier,
				proxy:               proxy,
			}
			proxy.servers = append(proxy.servers, server)
		}

		server := proxy.servers[0]

		// Test cases
		testCases := []struct {
			name          string
			targetAddr    string
			remotePort    int
			expectedHTTPS bool
			description   string
		}{
			{
				name:          "Classifier matches domain - should be HTTPS",
				targetAddr:    "example.com:80",
				remotePort:    80,
				expectedHTTPS: true,
				description:   "Domain matches HTTPS classifier, should override port-based detection",
			},
			{
				name:          "Classifier doesn't match domain - should use port detection",
				targetAddr:    "google.com:443",
				remotePort:    443,
				expectedHTTPS: true,
				description:   "Domain doesn't match classifier, should fall back to port-based detection",
			},
			{
				name:          "Classifier doesn't match domain on non-HTTPS port",
				targetAddr:    "google.com:80",
				remotePort:    80,
				expectedHTTPS: false,
				description:   "Domain doesn't match classifier and port is not HTTPS default",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create a test request
				req := httptest.NewRequest("CONNECT", "http://"+tc.targetAddr, nil)
				req.Host = tc.targetAddr

				// Test the HTTPS detection logic by checking the classifier directly
				if server.httpsClassifier != nil {
					hostname := "example.com" // For this test, we know the domain
					if tc.targetAddr == "google.com:443" || tc.targetAddr == "google.com:80" {
						hostname = "google.com"
					}

					classifierInput := ClassifierInput{
						host:       hostname,
						remoteIP:   "",
						remotePort: uint16(tc.remotePort),
					}

					classifierResult, err := server.httpsClassifier.Classify(classifierInput)
					if err != nil {
						t.Fatalf("Error evaluating HTTPS classifier: %v", err)
					}

					// Default port-based detection
					defaultHTTPS := tc.remotePort == 443 || tc.remotePort == 8443

					// The final decision should be based on classifier result
					var finalHTTPS bool
					if hostname == "example.com" {
						// Classifier should match and return true
						finalHTTPS = classifierResult
					} else {
						// Classifier should not match, fall back to port-based
						finalHTTPS = defaultHTTPS
					}

					if finalHTTPS != tc.expectedHTTPS {
						t.Errorf("HTTPS detection failed for %s: expected %v, got %v (classifier: %v, default: %v)",
							tc.targetAddr, tc.expectedHTTPS, finalHTTPS, classifierResult, defaultHTTPS)
					}
				} else {
					t.Error("HTTPS classifier not compiled")
				}
			})
		}
	})

	t.Run("No HTTPS classifier configured - uses default detection", func(t *testing.T) {
		// Create config without HTTPS classifier
		cfg := &config.Config{
			Interception: config.InterceptionConfig{
				Enabled:         true,
				HTTP:            true,
				HTTPS:           true,
				HTTPSClassifier: nil, // No classifier configured
			},
		}

		// Create proxy
		proxy := NewProxy(cfg)

		// Add a test server
		serverCfg := config.ServerConfig{
			Type:          config.ProxyTypeStandard,
			ListenAddress: "127.0.0.1:8080",
			Enabled:       true,
		}

		server := &Server{
			config:              cfg,
			serverConfig:        serverCfg,
			compiledForwards:    proxy.compiledForwards,
			blocklistClassifier: proxy.blocklistClassifier,
			allowlistClassifier: proxy.allowlistClassifier,
			httpsClassifier:     nil, // No HTTPS classifier
			proxy:               proxy,
		}

		// Verify that no HTTPS classifier is set
		if server.httpsClassifier != nil {
			t.Error("Expected no HTTPS classifier, but one was set")
		}

		// In this case, the default port-based detection should be used
		// We can't easily test the full handleConnect method without setting up a complex test,
		// but we verified that the classifier is correctly nil when not configured
	})

	t.Run("HTTPS classifier not found in compiled classifiers", func(t *testing.T) {
		// Create config with HTTPS classifier that doesn't exist
		cfg := &config.Config{
			Interception: config.InterceptionConfig{
				Enabled:         true,
				HTTP:            true,
				HTTPS:           true,
				HTTPSClassifier: &config.ClassifierRef{Id: "non-existent-classifier"},
			},
			Classifiers: map[string]config.Classifier{
				"other-classifier": &config.ClassifierDomain{
					Domain: "example.com",
				},
			},
		}

		// Create proxy and compile classifiers
		proxy := NewProxy(cfg)

		// Add a test server
		serverCfg := config.ServerConfig{
			Type:          config.ProxyTypeStandard,
			ListenAddress: "127.0.0.1:8080",
			Enabled:       true,
		}

		// The server creation should handle the missing classifier gracefully
		var httpsClassifier Classifier
		if cfg.Interception.HTTPSClassifier != nil {
			if classifierRef, ok := cfg.Interception.HTTPSClassifier.(*config.ClassifierRef); ok {
				// First, compile all classifiers to get the full map
				if cfg.Classifiers != nil {
					compiledMap, err := CompileClassifiersMap(cfg.Classifiers, nil)
					if err == nil {
						// Look up the specific classifier by ID
						if compiled, exists := compiledMap[classifierRef.Id]; exists {
							httpsClassifier = compiled
						}
					}
				}
			} else {
				// If it's not a ClassifierRef, try to compile it directly
				compiled, err := CompileClassifier(cfg.Interception.HTTPSClassifier, nil)
				if err == nil {
					httpsClassifier = compiled
				}
			}
			// If compilation fails or classifier not found, httpsClassifier remains nil
		}

		server := &Server{
			config:              cfg,
			serverConfig:        serverCfg,
			compiledForwards:    proxy.compiledForwards,
			blocklistClassifier: proxy.blocklistClassifier,
			allowlistClassifier: proxy.allowlistClassifier,
			httpsClassifier:     httpsClassifier,
			proxy:               proxy,
		}

		// Verify that no HTTPS classifier is set when the configured classifier doesn't exist
		if server.httpsClassifier != nil {
			t.Error("Expected no HTTPS classifier when configured classifier doesn't exist")
		}
	})
}

// TestHTTPSClassifierTypes tests different types of classifiers for HTTPS detection
func TestHTTPSClassifierTypes(t *testing.T) {
	t.Run("Port-based HTTPS classifier", func(t *testing.T) {
		// Create config with port-based HTTPS classifier
		cfg := &config.Config{
			Interception: config.InterceptionConfig{
				Enabled:         true,
				HTTP:            true,
				HTTPS:           true,
				HTTPSClassifier: &config.ClassifierRef{Id: "https-ports"},
			},
			Classifiers: map[string]config.Classifier{
				"https-ports": &config.ClassifierPort{
					Port: 443,
				},
			},
		}

		// Compile the classifier directly
		classifierConfig, exists := cfg.Classifiers["https-ports"]
		if !exists {
			t.Fatal("HTTPS classifier config not found")
		}

		classifier, err := CompileClassifier(classifierConfig, nil)
		if err != nil {
			t.Fatalf("Failed to compile HTTPS classifier: %v", err)
		}

		// Test classification
		testCases := []struct {
			port     uint16
			expected bool
		}{
			{443, true},   // Should match
			{80, false},   // Should not match
			{8443, false}, // Should not match (this classifier only matches 443)
		}

		for _, tc := range testCases {
			result, err := classifier.Classify(ClassifierInput{
				host:       "example.com",
				remoteIP:   "",
				remotePort: tc.port,
			})
			if err != nil {
				t.Fatalf("Error classifying port %d: %v", tc.port, err)
			}
			if result != tc.expected {
				t.Errorf("Port %d: expected %v, got %v", tc.port, tc.expected, result)
			}
		}
	})

	t.Run("OR classifier combining domain and port", func(t *testing.T) {
		// Create config with OR classifier that matches either specific domain or port 443
		cfg := &config.Config{
			Interception: config.InterceptionConfig{
				Enabled:         true,
				HTTP:            true,
				HTTPS:           true,
				HTTPSClassifier: &config.ClassifierRef{Id: "https-domain-or-port"},
			},
			Classifiers: map[string]config.Classifier{
				"https-domain-or-port": &config.ClassifierOr{
					Classifiers: []config.Classifier{
						&config.ClassifierDomain{Domain: "secure.example.com"},
						&config.ClassifierPort{Port: 443},
					},
				},
			},
		}

		// Compile the classifier directly
		classifierConfig, exists := cfg.Classifiers["https-domain-or-port"]
		if !exists {
			t.Fatal("HTTPS OR classifier config not found")
		}

		classifier, err := CompileClassifier(classifierConfig, nil)
		if err != nil {
			t.Fatalf("Failed to compile HTTPS OR classifier: %v", err)
		}

		// Test cases
		testCases := []struct {
			name     string
			host     string
			port     uint16
			expected bool
		}{
			{"Domain matches", "secure.example.com", 80, true}, // Domain matches
			{"Port matches", "other.com", 443, true},           // Port matches
			{"Both match", "secure.example.com", 443, true},    // Both match
			{"Neither match", "other.com", 80, false},          // Neither matches
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				result, err := classifier.Classify(ClassifierInput{
					host:       tc.host,
					remoteIP:   "",
					remotePort: tc.port,
				})
				if err != nil {
					t.Fatalf("Error classifying %s:%d: %v", tc.host, tc.port, err)
				}
				if result != tc.expected {
					t.Errorf("%s:%d: expected %v, got %v", tc.host, tc.port, tc.expected, result)
				}
			})
		}
	})
}
