package config

import (
	"os"
	"strings"
	"testing"
)

func TestLoadConfigJSON_InterceptionConfig(t *testing.T) {
	testCases := []struct {
		name                string
		configJSON          string
		expectedEnabled     bool
		expectedHTTP        bool
		expectedHTTPS       bool
		expectedCAFile      string
		expectedCAKeyFile   string
		expectedCAKeyPasswd string
		expectError         bool
		errorSubstring      string
	}{
		{
			name: "Complete interception config",
			configJSON: `{
				"interception": {
					"enabled": true,
					"http": true,
					"https": false,
					"ca-file": "/path/to/ca.crt",
					"ca-key-file": "/path/to/ca.key",
					"ca-key-passwd": "secret123"
				}
			}`,
			expectedEnabled:     true,
			expectedHTTP:        true,
			expectedHTTPS:       false,
			expectedCAFile:      "/path/to/ca.crt",
			expectedCAKeyFile:   "/path/to/ca.key",
			expectedCAKeyPasswd: "secret123",
			expectError:         false,
		},
		{
			name: "Minimal interception config",
			configJSON: `{
				"interception": {
					"enabled": false
				}
			}`,
			expectedEnabled:     false,
			expectedHTTP:        false,
			expectedHTTPS:       false,
			expectedCAFile:      "",
			expectedCAKeyFile:   "",
			expectedCAKeyPasswd: "",
			expectError:         false,
		},
		{
			name: "Only HTTPS enabled",
			configJSON: `{
				"interception": {
					"enabled": true,
					"https": true,
					"ca-file": "/etc/ssl/ca.pem"
				}
			}`,
			expectedEnabled:     true,
			expectedHTTP:        false,
			expectedHTTPS:       true,
			expectedCAFile:      "/etc/ssl/ca.pem",
			expectedCAKeyFile:   "",
			expectedCAKeyPasswd: "",
			expectError:         false,
		},
		{
			name: "Invalid enabled field type",
			configJSON: `{
				"interception": {
					"enabled": "invalid"
				}
			}`,
			expectError:    true,
			errorSubstring: "interception enabled must be a boolean",
		},
		{
			name: "Invalid http field type",
			configJSON: `{
				"interception": {
					"http": "yes"
				}
			}`,
			expectError:    true,
			errorSubstring: "interception http must be a boolean",
		},
		{
			name: "Invalid https field type",
			configJSON: `{
				"interception": {
					"https": 1
				}
			}`,
			expectError:    true,
			errorSubstring: "interception https must be a boolean",
		},
		{
			name: "Invalid ca-file field type",
			configJSON: `{
				"interception": {
					"ca-file": 123
				}
			}`,
			expectError:    true,
			errorSubstring: "interception ca-file must be a string",
		},
		{
			name: "Invalid ca-key-file field type",
			configJSON: `{
				"interception": {
					"ca-key-file": true
				}
			}`,
			expectError:    true,
			errorSubstring: "interception ca-key-file must be a string",
		},
		{
			name: "Invalid ca-key-passwd field type",
			configJSON: `{
				"interception": {
					"ca-key-passwd": ["password"]
				}
			}`,
			expectError:    true,
			errorSubstring: "interception ca-key-passwd must be a string",
		},
		{
			name: "Invalid interception configuration type",
			configJSON: `{
				"interception": "enabled"
			}`,
			expectError:    true,
			errorSubstring: "interception configuration must be an object",
		},
		{
			name: "Underscore key validation",
			configJSON: `{
				"interception": {
					"ca_file": "/path/to/ca.crt"
				}
			}`,
			expectError:    true,
			errorSubstring: "invalid interception config key 'ca_file': use 'ca-file' instead",
		},
		{
			name: "Multiple underscore keys validation",
			configJSON: `{
				"interception": {
					"ca_key_passwd": "secret",
					"ca_key_file": "/path/to/ca.key"
				}
			}`,
			expectError:    true,
			errorSubstring: "invalid interception config key 'ca_key_passwd': use 'ca-key-passwd' instead",
		},
		{
			name: "Empty interception object",
			configJSON: `{
				"interception": {}
			}`,
			expectedEnabled:     false,
			expectedHTTP:        false,
			expectedHTTPS:       false,
			expectedCAFile:      "",
			expectedCAKeyFile:   "",
			expectedCAKeyPasswd: "",
			expectError:         false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configPath := createTempConfigFileLocal(t, t.TempDir(), "config.json", tc.configJSON)
			cfg, err := LoadConfig(configPath)

			if tc.expectError {
				if err == nil {
					t.Fatalf("Expected error containing '%s', but got no error", tc.errorSubstring)
				}
				if !strings.Contains(err.Error(), tc.errorSubstring) {
					t.Fatalf("Expected error containing '%s', but got: %v", tc.errorSubstring, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Verify interception config values
			if cfg.Interception.Enabled != tc.expectedEnabled {
				t.Errorf("Expected Enabled: %t, got: %t", tc.expectedEnabled, cfg.Interception.Enabled)
			}
			if cfg.Interception.HTTP != tc.expectedHTTP {
				t.Errorf("Expected HTTP: %t, got: %t", tc.expectedHTTP, cfg.Interception.HTTP)
			}
			if cfg.Interception.HTTPS != tc.expectedHTTPS {
				t.Errorf("Expected HTTPS: %t, got: %t", tc.expectedHTTPS, cfg.Interception.HTTPS)
			}
			if cfg.Interception.CAFile != tc.expectedCAFile {
				t.Errorf("Expected CAFile: '%s', got: '%s'", tc.expectedCAFile, cfg.Interception.CAFile)
			}
			if cfg.Interception.CAKeyFile != tc.expectedCAKeyFile {
				t.Errorf("Expected CAKeyFile: '%s', got: '%s'", tc.expectedCAKeyFile, cfg.Interception.CAKeyFile)
			}
			if cfg.Interception.CAKeyPasswd != tc.expectedCAKeyPasswd {
				t.Errorf("Expected CAKeyPasswd: '%s', got: '%s'", tc.expectedCAKeyPasswd, cfg.Interception.CAKeyPasswd)
			}
		})
	}
}

func TestLoadConfigHCL_InterceptionConfig(t *testing.T) {
	testCases := []struct {
		name                string
		configHCL           string
		expectedEnabled     bool
		expectedHTTP        bool
		expectedHTTPS       bool
		expectedCAFile      string
		expectedCAKeyFile   string
		expectedCAKeyPasswd string
		expectError         bool
		errorSubstring      string
	}{
		{
			name: "Complete interception config",
			configHCL: `
interception = {
	enabled = true
	http = false
	https = true
	ca-file = "/etc/ssl/proxy-ca.crt"
	ca-key-file = "/etc/ssl/proxy-ca.key"
	ca-key-passwd = "hcl-secret"
}
`,
			expectedEnabled:     true,
			expectedHTTP:        false,
			expectedHTTPS:       true,
			expectedCAFile:      "/etc/ssl/proxy-ca.crt",
			expectedCAKeyFile:   "/etc/ssl/proxy-ca.key",
			expectedCAKeyPasswd: "hcl-secret",
			expectError:         false,
		},
		{
			name: "Boolean values as strings",
			configHCL: `
interception = {
	enabled = "true"
	http = "false"
	https = "1"
}
`,
			expectedEnabled: true,
			expectedHTTP:    false,
			expectedHTTPS:   true,
			expectError:     false,
		},
		{
			name: "Minimal config",
			configHCL: `
interception = {
	enabled = false
}
`,
			expectedEnabled: false,
			expectedHTTP:    false,
			expectedHTTPS:   false,
			expectError:     false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configPath := createTempConfigFileLocal(t, t.TempDir(), "config.hcl", tc.configHCL)
			cfg, err := LoadConfig(configPath)

			if tc.expectError {
				if err == nil {
					t.Fatalf("Expected error containing '%s', but got no error", tc.errorSubstring)
				}
				if !strings.Contains(err.Error(), tc.errorSubstring) {
					t.Fatalf("Expected error containing '%s', but got: %v", tc.errorSubstring, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Verify interception config values
			if cfg.Interception.Enabled != tc.expectedEnabled {
				t.Errorf("Expected Enabled: %t, got: %t", tc.expectedEnabled, cfg.Interception.Enabled)
			}
			if cfg.Interception.HTTP != tc.expectedHTTP {
				t.Errorf("Expected HTTP: %t, got: %t", tc.expectedHTTP, cfg.Interception.HTTP)
			}
			if cfg.Interception.HTTPS != tc.expectedHTTPS {
				t.Errorf("Expected HTTPS: %t, got: %t", tc.expectedHTTPS, cfg.Interception.HTTPS)
			}
			if cfg.Interception.CAFile != tc.expectedCAFile {
				t.Errorf("Expected CAFile: '%s', got: '%s'", tc.expectedCAFile, cfg.Interception.CAFile)
			}
			if cfg.Interception.CAKeyFile != tc.expectedCAKeyFile {
				t.Errorf("Expected CAKeyFile: '%s', got: '%s'", tc.expectedCAKeyFile, cfg.Interception.CAKeyFile)
			}
			if cfg.Interception.CAKeyPasswd != tc.expectedCAKeyPasswd {
				t.Errorf("Expected CAKeyPasswd: '%s', got: '%s'", tc.expectedCAKeyPasswd, cfg.Interception.CAKeyPasswd)
			}
		})
	}
}

func TestLoadConfigFromEnv_InterceptionConfig(t *testing.T) {
	// Save original env vars
	originalVars := map[string]string{
		"MSGTAUSCH_INTERCEPT":      os.Getenv("MSGTAUSCH_INTERCEPT"),
		"MSGTAUSCH_INTERCEPTHTTP":  os.Getenv("MSGTAUSCH_INTERCEPTHTTP"),
		"MSGTAUSCH_INTERCEPTHTTPS": os.Getenv("MSGTAUSCH_INTERCEPTHTTPS"),
		"MSGTAUSCH_CAFILE":         os.Getenv("MSGTAUSCH_CAFILE"),
		"MSGTAUSCH_CAKEYFILE":      os.Getenv("MSGTAUSCH_CAKEYFILE"),
		"MSGTAUSCH_CAKEYPASSWD":    os.Getenv("MSGTAUSCH_CAKEYPASSWD"),
	}

	// Cleanup function to restore env vars
	cleanup := func() {
		for key, val := range originalVars {
			if val == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, val)
			}
		}
	}
	defer cleanup()

	testCases := []struct {
		name                string
		envVars             map[string]string
		expectedEnabled     bool
		expectedHTTP        bool
		expectedHTTPS       bool
		expectedCAFile      string
		expectedCAKeyFile   string
		expectedCAKeyPasswd string
	}{
		{
			name: "All interception env vars set",
			envVars: map[string]string{
				"MSGTAUSCH_INTERCEPT":      "true",
				"MSGTAUSCH_INTERCEPTHTTP":  "1",
				"MSGTAUSCH_INTERCEPTHTTPS": "True",
				"MSGTAUSCH_CAFILE":         "/env/ca.crt",
				"MSGTAUSCH_CAKEYFILE":      "/env/ca.key",
				"MSGTAUSCH_CAKEYPASSWD":    "env-password",
			},
			expectedEnabled:     true,
			expectedHTTP:        true,
			expectedHTTPS:       true,
			expectedCAFile:      "/env/ca.crt",
			expectedCAKeyFile:   "/env/ca.key",
			expectedCAKeyPasswd: "env-password",
		},
		{
			name: "Mixed boolean values",
			envVars: map[string]string{
				"MSGTAUSCH_INTERCEPT":      "false",
				"MSGTAUSCH_INTERCEPTHTTP":  "0",
				"MSGTAUSCH_INTERCEPTHTTPS": "FALSE",
			},
			expectedEnabled: false,
			expectedHTTP:    false,
			expectedHTTPS:   false,
		},
		{
			name: "Only CA files set",
			envVars: map[string]string{
				"MSGTAUSCH_CAFILE":      "/opt/certs/ca.pem",
				"MSGTAUSCH_CAKEYFILE":   "/opt/certs/ca-key.pem",
				"MSGTAUSCH_CAKEYPASSWD": "super-secret",
			},
			expectedEnabled:     false,
			expectedHTTP:        false,
			expectedHTTPS:       false,
			expectedCAFile:      "/opt/certs/ca.pem",
			expectedCAKeyFile:   "/opt/certs/ca-key.pem",
			expectedCAKeyPasswd: "super-secret",
		},
		{
			name: "Case insensitive boolean values",
			envVars: map[string]string{
				"MSGTAUSCH_INTERCEPT":      "TRUE",
				"MSGTAUSCH_INTERCEPTHTTP":  "tRuE",
				"MSGTAUSCH_INTERCEPTHTTPS": "True",
			},
			expectedEnabled: true,
			expectedHTTP:    true,
			expectedHTTPS:   true,
		},
		{
			name: "Invalid boolean values (treated as false)",
			envVars: map[string]string{
				"MSGTAUSCH_INTERCEPT":      "yes",
				"MSGTAUSCH_INTERCEPTHTTP":  "on",
				"MSGTAUSCH_INTERCEPTHTTPS": "2",
			},
			expectedEnabled: false,
			expectedHTTP:    false,
			expectedHTTPS:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Clear all interception env vars first
			os.Unsetenv("MSGTAUSCH_INTERCEPT")
			os.Unsetenv("MSGTAUSCH_INTERCEPTHTTP")
			os.Unsetenv("MSGTAUSCH_INTERCEPTHTTPS")
			os.Unsetenv("MSGTAUSCH_CAFILE")
			os.Unsetenv("MSGTAUSCH_CAKEYFILE")
			os.Unsetenv("MSGTAUSCH_CAKEYPASSWD")

			// Set test env vars
			for key, val := range tc.envVars {
				os.Setenv(key, val)
			}

			// Load config (no file, just defaults + env vars)
			cfg, err := LoadConfig("")
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Verify interception config values
			if cfg.Interception.Enabled != tc.expectedEnabled {
				t.Errorf("Expected Enabled: %t, got: %t", tc.expectedEnabled, cfg.Interception.Enabled)
			}
			if cfg.Interception.HTTP != tc.expectedHTTP {
				t.Errorf("Expected HTTP: %t, got: %t", tc.expectedHTTP, cfg.Interception.HTTP)
			}
			if cfg.Interception.HTTPS != tc.expectedHTTPS {
				t.Errorf("Expected HTTPS: %t, got: %t", tc.expectedHTTPS, cfg.Interception.HTTPS)
			}
			if cfg.Interception.CAFile != tc.expectedCAFile {
				t.Errorf("Expected CAFile: '%s', got: '%s'", tc.expectedCAFile, cfg.Interception.CAFile)
			}
			if cfg.Interception.CAKeyFile != tc.expectedCAKeyFile {
				t.Errorf("Expected CAKeyFile: '%s', got: '%s'", tc.expectedCAKeyFile, cfg.Interception.CAKeyFile)
			}
			if cfg.Interception.CAKeyPasswd != tc.expectedCAKeyPasswd {
				t.Errorf("Expected CAKeyPasswd: '%s', got: '%s'", tc.expectedCAKeyPasswd, cfg.Interception.CAKeyPasswd)
			}
		})
	}
}

func TestLoadConfig_InterceptionConfigPrecedence(t *testing.T) {
	// Test that environment variables override config file values
	tempDir := t.TempDir()
	configJSON := `{
		"interception": {
			"enabled": false,
			"http": false,
			"https": false,
			"ca-file": "/config/ca.crt",
			"ca-key-file": "/config/ca.key",
			"ca-key-passwd": "config-password"
		}
	}`
	configPath := createTempConfigFileLocal(t, tempDir, "config.json", configJSON)

	// Save original env vars
	originalVars := map[string]string{
		"MSGTAUSCH_INTERCEPT":      os.Getenv("MSGTAUSCH_INTERCEPT"),
		"MSGTAUSCH_INTERCEPTHTTP":  os.Getenv("MSGTAUSCH_INTERCEPTHTTP"),
		"MSGTAUSCH_INTERCEPTHTTPS": os.Getenv("MSGTAUSCH_INTERCEPTHTTPS"),
		"MSGTAUSCH_CAFILE":         os.Getenv("MSGTAUSCH_CAFILE"),
		"MSGTAUSCH_CAKEYFILE":      os.Getenv("MSGTAUSCH_CAKEYFILE"),
		"MSGTAUSCH_CAKEYPASSWD":    os.Getenv("MSGTAUSCH_CAKEYPASSWD"),
	}

	defer func() {
		for key, val := range originalVars {
			if val == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, val)
			}
		}
	}()

	// Set env vars that should override config file
	os.Setenv("MSGTAUSCH_INTERCEPT", "true")
	os.Setenv("MSGTAUSCH_INTERCEPTHTTP", "true")
	os.Setenv("MSGTAUSCH_INTERCEPTHTTPS", "true")
	os.Setenv("MSGTAUSCH_CAFILE", "/env/ca.crt")
	os.Setenv("MSGTAUSCH_CAKEYFILE", "/env/ca.key")
	os.Setenv("MSGTAUSCH_CAKEYPASSWD", "env-password")

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify env vars override config file values
	if !cfg.Interception.Enabled {
		t.Error("Expected Enabled to be true (from env var), got false")
	}
	if !cfg.Interception.HTTP {
		t.Error("Expected HTTP to be true (from env var), got false")
	}
	if !cfg.Interception.HTTPS {
		t.Error("Expected HTTPS to be true (from env var), got false")
	}
	if cfg.Interception.CAFile != "/env/ca.crt" {
		t.Errorf("Expected CAFile to be '/env/ca.crt' (from env var), got: '%s'", cfg.Interception.CAFile)
	}
	if cfg.Interception.CAKeyFile != "/env/ca.key" {
		t.Errorf("Expected CAKeyFile to be '/env/ca.key' (from env var), got: '%s'", cfg.Interception.CAKeyFile)
	}
	if cfg.Interception.CAKeyPasswd != "env-password" {
		t.Errorf("Expected CAKeyPasswd to be 'env-password' (from env var), got: '%s'", cfg.Interception.CAKeyPasswd)
	}
}

// TestHTTPSClassifierConfig tests the HTTPS classifier configuration parsing
func TestHTTPSClassifierConfig(t *testing.T) {
	testCases := []struct {
		name                    string
		configJSON              string
		expectedHTTPSClassifier *ClassifierRef
		expectError             bool
		errorSubstring          string
	}{
		{
			name: "HTTPS classifier config",
			configJSON: `{
				"interception": {
					"enabled": true,
					"https": true,
					"https-classifier": "my-https-classifier",
					"ca-file": "/path/to/ca.pem",
					"ca-key-file": "/path/to/ca-key.pem"
				}
			}`,
			expectedHTTPSClassifier: &ClassifierRef{Id: "my-https-classifier"},
			expectError:             false,
		},
		{
			name: "Empty HTTPS classifier",
			configJSON: `{
				"interception": {
					"enabled": true,
					"https": true,
					"ca-file": "/path/to/ca.pem",
					"ca-key-file": "/path/to/ca-key.pem"
				}
			}`,
			expectedHTTPSClassifier: nil,
			expectError:             false,
		},
		{
			name: "Invalid HTTPS classifier field type",
			configJSON: `{
				"interception": {
					"https-classifier": 123
				}
			}`,
			expectError:    true,
			errorSubstring: "interception https-classifier must be a string",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configPath := createTempConfigFileLocal(t, t.TempDir(), "config.json", tc.configJSON)
			cfg, err := LoadConfig(configPath)

			if tc.expectError {
				if err == nil {
					t.Fatalf("Expected error containing '%s', but got no error", tc.errorSubstring)
				}
				if !strings.Contains(err.Error(), tc.errorSubstring) {
					t.Fatalf("Expected error containing '%s', but got: %v", tc.errorSubstring, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Check HTTPSClassifier
			if tc.expectedHTTPSClassifier == nil {
				if cfg.Interception.HTTPSClassifier != nil {
					t.Errorf("Expected HTTPSClassifier to be nil, got: %v", cfg.Interception.HTTPSClassifier)
				}
			} else {
				if cfg.Interception.HTTPSClassifier == nil {
					t.Errorf("Expected HTTPSClassifier to be %v, got: nil", tc.expectedHTTPSClassifier)
				} else if classifierRef, ok := cfg.Interception.HTTPSClassifier.(*ClassifierRef); ok {
					if classifierRef.Id != tc.expectedHTTPSClassifier.Id {
						t.Errorf("Expected HTTPSClassifier ID to be '%s', got: '%s'", tc.expectedHTTPSClassifier.Id, classifierRef.Id)
					}
				} else {
					t.Errorf("Expected HTTPSClassifier to be ClassifierRef, got: %T", cfg.Interception.HTTPSClassifier)
				}
			}
		})
	}
}

// TestHTTPSClassifierConfigHCL tests the HTTPS classifier configuration parsing for HCL
func TestHTTPSClassifierConfigHCL(t *testing.T) {
	hclConfig := `
interception = {
	enabled = true
	https = true
	https-classifier = "domain-based-https"
	ca-file = "/path/to/ca.pem"
	ca-key-file = "/path/to/ca-key.pem"
}`

	configPath := createTempConfigFileLocal(t, t.TempDir(), "config.hcl", hclConfig)
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config from HCL: %v", err)
	}

	if cfg.Interception.HTTPSClassifier == nil {
		t.Errorf("Expected HTTPSClassifier to be set, got: nil")
	} else if classifierRef, ok := cfg.Interception.HTTPSClassifier.(*ClassifierRef); ok {
		if classifierRef.Id != "domain-based-https" {
			t.Errorf("Expected HTTPSClassifier ID to be 'domain-based-https', got: '%s'", classifierRef.Id)
		}
	} else {
		t.Errorf("Expected HTTPSClassifier to be ClassifierRef, got: %T", cfg.Interception.HTTPSClassifier)
	}
}

// TestHTTPSClassifierConfigEnv tests environment variable parsing for HTTPS classifier
func TestHTTPSClassifierConfigEnv(t *testing.T) {
	// Set environment variable
	os.Setenv("MSGTAUSCH_HTTPSCLASSIFIER", "env-classifier")
	defer os.Unsetenv("MSGTAUSCH_HTTPSCLASSIFIER")

	// Create minimal config file
	configJSON := `{
		"interception": {
			"enabled": true
		}
	}`

	configPath := createTempConfigFileLocal(t, t.TempDir(), "config.json", configJSON)
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Interception.HTTPSClassifier == nil {
		t.Errorf("Expected HTTPSClassifier to be set, got: nil")
	} else if classifierRef, ok := cfg.Interception.HTTPSClassifier.(*ClassifierRef); ok {
		if classifierRef.Id != "env-classifier" {
			t.Errorf("Expected HTTPSClassifier ID to be 'env-classifier', got: '%s'", classifierRef.Id)
		}
	} else {
		t.Errorf("Expected HTTPSClassifier to be ClassifierRef, got: %T", cfg.Interception.HTTPSClassifier)
	}
}

func TestLoadConfigJSON_ExcludeClassifier(t *testing.T) {
	testCases := []struct {
		name                      string
		configJSON                string
		expectedExcludeClassifier *ClassifierRef
		expectError               bool
		errorSubstring            string
	}{
		{
			name: "Exclude classifier config",
			configJSON: `{
				"interception": {
					"enabled": true,
					"https": true,
					"exclude-classifier": "no-intercept-hosts",
					"ca-file": "/path/to/ca.pem",
					"ca-key-file": "/path/to/ca-key.pem"
				}
			}`,
			expectedExcludeClassifier: &ClassifierRef{Id: "no-intercept-hosts"},
			expectError:               false,
		},
		{
			name: "No exclude classifier",
			configJSON: `{
				"interception": {
					"enabled": true,
					"https": true,
					"ca-file": "/path/to/ca.pem",
					"ca-key-file": "/path/to/ca-key.pem"
				}
			}`,
			expectedExcludeClassifier: nil,
			expectError:               false,
		},
		{
			name: "Invalid exclude classifier field type",
			configJSON: `{
				"interception": {
					"exclude-classifier": 123
				}
			}`,
			expectError:    true,
			errorSubstring: "interception exclude-classifier must be a string",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configPath := createTempConfigFileLocal(t, t.TempDir(), "config.json", tc.configJSON)
			cfg, err := LoadConfig(configPath)

			if tc.expectError {
				if err == nil {
					t.Fatalf("Expected error containing '%s', but got no error", tc.errorSubstring)
				}
				if !strings.Contains(err.Error(), tc.errorSubstring) {
					t.Fatalf("Expected error containing '%s', but got: %v", tc.errorSubstring, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Check ExcludeClassifier
			if tc.expectedExcludeClassifier == nil {
				if cfg.Interception.ExcludeClassifier != nil {
					t.Errorf("Expected ExcludeClassifier to be nil, got: %v", cfg.Interception.ExcludeClassifier)
				}
			} else {
				if cfg.Interception.ExcludeClassifier == nil {
					t.Errorf("Expected ExcludeClassifier to be %v, got: nil", tc.expectedExcludeClassifier)
				} else if classifierRef, ok := cfg.Interception.ExcludeClassifier.(*ClassifierRef); ok {
					if classifierRef.Id != tc.expectedExcludeClassifier.Id {
						t.Errorf("Expected ExcludeClassifier ID to be '%s', got: '%s'", tc.expectedExcludeClassifier.Id, classifierRef.Id)
					}
				} else {
					t.Errorf("Expected ExcludeClassifier to be ClassifierRef, got: %T", cfg.Interception.ExcludeClassifier)
				}
			}
		})
	}
}

// TestExcludeClassifierConfigEnv tests environment variable parsing for exclude classifier
func TestExcludeClassifierConfigEnv(t *testing.T) {
	// Set environment variable
	os.Setenv("MSGTAUSCH_EXCLUDECLASSIFIER", "env-exclude")
	defer os.Unsetenv("MSGTAUSCH_EXCLUDECLASSIFIER")

	// Create minimal config file
	configJSON := `{
		"interception": {
			"enabled": true
		}
	}`

	configPath := createTempConfigFileLocal(t, t.TempDir(), "config.json", configJSON)
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Interception.ExcludeClassifier == nil {
		t.Errorf("Expected ExcludeClassifier to be set, got: nil")
	} else if classifierRef, ok := cfg.Interception.ExcludeClassifier.(*ClassifierRef); ok {
		if classifierRef.Id != "env-exclude" {
			t.Errorf("Expected ExcludeClassifier ID to be 'env-exclude', got: '%s'", classifierRef.Id)
		}
	} else {
		t.Errorf("Expected ExcludeClassifier to be ClassifierRef, got: %T", cfg.Interception.ExcludeClassifier)
	}
}
