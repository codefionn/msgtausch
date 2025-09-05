package config

import (
	"os"
	"strings"
	"testing"
)

// TestPortalConfiguration tests the portal configuration parsing
func TestPortalConfiguration(t *testing.T) {
	testDir := t.TempDir()

	testCases := []struct {
		name        string
		jsonContent string
		wantErr     bool
		validate    func(t *testing.T, cfg *Config)
	}{
		{
			name: "Portal with username and password",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": "admin",
					"password": "secure-password"
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Portal.Username != "admin" {
					t.Errorf("Expected portal username 'admin', got '%s'", cfg.Portal.Username)
				}
				if cfg.Portal.Password != "secure-password" {
					t.Errorf("Expected portal password 'secure-password', got '%s'", cfg.Portal.Password)
				}
			},
		},
		{
			name: "Portal with empty username and password",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": "",
					"password": ""
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Portal.Username != "" {
					t.Errorf("Expected empty portal username, got '%s'", cfg.Portal.Username)
				}
				if cfg.Portal.Password != "" {
					t.Errorf("Expected empty portal password, got '%s'", cfg.Portal.Password)
				}
			},
		},
		{
			name: "Portal with only username",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": "admin"
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Portal.Username != "admin" {
					t.Errorf("Expected portal username 'admin', got '%s'", cfg.Portal.Username)
				}
				if cfg.Portal.Password != "" {
					t.Errorf("Expected empty portal password, got '%s'", cfg.Portal.Password)
				}
			},
		},
		{
			name: "Portal with only password",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"password": "secure-password"
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Portal.Username != "" {
					t.Errorf("Expected empty portal username, got '%s'", cfg.Portal.Username)
				}
				if cfg.Portal.Password != "secure-password" {
					t.Errorf("Expected portal password 'secure-password', got '%s'", cfg.Portal.Password)
				}
			},
		},
		{
			name: "No portal configuration",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				]
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Portal.Username != "" {
					t.Errorf("Expected empty portal username, got '%s'", cfg.Portal.Username)
				}
				if cfg.Portal.Password != "" {
					t.Errorf("Expected empty portal password, got '%s'", cfg.Portal.Password)
				}
			},
		},
		{
			name: "Portal with special characters in credentials",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": "admin@example.com",
					"password": "P@ssw0rd!#$%"
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Portal.Username != "admin@example.com" {
					t.Errorf("Expected portal username 'admin@example.com', got '%s'", cfg.Portal.Username)
				}
				if cfg.Portal.Password != "P@ssw0rd!#$%" {
					t.Errorf("Expected portal password 'P@ssw0rd!#$%%', got '%s'", cfg.Portal.Password)
				}
			},
		},
		{
			name: "Portal with unicode characters",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": "用户名",
					"password": "密码123"
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Portal.Username != "用户名" {
					t.Errorf("Expected portal username '用户名', got '%s'", cfg.Portal.Username)
				}
				if cfg.Portal.Password != "密码123" {
					t.Errorf("Expected portal password '密码123', got '%s'", cfg.Portal.Password)
				}
			},
		},
		{
			name: "Portal with long credentials",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": "very-long-username-that-might-be-used-in-enterprise-environments-with-domain-names",
					"password": "very-long-password-with-multiple-requirements-including-uppercase-lowercase-numbers-and-special-characters-123456789!@#$%^&*()"
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				expectedUsername := "very-long-username-that-might-be-used-in-enterprise-environments-with-domain-names"
				expectedPassword := "very-long-password-with-multiple-requirements-including-uppercase-lowercase-numbers-and-special-characters-123456789!@#$%^&*()"

				if cfg.Portal.Username != expectedUsername {
					t.Errorf("Expected portal username '%s', got '%s'", expectedUsername, cfg.Portal.Username)
				}
				if cfg.Portal.Password != expectedPassword {
					t.Errorf("Expected portal password '%s', got '%s'", expectedPassword, cfg.Portal.Password)
				}
			},
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

// TestPortalConfigurationWithExamples tests the portal configuration with actual example files
func TestPortalConfigurationWithExamples(t *testing.T) {
	testCases := []struct {
		name         string
		configFile   string
		expectAuth   bool
		expectedUser string
	}{
		{
			name:         "Standard config with authentication",
			configFile:   "../../examples/config.json",
			expectAuth:   true,
			expectedUser: "admin",
		},
		{
			name:         "IPv4 forcing config with authentication",
			configFile:   "../../examples/config-with-ipv4-forcing.json",
			expectAuth:   true,
			expectedUser: "admin",
		},
		{
			name:         "Minimal config with authentication",
			configFile:   "../../examples/config-portal-minimal.json",
			expectAuth:   true,
			expectedUser: "admin",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadConfig(tc.configFile)
			if err != nil {
				t.Fatalf("Failed to load config file %s: %v", tc.configFile, err)
			}

			if tc.expectAuth {
				if cfg.Portal.Username == "" {
					t.Errorf("Expected non-empty portal username, got empty string")
				}
				if cfg.Portal.Password == "" {
					t.Errorf("Expected non-empty portal password, got empty string")
				}
				if cfg.Portal.Username != tc.expectedUser {
					t.Errorf("Expected portal username '%s', got '%s'", tc.expectedUser, cfg.Portal.Username)
				}
			} else {
				if cfg.Portal.Username != "" {
					t.Errorf("Expected empty portal username, got '%s'", cfg.Portal.Username)
				}
				if cfg.Portal.Password != "" {
					t.Errorf("Expected empty portal password, got '%s'", cfg.Portal.Password)
				}
			}
		})
	}
}

// TestPortalConfigurationEdgeCases tests edge cases and error conditions
func TestPortalConfigurationEdgeCases(t *testing.T) {
	testDir := t.TempDir()

	testCases := []struct {
		name        string
		jsonContent string
		wantErr     bool
		errorMsg    string
	}{
		{
			name: "Portal with null values",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": null,
					"password": null
				}
			}`,
			wantErr: true, // JSON null should cause an error
		},
		{
			name: "Portal with non-string username",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": 123,
					"password": "password"
				}
			}`,
			wantErr:  true,
			errorMsg: "portal username must be a string",
		},
		{
			name: "Portal with non-string password",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": "admin",
					"password": 123
				}
			}`,
			wantErr:  true,
			errorMsg: "portal password must be a string",
		},
		{
			name: "Portal with boolean values",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": true,
					"password": false
				}
			}`,
			wantErr:  true,
			errorMsg: "portal username must be a string",
		},
		{
			name: "Portal with extra fields",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": "admin",
					"password": "password",
					"extra_field": "ignored"
				}
			}`,
			wantErr: false, // Extra fields should be ignored
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
				if tc.errorMsg != "" && !strings.Contains(err.Error(), tc.errorMsg) {
					t.Errorf("Expected error to contain '%s', but got '%s'", tc.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error but got: %v", err)
				}
				// For successful cases, verify the config is valid
				if cfg == nil {
					t.Fatalf("Expected valid config but got nil")
				}
			}
		})
	}
}

// TestPortalConfigurationEnvironmentVariables tests portal configuration via environment variables
func TestPortalConfigurationEnvironmentVariables(t *testing.T) {
	testCases := []struct {
		name         string
		envUsername  string
		envPassword  string
		expectAuth   bool
		expectedUser string
		expectedPass string
	}{
		{
			name:         "Portal with both env vars set",
			envUsername:  "env-admin",
			envPassword:  "env-password",
			expectAuth:   true,
			expectedUser: "env-admin",
			expectedPass: "env-password",
		},
		{
			name:         "Portal with only username env var",
			envUsername:  "env-user",
			envPassword:  "",
			expectAuth:   false,
			expectedUser: "env-user",
			expectedPass: "",
		},
		{
			name:         "Portal with only password env var",
			envUsername:  "",
			envPassword:  "env-secret",
			expectAuth:   false,
			expectedUser: "",
			expectedPass: "env-secret",
		},
		{
			name:         "Portal with no env vars",
			envUsername:  "",
			envPassword:  "",
			expectAuth:   false,
			expectedUser: "",
			expectedPass: "",
		},
		{
			name:         "Portal with special characters in env vars",
			envUsername:  "admin@company.com",
			envPassword:  "P@ssw0rd!#$%^&*()",
			expectAuth:   true,
			expectedUser: "admin@company.com",
			expectedPass: "P@ssw0rd!#$%^&*()",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Clear any existing environment variables
			os.Unsetenv("MSGTAUSCH_PORTAL_USERNAME")
			os.Unsetenv("MSGTAUSCH_PORTAL_PASSWORD")

			// Set test environment variables
			if tc.envUsername != "" {
				os.Setenv("MSGTAUSCH_PORTAL_USERNAME", tc.envUsername)
				defer os.Unsetenv("MSGTAUSCH_PORTAL_USERNAME")
			}
			if tc.envPassword != "" {
				os.Setenv("MSGTAUSCH_PORTAL_PASSWORD", tc.envPassword)
				defer os.Unsetenv("MSGTAUSCH_PORTAL_PASSWORD")
			}

			// Load config without any config file (environment variables only)
			cfg, err := LoadConfig("")
			if err != nil {
				t.Fatalf("Failed to load config with environment variables: %v", err)
			}

			// Verify portal configuration
			if cfg.Portal.Username != tc.expectedUser {
				t.Errorf("Expected portal username '%s', got '%s'", tc.expectedUser, cfg.Portal.Username)
			}
			if cfg.Portal.Password != tc.expectedPass {
				t.Errorf("Expected portal password '%s', got '%s'", tc.expectedPass, cfg.Portal.Password)
			}

			// Additional validation for complete authentication setup
			if tc.expectAuth {
				if cfg.Portal.Username == "" || cfg.Portal.Password == "" {
					t.Errorf("Expected both username and password to be set for authentication, got username='%s', password='%s'",
						cfg.Portal.Username, cfg.Portal.Password)
				}
			}
		})
	}
}

// TestPortalConfigurationMixed tests portal configuration with both config file and environment variables
func TestPortalConfigurationMixed(t *testing.T) {
	testDir := t.TempDir()

	testCases := []struct {
		name         string
		jsonContent  string
		envUsername  string
		envPassword  string
		expectedUser string
		expectedPass string
		description  string
	}{
		{
			name: "Config file overridden by environment variables",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": "config-admin",
					"password": "config-password"
				}
			}`,
			envUsername:  "env-admin",
			envPassword:  "env-password",
			expectedUser: "env-admin",
			expectedPass: "env-password",
			description:  "Environment variables should override config file values",
		},
		{
			name: "Config file with partial env override (username only)",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": "config-admin",
					"password": "config-password"
				}
			}`,
			envUsername:  "env-admin",
			envPassword:  "",
			expectedUser: "env-admin",
			expectedPass: "config-password",
			description:  "Environment username should override config, password should remain from config",
		},
		{
			name: "Config file with partial env override (password only)",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				],
				"portal": {
					"username": "config-admin",
					"password": "config-password"
				}
			}`,
			envUsername:  "",
			envPassword:  "env-password",
			expectedUser: "config-admin",
			expectedPass: "env-password",
			description:  "Environment password should override config, username should remain from config",
		},
		{
			name: "Environment variables with no portal in config",
			jsonContent: `{
				"servers": [
					{
						"type": "standard",
						"listen-address": "127.0.0.1:8080",
						"enabled": true
					}
				]
			}`,
			envUsername:  "env-only-admin",
			envPassword:  "env-only-password",
			expectedUser: "env-only-admin",
			expectedPass: "env-only-password",
			description:  "Environment variables should work when no portal config in file",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Clear any existing environment variables
			os.Unsetenv("MSGTAUSCH_PORTAL_USERNAME")
			os.Unsetenv("MSGTAUSCH_PORTAL_PASSWORD")

			// Set test environment variables
			if tc.envUsername != "" {
				os.Setenv("MSGTAUSCH_PORTAL_USERNAME", tc.envUsername)
				defer os.Unsetenv("MSGTAUSCH_PORTAL_USERNAME")
			}
			if tc.envPassword != "" {
				os.Setenv("MSGTAUSCH_PORTAL_PASSWORD", tc.envPassword)
				defer os.Unsetenv("MSGTAUSCH_PORTAL_PASSWORD")
			}

			// Create config file
			configPath := createTempConfigFileLocal(t, testDir, tc.name+".json", tc.jsonContent)

			// Load config
			cfg, err := LoadConfig(configPath)
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}

			// Verify portal configuration
			if cfg.Portal.Username != tc.expectedUser {
				t.Errorf("Expected portal username '%s', got '%s'. %s",
					tc.expectedUser, cfg.Portal.Username, tc.description)
			}
			if cfg.Portal.Password != tc.expectedPass {
				t.Errorf("Expected portal password '%s', got '%s'. %s",
					tc.expectedPass, cfg.Portal.Password, tc.description)
			}
		})
	}
}
