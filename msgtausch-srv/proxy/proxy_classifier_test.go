package proxy

import (
	"testing"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
)

// TestIsHostAllowed tests the host filtering functionality with classifiers,
// including the new allowlist and blocklist features.
func TestIsHostAllowed(t *testing.T) {
	// Create test configs with different IP classifiers
	tests := []struct {
		name       string
		config     *config.Config
		host       string
		remoteIP   string
		remotePort uint16
		expected   bool
	}{
		{
			name: "No classifiers - allow all",
			config: &config.Config{
				Classifiers: map[string]config.Classifier{},
			},
			host:       "example.com",
			remoteIP:   "192.168.1.1",
			remotePort: 443,
			expected:   true,
		},
		// New tests for allowlist functionality
		{
			name: "Allowlist - host allowed",
			config: func() *config.Config {
				cf := &config.Config{}
				cf.Allowlist = &config.ClassifierDomain{
					Domain: "example.com",
					Op:     config.ClassifierOpEqual,
				}
				return cf
			}(),
			host:       "example.com",
			remoteIP:   "192.168.1.1",
			remotePort: 443,
			expected:   true,
		},
		{
			name: "Allowlist - host not allowed",
			config: func() *config.Config {
				cf := &config.Config{}
				cf.Allowlist = &config.ClassifierDomain{
					Domain: "example.com",
					Op:     config.ClassifierOpEqual,
				}
				return cf
			}(),
			host:       "other.com",
			remoteIP:   "192.168.1.1",
			remotePort: 443,
			expected:   false,
		},
		{
			name: "Allowlist with OR - any match allowed",
			config: func() *config.Config {
				cf := &config.Config{}
				cf.Allowlist = &config.ClassifierOr{
					Classifiers: []config.Classifier{
						&config.ClassifierDomain{
							Domain: "example.com",
							Op:     config.ClassifierOpEqual,
						},
						&config.ClassifierDomain{
							Domain: "test.com",
							Op:     config.ClassifierOpEqual,
						},
					},
				}
				return cf
			}(),
			host:       "test.com",
			remoteIP:   "192.168.1.1",
			remotePort: 443,
			expected:   true,
		},
		// New tests for blocklist functionality
		{
			name: "Blocklist - host blocked",
			config: func() *config.Config {
				cf := &config.Config{
					// No classifiers, so normally would allow all
					Classifiers: map[string]config.Classifier{},
				}
				cf.Blocklist = &config.ClassifierDomain{
					Domain: "example.com",
					Op:     config.ClassifierOpEqual,
				}
				return cf
			}(),
			host:       "example.com",
			remoteIP:   "192.168.1.1",
			remotePort: 443,
			expected:   false,
		},
		{
			name: "Blocklist - host not blocked",
			config: func() *config.Config {
				cf := &config.Config{
					// No classifiers, so normally would allow all
					Classifiers: map[string]config.Classifier{},
				}
				cf.Blocklist = &config.ClassifierDomain{
					Domain: "example.com",
					Op:     config.ClassifierOpEqual,
				}
				return cf
			}(),
			host:       "other.com",
			remoteIP:   "192.168.1.1",
			remotePort: 443,
			expected:   true,
		},
		// Test for blocklist and allowlist together
		{
			name: "Blocklist overrides Allowlist - host blocked",
			config: func() *config.Config {
				cf := &config.Config{}
				cf.Blocklist = &config.ClassifierDomain{
					Domain: "example.com",
					Op:     config.ClassifierOpEqual,
				}
				cf.Allowlist = &config.ClassifierDomain{
					Domain: "example.com", // Same domain in allowlist
					Op:     config.ClassifierOpEqual,
				}
				return cf
			}(),
			host:       "example.com",
			remoteIP:   "192.168.1.1",
			remotePort: 443,
			expected:   false, // Blocklist takes precedence
		},
		{
			name: "Blocklist and Allowlist - host not in blocklist but in allowlist",
			config: func() *config.Config {
				cf := &config.Config{}
				cf.Blocklist = &config.ClassifierDomain{
					Domain: "bad.com",
					Op:     config.ClassifierOpEqual,
				}
				cf.Allowlist = &config.ClassifierDomain{
					Domain: "example.com",
					Op:     config.ClassifierOpEqual,
				}
				return cf
			}(),
			host:       "example.com",
			remoteIP:   "192.168.1.1",
			remotePort: 443,
			expected:   true,
		},
		{
			name: "Blocklist and Allowlist - host not in blocklist or allowlist",
			config: func() *config.Config {
				cf := &config.Config{}
				cf.Blocklist = &config.ClassifierDomain{
					Domain: "bad.com",
					Op:     config.ClassifierOpEqual,
				}
				cf.Allowlist = &config.ClassifierDomain{
					Domain: "example.com",
					Op:     config.ClassifierOpEqual,
				}
				return cf
			}(),
			host:       "other.com",
			remoteIP:   "192.168.1.1",
			remotePort: 443,
			expected:   false, // Not in allowlist
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewProxy(tt.config)
			result := p.isHostAllowed(tt.host, tt.remoteIP, tt.remotePort)
			if result != tt.expected {
				t.Errorf("isHostAllowed() = %v, want %v", result, tt.expected)
			}
		})
	}
}
