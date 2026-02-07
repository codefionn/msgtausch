package config

import "time"

// DNSType defines the type of DNS server
type DNSType string

// Available DNS types
const (
	DNSTypeUDP DNSType = "udp" // Standard DNS over UDP
	DNSTypeTCP DNSType = "tcp" // Standard DNS over TCP
	DNSTypeDoT DNSType = "dot" // DNS over TLS
)

// DNSServerConfig defines configuration for a single DNS server
type DNSServerConfig struct {
	Address        string  `json:"address" hcl:"address"`                 // DNS server address (host:port or [IPv6]:port)
	Type           DNSType `json:"type" hcl:"type"`                       // DNS server type (udp, tcp, dot)
	TimeoutSeconds int     `json:"timeout-seconds" hcl:"timeout-seconds"` // Query timeout in seconds
	TLSHost        string  `json:"tls-host" hcl:"tls-host,optional"`      // TLS hostname for SNI (only used for DoT)
}

// GetTimeoutDuration returns the timeout as a time.Duration
func (d DNSServerConfig) GetTimeoutDuration() time.Duration {
	return time.Duration(d.TimeoutSeconds) * time.Second
}

// DNSConfig holds configuration for DNS resolver
type DNSConfig struct {
	Enabled bool              `json:"enabled" hcl:"enabled"` // Enable custom DNS resolver
	Servers []DNSServerConfig `json:"servers" hcl:"servers"` // List of DNS servers to use
}

// DefaultDNSConfig returns default DNS configuration.
// Address format: host:port for IPv4/hostnames, [IPv6]:port for IPv6 addresses.
// Examples: "8.8.8.8:53", "[2001:4860:4860::8888]:53"
func DefaultDNSConfig() DNSConfig {
	return DNSConfig{
		Enabled: false, // Disabled by default - uses system DNS
		Servers: []DNSServerConfig{
			{
				Address:        "8.8.8.8:53",
				Type:           DNSTypeUDP,
				TimeoutSeconds: 10,
			},
			{
				Address:        "1.1.1.1:53",
				Type:           DNSTypeUDP,
				TimeoutSeconds: 10,
			},
		},
	}
}
