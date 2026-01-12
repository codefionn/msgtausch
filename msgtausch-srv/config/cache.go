package config

import "time"

// CacheConfig holds configuration for domain URL caching
type CacheConfig struct {
	Enabled         bool `json:"enabled" hcl:"enabled"`
	DefaultTTL      int  `json:"default-ttl" hcl:"default-ttl"`
	RefreshInterval int  `json:"refresh-interval" hcl:"refresh-interval"`
	HTTPTimeout     int  `json:"http-timeout" hcl:"http-timeout"`
	MaxRetries      int  `json:"max-retries" hcl:"max-retries"`
	RetryDelay      int  `json:"retry-delay" hcl:"retry-delay"`
}

// DefaultCacheConfig returns default cache configuration
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		Enabled:         true,
		DefaultTTL:      3600, // 1 hour
		RefreshInterval: 300,  // 5 minutes
		HTTPTimeout:     30,   // 30 seconds
		MaxRetries:      3,
		RetryDelay:      5, // 5 seconds
	}
}

// GetTTLDuration returns the TTL as a time.Duration
func (c CacheConfig) GetTTLDuration() time.Duration {
	return time.Duration(c.DefaultTTL) * time.Second
}

// GetRefreshIntervalDuration returns the refresh interval as a time.Duration
func (c CacheConfig) GetRefreshIntervalDuration() time.Duration {
	return time.Duration(c.RefreshInterval) * time.Second
}

// GetHTTPTimeoutDuration returns the HTTP timeout as a time.Duration
func (c CacheConfig) GetHTTPTimeoutDuration() time.Duration {
	return time.Duration(c.HTTPTimeout) * time.Second
}

// GetRetryDelayDuration returns the retry delay as a time.Duration
func (c CacheConfig) GetRetryDelayDuration() time.Duration {
	return time.Duration(c.RetryDelay) * time.Second
}
