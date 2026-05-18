package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
	"github.com/codefionn/msgtausch/msgtausch-srv/resolver"
)

// newCacheHTTPClient builds the HTTP client used to fetch blocklists.
// When dnsCfg is enabled, requests resolve through the configured DNS
// resolver instead of the system resolver.
func newCacheHTTPClient(timeout time.Duration, dnsCfg config.DNSConfig) *http.Client {
	if !dnsCfg.Enabled || len(dnsCfg.Servers) == 0 {
		return &http.Client{Timeout: timeout}
	}

	dialer := &net.Dialer{
		Timeout:  30 * time.Second,
		Resolver: resolver.GetResolver(dnsCfg),
	}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

// CacheEntry represents a cached domain list
type CacheEntry struct {
	Trie        *ahocorasick.Trie
	ChunkedTrie *ChunkedTrie // Hybrid chunked trie for large domain lists
	Domains     *DomainSet   // Memory-efficient domain matcher (preferred)
	DomainList  []string
	URL         string   // Primary URL that was successfully fetched
	Mirrors     []string // Mirror URLs, needed to refresh under the same cache key
	Format      config.DomainsURLFormat
	LastFetch   time.Time
	LastError   error
	Expiry      time.Time
	SourceURL   string // Actual URL that provided the content (might be a mirror)
	IsChunked   bool   // Whether this cache entry uses chunked approach
}

// CacheManager handles background caching of domain lists from URLs
type CacheManager struct {
	cache      map[string]*CacheEntry // key is URL+format
	mutex      sync.RWMutex
	httpClient *http.Client
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	refreshing sync.Map // cacheKey -> struct{}, prevents overlapping refreshes
}

// internalCacheConfig holds configuration for the cache manager
type internalCacheConfig struct {
	DefaultTTL      time.Duration // Default cache TTL
	RefreshInterval time.Duration // Background refresh interval
	HTTPTimeout     time.Duration // HTTP request timeout
	MaxRetries      int           // Maximum retry attempts
	RetryDelay      time.Duration // Delay between retries
}

// DefaultCacheConfig returns default cache configuration
func DefaultCacheConfig() internalCacheConfig {
	return internalCacheConfig{
		DefaultTTL:      1 * time.Hour,
		RefreshInterval: 5 * time.Minute,
		HTTPTimeout:     30 * time.Second,
		MaxRetries:      3,
		RetryDelay:      5 * time.Second,
	}
}

// NewCacheManagerWithConfig creates a new cache manager with custom configuration.
// Blocklist downloads use the system DNS resolver. Use
// NewCacheManagerWithConfigAndDNS to route lookups through a custom resolver.
func NewCacheManagerWithConfig(cfg config.CacheConfig) *CacheManager {
	return NewCacheManagerWithConfigAndDNS(cfg, config.DNSConfig{})
}

// NewCacheManagerWithConfigAndDNS creates a new cache manager with custom
// configuration and routes blocklist HTTP downloads through the given DNS
// resolver configuration.
func NewCacheManagerWithConfigAndDNS(cfg config.CacheConfig, dnsCfg config.DNSConfig) *CacheManager {
	if !cfg.Enabled {
		return nil // Cache disabled
	}

	ctx, cancel := context.WithCancel(context.Background())

	cacheConfig := internalCacheConfig{
		DefaultTTL:      cfg.GetTTLDuration(),
		RefreshInterval: cfg.GetRefreshIntervalDuration(),
		HTTPTimeout:     cfg.GetHTTPTimeoutDuration(),
		MaxRetries:      cfg.MaxRetries,
		RetryDelay:      cfg.GetRetryDelayDuration(),
	}

	cm := &CacheManager{
		cache:      make(map[string]*CacheEntry),
		httpClient: newCacheHTTPClient(cacheConfig.HTTPTimeout, dnsCfg),
		ctx:        ctx,
		cancel:     cancel,
	}

	// Start background refresh goroutine
	cm.wg.Add(1)
	go cm.backgroundRefresh(cacheConfig.RefreshInterval)

	logger.Info("Cache manager started with config: refresh=%v, ttl=%v, timeout=%v",
		cacheConfig.RefreshInterval, cacheConfig.DefaultTTL, cacheConfig.HTTPTimeout)

	return cm
}

// NewCacheManager creates a new cache manager
func NewCacheManager(cacheCfg internalCacheConfig) *CacheManager {
	ctx, cancel := context.WithCancel(context.Background())

	cm := &CacheManager{
		cache: make(map[string]*CacheEntry),
		httpClient: &http.Client{
			Timeout: cacheCfg.HTTPTimeout,
		},
		ctx:    ctx,
		cancel: cancel,
	}

	// Start background refresh goroutine
	cm.wg.Add(1)
	go cm.backgroundRefresh(cacheCfg.RefreshInterval)

	logger.Info("Cache manager started with refresh interval: %v", cacheCfg.RefreshInterval)

	return cm
}

// Stop stops the cache manager background goroutines
func (cm *CacheManager) Stop() {
	logger.Info("Stopping cache manager...")
	cm.cancel()
	cm.wg.Wait()
	logger.Info("Cache manager stopped")
}

// GetDomains retrieves domains from cache, fetching if needed
func (cm *CacheManager) GetDomains(url string, format config.DomainsURLFormat, timeout int) (*CacheEntry, error) {
	return cm.GetDomainsWithMirrors(url, []string{}, format, timeout)
}

// GetDomainsWithMirrors retrieves domains from cache with mirror URL fallback support
func (cm *CacheManager) GetDomainsWithMirrors(primaryURL string, mirrors []string, format config.DomainsURLFormat, timeout int) (*CacheEntry, error) {
	cacheKey := cm.generateCacheKey(primaryURL, mirrors, format)

	// Check cache first
	cm.mutex.RLock()
	entry, exists := cm.cache[cacheKey]
	if exists && entry.LastError == nil && time.Now().Before(entry.Expiry) {
		cm.mutex.RUnlock()
		logger.Debug("Cache hit for URLs: %s (format: %s)", cm.formatURLsForLog(primaryURL, mirrors), format)
		return entry, nil
	}
	cm.mutex.RUnlock()

	// Cache miss or expired, fetch fresh data with mirror fallback
	logger.Info("Cache miss for URLs: %s (format: %s), fetching fresh data", cm.formatURLsForLog(primaryURL, mirrors), format)
	return cm.fetchAndCacheWithMirrors(primaryURL, mirrors, format, timeout)
}

// formatURLsForLog formats URLs for logging
func (cm *CacheManager) formatURLsForLog(primaryURL string, mirrors []string) string {
	if len(mirrors) == 0 {
		return primaryURL
	}
	return fmt.Sprintf("%s (+%d mirrors)", primaryURL, len(mirrors))
}

// fetchAndCacheWithMirrors fetches domains from URL with mirror fallback and caches them
func (cm *CacheManager) fetchAndCacheWithMirrors(primaryURL string, mirrors []string, format config.DomainsURLFormat, timeout int) (*CacheEntry, error) {
	// Try all URLs: primary first, then mirrors in order
	allURLs := append([]string{primaryURL}, mirrors...)
	var lastError error
	var domainList []string
	var successfulURL string

	for i, url := range allURLs {
		urlType := "primary"
		if i > 0 {
			urlType = fmt.Sprintf("mirror %d", i)
		}

		logger.Debug("Trying %s URL: %s", urlType, url)

		// Create timeout context if specified
		ctx := cm.ctx
		var cancel context.CancelFunc
		if timeout > 0 {
			ctx, cancel = context.WithTimeout(cm.ctx, time.Duration(timeout)*time.Second)
		}

		// Fetch with retries
		for attempt := 0; attempt <= 3; attempt++ { // Max 3 attempts
			if attempt > 0 {
				select {
				case <-time.After(5 * time.Second):
					// Wait before retry
				case <-ctx.Done():
					if cancel != nil {
						cancel()
					}
					return nil, ctx.Err()
				}
			}

			domainList, lastError = cm.fetchDomains(ctx, url, format)
			if lastError == nil {
				successfulURL = url
				break
			}

			logger.Debug("Fetch attempt %d failed for %s URL %s: %v", attempt+1, urlType, url, lastError)
		}

		// Clean up context
		if cancel != nil {
			cancel()
		}

		if lastError == nil {
			logger.Info("Successfully fetched from %s URL: %s", urlType, url)
			break // Success, no need to try other URLs
		} else {
			logger.Warn("Failed to fetch from %s URL %s: %v", urlType, url, lastError)
		}
	}

	if lastError != nil {
		// All URLs failed, cache the error to avoid repeated requests
		cm.cacheErrorWithMirrors(primaryURL, mirrors, format, lastError)
		return nil, fmt.Errorf("failed to fetch domains from all URLs (%s), last error: %w", cm.formatURLsForLog(primaryURL, mirrors), lastError)
	}

	// Build a memory-efficient domain set. The previous Aho-Corasick /
	// chunked-AC tries allocated multiple GiB for large lists (heap profile:
	// 99.7% of process memory in TrieBuilder.Build); a hashset uses orders of
	// magnitude less for identical match semantics.
	var domains *DomainSet
	if len(domainList) > 0 {
		domains = NewDomainSet(domainList)
		logger.Info("Loaded %d domains (%d unique) from %s (format: %s)",
			len(domainList), domains.Len(), successfulURL, format)
	}

	// Create cache entry
	var ttl = 1 * time.Hour // Default fallback

	entry := &CacheEntry{
		Domains:    domains,
		DomainList: domainList,
		URL:        primaryURL,
		Mirrors:    mirrors,
		Format:     format,
		LastFetch:  time.Now(),
		LastError:  nil,
		Expiry:     time.Now().Add(ttl),
		SourceURL:  successfulURL,
		IsChunked:  false,
	}

	// Cache the entry
	cacheKey := cm.generateCacheKey(primaryURL, mirrors, format)
	cm.mutex.Lock()
	cm.cache[cacheKey] = entry
	cm.mutex.Unlock()

	logger.Info("Successfully cached %d domains from %s (primary: %s, source: %s)", len(domainList), cm.formatURLsForLog(primaryURL, mirrors), primaryURL, successfulURL)

	return entry, nil
}

// fetchDomains performs the actual HTTP fetch and parsing
func (cm *CacheManager) fetchDomains(ctx context.Context, url string, format config.DomainsURLFormat) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("User-Agent", "msgtausch-proxy/1.0")

	resp, err := cm.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP request failed with status: %d", resp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse domains based on format
	domainList, err := parseDomainsFromContent(string(body), format)
	if err != nil {
		return nil, fmt.Errorf("failed to parse domains: %w", err)
	}

	return domainList, nil
}

// cacheErrorWithMirrors caches a failed fetch attempt to avoid repeated requests
func (cm *CacheManager) cacheErrorWithMirrors(primaryURL string, mirrors []string, format config.DomainsURLFormat, err error) {
	entry := &CacheEntry{
		Trie:       nil,
		DomainList: nil,
		URL:        primaryURL,
		Mirrors:    mirrors,
		Format:     format,
		LastFetch:  time.Now(),
		LastError:  err,
		Expiry:     time.Now().Add(5 * time.Minute), // Short TTL for errors
		SourceURL:  "",
	}

	cacheKey := cm.generateCacheKey(primaryURL, mirrors, format)
	cm.mutex.Lock()
	cm.cache[cacheKey] = entry
	cm.mutex.Unlock()
}

// backgroundRefresh periodically refreshes cached entries
func (cm *CacheManager) backgroundRefresh(interval time.Duration) {
	defer cm.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-cm.ctx.Done():
			return
		case <-ticker.C:
			cm.refreshCache()
		}
	}
}

// refreshCache refreshes all cache entries that are due for refresh
func (cm *CacheManager) refreshCache() {
	cm.mutex.RLock()
	entriesToRefresh := make([]*CacheEntry, 0, len(cm.cache))
	now := time.Now()

	for _, entry := range cm.cache {
		// Refresh if entry is expiring in the next 10 minutes or has an error
		if (entry.LastError != nil && now.After(entry.LastFetch.Add(5*time.Minute))) ||
			(entry.LastError == nil && now.After(entry.Expiry.Add(-10*time.Minute))) {
			entriesToRefresh = append(entriesToRefresh, entry)
		}
	}
	cm.mutex.RUnlock()

	if len(entriesToRefresh) == 0 {
		return
	}

	logger.Info("Background refresh: refreshing %d cache entries", len(entriesToRefresh))

	for _, entry := range entriesToRefresh {
		// Fetch fresh data in background
		key := cm.generateCacheKey(entry.URL, entry.Mirrors, entry.Format)
		if _, busy := cm.refreshing.LoadOrStore(key, struct{}{}); busy {
			// A refresh for this key is already running; skip to avoid
			// concurrent fetches building duplicate tries.
			continue
		}
		go func(e *CacheEntry, k string) {
			defer cm.refreshing.Delete(k)
			// Refresh under the same cache key the readers use (primary + mirrors),
			// otherwise the refreshed entry lands under a different key and the
			// original is never replaced, causing repeated refetches/rebuilds.
			_, err := cm.fetchAndCacheWithMirrors(e.URL, e.Mirrors, e.Format, 30)
			if err != nil {
				logger.Warn("Background refresh failed for URL %s: %v", e.URL, err)
			}
		}(entry, key)
	}
}

// generateCacheKey creates a cache key for primary URL and mirrors
func (cm *CacheManager) generateCacheKey(primaryURL string, mirrors []string, format config.DomainsURLFormat) string {
	// Create a consistent key based on all URLs to ensure cache hits when using mirrors
	allURLs := append([]string{primaryURL}, mirrors...)
	return fmt.Sprintf("%s|%s", strings.Join(allURLs, ","), format)
}

// GetCacheStats returns cache statistics
func (cm *CacheManager) GetCacheStats() map[string]interface{} {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_entries": len(cm.cache),
		"entries":       make([]map[string]interface{}, 0, len(cm.cache)),
	}

	for key, entry := range cm.cache {
		entryStats := map[string]interface{}{
			"key":          key,
			"url":          entry.URL,
			"format":       entry.Format,
			"last_fetch":   entry.LastFetch,
			"last_error":   entry.LastError != nil,
			"expiry":       entry.Expiry,
			"domain_count": len(entry.DomainList),
		}
		stats["entries"] = append(stats["entries"].([]map[string]interface{}), entryStats)
	}

	return stats
}

// Global cache manager instance
var globalCacheManager *CacheManager
var cacheManagerOnce sync.Once
var cacheManagerConfig config.CacheConfig
var cacheManagerDNSConfig config.DNSConfig

// ResetGlobalCacheManager resets the global cache manager for testing
func ResetGlobalCacheManager() {
	if globalCacheManager != nil {
		globalCacheManager.Stop()
		globalCacheManager = nil
	}
	cacheManagerOnce = sync.Once{}
}

// InitGlobalCacheManager initializes the global cache manager with configuration.
// Blocklist downloads use the system DNS resolver. Use
// InitGlobalCacheManagerWithDNS to route lookups through a custom resolver.
func InitGlobalCacheManager(cfg config.CacheConfig) {
	cacheManagerConfig = cfg
	cacheManagerDNSConfig = config.DNSConfig{}
}

// InitGlobalCacheManagerWithDNS initializes the global cache manager and
// routes blocklist HTTP downloads through the given DNS resolver configuration.
func InitGlobalCacheManagerWithDNS(cfg config.CacheConfig, dnsCfg config.DNSConfig) {
	cacheManagerConfig = cfg
	cacheManagerDNSConfig = dnsCfg
}

// GetGlobalCacheManager returns the global cache manager instance
func GetGlobalCacheManager() *CacheManager {
	cacheManagerOnce.Do(func() {
		if cacheManagerConfig.Enabled {
			globalCacheManager = NewCacheManagerWithConfigAndDNS(cacheManagerConfig, cacheManagerDNSConfig)
		} else {
			// Cache disabled, create a minimal cache manager
			defaultConfig := DefaultCacheConfig()
			globalCacheManager = NewCacheManager(defaultConfig)
			if cacheManagerDNSConfig.Enabled {
				globalCacheManager.httpClient = newCacheHTTPClient(defaultConfig.HTTPTimeout, cacheManagerDNSConfig)
			}
		}
	})
	return globalCacheManager
}

// StopGlobalCacheManager stops the global cache manager
func StopGlobalCacheManager() {
	if globalCacheManager != nil {
		globalCacheManager.Stop()
	}
}
