package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
)

// CacheEntry represents a cached domain list
type CacheEntry struct {
	Trie        *ahocorasick.Trie
	ChunkedTrie *ChunkedTrie // Hybrid chunked trie for large domain lists
	DomainList  []string
	URL         string // Primary URL that was successfully fetched
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

// NewCacheManagerWithConfig creates a new cache manager with custom configuration
func NewCacheManagerWithConfig(config config.CacheConfig) *CacheManager {
	if !config.Enabled {
		return nil // Cache disabled
	}

	ctx, cancel := context.WithCancel(context.Background())

	cacheConfig := internalCacheConfig{
		DefaultTTL:      config.GetTTLDuration(),
		RefreshInterval: config.GetRefreshIntervalDuration(),
		HTTPTimeout:     config.GetHTTPTimeoutDuration(),
		MaxRetries:      config.MaxRetries,
		RetryDelay:      config.GetRetryDelayDuration(),
	}

	cm := &CacheManager{
		cache: make(map[string]*CacheEntry),
		httpClient: &http.Client{
			Timeout: cacheConfig.HTTPTimeout,
		},
		ctx:    ctx,
		cancel: cancel,
	}

	// Start background refresh goroutine
	cm.wg.Add(1)
	go cm.backgroundRefresh(cacheConfig.RefreshInterval)

	logger.Info("Cache manager started with config: refresh=%v, ttl=%v, timeout=%v",
		cacheConfig.RefreshInterval, cacheConfig.DefaultTTL, cacheConfig.HTTPTimeout)

	return cm
}

// NewCacheManager creates a new cache manager
func NewCacheManager(config internalCacheConfig) *CacheManager {
	ctx, cancel := context.WithCancel(context.Background())

	cm := &CacheManager{
		cache: make(map[string]*CacheEntry),
		httpClient: &http.Client{
			Timeout: config.HTTPTimeout,
		},
		ctx:    ctx,
		cancel: cancel,
	}

	// Start background refresh goroutine
	cm.wg.Add(1)
	go cm.backgroundRefresh(config.RefreshInterval)

	logger.Info("Cache manager started with refresh interval: %v", config.RefreshInterval)

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

	// Create trie for efficient matching
	var trie *ahocorasick.Trie
	var chunkedTrie *ChunkedTrie
	var isChunked bool

	if len(domainList) > 0 {
		// Determine if we should use chunking based on domain count
		// Default threshold is 2048 domains
		chunkThreshold := 2048

		if shouldUseChunking(len(domainList)) {
			// Use hybrid chunked approach for large domain lists
			chunkedTrie = NewChunkedTrie(domainList, chunkThreshold)
			isChunked = true

			memStats := chunkedTrie.GetMemoryUsage()
			logger.Info("Created hybrid chunked AC trie with %d domains from %s (format: %s, %d chunks, memory: %s)",
				len(domainList), successfulURL, format, memStats.NumChunks, formatMemorySize(memStats.TotalMemory))
		} else {
			// Use regular single trie for smaller domain lists
			trie = ahocorasick.NewTrieBuilder().AddStrings(domainList).Build()
			logger.Info("Created Aho-Corasick trie with %d domains from %s (format: %s)", len(domainList), successfulURL, format)
		}
	}

	// Create cache entry
	var ttl time.Duration = 1 * time.Hour // Default fallback

	entry := &CacheEntry{
		Trie:        trie,
		ChunkedTrie: chunkedTrie,
		DomainList:  domainList,
		URL:         primaryURL,
		Format:      format,
		LastFetch:   time.Now(),
		LastError:   nil,
		Expiry:      time.Now().Add(ttl),
		SourceURL:   successfulURL,
		IsChunked:   isChunked,
	}

	// Cache the entry
	cacheKey := cm.generateCacheKey(primaryURL, mirrors, format)
	cm.mutex.Lock()
	cm.cache[cacheKey] = entry
	cm.mutex.Unlock()

	logger.Info("Successfully cached %d domains from %s (primary: %s, source: %s)", len(domainList), cm.formatURLsForLog(primaryURL, mirrors), primaryURL, successfulURL)

	return entry, nil
}

// fetchAndCache fetches domains from URL and caches them (legacy method without mirrors)
func (cm *CacheManager) fetchAndCache(url string, format config.DomainsURLFormat, timeout int) (*CacheEntry, error) {
	// Create timeout context if specified
	ctx := cm.ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(cm.ctx, time.Duration(timeout)*time.Second)
		defer cancel()
	}

	// Fetch with retries
	var domainList []string
	var lastErr error

	for attempt := 0; attempt <= 3; attempt++ { // Max 3 attempts
		if attempt > 0 {
			select {
			case <-time.After(5 * time.Second):
				// Wait before retry
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		domainList, lastErr = cm.fetchDomains(ctx, url, format)
		if lastErr == nil {
			break
		}

		logger.Warn("Fetch attempt %d failed for URL %s: %v", attempt+1, url, lastErr)
	}

	if lastErr != nil {
		// Even on failure, cache the error to avoid repeated failed requests
		cm.cacheError(url, format, lastErr)
		return nil, fmt.Errorf("failed to fetch domains after retries: %w", lastErr)
	}

	// Create trie for efficient matching
	var trie *ahocorasick.Trie
	if len(domainList) > 0 {
		trie = ahocorasick.NewTrieBuilder().AddStrings(domainList).Build()
		logger.Info("Created Aho-Corasick trie with %d domains from URL: %s (format: %s)", len(domainList), url, format)
	}

	// Create cache entry with configured TTL
	var ttl time.Duration = 1 * time.Hour // Default fallback
	if cm.cache != nil {
		// Try to get TTL from current configuration, or use default
		ttl = 1 * time.Hour
	}

	entry := &CacheEntry{
		Trie:       trie,
		DomainList: domainList,
		URL:        url,
		Format:     format,
		LastFetch:  time.Now(),
		LastError:  nil,
		Expiry:     time.Now().Add(ttl),
	}

	// Cache the entry
	cm.mutex.Lock()
	cm.cache[cm.cacheKey(url, format)] = entry
	cm.mutex.Unlock()

	logger.Info("Successfully cached %d domains from URL: %s (format: %s)", len(domainList), url, format)

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

// cacheError caches a failed fetch attempt to avoid repeated requests (legacy method)
func (cm *CacheManager) cacheError(url string, format config.DomainsURLFormat, err error) {
	cm.cacheErrorWithMirrors(url, []string{}, format, err)
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
		go func(e *CacheEntry) {
			_, err := cm.fetchAndCache(e.URL, e.Format, 30) // Use 30s timeout for refresh
			if err != nil {
				logger.Warn("Background refresh failed for URL %s: %v", e.URL, err)
			}
		}(entry)
	}
}

// cacheKey creates a unique cache key for URL+format combination
func (cm *CacheManager) cacheKey(url string, format config.DomainsURLFormat) string {
	return fmt.Sprintf("%s|%s", url, format)
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

// ResetGlobalCacheManager resets the global cache manager for testing
func ResetGlobalCacheManager() {
	if globalCacheManager != nil {
		globalCacheManager.Stop()
		globalCacheManager = nil
	}
	cacheManagerOnce = sync.Once{}
}

// InitGlobalCacheManager initializes the global cache manager with configuration
func InitGlobalCacheManager(config config.CacheConfig) {
	cacheManagerConfig = config
}

// GetGlobalCacheManager returns the global cache manager instance
func GetGlobalCacheManager() *CacheManager {
	cacheManagerOnce.Do(func() {
		if cacheManagerConfig.Enabled {
			globalCacheManager = NewCacheManagerWithConfig(cacheManagerConfig)
		} else {
			// Cache disabled, create a minimal cache manager
			defaultConfig := DefaultCacheConfig()
			globalCacheManager = NewCacheManager(defaultConfig)
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
