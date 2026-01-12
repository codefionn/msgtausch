package proxy

import (
	"net/http"
	"testing"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
)

func TestCacheManager_GetDomainsWithMirrors_PrimarySuccess(t *testing.T) {
	// Initialize cache manager
	cacheConfig := DefaultCacheConfig()
	cacheManager := NewCacheManager(cacheConfig)
	defer cacheManager.Stop()

	// Create test server with successful response
	cluster := NewTestServerCluster()
	defer cluster.StopAll()

	serverConfig := TestServerConfig{
		Content: "example.com\ntest.com\nblocked.com\n",
		Status:  http.StatusOK,
	}

	server, err := cluster.AddServer(serverConfig)
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	// Test primary URL success
	entry, err := cacheManager.GetDomainsWithMirrors(server.URL, []string{}, config.DomainsURLFormatPlain, 10)
	if err != nil {
		t.Fatalf("Expected success, got error: %v", err)
	}

	if len(entry.DomainList) != 3 {
		t.Errorf("Expected 3 domains, got %d", len(entry.DomainList))
	}

	if entry.SourceURL != server.URL {
		t.Errorf("Expected source URL %s, got %s", server.URL, entry.SourceURL)
	}

	// Test cache hit - should be instant
	start := time.Now()
	entry2, err := cacheManager.GetDomainsWithMirrors(server.URL, []string{}, config.DomainsURLFormatPlain, 10)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Cache hit failed: %v", err)
	}

	if duration > 10*time.Millisecond {
		t.Errorf("Cache hit took too long: %v (should be < 10ms)", duration)
	}

	if len(entry2.DomainList) != 3 {
		t.Errorf("Cache hit returned wrong number of domains: %d", len(entry2.DomainList))
	}
}

func TestCacheManager_GetDomainsWithMirrors_MirrorPriority(t *testing.T) {
	// Initialize cache manager
	cacheConfig := DefaultCacheConfig()
	cacheManager := NewCacheManager(cacheConfig)
	defer cacheManager.Stop()

	cluster := NewTestServerCluster()
	defer cluster.StopAll()

	// Create servers with different content to track which was used
	configs := []TestServerConfig{
		{Content: "first.com\n", Status: http.StatusOK},
		{Content: "second.com\n", Status: http.StatusOK},
		{Content: "third.com\n", Status: http.StatusOK},
	}

	servers, err := cluster.AddMultipleServers(configs)
	if err != nil {
		t.Fatalf("Failed to create servers: %v", err)
	}

	// Test that first mirror is preferred
	entry, err := cacheManager.GetDomainsWithMirrors(
		servers[0].URL,                           // Primary that will work
		[]string{servers[1].URL, servers[2].URL}, // Mirrors
		config.DomainsURLFormatPlain,
		10,
	)
	if err != nil {
		t.Fatalf("Expected success, got error: %v", err)
	}

	// Should use primary since it works
	if entry.SourceURL != servers[0].URL {
		t.Errorf("Expected source URL %s (primary), got %s", servers[0].URL, entry.SourceURL)
	}

	if len(entry.DomainList) != 1 || entry.DomainList[0] != "first.com" {
		t.Errorf("Expected 'first.com' from primary, got %v", entry.DomainList)
	}
}

func TestCacheManager_GetDomainsWithMirrors_CacheStatistics(t *testing.T) {
	// Initialize cache manager
	cacheConfig := DefaultCacheConfig()
	cacheManager := NewCacheManager(cacheConfig)
	defer cacheManager.Stop()

	cluster := NewTestServerCluster()
	defer cluster.StopAll()

	serverConfig := TestServerConfig{
		Content: "stats.com\n",
		Status:  http.StatusOK,
	}
	server, err := cluster.AddServer(serverConfig)
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	// Initial stats
	stats := cacheManager.GetCacheStats()
	initialCount := stats["total_entries"].(int)
	if initialCount != 0 {
		t.Errorf("Expected 0 initial cache entries, got %d", initialCount)
	}

	// Fetch domains
	_, err = cacheManager.GetDomainsWithMirrors(server.URL, []string{}, config.DomainsURLFormatPlain, 10)
	if err != nil {
		t.Fatalf("Failed to fetch domains: %v", err)
	}

	// Check stats after fetch
	stats = cacheManager.GetCacheStats()
	afterCount := stats["total_entries"].(int)
	if afterCount != 1 {
		t.Errorf("Expected 1 cache entry after fetch, got %d", afterCount)
	}

	// Fetch again (should hit cache)
	_, err = cacheManager.GetDomainsWithMirrors(server.URL, []string{}, config.DomainsURLFormatPlain, 10)
	if err != nil {
		t.Fatalf("Failed to fetch domains (cache hit): %v", err)
	}

	// Stats should remain the same
	stats = cacheManager.GetCacheStats()
	finalCount := stats["total_entries"].(int)
	if finalCount != 1 {
		t.Errorf("Expected 1 cache entry after cache hit, got %d", finalCount)
	}
}
