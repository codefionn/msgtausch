package proxy

import (
	"net/http"
	"testing"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
)

// createTestCacheManagerMirrors creates a cache manager for testing
func createTestCacheManagerMirrors() *CacheManager {
	cacheConfig := config.DefaultCacheConfig()
	internalConfig := internalCacheConfig{
		DefaultTTL:      cacheConfig.GetTTLDuration(),
		RefreshInterval: cacheConfig.GetRefreshIntervalDuration(),
		HTTPTimeout:     cacheConfig.GetHTTPTimeoutDuration(),
		MaxRetries:      cacheConfig.MaxRetries,
		RetryDelay:      cacheConfig.GetRetryDelayDuration(),
	}
	return NewCacheManager(internalConfig)
}

func TestCacheManager_GetDomainsWithMirrors_PrimarySuccessMirror(t *testing.T) {
	// Initialize cache manager
	cacheManager := createTestCacheManagerMirrors()
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

func TestCacheManager_GetDomainsWithMirrors_AllFailuresMirror(t *testing.T) {
	// Initialize cache manager
	cacheManager := createTestCacheManagerMirrors()
	defer cacheManager.Stop()

	cluster := NewTestServerCluster()
	defer cluster.StopAll()

	// Create failing primary server
	primaryConfig := TestServerConfig{
		Content: "",
		Status:  http.StatusInternalServerError,
	}
	primaryServer, err := cluster.AddServer(primaryConfig)
	if err != nil {
		t.Fatalf("Failed to create primary server: %v", err)
	}

	// Create failing mirror servers
	mirrorConfigs := []TestServerConfig{
		{Content: "", Status: http.StatusServiceUnavailable},
		{Content: "", Status: http.StatusNotFound},
	}

	mirrorServers, err := cluster.AddMultipleServers(mirrorConfigs)
	if err != nil {
		t.Fatalf("Failed to create mirror servers: %v", err)
	}

	mirrorURLs := make([]string, len(mirrorServers))
	for i, server := range mirrorServers {
		mirrorURLs[i] = server.URL
	}

	// Test all failures
	entry, err := cacheManager.GetDomainsWithMirrors(
		primaryServer.URL,
		mirrorURLs,
		config.DomainsURLFormatPlain,
		5,
	)
	if err == nil {
		t.Fatal("Expected error when all URLs fail, got success")
	}

	if entry != nil {
		t.Error("Expected nil entry when all URLs fail")
	}
}
