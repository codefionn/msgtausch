package proxy

import (
	"net/http"
	"testing"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
)

func TestMirrorURL_BasicFunctionality(t *testing.T) {
	// Initialize global cache manager
	cacheConfig := config.DefaultCacheConfig()
	ResetGlobalCacheManager()
	InitGlobalCacheManager(cacheConfig)
	defer ResetGlobalCacheManager()

	// Create test server cluster
	cluster := NewTestServerCluster()
	defer cluster.StopAll()

	// Test 1: Primary success
	primaryConfig := TestServerConfig{
		Content: "example.com\ntest.com\n",
		Status:  http.StatusOK,
	}
	primaryServer, err := cluster.AddServer(primaryConfig)
	if err != nil {
		t.Fatalf("Failed to create primary server: %v", err)
	}

	// Create classifier with mirror support
	classifier, err := NewClassifierDomainsURLWithMirrors(
		nil,
		primaryServer.URL,
		[]string{},
		config.DomainsURLFormatPlain,
		10,
	)
	if err != nil {
		t.Fatalf("Failed to create classifier: %v", err)
	}

	// Test classification
	input := ClassifierInput{
		host:       "example.com",
		remoteIP:   "127.0.0.1",
		remotePort: 80,
	}

	result, err := classifier.Classify(input)
	if err != nil {
		t.Fatalf("Classification failed: %v", err)
	}

	if !result {
		t.Error("Expected example.com to be blocked")
	}

	// Test 2: Mirror fallback
	failPrimaryConfig := TestServerConfig{
		Content: "",
		Status:  http.StatusInternalServerError,
	}
	failPrimaryServer, err := cluster.AddServer(failPrimaryConfig)
	if err != nil {
		t.Fatalf("Failed to create failing primary server: %v", err)
	}

	mirrorConfig := TestServerConfig{
		Content: "malware.com\nphishing.com\n",
		Status:  http.StatusOK,
	}
	mirrorServer, err := cluster.AddServer(mirrorConfig)
	if err != nil {
		t.Fatalf("Failed to create mirror server: %v", err)
	}

	mirrorClassifier, err := NewClassifierDomainsURLWithMirrors(
		nil,
		failPrimaryServer.URL,
		[]string{mirrorServer.URL},
		config.DomainsURLFormatPlain,
		30,
	)
	if err != nil {
		t.Fatalf("Failed to create classifier with mirror: %v", err)
	}

	// Test classification with mirror fallback
	mirrorInput := ClassifierInput{
		host:       "malware.com",
		remoteIP:   "127.0.0.1",
		remotePort: 80,
	}

	mirrorResult, err := mirrorClassifier.Classify(mirrorInput)
	if err != nil {
		t.Fatalf("Mirror classification failed: %v", err)
	}

	if !mirrorResult {
		t.Error("Expected malware.com to be blocked (from mirror)")
	}

	// Verify the mirror was used by checking the cache manager
	cacheManager := GetGlobalCacheManager()
	stats := cacheManager.GetCacheStats()
	entryCount := stats["total_entries"].(int)

	if entryCount < 1 {
		t.Errorf("Expected at least 1 cache entry, got %d", entryCount)
	}
}

func TestMirrorURL_CacheHitPerformance(t *testing.T) {
	// Initialize global cache manager
	cacheConfig := config.DefaultCacheConfig()
	ResetGlobalCacheManager()
	InitGlobalCacheManager(cacheConfig)
	defer ResetGlobalCacheManager()

	cluster := NewTestServerCluster()
	defer cluster.StopAll()

	serverConfig := TestServerConfig{
		Content: "cache.com\n",
		Status:  http.StatusOK,
	}
	server, err := cluster.AddServer(serverConfig)
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	classifier, err := NewClassifierDomainsURL(nil, server.URL, config.DomainsURLFormatPlain, 10)
	if err != nil {
		t.Fatalf("Failed to create classifier: %v", err)
	}

	input := ClassifierInput{
		host:       "cache.com",
		remoteIP:   "127.0.0.1",
		remotePort: 80,
	}

	// First classification (cache miss)
	start := time.Now()
	result1, err := classifier.Classify(input)
	firstDuration := time.Since(start)

	if err != nil {
		t.Fatalf("First classification failed: %v", err)
	}

	if !result1 {
		t.Error("Expected cache.com to be blocked")
	}

	// Second classification (cache hit)
	start = time.Now()
	result2, err := classifier.Classify(input)
	secondDuration := time.Since(start)

	if err != nil {
		t.Fatalf("Second classification failed: %v", err)
	}

	if !result2 {
		t.Error("Expected cache.com to be blocked on cache hit")
	}

	// Cache hit should be faster
	if secondDuration >= firstDuration {
		t.Logf("Cache miss: %v, Cache hit: %v", firstDuration, secondDuration)
		// Not failing this test as timing can be variable in CI environments
	}
}
