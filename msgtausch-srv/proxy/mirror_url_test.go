package proxy

import (
	"net/http"
	"testing"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
)

func TestMirrorURL_PrimarySuccess_Mirror(t *testing.T) {
	// Initialize cache manager
	cacheConfig := DefaultCacheConfig()
	cacheManager := NewCacheManager(cacheConfig)
	defer cacheManager.Stop()

	// Create test server cluster
	cluster := NewTestServerCluster()
	defer cluster.StopAll()

	// Create successful primary server
	primaryConfig := TestServerConfig{
		Content: "example.com\ntest.com\n",
		Status:  http.StatusOK,
	}
	primaryServer, err := cluster.AddServer(primaryConfig)
	if err != nil {
		t.Fatalf("Failed to create primary server: %v", err)
	}

	// Test primary URL success
	entry, err := cacheManager.GetDomainsWithMirrors(
		primaryServer.URL,
		[]string{},
		config.DomainsURLFormatPlain,
		10,
	)
	if err != nil {
		t.Fatalf("Expected success, got error: %v", err)
	}

	if len(entry.DomainList) != 2 {
		t.Errorf("Expected 2 domains, got %d", len(entry.DomainList))
	}

	if entry.SourceURL != primaryServer.URL {
		t.Errorf("Expected source URL %s, got %s", primaryServer.URL, entry.SourceURL)
	}
}

func TestMirrorURL_CachePerformance_Mirror(t *testing.T) {
	// Initialize cache manager
	cacheConfig := DefaultCacheConfig()
	cacheManager := NewCacheManager(cacheConfig)
	defer cacheManager.Stop()

	// Create test server cluster
	cluster := NewTestServerCluster()
	defer cluster.StopAll()

	// Create successful primary server
	primaryConfig := TestServerConfig{
		Content: "cache.com\n",
		Status:  http.StatusOK,
	}
	primaryServer, err := cluster.AddServer(primaryConfig)
	if err != nil {
		t.Fatalf("Failed to create primary server: %v", err)
	}

	// First fetch (cache miss)
	start := time.Now()
	entry1, err := cacheManager.GetDomainsWithMirrors(
		primaryServer.URL,
		[]string{},
		config.DomainsURLFormatPlain,
		10,
	)
	firstDuration := time.Since(start)

	if err != nil {
		t.Fatalf("First fetch failed: %v", err)
	}

	if len(entry1.DomainList) != 1 {
		t.Errorf("Expected 1 domain, got %d", len(entry1.DomainList))
	}

	// Second fetch (cache hit)
	start = time.Now()
	_, err = cacheManager.GetDomainsWithMirrors(
		primaryServer.URL,
		[]string{},
		config.DomainsURLFormatPlain,
		10,
	)
	secondDuration := time.Since(start)

	if err != nil {
		t.Fatalf("Cache hit failed: %v", err)
	}

	// Cache hit should be much faster
	if secondDuration >= firstDuration {
		t.Errorf("Cache hit (%v) should be faster than cache miss (%v)", secondDuration, firstDuration)
	}

	if secondDuration > 10*time.Millisecond {
		t.Errorf("Cache hit took too long: %v (should be < 10ms)", secondDuration)
	}
}

func TestMirrorURL_ClassifierIntegration_Mirror(t *testing.T) {
	// Initialize global cache manager
	cacheConfig := config.DefaultCacheConfig()
	ResetGlobalCacheManager()
	InitGlobalCacheManager(cacheConfig)
	defer ResetGlobalCacheManager()

	// Create test server cluster
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

	// Create successful mirror server
	mirrorConfig := TestServerConfig{
		Content: "blocked.com\nmalware.com\n",
		Status:  http.StatusOK,
	}
	mirrorServer, err := cluster.AddServer(mirrorConfig)
	if err != nil {
		t.Fatalf("Failed to create mirror server: %v", err)
	}

	// Create configuration with mirrors
	domainsURLConfig := &config.ClassifierDomainsURL{
		URL:     primaryServer.URL,
		Mirrors: []string{mirrorServer.URL},
		Format:  config.DomainsURLFormatPlain,
		Timeout: 30,
	}

	// Compile classifier
	classifier := config.Classifier(domainsURLConfig)
	compiledClassifier, err := CompileClassifier(classifier, nil)
	if err != nil {
		t.Fatalf("Failed to compile classifier with mirrors: %v", err)
	}

	// Verify it's the correct type
	domainsURLClassifier, ok := compiledClassifier.(*ClassifierDomainsURL)
	if !ok {
		t.Fatalf("Expected *ClassifierDomainsURL, got %T", compiledClassifier)
	}

	if len(domainsURLClassifier.Mirrors) != 1 {
		t.Errorf("Expected 1 mirror, got %d", len(domainsURLClassifier.Mirrors))
	}

	// Test classification
	input := ClassifierInput{
		host:       "blocked.com",
		remoteIP:   "127.0.0.1",
		remotePort: 80,
	}

	result, err := compiledClassifier.Classify(input)
	if err != nil {
		t.Fatalf("Classification failed: %v", err)
	}

	if !result {
		t.Error("Expected blocked.com to be blocked")
	}
}
