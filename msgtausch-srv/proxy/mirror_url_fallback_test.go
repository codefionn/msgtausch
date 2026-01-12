package proxy

import (
	"net/http"
	"testing"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
)

func TestMirrorURL_BasicFallback_Fallback(t *testing.T) {
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

	// Create classifier with mirror support
	classifier, err := NewClassifierDomainsURLWithMirrors(
		nil,
		primaryServer.URL,
		[]string{mirrorServer.URL},
		config.DomainsURLFormatPlain,
		30,
	)
	if err != nil {
		t.Fatalf("Failed to create classifier with mirrors: %v", err)
	}

	// Test classification - should use mirror
	input := ClassifierInput{
		host:       "blocked.com",
		remoteIP:   "127.0.0.1",
		remotePort: 80,
	}

	result, err := classifier.Classify(input)
	if err != nil {
		t.Fatalf("Classification failed: %v", err)
	}

	if !result {
		t.Error("Expected blocked.com to be blocked (from mirror)")
	}
}
