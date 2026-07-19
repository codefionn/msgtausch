package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/stretchr/testify/require"
)

func TestCacheManagerUsesConfiguredTTL(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("example.com\n"))
	}))
	defer server.Close()

	manager := NewCacheManager(internalCacheConfig{
		DefaultTTL:      20 * time.Millisecond,
		RefreshInterval: time.Hour,
		HTTPTimeout:     time.Second,
		MaxRetries:      0,
	})
	defer manager.Stop()

	_, err := manager.GetDomains(server.URL, config.DomainsURLFormatPlain, 1)
	require.NoError(t, err)
	_, err = manager.GetDomains(server.URL, config.DomainsURLFormatPlain, 1)
	require.NoError(t, err)
	require.Equal(t, int64(1), requests.Load())

	time.Sleep(30 * time.Millisecond)
	_, err = manager.GetDomains(server.URL, config.DomainsURLFormatPlain, 1)
	require.NoError(t, err)
	require.Equal(t, int64(2), requests.Load())
}

func TestCacheManagerCoalescesConcurrentMisses(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		time.Sleep(25 * time.Millisecond)
		_, _ = w.Write([]byte("example.com\n"))
	}))
	defer server.Close()

	manager := NewCacheManager(internalCacheConfig{
		DefaultTTL:      time.Hour,
		RefreshInterval: time.Hour,
		HTTPTimeout:     time.Second,
		MaxRetries:      0,
	})
	defer manager.Stop()

	const callers = 16
	start := make(chan struct{})
	errors := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := manager.GetDomains(server.URL, config.DomainsURLFormatPlain, 1)
			errors <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errors)

	for err := range errors {
		require.NoError(t, err)
	}
	require.Equal(t, int64(1), requests.Load())
}

func TestCacheManagerUsesConfiguredRetryCount(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	manager := NewCacheManager(internalCacheConfig{
		DefaultTTL:      time.Hour,
		RefreshInterval: time.Hour,
		HTTPTimeout:     time.Second,
		MaxRetries:      1,
		RetryDelay:      time.Millisecond,
	})
	defer manager.Stop()

	_, err := manager.GetDomains(server.URL, config.DomainsURLFormatPlain, 1)
	require.Error(t, err)
	require.Equal(t, int64(2), requests.Load())

	// The cached failure prevents each classification from starting another
	// retry sequence until the short error TTL expires.
	_, err = manager.GetDomains(server.URL, config.DomainsURLFormatPlain, 1)
	require.Error(t, err)
	require.Equal(t, int64(2), requests.Load())
}
