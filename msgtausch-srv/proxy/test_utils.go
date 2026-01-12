package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// TestHTTPServer represents a test HTTP server for testing
type TestHTTPServer struct {
	server   *http.Server
	listener net.Listener
	URL      string
	port     int
	mutex    sync.RWMutex
}

// TestServerConfig holds configuration for test server
type TestServerConfig struct {
	Content  string
	Status   int
	Headers  map[string]string
	Delay    time.Duration
	FailRate float64 // 0.0 to 1.0, probability of failure
}

// NewTestHTTPServer creates a new test HTTP server on a random port
func NewTestHTTPServer(config TestServerConfig) (*TestHTTPServer, error) {
	// Find available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to find available port: %w", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port
	url := fmt.Sprintf("http://127.0.0.1:%d", port)

	server := &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", port),
		Handler: http.HandlerFunc(config.handler),
	}

	testServer := &TestHTTPServer{
		server:   server,
		listener: listener,
		URL:      url,
		port:     port,
	}

	// Start server in goroutine
	go func() {
		_ = server.Serve(listener) // Ignore error - test server
	}()

	// Wait a moment for server to start
	time.Sleep(50 * time.Millisecond)

	return testServer, nil
}

// handler creates the HTTP handler for the test server
func (c TestServerConfig) handler(w http.ResponseWriter, r *http.Request) {
	// Add delay if configured
	if c.Delay > 0 {
		time.Sleep(c.Delay)
	}

	// Add headers if configured
	for key, value := range c.Headers {
		w.Header().Set(key, value)
	}

	// Simulate random failures
	if c.FailRate > 0 {
		// Simple pseudo-random based on request path for consistency
		hash := 0
		for _, char := range r.URL.Path {
			hash += int(char)
		}
		if float64(hash%100)/100.0 < c.FailRate {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("Simulated server failure"))
			return
		}
	}

	// Write response
	w.WriteHeader(c.Status)
	_, _ = w.Write([]byte(c.Content))
}

// UpdateConfig updates the server configuration
func (s *TestHTTPServer) UpdateConfig(config TestServerConfig) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.server.Handler = http.HandlerFunc(config.handler)
}

// Stop stops the test server gracefully
func (s *TestHTTPServer) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

// GetPort returns the server port
func (s *TestHTTPServer) GetPort() int {
	return s.port
}

// TestServerCluster manages multiple test servers
type TestServerCluster struct {
	servers []*TestHTTPServer
	mutex   sync.Mutex
}

// NewTestServerCluster creates a new test server cluster
func NewTestServerCluster() *TestServerCluster {
	return &TestServerCluster{
		servers: make([]*TestHTTPServer, 0),
	}
}

// AddServer adds a new server to the cluster
func (c *TestServerCluster) AddServer(config TestServerConfig) (*TestHTTPServer, error) {
	server, err := NewTestHTTPServer(config)
	if err != nil {
		return nil, err
	}

	c.mutex.Lock()
	c.servers = append(c.servers, server)
	c.mutex.Unlock()

	return server, nil
}

// AddMultipleServers adds multiple servers with different configurations
func (c *TestServerCluster) AddMultipleServers(configs []TestServerConfig) ([]*TestHTTPServer, error) {
	servers := make([]*TestHTTPServer, 0, len(configs))

	for _, config := range configs {
		server, err := c.AddServer(config)
		if err != nil {
			// Clean up already created servers
			c.StopAll()
			return nil, err
		}
		servers = append(servers, server)
	}

	return servers, nil
}

// GetURLs returns URLs of all servers in the cluster
func (c *TestServerCluster) GetURLs() []string {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	urls := make([]string, len(c.servers))
	for i, server := range c.servers {
		urls[i] = server.URL
	}
	return urls
}

// StopAll stops all servers in the cluster
func (c *TestServerCluster) StopAll() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for _, server := range c.servers {
		_ = server.Stop() // Ignore error - test cleanup
	}
	c.servers = c.servers[:0]
}

// ServerCount returns the number of servers in the cluster
func (c *TestServerCluster) ServerCount() int {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return len(c.servers)
}
