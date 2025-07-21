package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
)

// TestConnectionCloseHandling tests that the proxy handles "Connection: close" responses quickly
func TestConnectionCloseHandling(t *testing.T) {
	// Create a mock HTTPS server that sends Connection: close
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener for mock server: %v", err)
	}
	defer ln.Close()

	serverAddr := ln.Addr().String()
	
	// JavaScript content similar to the problematic wgv.de response
	jsContent := `/* Dynamically generated content! DON'T COPY IT TO YOUR SERVERS! */
(function(){var w=window,d=document,t="script";console.log("test")})();`

	// Start mock server that sends Connection: close
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // Listener closed
			}
			
			go func(conn net.Conn) {
				defer conn.Close()
				
				// Read the HTTP request
				reader := bufio.NewReader(conn)
				_, err := http.ReadRequest(reader)
				if err != nil {
					return
				}
				
				// Send response with Connection: close (like wgv.de does)
				response := fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
					"Content-Type: text/javascript\r\n"+
					"Connection: close\r\n"+
					"Content-Length: %d\r\n"+
					"Cache-Control: private, no-cache, no-store, must-revalidate\r\n"+
					"\r\n"+
					"%s", len(jsContent), jsContent)
				
				conn.Write([]byte(response))
				// Immediately close the connection after sending (like Connection: close should)
			}(conn)
		}
	}()

	// Create proxy configuration
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		TimeoutSeconds:           30,
		MaxConcurrentConnections: 100,
		Classifiers:              make(map[string]config.Classifier),
	}

	proxy := NewProxy(cfg)

	// Start proxy server
	proxyListener, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	if err != nil {
		t.Fatalf("Failed to create proxy listener: %v", err)
	}
	proxyAddr := proxyListener.Addr().String()

	go func() {
		if err := proxy.StartWithListener(proxyListener); err != http.ErrServerClosed && err != nil {
			t.Errorf("Proxy server error: %v", err)
		}
	}()
	defer proxy.Stop()

	// Wait for proxy to start
	time.Sleep(100 * time.Millisecond)

	// Test the Connection: close handling
	t.Run("Connection close handling", func(t *testing.T) {
		// Create HTTP client that uses our proxy
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(&url.URL{Host: proxyAddr}),
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // For testing
				},
			},
			Timeout: 10 * time.Second, // Should complete much faster
		}

		// Measure the time it takes to complete the request
		start := time.Now()
		
		// Make request to our mock server through the proxy
		targetURL := fmt.Sprintf("http://%s/test.js", serverAddr)
		req, err := http.NewRequestWithContext(context.Background(), "GET", targetURL, nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request through proxy failed: %v", err)
		}
		defer resp.Body.Close()

		duration := time.Since(start)

		// Verify response
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
		}

		// Read response body
		body := make([]byte, len(jsContent))
		n, err := resp.Body.Read(body)
		if err != nil && err.Error() != "EOF" {
			t.Fatalf("Failed to read response body: %v", err)
		}

		if string(body[:n]) != jsContent {
			t.Errorf("Response body mismatch.\nExpected: %s\nGot: %s", jsContent, string(body[:n]))
		}

		// Verify that the connection closed quickly (should be under 2 seconds)
		// Before the fix, this would take 30+ seconds due to timeout
		if duration > 2*time.Second {
			t.Errorf("Connection close handling too slow: %v (should be < 2s)", duration)
		}

		t.Logf("Connection close handling completed in: %v", duration)
	})
}

// TestConnectionCloseHTTPS tests Connection: close handling over HTTPS tunnel
func TestConnectionCloseHTTPS(t *testing.T) {
	// Create a TLS server that sends Connection: close
	tlsServer, certPool := setupTLSServer(t)
	defer tlsServer.Close()

	// Replace the default handler with one that sends Connection: close
	tlsServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Type", "text/javascript")
		w.Header().Set("Cache-Control", "private, no-cache, no-store, must-revalidate")
		
		jsContent := `/* Test JS content with Connection: close */
(function(){console.log("connection close test")})();`
		w.Write([]byte(jsContent))
	})

	// Create proxy configuration
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		TimeoutSeconds:           30,
		MaxConcurrentConnections: 100,
		Classifiers:              make(map[string]config.Classifier),
	}

	proxy := NewProxy(cfg)

	// Start proxy server
	proxyListener, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	if err != nil {
		t.Fatalf("Failed to create proxy listener: %v", err)
	}
	proxyAddr := proxyListener.Addr().String()

	go func() {
		if err := proxy.StartWithListener(proxyListener); err != http.ErrServerClosed && err != nil {
			t.Errorf("Proxy server error: %v", err)
		}
	}()
	defer proxy.Stop()

	// Wait for proxy to start
	time.Sleep(100 * time.Millisecond)

	t.Run("HTTPS Connection close handling", func(t *testing.T) {
		// Create HTTP client that uses our proxy
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(&url.URL{Host: proxyAddr}),
				TLSClientConfig: &tls.Config{
					RootCAs: certPool,
				},
			},
			Timeout: 10 * time.Second,
		}

		// Measure the time it takes to complete the request
		start := time.Now()
		
		resp, err := client.Get(tlsServer.URL + "/test.js")
		if err != nil {
			t.Fatalf("HTTPS request through proxy failed: %v", err)
		}
		defer resp.Body.Close()

		duration := time.Since(start)

		// Verify response
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
		}

		// Note: Connection: close header might not be preserved in HTTP/2 
		// but the connection handling should still be fast
		t.Logf("Connection header: %v", resp.Header.Get("Connection"))

		// Verify that the connection closed quickly
		if duration > 2*time.Second {
			t.Errorf("HTTPS connection close handling too slow: %v (should be < 2s)", duration)
		}

		t.Logf("HTTPS connection close handling completed in: %v", duration)
	})
}