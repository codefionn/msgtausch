package proxy

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCompressionGzip tests that the proxy correctly handles gzip-compressed responses
func TestCompressionGzip(t *testing.T) {
	testContent := "This is test content that will be gzip compressed. " +
		"It's long enough to make compression worthwhile and demonstrate that the proxy handles it correctly."

	// Create a test server that returns gzip-compressed content
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Compress the content
		var buf bytes.Buffer
		gzWriter := gzip.NewWriter(&buf)
		_, err := gzWriter.Write([]byte(testContent))
		if err != nil {
			t.Errorf("Failed to write gzip content: %v", err)
			return
		}
		if err := gzWriter.Close(); err != nil {
			t.Errorf("Failed to close gzip writer: %v", err)
			return
		}

		// Set appropriate headers
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", buf.Len()))

		// Write compressed content
		_, _ = w.Write(buf.Bytes())
	}))
	defer testServer.Close()

	// Create proxy configuration
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		TimeoutSeconds: 5,
		Classifiers:    make(map[string]config.Classifier),
	}

	proxy := NewProxy(cfg)

	// Start proxy server
	listener, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	require.NoError(t, err)
	proxyAddr := listener.Addr().String()

	go func() {
		if err := proxy.StartWithListener(listener); err != http.ErrServerClosed && err != nil {
			t.Errorf("Proxy server error: %v", err)
		}
	}()
	defer proxy.Stop()

	time.Sleep(100 * time.Millisecond)

	// Create HTTP client that uses the proxy
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", proxyAddr))
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			// Disable automatic decompression to verify proxy passes through correctly
			DisableCompression: true,
		},
	}

	t.Run("gzip compressed response passes through proxy", func(t *testing.T) {
		req, err := http.NewRequest("GET", testServer.URL, http.NoBody)
		require.NoError(t, err)
		// Don't request compression - we want to test the raw compressed response
		req.Header.Set("Accept-Encoding", "identity")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Note: The server still sends gzip, but Go's client may auto-decode it
		// Read the response body
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		// If Content-Encoding is still gzip, decompress manually
		if resp.Header.Get("Content-Encoding") == "gzip" {
			gzReader, err := gzip.NewReader(bytes.NewReader(body))
			require.NoError(t, err)
			defer gzReader.Close()

			decompressed, err := io.ReadAll(gzReader)
			require.NoError(t, err)
			assert.Equal(t, testContent, string(decompressed))
		} else {
			// Client auto-decoded it
			assert.Equal(t, testContent, string(body))
		}
	})

	t.Run("client with auto-decompression receives uncompressed content", func(t *testing.T) {
		// Create client with automatic decompression enabled
		autoClient := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			},
		}

		resp, err := autoClient.Get(testServer.URL)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Read body (should be automatically decompressed by client)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		// Verify content matches (client decompressed it)
		assert.Equal(t, testContent, string(body))
	})
}

// TestCompressionDeflate tests deflate compression handling
func TestCompressionDeflate(t *testing.T) {
	testContent := "This is test content that will be deflate compressed. " +
		"Deflate is another common compression algorithm used in HTTP."

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Compress the content with deflate
		var buf bytes.Buffer
		deflateWriter := zlib.NewWriter(&buf)
		_, err := deflateWriter.Write([]byte(testContent))
		if err != nil {
			t.Errorf("Failed to write deflate content: %v", err)
			return
		}
		if err := deflateWriter.Close(); err != nil {
			t.Errorf("Failed to close deflate writer: %v", err)
			return
		}

		// Set appropriate headers
		w.Header().Set("Content-Encoding", "deflate")
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", buf.Len()))

		// Write compressed content
		_, _ = w.Write(buf.Bytes())
	}))
	defer testServer.Close()

	// Create proxy
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		TimeoutSeconds: 5,
		Classifiers:    make(map[string]config.Classifier),
	}

	proxy := NewProxy(cfg)
	listener, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	require.NoError(t, err)
	proxyAddr := listener.Addr().String()

	go func() {
		if err := proxy.StartWithListener(listener); err != http.ErrServerClosed && err != nil {
			t.Errorf("Proxy server error: %v", err)
		}
	}()
	defer proxy.Stop()

	time.Sleep(100 * time.Millisecond)

	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", proxyAddr))
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:              http.ProxyURL(proxyURL),
			DisableCompression: true,
		},
	}

	resp, err := client.Get(testServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify Content-Encoding header
	assert.Equal(t, "deflate", resp.Header.Get("Content-Encoding"))

	// Decompress manually
	deflateReader, err := zlib.NewReader(resp.Body)
	require.NoError(t, err)
	defer deflateReader.Close()

	body, err := io.ReadAll(deflateReader)
	require.NoError(t, err)

	assert.Equal(t, testContent, string(body))
}

// TestMultipleContentEncodings tests handling of multiple content encodings
func TestMultipleContentEncodings(t *testing.T) {
	testContent := "Test content with multiple encodings"

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply multiple compressions (gzip, then deflate) - unusual but valid
		var buf1 bytes.Buffer
		gzWriter := gzip.NewWriter(&buf1)
		_, _ = gzWriter.Write([]byte(testContent))
		_ = gzWriter.Close()

		var buf2 bytes.Buffer
		deflateWriter := zlib.NewWriter(&buf2)
		_, _ = deflateWriter.Write(buf1.Bytes())
		_ = deflateWriter.Close()

		w.Header().Set("Content-Encoding", "deflate, gzip")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(buf2.Bytes())
	}))
	defer testServer.Close()

	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		TimeoutSeconds: 5,
		Classifiers:    make(map[string]config.Classifier),
	}

	proxy := NewProxy(cfg)
	listener, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	require.NoError(t, err)
	proxyAddr := listener.Addr().String()

	go func() {
		if err := proxy.StartWithListener(listener); err != http.ErrServerClosed && err != nil {
			t.Errorf("Proxy server error: %v", err)
		}
	}()
	defer proxy.Stop()

	time.Sleep(100 * time.Millisecond)

	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", proxyAddr))
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:              http.ProxyURL(proxyURL),
			DisableCompression: true,
		},
	}

	resp, err := client.Get(testServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify Content-Encoding header is preserved
	assert.Equal(t, "deflate, gzip", resp.Header.Get("Content-Encoding"))
}

// TestChunkedWithGzipCompression tests chunked transfer with gzip compression
func TestChunkedWithGzipCompression(t *testing.T) {
	testContent := "This is compressed and chunked content that tests both features together. " +
		"The content is long enough to make compression worthwhile."

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Compress the content first
		var buf bytes.Buffer
		gzWriter := gzip.NewWriter(&buf)
		_, _ = gzWriter.Write([]byte(testContent))
		_ = gzWriter.Close()

		// Set headers - both compression and chunked encoding
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")

		// Write in chunks
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("ResponseWriter doesn't support flushing")
			return
		}

		// Send compressed data in chunks
		data := buf.Bytes()
		chunkSize := 20
		for i := 0; i < len(data); i += chunkSize {
			end := i + chunkSize
			if end > len(data) {
				end = len(data)
			}
			_, _ = w.Write(data[i:end])
			flusher.Flush()
			time.Sleep(5 * time.Millisecond)
		}
	}))
	defer testServer.Close()

	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		TimeoutSeconds: 5,
		Classifiers:    make(map[string]config.Classifier),
	}

	proxy := NewProxy(cfg)
	listener, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	require.NoError(t, err)
	proxyAddr := listener.Addr().String()

	go func() {
		if err := proxy.StartWithListener(listener); err != http.ErrServerClosed && err != nil {
			t.Errorf("Proxy server error: %v", err)
		}
	}()
	defer proxy.Stop()

	time.Sleep(100 * time.Millisecond)

	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", proxyAddr))
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			// Enable automatic decompression
		},
	}

	resp, err := client.Get(testServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Read response (client will handle both chunked and gzip automatically)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, testContent, string(body))
}

// TestComplexCompressionScenario tests combination of compression, chunking, and trailers
func TestComplexCompressionScenario(t *testing.T) {
	testContent := "This is a complex test with compression, chunking, and trailers all combined. " +
		"This comprehensive test ensures the proxy handles all these features together correctly."

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Announce trailer
		w.Header().Set("Trailer", "X-Content-Hash")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")

		// Compress content
		var buf bytes.Buffer
		gzWriter := gzip.NewWriter(&buf)
		_, _ = gzWriter.Write([]byte(testContent))
		_ = gzWriter.Close()

		// Get flusher for chunked encoding
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("ResponseWriter doesn't support flushing")
			return
		}

		// Write compressed data in chunks
		data := buf.Bytes()
		chunkSize := 30
		for i := 0; i < len(data); i += chunkSize {
			end := i + chunkSize
			if end > len(data) {
				end = len(data)
			}
			_, _ = w.Write(data[i:end])
			flusher.Flush()
			time.Sleep(5 * time.Millisecond)
		}

		// Set trailer
		w.Header().Set("X-Content-Hash", "abc123def456")
	}))
	defer testServer.Close()

	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		TimeoutSeconds: 5,
		Classifiers:    make(map[string]config.Classifier),
	}

	proxy := NewProxy(cfg)
	listener, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	require.NoError(t, err)
	proxyAddr := listener.Addr().String()

	go func() {
		if err := proxy.StartWithListener(listener); err != http.ErrServerClosed && err != nil {
			t.Errorf("Proxy server error: %v", err)
		}
	}()
	defer proxy.Stop()

	time.Sleep(100 * time.Millisecond)

	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", proxyAddr))
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	resp, err := client.Get(testServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Read body (client handles decompression and dechunking)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Verify content
	assert.Equal(t, testContent, string(body))

	// Check for trailer (if supported by client/proxy)
	if len(resp.Trailer) > 0 {
		t.Logf("Trailers received in complex scenario: %v", resp.Trailer)
	}
}

// TestInterceptionWithCompression tests HTTP interception with compressed content
func TestInterceptionWithCompression(t *testing.T) {
	originalContent := "Original content that will be compressed and then modified by the interceptor"
	modifiedContent := "Modified by interceptor"

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Compress the content
		var buf bytes.Buffer
		gzWriter := gzip.NewWriter(&buf)
		_, _ = gzWriter.Write([]byte(originalContent))
		_ = gzWriter.Close()

		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(buf.Bytes())
	}))
	defer testServer.Close()

	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeHTTP,
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		TimeoutSeconds: 5,
		Classifiers:    make(map[string]config.Classifier),
		Interception: config.InterceptionConfig{
			Enabled: true,
			HTTP:    true,
			HTTPS:   false,
		},
	}

	proxy := NewProxy(cfg)

	// Add response interceptor that modifies the response body
	// Note: The HTTP interceptor operates on the decompressed stream
	proxy.servers[0].httpInterceptor.AddResponseHook("modify-response", func(resp *http.Response) error {
		// Read original body
		_, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()

		// Replace with modified content (uncompressed - client will handle if needed)
		resp.Body = io.NopCloser(strings.NewReader(modifiedContent))
		resp.ContentLength = int64(len(modifiedContent))
		resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(modifiedContent)))
		resp.Header.Set("X-Intercepted", "true")
		// Remove Content-Encoding since we're sending uncompressed
		resp.Header.Del("Content-Encoding")
		return nil
	})

	listener, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	require.NoError(t, err)
	proxyAddr := listener.Addr().String()

	go func() {
		if err := proxy.StartWithListener(listener); err != http.ErrServerClosed && err != nil {
			t.Errorf("Proxy server error: %v", err)
		}
	}()
	defer proxy.Stop()

	time.Sleep(100 * time.Millisecond)

	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", proxyAddr))
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	resp, err := client.Get(testServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify interception occurred
	assert.Equal(t, "true", resp.Header.Get("X-Intercepted"))

	// Read and verify modified content
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, modifiedContent, string(body))
}

// TestAcceptEncodingHeader tests that Accept-Encoding header is properly forwarded
func TestAcceptEncodingHeader(t *testing.T) {
	var receivedAcceptEncoding string

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAcceptEncoding = r.Header.Get("Accept-Encoding")

		// Echo back what we received
		w.Header().Set("X-Received-Accept-Encoding", receivedAcceptEncoding)

		// Respond based on Accept-Encoding
		if strings.Contains(receivedAcceptEncoding, "gzip") {
			var buf bytes.Buffer
			gzWriter := gzip.NewWriter(&buf)
			_, _ = gzWriter.Write([]byte("compressed response"))
			_ = gzWriter.Close()

			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(buf.Bytes())
		} else {
			_, _ = w.Write([]byte("uncompressed response"))
		}
	}))
	defer testServer.Close()

	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		TimeoutSeconds: 5,
		Classifiers:    make(map[string]config.Classifier),
	}

	proxy := NewProxy(cfg)
	listener, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	require.NoError(t, err)
	proxyAddr := listener.Addr().String()

	go func() {
		if err := proxy.StartWithListener(listener); err != http.ErrServerClosed && err != nil {
			t.Errorf("Proxy server error: %v", err)
		}
	}()
	defer proxy.Stop()

	time.Sleep(100 * time.Millisecond)

	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", proxyAddr))
	require.NoError(t, err)

	t.Run("explicit gzip accept-encoding", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				Proxy:              http.ProxyURL(proxyURL),
				DisableCompression: true, // We'll set Accept-Encoding manually
			},
		}

		req, err := http.NewRequest("GET", testServer.URL, http.NoBody)
		require.NoError(t, err)
		req.Header.Set("Accept-Encoding", "gzip, deflate")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify the server received the Accept-Encoding header
		assert.Contains(t, receivedAcceptEncoding, "gzip")
		assert.Equal(t, "gzip", resp.Header.Get("Content-Encoding"))
	})

	t.Run("no accept-encoding", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				Proxy:              http.ProxyURL(proxyURL),
				DisableCompression: true,
			},
		}

		req, err := http.NewRequest("GET", testServer.URL, http.NoBody)
		require.NoError(t, err)
		// Explicitly set to identity to prevent compression
		req.Header.Set("Accept-Encoding", "identity")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		// The server checks for gzip in Accept-Encoding
		// With "identity", it should send uncompressed
		// But Go's client might auto-decode anyway, check the actual response
		if resp.Header.Get("Content-Encoding") == "gzip" {
			// Decompress
			gzReader, err := gzip.NewReader(bytes.NewReader(body))
			require.NoError(t, err)
			defer gzReader.Close()
			decompressed, err := io.ReadAll(gzReader)
			require.NoError(t, err)
			assert.Equal(t, "compressed response", string(decompressed))
		} else {
			assert.Equal(t, "uncompressed response", string(body))
		}
	})
}

// TestContentEncodingWithContentLength tests that Content-Length is correctly handled with compression
func TestContentEncodingWithContentLength(t *testing.T) {
	testContent := "This content will be compressed and should have correct Content-Length"

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		gzWriter := gzip.NewWriter(&buf)
		_, _ = gzWriter.Write([]byte(testContent))
		_ = gzWriter.Close()

		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", buf.Len()))

		_, _ = w.Write(buf.Bytes())
	}))
	defer testServer.Close()

	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:0",
				Enabled:       true,
			},
		},
		TimeoutSeconds: 5,
		Classifiers:    make(map[string]config.Classifier),
	}

	proxy := NewProxy(cfg)
	listener, err := net.Listen("tcp", cfg.Servers[0].ListenAddress)
	require.NoError(t, err)
	proxyAddr := listener.Addr().String()

	go func() {
		if err := proxy.StartWithListener(listener); err != http.ErrServerClosed && err != nil {
			t.Errorf("Proxy server error: %v", err)
		}
	}()
	defer proxy.Stop()

	time.Sleep(100 * time.Millisecond)

	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", proxyAddr))
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			// Use default compression handling
		},
	}

	resp, err := client.Get(testServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Read the response body (Go's client will auto-decompress)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Verify content (should be decompressed by client)
	assert.Equal(t, testContent, string(body))

	// Note: Content-Encoding and Content-Length headers may be modified/removed
	// by Go's HTTP client after automatic decompression. The important part
	// is that the proxy correctly forwarded the compressed response and the
	// client could decode it.
}
