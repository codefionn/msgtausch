package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
	"github.com/codefionn/msgtausch/msgtausch-srv/proxy"
)

// TestResult represents the outcome of a single test case.
type TestResult struct {
	Name     string        `json:"name"`
	URL      string        `json:"url"`
	Success  bool          `json:"success"`
	Duration time.Duration `json:"duration"`
	Error    string        `json:"error,omitempty"`
	Status   int           `json:"status"`
}

// TestSuite manages a collection of test cases against a proxy server.
type TestSuite struct {
	ProxyURL string
	Client   *http.Client
	Results  []TestResult
}

func main() {
	proxyAddr := flag.String("proxy", "127.0.0.1:7451", "Proxy address (host:port)")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	timeout := flag.Int("timeout", 30, "Request timeout in seconds")
	pastebin := flag.Bool("use-pastebin", false, "Use pastebin.com for large response tests")
	flag.Parse()

	logger.SetLevel(logger.INFO)
	if *verbose {
		logger.SetLevel(logger.DEBUG)
	}

	proxyURL, err := url.Parse("http://" + *proxyAddr)
	if err != nil {
		logger.Fatal("Invalid proxy address: %v", err)
	}

	repoDir := findRepoDir()

	createConfig := func(interception bool) *config.Config {
		return &config.Config{
			Servers: []config.ServerConfig{
				{
					Enabled:         true,
					Type:            config.ProxyTypeStandard,
					ListenAddress:   *proxyAddr,
					InterceptorName: "",
				},
			},
			TimeoutSeconds: 2 * *timeout,
			Classifiers:    map[string]config.Classifier{},
			Forwards:       []config.Forward{},
			Interception: config.InterceptionConfig{
				Enabled:   interception,
				HTTP:      interception,
				HTTPS:     interception,
				CAFile:    filepath.Join(repoDir, "msgtausch-srv", "proxy", "testdata", "test_ca.crt"),
				CAKeyFile: filepath.Join(repoDir, "msgtausch-srv", "proxy", "testdata", "test_ca.key"),
			},
		}
	}

	proxyNormal := proxy.NewProxy(createConfig(false))
	go func() {
		if err := proxyNormal.Start(); err != nil {
			logger.Error("proxy (normal) stopped with error: %v", err)
		}
	}()
	time.Sleep(time.Second * 5)
	isSuccess := runTests(proxyURL, *timeout, *pastebin, false)
	proxyNormal.Close()

	proxyInterception := proxy.NewProxy(createConfig(true))
	go func() {
		if err := proxyInterception.Start(); err != nil {
			logger.Error("proxy (interception) stopped with error: %v", err)
		}
	}()
	time.Sleep(time.Second * 5)
	isSuccess = runTests(proxyURL, *timeout, *pastebin, true) && isSuccess
	proxyInterception.Close()

	if !isSuccess {
		os.Exit(1)
	}
}

func findRepoDir() string {
	dir, err := os.Getwd()
	if err != nil {
		logger.Fatal("Failed to get current directory: %v", err)
		panic(err)
	}

	isRepoDir := func(d string) bool {
		info0, err0 := os.Stat(d + "cmd")
		info1, err1 := os.Stat(d + "msgtausch-srv")
		return err0 == nil && info0.IsDir() && err1 == nil && info1.IsDir()
	}

	for !isRepoDir(dir + string(os.PathSeparator)) {
		dir = filepath.Dir(dir)
		if strings.HasSuffix(dir, string(os.PathSeparator)) || dir == "/" || dir == "." {
			logger.Fatal("Failed to find repository root directory")
			panic("Failed to find repository root directory")
		}
	}

	return dir
}

func runTests(proxyURL *url.URL, timeout int, pastebin, interception bool) bool {
	var tlsClientConfig *tls.Config = nil
	if interception {
		publicRaw, err := os.ReadFile(filepath.Join(findRepoDir(), "msgtausch-srv", "proxy", "testdata", "test_ca.crt"))
		if err != nil {
			panic(err)
		}
		publicPemBlock, _ := pem.Decode(publicRaw)
		publicCrt, err := x509.ParseCertificate(publicPemBlock.Bytes)
		if err != nil {
			panic(err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(publicCrt)
		pool.AppendCertsFromPEM(publicRaw)
		tlsClientConfig = &tls.Config{
			RootCAs: pool,
		}

		logger.Debug("Loaded custom CA certificate for interception testing: Subject=%s, Issuer=%s", publicCrt.Subject, publicCrt.Issuer)
	}

	suite := &TestSuite{
		ProxyURL: proxyURL.String(),
		Client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			Transport: &http.Transport{
				Proxy:           http.ProxyURL(proxyURL),
				TLSClientConfig: tlsClientConfig,
			},
		},
	}

	logger.Info("Starting proxy tests with proxy: %s", suite.ProxyURL)

	// Run httpbin tests
	logger.Info("Running httpbin.org tests...")
	if pastebin {
		suite.runHTTPBinTests()
	}

	// Run search engine tests
	logger.Info("Running search engine tests...")
	suite.runSearchEngineTests()

	// Minimal GET to OpenAI /v1/responses to reproduce current failure
	logger.Info("Running OpenAI /v1/responses GET test...")
	openAIGetURL := "https://api.openai.com/v1/responses"
	res := suite.testOpenAIGet(openAIGetURL)
	res.Name = "openai-get-responses"
	res.URL = openAIGetURL
	suite.Results = append(suite.Results, res)

	// Print results
	return suite.printResults()
}

func (ts *TestSuite) runHTTPBinTests() {
	tests := []struct {
		name string
		url  string
		test func(string) TestResult
	}{
		{"httpbin-ip", "http://httpbin.org/ip", ts.testBasicGet},
		{"httpbin-headers", "http://httpbin.org/headers", ts.testBasicGet},
		{"httpbin-user-agent", "http://httpbin.org/user-agent", ts.testBasicGet},
		{"httpbin-post", "http://httpbin.org/post", ts.testPost},
		{"httpbin-json", "http://httpbin.org/json", ts.testJSON},
		{"httpbin-gzip", "http://httpbin.org/gzip", ts.testGzip},
		{"httpbin-https", "https://httpbin.org/ip", ts.testHTTPS},
		{"httpbin-redirect", "http://httpbin.org/redirect/1", ts.testRedirect},
		{"httpbin-status-404", "http://httpbin.org/status/404", ts.testStatus404},
	}

	for _, test := range tests {
		logger.Debug("Running test: %s", test.name)
		result := test.test(test.url)
		result.Name = test.name
		result.URL = test.url
		ts.Results = append(ts.Results, result)
	}
}

func (ts *TestSuite) runSearchEngineTests() {
	tests := []struct {
		name string
		url  string
	}{
		{"google-search", "https://www.google.com/search?q=test"},
		{"bing-search", "https://www.bing.com/search?q=test"},
		{"duckduckgo-search", "https://duckduckgo.com/?q=test"},
		{"google-homepage", "https://www.google.com/"},
		{"bing-homepage", "https://www.bing.com/"},
		{"duckduckgo-homepage", "https://duckduckgo.com/"},
	}

	for _, test := range tests {
		logger.Debug("Running search engine test: %s", test.name)
		result := ts.testSearchEngine(test.url)
		result.Name = test.name
		result.URL = test.url
		ts.Results = append(ts.Results, result)
	}
}

func (ts *TestSuite) testBasicGet(testURL string) TestResult {
	start := time.Now()

	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return TestResult{
			Success:  false,
			Duration: time.Since(start),
			Error:    fmt.Sprintf("Failed to create request: %v", err),
		}
	}

	req.Header.Set("User-Agent", "msgtausch-proxy-test/1.0")

	resp, err := ts.Client.Do(req)
	duration := time.Since(start)

	if err != nil {
		return TestResult{
			Success:  false,
			Duration: duration,
			Error:    fmt.Sprintf("Request failed: %v", err),
		}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Error("Error closing response body: %v", closeErr)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return TestResult{
			Success:  false,
			Duration: duration,
			Status:   resp.StatusCode,
			Error:    fmt.Sprintf("Failed to read response: %v", err),
		}
	}

	logger.Debug("Response for %s: %d bytes, status %d", testURL, len(body), resp.StatusCode)

	return TestResult{
		Success:  resp.StatusCode == 200,
		Duration: duration,
		Status:   resp.StatusCode,
	}
}

func (ts *TestSuite) testPost(testURL string) TestResult {
	start := time.Now()

	postData := strings.NewReader("test=data&proxy=msgtausch")
	req, err := http.NewRequest("POST", testURL, postData)
	if err != nil {
		return TestResult{
			Success:  false,
			Duration: time.Since(start),
			Error:    fmt.Sprintf("Failed to create request: %v", err),
		}
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "msgtausch-proxy-test/1.0")

	resp, err := ts.Client.Do(req)
	duration := time.Since(start)

	if err != nil {
		return TestResult{
			Success:  false,
			Duration: duration,
			Error:    fmt.Sprintf("Request failed: %v", err),
		}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Error("Error closing response body: %v", closeErr)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return TestResult{
			Success:  false,
			Duration: duration,
			Status:   resp.StatusCode,
			Error:    fmt.Sprintf("Failed to read response: %v", err),
		}
	}

	// Check if the POST data was echoed back
	success := resp.StatusCode == 200 && strings.Contains(string(body), "test")

	return TestResult{
		Success:  success,
		Duration: duration,
		Status:   resp.StatusCode,
	}
}

func (ts *TestSuite) testJSON(testURL string) TestResult {
	start := time.Now()

	resp, err := ts.Client.Get(testURL)
	duration := time.Since(start)

	if err != nil {
		return TestResult{
			Success:  false,
			Duration: duration,
			Error:    fmt.Sprintf("Request failed: %v", err),
		}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Error("Error closing response body: %v", closeErr)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return TestResult{
			Success:  false,
			Duration: duration,
			Status:   resp.StatusCode,
			Error:    fmt.Sprintf("Failed to read response: %v", err),
		}
	}

	// Try to parse JSON
	var jsonData map[string]interface{}
	err = json.Unmarshal(body, &jsonData)
	success := err == nil && resp.StatusCode == 200

	return TestResult{
		Success:  success,
		Duration: duration,
		Status:   resp.StatusCode,
	}
}

func (ts *TestSuite) testGzip(testURL string) TestResult {
	start := time.Now()

	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return TestResult{
			Success:  false,
			Duration: time.Since(start),
			Error:    fmt.Sprintf("Failed to create request: %v", err),
		}
	}

	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("User-Agent", "msgtausch-proxy-test/1.0")

	resp, err := ts.Client.Do(req)
	duration := time.Since(start)

	if err != nil {
		return TestResult{
			Success:  false,
			Duration: duration,
			Error:    fmt.Sprintf("Request failed: %v", err),
		}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Error("Error closing response body: %v", closeErr)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return TestResult{
			Success:  false,
			Duration: duration,
			Status:   resp.StatusCode,
			Error:    fmt.Sprintf("Failed to read response: %v", err),
		}
	}

	// Check if we got a gzipped response
	success := resp.StatusCode == 200 && len(body) > 0

	return TestResult{
		Success:  success,
		Duration: duration,
		Status:   resp.StatusCode,
	}
}

func (ts *TestSuite) testHTTPS(testURL string) TestResult {
	start := time.Now()

	resp, err := ts.Client.Get(testURL)
	duration := time.Since(start)

	if err != nil {
		return TestResult{
			Success:  false,
			Duration: duration,
			Error:    fmt.Sprintf("HTTPS request failed: %v", err),
		}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Error("Error closing response body: %v", closeErr)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return TestResult{
			Success:  false,
			Duration: duration,
			Status:   resp.StatusCode,
			Error:    fmt.Sprintf("Failed to read response: %v", err),
		}
	}

	logger.Debug("HTTPS response: %d bytes, status %d", len(body), resp.StatusCode)

	return TestResult{
		Success:  resp.StatusCode == 200,
		Duration: duration,
		Status:   resp.StatusCode,
	}
}

func (ts *TestSuite) testRedirect(testURL string) TestResult {
	start := time.Now()

	resp, err := ts.Client.Get(testURL)
	duration := time.Since(start)

	if err != nil {
		return TestResult{
			Success:  false,
			Duration: duration,
			Error:    fmt.Sprintf("Redirect test failed: %v", err),
		}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Error("Error closing response body: %v", closeErr)
		}
	}()

	// httpbin.org/redirect/1 should redirect and then return 200
	success := resp.StatusCode == 200

	return TestResult{
		Success:  success,
		Duration: duration,
		Status:   resp.StatusCode,
	}
}

func (ts *TestSuite) testStatus404(testURL string) TestResult {
	start := time.Now()

	resp, err := ts.Client.Get(testURL)
	duration := time.Since(start)

	if err != nil {
		return TestResult{
			Success:  false,
			Duration: duration,
			Error:    fmt.Sprintf("Status test failed: %v", err),
		}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Error("Error closing response body: %v", closeErr)
		}
	}()

	// This should return 404
	success := resp.StatusCode == 404

	return TestResult{
		Success:  success,
		Duration: duration,
		Status:   resp.StatusCode,
	}
}

func (ts *TestSuite) testSearchEngine(testURL string) TestResult {
	start := time.Now()

	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return TestResult{
			Success:  false,
			Duration: time.Since(start),
			Error:    fmt.Sprintf("Failed to create request: %v", err),
		}
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := ts.Client.Do(req)
	duration := time.Since(start)

	if err != nil {
		return TestResult{
			Success:  false,
			Duration: duration,
			Error:    fmt.Sprintf("Search engine request failed: %v", err),
		}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Error("Error closing response body: %v", closeErr)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return TestResult{
			Success:  false,
			Duration: duration,
			Status:   resp.StatusCode,
			Error:    fmt.Sprintf("Failed to read response: %v", err),
		}
	}

	// Check for successful response and some expected content
	success := resp.StatusCode == 200 && len(body) > 1000

	logger.Debug("Search engine response for %s: %d bytes, status %d", testURL, len(body), resp.StatusCode)

	return TestResult{
		Success:  success,
		Duration: duration,
		Status:   resp.StatusCode,
	}
}

func (ts *TestSuite) printResults() bool {
	fmt.Printf("\n=== Proxy Test Results ===\n")
	fmt.Printf("Proxy: %s\n\n", ts.ProxyURL)

	passed := 0
	failed := 0

	for _, result := range ts.Results {
		status := "✓ PASS"
		if !result.Success {
			status = "✗ FAIL"
			failed++
		} else {
			passed++
		}

		fmt.Printf("%-20s %s (%d) %v\n",
			result.Name,
			status,
			result.Status,
			result.Duration.Round(time.Millisecond))

		if result.Error != "" {
			fmt.Printf("                     Error: %s\n", result.Error)
		}
	}

	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Total tests: %d\n", len(ts.Results))
	fmt.Printf("Passed: %d\n", passed)
	fmt.Printf("Failed: %d\n", failed)

	if failed > 0 {
		fmt.Printf("\nSome tests failed. Check proxy configuration and connectivity.\n")
		return false
	} else {
		fmt.Printf("\nAll tests passed! Proxy is working correctly.\n")
		return true
	}
}

// testOpenAIGet performs a simple GET to OpenAI's /v1/responses endpoint.
// Success criteria: any HTTP response is considered success (even 4xx/5xx).
// Failure indicates a transport/proxy error reproducing the interception issue.
func (ts *TestSuite) testOpenAIGet(testURL string) TestResult {
	start := time.Now()

	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return TestResult{
			Success:  false,
			Duration: time.Since(start),
			Error:    fmt.Sprintf("Failed to create request: %v", err),
		}
	}

	// If API key is present, add it, but it's not required
	if apiKey := strings.TrimSpace(os.Getenv("OPENAI_API_KEY")); apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "msgtausch-proxy-test/1.0")

	resp, err := ts.Client.Do(req)
	duration := time.Since(start)
	if err != nil {
		return TestResult{
			Success:  false,
			Duration: duration,
			Error:    fmt.Sprintf("Request failed: %v", err),
		}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Error("Error closing OpenAI GET response body: %v", closeErr)
		}
	}()

	// Read a small snippet for diagnostics
	buf := make([]byte, 1024)
	n, _ := io.ReadFull(resp.Body, buf)
	snippet := strings.TrimSpace(string(buf[:n]))
	logger.Debug("OpenAI GET status=%d, content-type=%s, body-snippet=%q", resp.StatusCode, resp.Header.Get("Content-Type"), snippet)

	return TestResult{
		Success:  true, // any HTTP response indicates proxy path worked
		Duration: duration,
		Status:   resp.StatusCode,
	}
}
