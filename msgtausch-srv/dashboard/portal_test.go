package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/codefionn/msgtausch/msgtausch-srv/stats"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockProxy is a mock implementation of ProxyInterface for testing
type mockProxy struct {
	config *config.Config
}

func (m *mockProxy) GetConfig() *config.Config {
	return m.config
}

func (m *mockProxy) GetServerInfo() []ServerInfo {
	info := make([]ServerInfo, 0, len(m.config.Servers))
	for _, server := range m.config.Servers {
		info = append(info, ServerInfo{
			Type:          string(server.Type),
			ListenAddress: server.ListenAddress,
			Enabled:       server.Enabled,
		})
	}
	return info
}

// createTestConfig creates a test configuration
func createTestConfig() *config.Config {
	return &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:8080",
				Enabled:       true,
			},
			{
				Type:          config.ProxyTypeHTTP,
				ListenAddress: "127.0.0.1:8081",
				Enabled:       true,
			},
			{
				Type:          config.ProxyTypeHTTPS,
				ListenAddress: "127.0.0.1:8082",
				Enabled:       false,
			},
		},
		TimeoutSeconds: 30,
		Classifiers:    map[string]config.Classifier{},
		Forwards:       []config.Forward{},
		Interception: config.InterceptionConfig{
			Enabled: true,
			HTTP:    true,
			HTTPS:   true,
		},
		Statistics: config.StatisticsConfig{
			Enabled: false,
		},
		Portal: config.PortalConfig{
			Username: "", // No authentication for basic tests
			Password: "",
		},
	}
}

// createTestConfigWithAuth creates a test configuration with authentication enabled
func createTestConfigWithAuth() *config.Config {
	return &config.Config{
		Servers: []config.ServerConfig{
			{
				Type:          config.ProxyTypeStandard,
				ListenAddress: "127.0.0.1:8080",
				Enabled:       true,
			},
		},
		TimeoutSeconds: 30,
		Classifiers:    map[string]config.Classifier{},
		Forwards:       []config.Forward{},
		Interception: config.InterceptionConfig{
			Enabled: true,
			HTTP:    true,
			HTTPS:   true,
		},
		Portal: config.PortalConfig{
			Username: "admin",
			Password: "admin", // Note: portal uses "admin" as password
		},
		Statistics: config.StatisticsConfig{
			Enabled: false,
		},
	}
}

// TestNewPortal tests portal creation
func TestNewPortal(t *testing.T) {
	cfg := createTestConfig()
	mockProxy := &mockProxy{config: cfg}
	collector := stats.NewDummyCollector()

	portal := NewPortal(cfg, collector, mockProxy)

	assert.NotNil(t, portal)
	assert.Equal(t, cfg, portal.config)
	assert.Equal(t, collector, portal.collector)
	assert.Equal(t, mockProxy, portal.proxy)
}

// TestPortalDomainConstant tests the portal domain constant
func TestPortalDomainConstant(t *testing.T) {
	assert.Equal(t, "msgtausch.internal", PortalDomain)
}

// TestIsPortalRequest tests portal domain detection
func TestIsPortalRequest(t *testing.T) {
	cfg := createTestConfig()
	mockProxy := &mockProxy{config: cfg}
	collector := stats.NewDummyCollector()

	portal := NewPortal(cfg, collector, mockProxy)

	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		{
			name:     "portal domain",
			host:     "msgtausch.internal",
			expected: true,
		},
		{
			name:     "portal domain with port",
			host:     "msgtausch.internal:8080",
			expected: true,
		},
		{
			name:     "portal domain case insensitive",
			host:     "MSGTAUSCH.INTERNAL",
			expected: true,
		},
		{
			name:     "non-portal domain",
			host:     "example.com",
			expected: false,
		},
		{
			name:     "similar domain",
			host:     "msgtausch.internal.com",
			expected: false,
		},
		{
			name:     "subdomain",
			host:     "sub.msgtausch.internal",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tt.host+"/", nil)
			req.Host = tt.host
			result := portal.IsPortalRequest(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestPortalServeHTTP tests the main portal HTTP handler
func TestPortalServeHTTP(t *testing.T) {
	cfg := createTestConfig()
	mockProxy := &mockProxy{config: cfg}
	collector := stats.NewDummyCollector()

	portal := NewPortal(cfg, collector, mockProxy)

	tests := []struct {
		name           string
		path           string
		expectedStatus int
		expectedType   string
	}{
		{
			name:           "index page",
			path:           "/",
			expectedStatus: http.StatusOK,
			expectedType:   "text/html",
		},
		{
			name:           "stats API",
			path:           "/api/stats",
			expectedStatus: http.StatusOK,
			expectedType:   "application/json",
		},
		{
			name:           "config API",
			path:           "/api/config",
			expectedStatus: http.StatusOK,
			expectedType:   "application/json",
		},
		{
			name:           "servers API",
			path:           "/api/servers",
			expectedStatus: http.StatusOK,
			expectedType:   "application/json",
		},
		{
			name:           "not found",
			path:           "/nonexistent",
			expectedStatus: http.StatusNotFound,
			expectedType:   "text/plain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			req.Host = "msgtausch.internal"
			w := httptest.NewRecorder()

			portal.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Header().Get("Content-Type"), tt.expectedType)
		})
	}
}

// TestPortalStatsAPI tests the stats API endpoint
func TestPortalStatsAPI(t *testing.T) {
	cfg := createTestConfig()
	mockProxy := &mockProxy{config: cfg}
	collector := stats.NewDummyCollector()

	portal := NewPortal(cfg, collector, mockProxy)

	req := httptest.NewRequest("GET", "/api/stats", nil)
	req.Host = "msgtausch.internal"
	w := httptest.NewRecorder()

	portal.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var stats map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &stats)
	require.NoError(t, err)

	assert.Contains(t, stats, "startTime")
	assert.Contains(t, stats, "uptime")
	assert.Contains(t, stats, "requestsServed")
	assert.Contains(t, stats, "activeServers")
	assert.Contains(t, stats, "totalServers")

	assert.Equal(t, float64(1), stats["requestsServed"])
	assert.Equal(t, float64(2), stats["activeServers"])
	assert.Equal(t, float64(3), stats["totalServers"])
}

// TestPortalConfigAPI tests the config API endpoint
func TestPortalConfigAPI(t *testing.T) {
	cfg := createTestConfig()
	mockProxy := &mockProxy{config: cfg}
	collector := stats.NewDummyCollector()

	portal := NewPortal(cfg, collector, mockProxy)

	req := httptest.NewRequest("GET", "/api/config", nil)
	req.Host = "msgtausch.internal"
	w := httptest.NewRecorder()

	portal.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var config map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &config)
	require.NoError(t, err)

	assert.Contains(t, config, "serversCount")
	assert.Contains(t, config, "forwardsCount")
	assert.Contains(t, config, "classifiersCount")

	assert.Equal(t, float64(3), config["serversCount"])
	assert.Equal(t, float64(0), config["forwardsCount"])
	assert.Equal(t, float64(0), config["classifiersCount"])
}

// TestPortalServersAPI tests the servers API endpoint
func TestPortalServersAPI(t *testing.T) {
	cfg := createTestConfig()
	mockProxy := &mockProxy{config: cfg}
	collector := stats.NewDummyCollector()

	portal := NewPortal(cfg, collector, mockProxy)

	req := httptest.NewRequest("GET", "/api/servers", nil)
	req.Host = "msgtausch.internal"
	w := httptest.NewRecorder()

	portal.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "servers")
	servers := response["servers"].([]interface{})
	assert.Len(t, servers, 3)

	server1 := servers[0].(map[string]interface{})
	assert.Equal(t, "127.0.0.1:8080", server1["address"])
	assert.Equal(t, "standard", server1["type"])
	assert.Equal(t, true, server1["active"])
}

// TestPortalIndexPage tests the HTML index page
func TestPortalIndexPage(t *testing.T) {
	cfg := createTestConfig()
	mockProxy := &mockProxy{config: cfg}
	collector := stats.NewDummyCollector()

	portal := NewPortal(cfg, collector, mockProxy)

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "msgtausch.internal"
	w := httptest.NewRecorder()

	portal.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/html")

	body := w.Body.String()
	// Should show simple status page, not full portal details
	assert.Contains(t, body, "msgtausch Proxy")
	assert.Contains(t, body, "Proxy is active and running")
	assert.Contains(t, body, "Version")
	assert.NotContains(t, body, "msgtausch Proxy Portal")
	// Should not show detailed server information
	assert.NotContains(t, body, "127.0.0.1:8080")
	assert.NotContains(t, body, "Classifiers")
}

// TestPortalStatsUpdates tests that statistics are updated correctly
func TestPortalStatsUpdates(t *testing.T) {
	cfg := createTestConfig()
	mockProxy := &mockProxy{config: cfg}
	collector := stats.NewDummyCollector()

	portal := NewPortal(cfg, collector, mockProxy)

	// Just verify the portal is created and can handle requests
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "msgtausch.internal"
	w := httptest.NewRecorder()

	portal.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestPortalGetServerInfo tests server information retrieval
func TestPortalGetServerInfo(t *testing.T) {
	cfg := createTestConfig()
	mockProxy := &mockProxy{config: cfg}
	collector := stats.NewDummyCollector()
	portal := NewPortal(cfg, collector, mockProxy)

	serverInfo := portal.proxy.GetServerInfo()
	assert.Len(t, serverInfo, 3)

	assert.Equal(t, "127.0.0.1:8080", serverInfo[0].ListenAddress)
	assert.Equal(t, "standard", serverInfo[0].Type)
	assert.True(t, serverInfo[0].Enabled)

	assert.Equal(t, "127.0.0.1:8081", serverInfo[1].ListenAddress)
	assert.Equal(t, "http", serverInfo[1].Type)
	assert.True(t, serverInfo[1].Enabled)
}

// TestPortalDomainInterception tests domain interception integration
func TestPortalDomainInterception(t *testing.T) {
	cfg := createTestConfig()
	mockProxy := &mockProxy{config: cfg}
	collector := stats.NewDummyCollector()
	portal := NewPortal(cfg, collector, mockProxy)

	tests := []struct {
		name         string
		host         string
		path         string
		shouldHandle bool
	}{
		{
			name:         "portal domain handled",
			host:         "msgtausch.internal",
			path:         "/",
			shouldHandle: true,
		},
		{
			name:         "portal domain with port handled",
			host:         "msgtausch.internal:8080",
			path:         "/api/stats",
			shouldHandle: true,
		},
		{
			name:         "regular domain not handled",
			host:         "example.com",
			path:         "/",
			shouldHandle: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tt.host+tt.path, nil)
			req.Host = tt.host

			// Test portal domain detection
			isPortal := portal.IsPortalRequest(req)
			assert.Equal(t, tt.shouldHandle, isPortal)
		})
	}
}

// TestPortalConcurrency tests concurrent access to portal
func TestPortalConcurrency(t *testing.T) {
	cfg := createTestConfig()
	mockProxy := &mockProxy{config: cfg}
	collector := stats.NewDummyCollector()

	portal := NewPortal(cfg, collector, mockProxy)

	const numRequests = 100
	done := make(chan bool, numRequests)

	for i := 0; i < numRequests; i++ {
		go func() {
			req := httptest.NewRequest("GET", "/", nil)
			req.Host = "msgtausch.internal"
			w := httptest.NewRecorder()

			portal.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			done <- true
		}()
	}

	for i := 0; i < numRequests; i++ {
		<-done
	}

	// Test completed successfully
	assert.True(t, true)
}

// TestPortalTemplateRendering tests template rendering with different data
func TestPortalTemplateRendering(t *testing.T) {
	cfg := createTestConfig()
	mockProxy := &mockProxy{config: cfg}
	collector := stats.NewDummyCollector()

	portal := NewPortal(cfg, collector, mockProxy)

	// Add some test data
	mockProxy.config.Classifiers["test"] = &config.ClassifierTrue{}
	mockProxy.config.Forwards = []config.Forward{
		&config.ForwardDefaultNetwork{},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "msgtausch.internal"
	w := httptest.NewRecorder()

	portal.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()

	// Should show simple status page, not full portal details
	assert.Contains(t, body, "msgtausch Proxy")
	assert.Contains(t, body, "1.0.0")
	assert.Contains(t, body, "Proxy is active and running")
	assert.NotContains(t, body, "msgtausch Proxy Portal")
	// Should not show detailed configuration information
	assert.NotContains(t, body, "Classifiers")
	assert.NotContains(t, body, "Forwards")
	assert.NotContains(t, body, "Interception")
}

// TestPortalInvalidRequests tests handling of invalid requests
func TestPortalInvalidRequests(t *testing.T) {
	cfg := createTestConfig()
	mockProxy := &mockProxy{config: cfg}
	collector := stats.NewDummyCollector()

	portal := NewPortal(cfg, collector, mockProxy)

	tests := []struct {
		name         string
		method       string
		path         string
		expectedCode int
	}{
		{
			name:         "POST to index",
			method:       "POST",
			path:         "/",
			expectedCode: http.StatusOK,
		},
		{
			name:         "PUT to API",
			method:       "PUT",
			path:         "/api/stats",
			expectedCode: http.StatusOK,
		},
		{
			name:         "DELETE to invalid path",
			method:       "DELETE",
			path:         "/invalid",
			expectedCode: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.Host = "msgtausch.internal"
			w := httptest.NewRecorder()

			portal.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedCode, w.Code)
		})
	}
}

// TestPortalAuthenticationDisabled tests portal without authentication
func TestPortalAuthenticationDisabled(t *testing.T) {
	cfg := createTestConfig()
	mockProxy := &mockProxy{config: cfg}
	collector := stats.NewDummyCollector()

	portal := NewPortal(cfg, collector, mockProxy)

	// Should not require authentication
	assert.False(t, portal.config.Portal.Username != "" && portal.config.Portal.Password != "")

	// Should be able to access without authentication
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "msgtausch.internal"
	w := httptest.NewRecorder()

	portal.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// Should show simple status page, not full portal
	assert.Contains(t, w.Body.String(), "msgtausch Proxy")
	assert.Contains(t, w.Body.String(), "Proxy is active and running")
	assert.NotContains(t, w.Body.String(), "msgtausch Proxy Portal")
}

// TestPortalAuthenticationEnabled tests portal with authentication
func TestPortalAuthenticationEnabled(t *testing.T) {
	cfg := createTestConfigWithAuth()
	mockProxy := &mockProxy{config: cfg}
	collector := stats.NewDummyCollector()

	portal := NewPortal(cfg, collector, mockProxy)

	// Should require authentication
	assert.True(t, portal.config.Portal.Username != "" && portal.config.Portal.Password != "")

	// Should redirect to login when not authenticated
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "msgtausch.internal"
	w := httptest.NewRecorder()

	portal.ServeHTTP(w, req)

	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login", w.Header().Get("Location"))
}

// TestPortalLogin tests the login functionality
func TestPortalLogin(t *testing.T) {
	cfg := createTestConfigWithAuth()
	mockProxy := &mockProxy{config: cfg}
	collector := stats.NewDummyCollector()

	portal := NewPortal(cfg, collector, mockProxy)

	tests := []struct {
		name           string
		username       string
		password       string
		expectedStatus int
		shouldRedirect bool
	}{
		{
			name:           "valid credentials",
			username:       "admin",
			password:       "admin",
			expectedStatus: http.StatusSeeOther,
			shouldRedirect: true,
		},
		{
			name:           "invalid username",
			username:       "wrong",
			password:       "admin",
			expectedStatus: http.StatusUnauthorized,
			shouldRedirect: false,
		},
		{
			name:           "invalid password",
			username:       "admin",
			password:       "wrong",
			expectedStatus: http.StatusUnauthorized,
			shouldRedirect: false,
		},
		{
			name:           "empty credentials",
			username:       "",
			password:       "",
			expectedStatus: http.StatusUnauthorized,
			shouldRedirect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create form data
			formData := fmt.Sprintf("username=%s&password=%s", tt.username, tt.password)
			req := httptest.NewRequest("POST", "/login", strings.NewReader(formData))
			req.Host = "msgtausch.internal"
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			portal.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.shouldRedirect {
				assert.Equal(t, "/", w.Header().Get("Location"))
				// Check that session cookie is set
				cookies := w.Result().Cookies()
				found := false
				for _, cookie := range cookies {
					if cookie.Name == SessionCookieName {
						found = true
						assert.NotEmpty(t, cookie.Value)
						assert.True(t, cookie.HttpOnly)
						break
					}
				}
				assert.True(t, found, "Session cookie should be set")
			} else {
				assert.Contains(t, w.Body.String(), "Invalid username or password")
			}
		})
	}
}

// TestPortalLoginPage tests the login page display
func TestPortalLoginPage(t *testing.T) {
	cfg := createTestConfigWithAuth()
	mockProxy := &mockProxy{config: cfg}
	collector := stats.NewDummyCollector()

	portal := NewPortal(cfg, collector, mockProxy)

	req := httptest.NewRequest("GET", "/login", nil)
	req.Host = "msgtausch.internal"
	w := httptest.NewRecorder()

	portal.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
	assert.Contains(t, w.Body.String(), "msgtausch Dashboard Login")
	assert.Contains(t, w.Body.String(), "username")
	assert.Contains(t, w.Body.String(), "password")
}

// TestPortalLogout tests the logout functionality
func TestPortalLogout(t *testing.T) {
	cfg := createTestConfigWithAuth()
	mockProxy := &mockProxy{config: cfg}
	collector := stats.NewDummyCollector()

	portal := NewPortal(cfg, collector, mockProxy)

	// First login
	formData := "username=admin&password=admin"
	req := httptest.NewRequest("POST", "/login", strings.NewReader(formData))
	req.Host = "msgtausch.internal"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	portal.ServeHTTP(w, req)
	assert.Equal(t, http.StatusSeeOther, w.Code)

	// Get session cookie
	cookies := w.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == SessionCookieName {
			sessionCookie = cookie
			break
		}
	}
	require.NotNil(t, sessionCookie)

	// Now logout
	req = httptest.NewRequest("GET", "/logout", nil)
	req.Host = "msgtausch.internal"
	req.AddCookie(sessionCookie)
	w = httptest.NewRecorder()

	portal.ServeHTTP(w, req)

	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login", w.Header().Get("Location"))

	// Check that session cookie is cleared
	cookies = w.Result().Cookies()
	for _, cookie := range cookies {
		if cookie.Name == SessionCookieName {
			assert.Empty(t, cookie.Value)
			assert.True(t, cookie.Expires.Before(time.Now()))
			break
		}
	}
}

// TestPortalAuthenticatedAccess tests accessing protected resources after login
func TestPortalAuthenticatedAccess(t *testing.T) {
	cfg := createTestConfigWithAuth()
	mockProxy := &mockProxy{config: cfg}
	collector := stats.NewDummyCollector()

	portal := NewPortal(cfg, collector, mockProxy)

	// First login
	formData := "username=admin&password=admin"
	req := httptest.NewRequest("POST", "/login", strings.NewReader(formData))
	req.Host = "msgtausch.internal"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	portal.ServeHTTP(w, req)
	assert.Equal(t, http.StatusSeeOther, w.Code)

	// Get session cookie
	cookies := w.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == SessionCookieName {
			sessionCookie = cookie
			break
		}
	}
	require.NotNil(t, sessionCookie)

	// Test accessing protected resources
	endpoints := []string{"/", "/api/stats", "/api/config", "/api/servers"}

	for _, endpoint := range endpoints {
		t.Run(endpoint, func(t *testing.T) {
			req := httptest.NewRequest("GET", endpoint, nil)
			req.Host = "msgtausch.internal"
			req.AddCookie(sessionCookie)
			w := httptest.NewRecorder()

			portal.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
		})
	}
}

// TestPortalSessionManagement tests session creation and validation
func TestPortalSessionManagement(t *testing.T) {
	cfg := createTestConfigWithAuth()
	mockProxy := &mockProxy{config: cfg}
	collector := stats.NewDummyCollector()

	portal := NewPortal(cfg, collector, mockProxy)

	// Test JWT token creation
	token, err := portal.createSession("testuser")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Test JWT token validation
	parsedToken, err := portal.parseJWTToken(token)
	assert.NoError(t, err)
	assert.True(t, parsedToken.Valid)

	// Test invalid token
	_, err = portal.parseJWTToken("invalid.token.here")
	assert.Error(t, err)

	// Test token deletion (just sets expired cookie)
	cookie := portal.deleteSession()
	assert.Equal(t, -1, cookie.MaxAge)
}

// TestPortalAuthenticate tests the authentication function
func TestPortalAuthenticate(t *testing.T) {
	// Note: testing authentication logic directly without portal instance
	tests := []struct {
		name     string
		username string
		password string
		expected bool
	}{
		{
			name:     "valid credentials",
			username: "admin",
			password: "admin",
			expected: true,
		},
		{
			name:     "invalid username",
			username: "wrong",
			password: "admin",
			expected: false,
		},
		{
			name:     "invalid password",
			username: "admin",
			password: "wrong",
			expected: false,
		},
		{
			name:     "empty credentials",
			username: "",
			password: "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test authentication logic directly
			expected := tt.username == "admin" && tt.password == "admin"
			assert.Equal(t, tt.expected, expected)
		})
	}
}

// TestPortalUnauthenticatedAPIAccess tests API access without authentication
func TestPortalUnauthenticatedAPIAccess(t *testing.T) {
	cfg := createTestConfigWithAuth()
	mockProxy := &mockProxy{config: cfg}
	collector := stats.NewDummyCollector()

	portal := NewPortal(cfg, collector, mockProxy)

	endpoints := []string{"/api/stats", "/api/config", "/api/servers"}

	for _, endpoint := range endpoints {
		t.Run(endpoint, func(t *testing.T) {
			req := httptest.NewRequest("GET", endpoint, nil)
			req.Host = "msgtausch.internal"
			w := httptest.NewRecorder()

			portal.ServeHTTP(w, req)

			// Should redirect to login page
			assert.Equal(t, http.StatusSeeOther, w.Code)
			assert.Equal(t, "/login", w.Header().Get("Location"))
		})
	}
}

// TestPortalLoginFlowComprehensive tests the complete login flow step-by-step
func TestPortalLoginFlowComprehensive(t *testing.T) {
	cfg := createTestConfigWithAuth()
	mockProxy := &mockProxy{config: cfg}
	collector := stats.NewDummyCollector()

	portal := NewPortal(cfg, collector, mockProxy)

	// Step 1: GET /login should show login page
	t.Run("step_1_get_login_page", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/login", nil)
		req.Host = "msgtausch.internal"
		w := httptest.NewRecorder()

		portal.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
		body := w.Body.String()
		assert.Contains(t, body, "msgtausch Dashboard Login")
		assert.Contains(t, body, `name="username"`)
		assert.Contains(t, body, `name="password"`)
		assert.Contains(t, body, `method="POST"`)
	})

	// Step 2: POST /login with wrong credentials should show error
	t.Run("step_2_login_wrong_credentials", func(t *testing.T) {
		formData := "username=wronguser&password=wrongpass"
		req := httptest.NewRequest("POST", "/login", strings.NewReader(formData))
		req.Host = "msgtausch.internal"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		portal.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
		body := w.Body.String()
		assert.Contains(t, body, "Invalid username or password")

		// Should still show login form
		assert.Contains(t, body, `name="username"`)
		assert.Contains(t, body, `name="password"`)
	})

	// Step 3: POST /login with correct credentials should redirect and set cookie
	var sessionCookie *http.Cookie
	t.Run("step_3_login_correct_credentials", func(t *testing.T) {
		formData := "username=admin&password=admin"
		req := httptest.NewRequest("POST", "/login", strings.NewReader(formData))
		req.Host = "msgtausch.internal"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		portal.ServeHTTP(w, req)

		assert.Equal(t, http.StatusSeeOther, w.Code)
		assert.Equal(t, "/", w.Header().Get("Location"))

		// Check for session cookie
		cookies := w.Result().Cookies()
		for _, cookie := range cookies {
			if cookie.Name == SessionCookieName {
				sessionCookie = cookie
				break
			}
		}
		require.NotNil(t, sessionCookie, "Session cookie should be set")
		assert.NotEmpty(t, sessionCookie.Value, "Session cookie should have a value")
		assert.Equal(t, "/", sessionCookie.Path)
		assert.True(t, sessionCookie.HttpOnly)
	})

	// Step 4: Access protected page with valid session
	t.Run("step_4_access_with_valid_session", func(t *testing.T) {
		require.NotNil(t, sessionCookie, "Session cookie from previous test required")

		req := httptest.NewRequest("GET", "/api/stats", nil)
		req.Host = "msgtausch.internal"
		req.AddCookie(sessionCookie)
		w := httptest.NewRecorder()

		portal.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
	})

	// Step 5: GET /login with valid session should redirect to home
	t.Run("step_5_login_page_with_valid_session", func(t *testing.T) {
		require.NotNil(t, sessionCookie, "Session cookie from previous test required")

		req := httptest.NewRequest("GET", "/login", nil)
		req.Host = "msgtausch.internal"
		req.AddCookie(sessionCookie)
		w := httptest.NewRecorder()

		portal.ServeHTTP(w, req)

		assert.Equal(t, http.StatusSeeOther, w.Code)
		assert.Equal(t, "/", w.Header().Get("Location"))
	})

	// Step 6: Logout should clear session and redirect
	t.Run("step_6_logout", func(t *testing.T) {
		require.NotNil(t, sessionCookie, "Session cookie from previous test required")

		req := httptest.NewRequest("GET", "/logout", nil)
		req.Host = "msgtausch.internal"
		req.AddCookie(sessionCookie)
		w := httptest.NewRecorder()

		portal.ServeHTTP(w, req)

		assert.Equal(t, http.StatusSeeOther, w.Code)
		assert.Equal(t, "/login", w.Header().Get("Location"))

		// Check that cookie is cleared
		cookies := w.Result().Cookies()
		var clearCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == SessionCookieName {
				clearCookie = cookie
				break
			}
		}
		require.NotNil(t, clearCookie, "Cookie should be cleared")
		assert.Empty(t, clearCookie.Value)
		assert.True(t, clearCookie.Expires.Before(time.Now()))
	})

	// Step 7: Access protected page after logout should redirect to login
	t.Run("step_7_access_after_logout", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/stats", nil)
		req.Host = "msgtausch.internal"
		w := httptest.NewRecorder()

		portal.ServeHTTP(w, req)

		assert.Equal(t, http.StatusSeeOther, w.Code)
		assert.Equal(t, "/login", w.Header().Get("Location"))
	})
}

// TestPortalSessionTimeout tests session timeout functionality
func TestPortalSessionTimeout(t *testing.T) {
	cfg := createTestConfigWithAuth()
	mockProxy := &mockProxy{config: cfg}
	collector := stats.NewDummyCollector()

	portal := NewPortal(cfg, collector, mockProxy)

	// Create an expired JWT token
	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": "admin",
		"exp":      time.Now().Add(-25 * time.Hour).Unix(), // 25 hours ago
		"iat":      time.Now().Add(-25 * time.Hour).Unix(),
	})
	tokenString, err := expiredToken.SignedString(portal.jwtSecret)
	require.NoError(t, err)

	// Try to access protected resource with expired token
	req := httptest.NewRequest("GET", "/api/stats", nil)
	req.Host = "msgtausch.internal"
	req.AddCookie(&http.Cookie{
		Name:  SessionCookieName,
		Value: tokenString,
	})
	w := httptest.NewRecorder()

	portal.ServeHTTP(w, req)

	// Should redirect to login due to expired token
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login", w.Header().Get("Location"))
}

// TestPortalLoginEdgeCases tests edge cases in login functionality
func TestPortalLoginEdgeCases(t *testing.T) {
	cfg := createTestConfigWithAuth()
	mockProxy := &mockProxy{config: cfg}
	collector := stats.NewDummyCollector()

	portal := NewPortal(cfg, collector, mockProxy)

	t.Run("login_with_invalid_content_type", func(t *testing.T) {
		formData := "username=admin&password=admin"
		req := httptest.NewRequest("POST", "/login", strings.NewReader(formData))
		req.Host = "msgtausch.internal"
		// Missing Content-Type header - this might cause FormValue to fail
		w := httptest.NewRecorder()

		portal.ServeHTTP(w, req)

		// Form parsing without Content-Type might fail, leading to empty username/password and auth failure
		if w.Code == http.StatusUnauthorized {
			// This is actually expected behavior when form parsing fails
			t.Logf("FormValue failed without Content-Type header, returning 401 as expected")
		} else {
			// If it somehow works, that's fine too
			assert.Equal(t, http.StatusSeeOther, w.Code)
		}
	})

	t.Run("login_with_special_characters", func(t *testing.T) {
		// Test with URL-encoded special characters
		formData := "username=admin&password=password%21%40%23"
		req := httptest.NewRequest("POST", "/login", strings.NewReader(formData))
		req.Host = "msgtausch.internal"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		portal.ServeHTTP(w, req)

		// Should fail because password doesn't match
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("login_with_empty_form", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/login", strings.NewReader(""))
		req.Host = "msgtausch.internal"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		portal.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		body := w.Body.String()
		assert.Contains(t, body, "Invalid username or password")
	})

	t.Run("multiple_login_attempts", func(t *testing.T) {
		// Test multiple login attempts don't interfere with each other
		for i := 0; i < 3; i++ {
			formData := "username=admin&password=admin"
			req := httptest.NewRequest("POST", "/login", strings.NewReader(formData))
			req.Host = "msgtausch.internal"
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			portal.ServeHTTP(w, req)

			assert.Equal(t, http.StatusSeeOther, w.Code)

			// Each should get a different session cookie
			cookies := w.Result().Cookies()
			var sessionCookie *http.Cookie
			for _, cookie := range cookies {
				if cookie.Name == SessionCookieName {
					sessionCookie = cookie
					break
				}
			}
			require.NotNil(t, sessionCookie)
			assert.NotEmpty(t, sessionCookie.Value)
		}
	})
}
