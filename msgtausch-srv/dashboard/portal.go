package dashboard

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/codefionn/msgtausch/msgtausch-srv/dashboard/templates"
	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
	"github.com/codefionn/msgtausch/msgtausch-srv/stats"
	"github.com/golang-jwt/jwt/v5"
)

const (
	// PortalDomain is the default domain for the proxy portal
	PortalDomain = "msgtausch.internal"
	// SessionCookieName is the name of the authentication session cookie
	SessionCookieName = "msgtausch_portal_session"
	// SessionTimeout is the duration for which sessions are valid
	SessionTimeout = 24 * time.Hour
)

// Portal provides a web interface for the proxy with integrated dashboard
type Portal struct {
	config    *config.Config
	collector stats.Collector
	proxy     ProxyInterface
	jwtSecret []byte
	cache     *portalCache
	startTime time.Time
	version   string
	_         string // goVersion (unused)
	_         string // buildDate (unused)
	requests  int64
	_         int64 // activeReqs (unused)
}

// ProxyInterface defines the interface needed from the proxy
type ProxyInterface interface {
	GetConfig() *config.Config
	GetServerInfo() []ServerInfo
}

// ServerInfo provides information about a server
type ServerInfo struct {
	Type          string
	ListenAddress string
	Enabled       bool
}

// JWTClaims represents the claims in a JWT token
type JWTClaims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// portalCache caches dashboard data
type portalCache struct {
	lastUpdate time.Time
	_          *Data // data (unused)
}

// NewPortal creates a new portal instance
func NewPortal(config *config.Config, collector stats.Collector, proxy ProxyInterface) *Portal {
	// Generate a random JWT secret on the fly
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		// Fallback to a deterministic secret if random generation fails
		secret = fmt.Appendf(nil, "msgtausch-portal-%d", time.Now().Unix())
	}

	p := &Portal{
		config:    config,
		collector: collector,
		proxy:     proxy,
		jwtSecret: secret,
		cache:     &portalCache{lastUpdate: time.Time{}},
		startTime: time.Now(),
		version:   "1.0.0",
	}

	// Portal uses the provided stats collector directly

	logger.Info("Portal initialized with statistics: %t", config.Statistics.Enabled)
	return p
}

// IsPortalRequest checks if a request is for the portal domain
func (p *Portal) IsPortalRequest(req *http.Request) bool {
	host := req.Host
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}
	return strings.EqualFold(host, PortalDomain)
}

// ServeHTTP handles HTTP requests for the portal
func (p *Portal) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Debug("Portal request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

	// Check authentication for dashboard routes (only if authentication is configured)
	if p.requiresAuthentication() && !strings.HasPrefix(r.URL.Path, "/login") && !strings.HasPrefix(r.URL.Path, "/static") {
		if !p.isAuthenticated(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
	}

	switch {
	case r.URL.Path == "/" || r.URL.Path == "/dashboard":
		p.serveDashboard(w, r)
	case r.URL.Path == "/domains" || r.URL.Path == "/security" || r.URL.Path == "/errors" || r.URL.Path == "/bandwidth":
		p.serveDashboard(w, r)
	case r.URL.Path == "/api/dashboard":
		p.serveData(w, r)
	case r.URL.Path == "/api/dashboard/system":
		p.serveDataSystem(w, r)
	case r.URL.Path == "/api/domains":
		p.serveDomainsData(w, r)
	case r.URL.Path == "/api/security":
		p.serveSecurityData(w, r)
	case r.URL.Path == "/api/errors":
		p.serveErrorsData(w, r)
	case r.URL.Path == "/api/bandwidth":
		p.serveBandwidthData(w, r)
	case r.URL.Path == "/api/stats":
		p.serveLegacyStats(w, r)
	case r.URL.Path == "/api/config":
		p.serveConfig(w, r)
	case r.URL.Path == "/api/servers":
		p.serveServers(w, r)
	case r.URL.Path == "/login":
		p.serveLogin(w, r)
	case r.URL.Path == "/logout":
		p.serveLogout(w, r)
	default:
		http.NotFound(w, r)
	}
}

// serveDashboard serves the main dashboard page
func (p *Portal) serveDashboard(w http.ResponseWriter, r *http.Request) {
	logger.Debug("Serving dashboard to %s", r.RemoteAddr)
	if !p.config.Statistics.Enabled {
		p.serveStatus(w, r)
		return
	}
	err := templates.Dashboard("msgtausch Dashboard", p.config.Statistics.Enabled).Render(r.Context(), w)
	if err != nil {
		logger.Error("Failed to render dashboard template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// serveStatus serves a simple status page when statistics are disabled
func (p *Portal) serveStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, err := fmt.Fprintf(w, `
		<!DOCTYPE html>
		<html>
		<head>
			<title>msgtausch Proxy</title>
			<style>
				body { font-family: sans-serif; text-align: center; padding-top: 50px; }
				h1 { color: #333; }
				p { color: #666; }
				.status { color: green; }
			</style>
		</head>
		<body>
			<h1>msgtausch Proxy</h1>
			<p class="status">Proxy is active and running</p>
			<p>Version: %s</p>
			<p>Requests Served: %d</p>
			<p>Active Servers: %d / %d</p>
		</body>
		</html>
	`, p.version, p.requests, p.countActiveServers(), len(p.proxy.GetServerInfo()))
	if err != nil {
		logger.Error("Failed to write status page: %v", err)
	}
}

// serveData serves dashboard statistics as JSON
func (p *Portal) serveData(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	data, err := p.getData(ctx)
	if err != nil {
		logger.Error("Failed to query legacy stats: %v", err)
		http.Error(w, "Failed to load data", http.StatusInternalServerError)
		return
	}

	writeJSON(w, data)
}

// getData loads dashboard data using stats collector
func (p *Portal) getData(ctx context.Context) (*Data, error) {
	if p.collector == nil {
		logger.Debug("Stats collector not available, returning empty dashboard data")
		return &Data{LastUpdated: time.Now()}, nil
	}

	data := &Data{
		LastUpdated: time.Now(),
	}

	// Load overview stats
	overview, err := p.collector.GetOverviewStats(ctx)
	if err != nil {
		logger.Error("Failed to load overview stats: %v", err)
		return nil, err
	}
	data.Overview = overview

	// Load top domains
	domains, err := p.collector.GetTopDomains(ctx, 50)
	if err != nil {
		logger.Error("Failed to load top domains: %v", err)
		return nil, err
	}
	data.TopDomains = domains

	// Load security events
	events, err := p.collector.GetSecurityEvents(ctx, 100)
	if err != nil {
		logger.Error("Failed to load security events: %v", err)
		return nil, err
	}
	data.SecurityEvents = events

	// Load recent errors
	errors, err := p.collector.GetRecentErrors(ctx, 20)
	if err != nil {
		logger.Error("Failed to load recent errors: %v", err)
		return nil, err
	}
	data.RecentErrors = errors

	// Load bandwidth stats
	bandwidth, err := p.collector.GetBandwidthStats(ctx, 30)
	if err != nil {
		logger.Error("Failed to load bandwidth stats: %v", err)
		return nil, err
	}
	data.BandwidthStats = bandwidth

	// Load system stats
	systemStats, err := p.collector.GetSystemStats(ctx)
	if err != nil {
		logger.Error("Failed to load system stats: %v", err)
		return nil, err
	}
	data.SystemStats = systemStats

	// Set server stats
	data.ServerStats = &ServerStats{
		TotalServers:  len(p.proxy.GetServerInfo()),
		ActiveServers: p.countActiveServers(),
	}

	return data, nil
}

// serveDataSystem serves dashboard statistics as JSON
func (p *Portal) serveDataSystem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	data, err := p.getDataSystem(ctx)
	if err != nil {
		logger.Error("Failed to query legacy stats: %v", err)
		http.Error(w, "Failed to load data", http.StatusInternalServerError)
		return
	}

	writeJSON(w, data)
}

// getData loads dashboard data using stats collector
func (p *Portal) getDataSystem(ctx context.Context) (*stats.SystemStats, error) {
	if p.collector == nil {
		logger.Debug("Stats collector not available, returning empty dashboard data")
		return nil, fmt.Errorf("stats collector not available")
	}

	systemStats, err := p.collector.GetSystemStats(ctx)
	if err != nil {
		logger.Error("Failed to load system stats: %v", err)
		return nil, err
	}

	return systemStats, nil
}

// countActiveServers counts the number of active servers
func (p *Portal) countActiveServers() int {
	servers := p.proxy.GetServerInfo()
	count := 0
	for _, server := range servers {
		if server.Enabled {
			count++
		}
	}
	return count
}

// serveDomainsData serves domain statistics as JSON
func (p *Portal) serveDomainsData(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if p.collector == nil {
		logger.Debug("Stats collector not available, returning empty domain data")
		writeJSON(w, []DomainStats{})
		return
	}

	domains, err := p.collector.GetTopDomains(ctx, 100)
	if err != nil {
		logger.Error("Failed to get domain data: %v", err)
		http.Error(w, "Failed to load data", http.StatusInternalServerError)
		return
	}

	writeJSON(w, domains)
}

// serveSecurityData serves security events as JSON
func (p *Portal) serveSecurityData(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if p.collector == nil {
		logger.Debug("Stats collector not available, returning empty security data")
		writeJSON(w, []SecurityEvent{})
		return
	}

	events, err := p.collector.GetSecurityEvents(ctx, 200)
	if err != nil {
		logger.Error("Failed to get security data: %v", err)
		http.Error(w, "Failed to load data", http.StatusInternalServerError)
		return
	}

	writeJSON(w, events)
}

// serveErrorsData serves error statistics as JSON
func (p *Portal) serveErrorsData(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if p.collector == nil {
		logger.Debug("Stats collector not available, returning empty error data")
		writeJSON(w, []ErrorSummary{})
		return
	}

	errors, err := p.collector.GetRecentErrors(ctx, 50)
	if err != nil {
		logger.Error("Failed to get errors data: %v", err)
		http.Error(w, "Failed to load data", http.StatusInternalServerError)
		return
	}

	writeJSON(w, errors)
}

// serveBandwidthData serves bandwidth statistics as JSON
func (p *Portal) serveBandwidthData(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if p.collector == nil {
		logger.Debug("Stats collector not available, returning empty bandwidth data")
		writeJSON(w, &BandwidthStats{Daily: []DailyBandwidth{}, Total: 0})
		return
	}

	stats, err := p.collector.GetBandwidthStats(ctx, 30)
	if err != nil {
		logger.Error("Failed to get bandwidth data: %v", err)
		http.Error(w, "Failed to load data", http.StatusInternalServerError)
		return
	}

	writeJSON(w, stats)
}

// serveLegacyStats serves legacy statistics for backward compatibility
func (p *Portal) serveLegacyStats(w http.ResponseWriter, _ *http.Request) {
	p.requests++
	w.Header().Set("Content-Type", "application/json")
	stats := map[string]interface{}{
		"startTime":      p.startTime.Format(time.RFC3339),
		"uptime":         time.Since(p.startTime).Seconds(),
		"requestsServed": p.requests,
		"activeServers":  p.countActiveServers(),
		"totalServers":   len(p.proxy.GetServerInfo()),
	}
	writeJSON(w, stats)
}

// serveConfig serves the proxy configuration as JSON
func (p *Portal) serveConfig(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, map[string]interface{}{
		"serversCount":     len(p.config.Servers),
		"forwardsCount":    len(p.config.Forwards),
		"classifiersCount": len(p.config.Classifiers),
	})
}

// serveServers serves the list of servers as JSON
func (p *Portal) serveServers(w http.ResponseWriter, _ *http.Request) {
	servers := p.proxy.GetServerInfo()
	serverList := make([]map[string]interface{}, 0, len(servers))
	for _, s := range servers {
		serverList = append(serverList, map[string]interface{}{
			"type":    s.Type,
			"address": s.ListenAddress,
			"active":  s.Enabled,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, map[string]interface{}{
		"servers": serverList,
	})
}

// serveLogin serves the login page
func (p *Portal) serveLogin(w http.ResponseWriter, r *http.Request) {
	if p.isAuthenticated(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		logger.Debug("Login attempt for username: %s from %s", username, r.RemoteAddr)

		// Get credentials from portal config
		configUsername := p.config.Portal.Username
		configPassword := p.config.Portal.Password

		// Use default credentials if not configured
		if configUsername == "" {
			configUsername = "admin"
		}
		if configPassword == "" {
			configPassword = "admin"
		}

		// Constant-time comparison to prevent timing attacks
		usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(configUsername)) == 1
		passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(configPassword)) == 1

		if usernameMatch && passwordMatch {
			token, err := p.createSession(username)
			if err != nil {
				logger.Error("Failed to create JWT session token: %v", err)
				http.Error(w, "Failed to create session", http.StatusInternalServerError)
				return
			}

			http.SetCookie(w, &http.Cookie{
				Name:     SessionCookieName,
				Value:    token,
				Path:     "/",
				HttpOnly: true,
				MaxAge:   int(SessionTimeout.Seconds()),
				Secure:   false, // Set to true in production with HTTPS
				SameSite: http.SameSiteLaxMode,
			})
			logger.Info("Successful login for username: %s from %s", username, r.RemoteAddr)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		logger.Warn("Failed login attempt for username: %s from %s", username, r.RemoteAddr)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		err := templates.Login("Login - msgtausch Dashboard", "Invalid username or password").Render(r.Context(), w)
		if err != nil {
			logger.Error("Failed to render login template: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		return
	}

	err := templates.Login("Login - msgtausch Dashboard", "").Render(r.Context(), w)
	if err != nil {
		logger.Error("Failed to render login template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// serveLogout handles logout
func (p *Portal) serveLogout(w http.ResponseWriter, r *http.Request) {
	logger.Info("User logged out from %s", r.RemoteAddr)
	http.SetCookie(w, p.deleteSession())
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// requiresAuthentication checks if authentication is required (username and password are configured)
func (p *Portal) requiresAuthentication() bool {
	return p.config.Portal.Username != "" && p.config.Portal.Password != ""
}

// isAuthenticated checks if the request has a valid session
func (p *Portal) isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		if err != http.ErrNoCookie {
			logger.Debug("Cookie error: %v", err)
		}
		return false
	}

	token, err := p.parseJWTToken(cookie.Value)
	if err != nil {
		logger.Debug("JWT token validation failed: %v", err)
		return false
	}
	return token.Valid
}

// parseJWTToken parses and validates a JWT token
func (p *Portal) parseJWTToken(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			logger.Warn("Unexpected JWT signing method: %v", token.Header["alg"])
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return p.jwtSecret, nil
	})
}

// createJWTSession creates a new JWT token for the session
func (p *Portal) createJWTSession(username string) (string, error) {
	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(SessionTimeout).Unix(),
		"iat":      time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(p.jwtSecret)
	if err != nil {
		logger.Error("Failed to sign JWT token: %v", err)
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return tokenString, nil
}

// createSession creates a new session and returns the JWT token
func (p *Portal) createSession(username string) (string, error) {
	logger.Debug("Creating new session for username: %s", username)
	token, err := p.createJWTSession(username)
	if err != nil {
		logger.Error("Failed to create session for username %s: %v", username, err)
	}
	return token, err
}

// deleteSession removes a session by setting an expired JWT token
func (p *Portal) deleteSession() *http.Cookie {
	logger.Debug("Creating expired session cookie for logout")
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}
}

// Close cleans up resources
func (p *Portal) Close() error {
	// Portal now uses stats collector which is managed separately
	logger.Info("Portal resources cleaned up")
	return nil
}
