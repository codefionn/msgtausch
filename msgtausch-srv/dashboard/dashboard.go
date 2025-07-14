package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/dashboard/templates"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
	"github.com/codefionn/msgtausch/msgtausch-srv/stats"
)

// writeJSON writes a JSON response with proper error handling
func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		logger.Error("Failed to encode JSON response: %v", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// Dashboard provides a web interface for viewing proxy statistics
type Dashboard struct {
	config    *config.Config
	collector stats.Collector

	mutex sync.RWMutex
	cache *cache
}

type cache struct {
	lastUpdate time.Time
	data       *Data
}

// Data represents the statistics data for the dashboard
type Data struct {
	Overview       *stats.OverviewStats      `json:"overview"`
	TopDomains     []stats.DomainStats       `json:"top_domains"`
	SecurityEvents []stats.SecurityEventInfo `json:"security_events"`
	RecentErrors   []stats.ErrorSummary      `json:"recent_errors"`
	BandwidthStats *stats.BandwidthStats     `json:"bandwidth_stats"`
	ServerStats    *ServerStats              `json:"server_stats"`
	LastUpdated    time.Time                 `json:"last_updated"`
}

// Type aliases for compatibility with existing dashboard code
type OverviewStats = stats.OverviewStats
type DomainStats = stats.DomainStats
type SecurityEvent = stats.SecurityEventInfo
type ErrorSummary = stats.ErrorSummary
type BandwidthStats = stats.BandwidthStats
type DailyBandwidth = stats.DailyBandwidth

// ServerStats provides server information
type ServerStats struct {
	TotalServers  int `json:"total_servers"`
	ActiveServers int `json:"active_servers"`
}

// NewDashboard creates a new dashboard instance
func NewDashboard(cfg *config.Config, collector stats.Collector) (*Dashboard, error) {
	d := &Dashboard{
		config:    cfg,
		collector: collector,
		cache:     &cache{lastUpdate: time.Time{}},
	}

	// Dashboard now uses the provided stats collector directly
	logger.Info("Dashboard initialized with statistics: %t", cfg.Statistics.Enabled)
	return d, nil
}

// ServeHTTP handles dashboard requests
func (d *Dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/dashboard":
		d.serveDashboard(w, r)
	case "/api/dashboard/data":
		d.serveData(w, r)
	case "/api/dashboard/domains":
		d.serveDomainsData(w, r)
	case "/api/dashboard/security":
		d.serveSecurityData(w, r)
	case "/api/dashboard/errors":
		d.serveErrorsData(w, r)
	case "/api/dashboard/bandwidth":
		d.serveBandwidthData(w, r)
	default:
		http.NotFound(w, r)
	}
}

// serveDashboard serves the main dashboard page
func (d *Dashboard) serveDashboard(w http.ResponseWriter, r *http.Request) {
	if !d.config.Statistics.Enabled {
		http.Error(w, "Statistics not enabled", http.StatusServiceUnavailable)
		return
	}

	err := templates.Dashboard("msgtausch Dashboard", d.config.Statistics.Enabled).Render(r.Context(), w)
	if err != nil {
		logger.Error("Failed to render dashboard: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// serveData serves dashboard statistics as JSON
func (d *Dashboard) serveData(w http.ResponseWriter, r *http.Request) {
	if !d.config.Statistics.Enabled {
		http.Error(w, "Statistics not enabled", http.StatusServiceUnavailable)
		return
	}

	data, err := d.getData(r.Context())
	if err != nil {
		logger.Error("Failed to get dashboard data: %v", err)
		http.Error(w, "Failed to load statistics", http.StatusInternalServerError)
		return
	}

	writeJSON(w, data)
}

// getData loads dashboard data using stats collector
func (d *Dashboard) getData(ctx context.Context) (*Data, error) {
	d.mutex.RLock()
	if d.cache.data != nil && time.Since(d.cache.lastUpdate) < 30*time.Second {
		defer d.mutex.RUnlock()
		return d.cache.data, nil
	}
	d.mutex.RUnlock()

	if d.collector == nil {
		logger.Debug("Stats collector not available, returning empty dashboard data")
		return &Data{LastUpdated: time.Now()}, nil
	}

	data := &Data{
		LastUpdated: time.Now(),
	}

	// Load overview stats
	overview, err := d.collector.GetOverviewStats(ctx)
	if err != nil {
		logger.Error("Failed to load overview stats: %v", err)
		return nil, err
	}
	data.Overview = overview

	// Load top domains
	domains, err := d.collector.GetTopDomains(ctx, 50)
	if err != nil {
		logger.Error("Failed to load top domains: %v", err)
		return nil, err
	}
	data.TopDomains = domains

	// Load security events
	events, err := d.collector.GetSecurityEvents(ctx, 20)
	if err != nil {
		logger.Error("Failed to load security events: %v", err)
		return nil, err
	}
	data.SecurityEvents = events

	// Load recent errors
	errors, err := d.collector.GetRecentErrors(ctx, 10)
	if err != nil {
		logger.Error("Failed to load recent errors: %v", err)
		return nil, err
	}
	data.RecentErrors = errors

	// Load bandwidth stats
	bandwidth, err := d.collector.GetBandwidthStats(ctx, 7)
	if err != nil {
		logger.Error("Failed to load bandwidth stats: %v", err)
		return nil, err
	}
	data.BandwidthStats = bandwidth

	// Load server stats
	data.ServerStats = &ServerStats{
		TotalServers:  len(d.config.Servers),
		ActiveServers: d.countActiveServers(),
	}

	// Update cache
	d.mutex.Lock()
	d.cache.data = data
	d.cache.lastUpdate = time.Now()
	d.mutex.Unlock()

	return data, nil
}

func (d *Dashboard) countActiveServers() int {
	count := 0
	for _, server := range d.config.Servers {
		if server.Enabled {
			count++
		}
	}
	return count
}

func (d *Dashboard) serveDomainsData(w http.ResponseWriter, r *http.Request) {
	if !d.config.Statistics.Enabled {
		http.Error(w, "Statistics not enabled", http.StatusServiceUnavailable)
		return
	}

	ctx := r.Context()
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	if d.collector == nil {
		logger.Debug("Stats collector not available, returning empty domain data")
		writeJSON(w, []DomainStats{})
		return
	}

	domains, err := d.collector.GetTopDomains(ctx, limit)
	if err != nil {
		logger.Error("Failed to get domain data: %v", err)
		http.Error(w, "Failed to load domains data", http.StatusInternalServerError)
		return
	}

	writeJSON(w, domains)
}

func (d *Dashboard) serveSecurityData(w http.ResponseWriter, r *http.Request) {
	if !d.config.Statistics.Enabled {
		http.Error(w, "Statistics not enabled", http.StatusServiceUnavailable)
		return
	}

	ctx := r.Context()
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	if d.collector == nil {
		logger.Debug("Stats collector not available, returning empty security data")
		writeJSON(w, []SecurityEvent{})
		return
	}

	events, err := d.collector.GetSecurityEvents(ctx, limit)
	if err != nil {
		logger.Error("Failed to get security data: %v", err)
		http.Error(w, "Failed to load security data", http.StatusInternalServerError)
		return
	}

	writeJSON(w, events)
}

func (d *Dashboard) serveErrorsData(w http.ResponseWriter, r *http.Request) {
	if !d.config.Statistics.Enabled {
		http.Error(w, "Statistics not enabled", http.StatusServiceUnavailable)
		return
	}

	ctx := r.Context()
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	if d.collector == nil {
		logger.Debug("Stats collector not available, returning empty error data")
		writeJSON(w, []ErrorSummary{})
		return
	}

	errors, err := d.collector.GetRecentErrors(ctx, limit)
	if err != nil {
		logger.Error("Failed to get errors data: %v", err)
		http.Error(w, "Failed to load errors data", http.StatusInternalServerError)
		return
	}

	writeJSON(w, errors)
}

func (d *Dashboard) serveBandwidthData(w http.ResponseWriter, r *http.Request) {
	if !d.config.Statistics.Enabled {
		http.Error(w, "Statistics not enabled", http.StatusServiceUnavailable)
		return
	}

	ctx := r.Context()
	daysStr := r.URL.Query().Get("days")
	days := 7
	if daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 {
			days = d
		}
	}

	if d.collector == nil {
		logger.Debug("Stats collector not available, returning empty bandwidth data")
		writeJSON(w, &BandwidthStats{Daily: []DailyBandwidth{}, Total: 0})
		return
	}

	stats, err := d.collector.GetBandwidthStats(ctx, days)
	if err != nil {
		logger.Error("Failed to get bandwidth data: %v", err)
		http.Error(w, "Failed to load bandwidth data", http.StatusInternalServerError)
		return
	}

	writeJSON(w, stats)
}

// Close cleans up resources
func (d *Dashboard) Close() error {
	// Dashboard now uses stats collector which is managed separately
	logger.Info("Dashboard resources cleaned up")
	return nil
}
