package dashboard

import (
	"encoding/json"
	"net/http"
	"time"

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

// Data represents the statistics data for the dashboard
type Data struct {
	Overview       *stats.OverviewStats      `json:"overview"`
	TopDomains     []stats.DomainStats       `json:"top_domains"`
	SecurityEvents []stats.SecurityEventInfo `json:"security_events"`
	RecentErrors   []stats.ErrorSummary      `json:"recent_errors"`
	BandwidthStats *stats.BandwidthStats     `json:"bandwidth_stats"`
	ServerStats    *ServerStats              `json:"server_stats"`
	SystemStats    *stats.SystemStats        `json:"system_stats"`
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
