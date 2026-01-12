package stats

import (
	"sync"
	"time"
)

// StatisticsAccumulator provides lock-free accumulation of various statistics
type StatisticsAccumulator struct {
	// Basic counters
	connections AtomicInt64Counter
	requests    AtomicInt64Counter
	errors      AtomicInt64Counter
	bytesIn     AtomicInt64Counter
	bytesOut    AtomicInt64Counter

	// Request classification
	blockedRequests AtomicInt64Counter
	allowedRequests AtomicInt64Counter

	// Error classification
	connectionErrors AtomicInt64Counter
	httpErrors       AtomicInt64Counter
	dnsErrors        AtomicInt64Counter
	timeoutErrors    AtomicInt64Counter

	// Performance metrics
	totalLatency AtomicInt64Counter // nanoseconds
	requestCount AtomicInt64Counter // for latency averaging

	// Rate tracking (per-second counters)
	currentBytesIn  AtomicInt64Counter
	currentBytesOut AtomicInt64Counter
	currentRequests AtomicInt64Counter

	// Peak tracking
	peakConnections AtomicInt64Counter
	peakBytesPerSec AtomicInt64Counter

	// Time-based windows
	windows  map[int64]*TimeWindow
	windowMu sync.RWMutex

	// Last reset time
	lastReset time.Time
}

// TimeWindow represents statistics for a specific time window
type TimeWindow struct {
	Timestamp    time.Time
	Connections  int64
	Requests     int64
	BytesIn      int64
	BytesOut     int64
	Errors       int64
	LatencySum   int64
	LatencyCount int64
}

// LatencyStats represents latency statistics
type LatencyStats struct {
	AverageNanos int64
	MinNanos     int64
	MaxNanos     int64
	P50Nanos     int64
	P95Nanos     int64
	P99Nanos     int64
}

// AccumulatorConfig configures the statistics accumulator
type AccumulatorConfig struct {
	WindowSize   time.Duration // Default: 1 minute
	MaxWindows   int           // Default: 60 (1 hour history)
	RateWindow   time.Duration // Default: 1 second for rate calculation
	TrackLatency bool          // Default: true
	TrackPeaks   bool          // Default: true
}

// DefaultAccumulatorConfig returns a default configuration
func DefaultAccumulatorConfig() AccumulatorConfig {
	return AccumulatorConfig{
		WindowSize:   time.Minute,
		MaxWindows:   60,
		RateWindow:   time.Second,
		TrackLatency: true,
		TrackPeaks:   true,
	}
}

// NewStatisticsAccumulator creates a new statistics accumulator
func NewStatisticsAccumulator(config AccumulatorConfig) *StatisticsAccumulator {
	acc := &StatisticsAccumulator{
		windows:   make(map[int64]*TimeWindow),
		lastReset: time.Now(),
	}

	// Start background cleanup goroutine
	go acc.cleanupWindows(config.WindowSize, config.MaxWindows)

	return acc
}

// RecordConnection records a new connection
func (a *StatisticsAccumulator) RecordConnection() {
	current := a.connections.Add(1)

	// Track peak if enabled
	if current > a.peakConnections.Load() {
		a.peakConnections.Store(current)
	}
}

// RecordConnectionEnd records the end of a connection
func (a *StatisticsAccumulator) RecordConnectionEnd() {
	a.connections.Add(-1)
}

// RecordRequest records a new request
func (a *StatisticsAccumulator) RecordRequest(bytesIn, bytesOut int64) {
	a.requests.Add(1)
	a.bytesIn.Add(bytesIn)
	a.bytesOut.Add(bytesOut)

	// Update rate counters
	a.currentRequests.Add(1)
	a.currentBytesIn.Add(bytesIn)
	a.currentBytesOut.Add(bytesOut)
}

// RecordBlockedRequest records a blocked request
func (a *StatisticsAccumulator) RecordBlockedRequest() {
	a.blockedRequests.Add(1)
}

// RecordAllowedRequest records an allowed request
func (a *StatisticsAccumulator) RecordAllowedRequest() {
	a.allowedRequests.Add(1)
}

// RecordError records an error with type classification
func (a *StatisticsAccumulator) RecordError(errorType string) {
	a.errors.Add(1)

	switch errorType {
	case "connection", "connect", "network":
		a.connectionErrors.Add(1)
	case "http", "http_error", "status":
		a.httpErrors.Add(1)
	case "dns", "resolve":
		a.dnsErrors.Add(1)
	case "timeout", "deadline":
		a.timeoutErrors.Add(1)
	}
}

// RecordLatency records request latency in nanoseconds
func (a *StatisticsAccumulator) RecordLatency(nanoseconds int64) {
	a.totalLatency.Add(nanoseconds)
	a.requestCount.Add(1)
}

// GetSnapshot returns a current snapshot of all statistics
func (a *StatisticsAccumulator) GetSnapshot() StatisticsSnapshot {
	return StatisticsSnapshot{
		Connections:      a.connections.Load(),
		Requests:         a.requests.Load(),
		Errors:           a.errors.Load(),
		BytesIn:          a.bytesIn.Load(),
		BytesOut:         a.bytesOut.Load(),
		BlockedRequests:  a.blockedRequests.Load(),
		AllowedRequests:  a.allowedRequests.Load(),
		ConnectionErrors: a.connectionErrors.Load(),
		HTTPErrors:       a.httpErrors.Load(),
		DNSErrors:        a.dnsErrors.Load(),
		TimeoutErrors:    a.timeoutErrors.Load(),
		PeakConnections:  a.peakConnections.Load(),
		PeakBytesPerSec:  a.peakBytesPerSec.Load(),
		CurrentBytesIn:   a.currentBytesIn.Load(),
		CurrentBytesOut:  a.currentBytesOut.Load(),
		CurrentRequests:  a.currentRequests.Load(),
		LastReset:        a.lastReset,
	}
}

// GetLatencyStats returns latency statistics
func (a *StatisticsAccumulator) GetLatencyStats() LatencyStats {
	totalLatency := a.totalLatency.Load()
	requestCount := a.requestCount.Load()

	if requestCount == 0 {
		return LatencyStats{}
	}

	avg := totalLatency / requestCount

	return LatencyStats{
		AverageNanos: avg,
		MinNanos:     0,   // Would need histogram for min/max
		MaxNanos:     0,   // Would need histogram for min/max
		P50Nanos:     avg, // Approximation
		P95Nanos:     avg, // Would need percentile calculation
		P99Nanos:     avg, // Would need percentile calculation
	}
}

// GetRates returns current rates (per second)
func (a *StatisticsAccumulator) GetRates() RateStats {
	return RateStats{
		BytesInPerSec:  a.currentBytesIn.Load(),
		BytesOutPerSec: a.currentBytesOut.Load(),
		RequestsPerSec: a.currentRequests.Load(),
	}
}

// ResetRates resets the rate counters (should be called periodically)
func (a *StatisticsAccumulator) ResetRates() {
	// Track peak bytes per second
	currentBytes := a.currentBytesIn.Load() + a.currentBytesOut.Load()
	if currentBytes > a.peakBytesPerSec.Load() {
		a.peakBytesPerSec.Store(currentBytes)
	}

	a.currentBytesIn.Store(0)
	a.currentBytesOut.Store(0)
	a.currentRequests.Store(0)
}

// ResetAll resets all counters and returns the previous values
func (a *StatisticsAccumulator) ResetAll() StatisticsSnapshot {
	snapshot := a.GetSnapshot()

	a.connections.Store(0)
	a.requests.Store(0)
	a.errors.Store(0)
	a.bytesIn.Store(0)
	a.bytesOut.Store(0)
	a.blockedRequests.Store(0)
	a.allowedRequests.Store(0)
	a.connectionErrors.Store(0)
	a.httpErrors.Store(0)
	a.dnsErrors.Store(0)
	a.timeoutErrors.Store(0)
	a.totalLatency.Store(0)
	a.requestCount.Store(0)
	a.currentBytesIn.Store(0)
	a.currentBytesOut.Store(0)
	a.currentRequests.Store(0)

	a.lastReset = time.Now()

	return snapshot
}

// cleanupWindows removes old time windows to prevent memory leaks
func (a *StatisticsAccumulator) cleanupWindows(windowSize time.Duration, maxWindows int) {
	ticker := time.NewTicker(windowSize)
	defer ticker.Stop()

	for range ticker.C {
		a.windowMu.Lock()
		now := time.Now().Unix()

		// Remove windows older than maxWindows * windowSize
		cutoff := now - (int64(maxWindows) * int64(windowSize/time.Second))

		for timestamp := range a.windows {
			if timestamp < cutoff {
				delete(a.windows, timestamp)
			}
		}
		a.windowMu.Unlock()
	}
}

// StatisticsSnapshot represents a snapshot of accumulator statistics
type StatisticsSnapshot struct {
	Connections      int64
	Requests         int64
	Errors           int64
	BytesIn          int64
	BytesOut         int64
	BlockedRequests  int64
	AllowedRequests  int64
	ConnectionErrors int64
	HTTPErrors       int64
	DNSErrors        int64
	TimeoutErrors    int64
	PeakConnections  int64
	PeakBytesPerSec  int64
	CurrentBytesIn   int64
	CurrentBytesOut  int64
	CurrentRequests  int64
	LastReset        time.Time
}

// Add adds another snapshot to this one
func (s *StatisticsSnapshot) Add(other StatisticsSnapshot) {
	s.Connections += other.Connections
	s.Requests += other.Requests
	s.Errors += other.Errors
	s.BytesIn += other.BytesIn
	s.BytesOut += other.BytesOut
	s.BlockedRequests += other.BlockedRequests
	s.AllowedRequests += other.AllowedRequests
	s.ConnectionErrors += other.ConnectionErrors
	s.HTTPErrors += other.HTTPErrors
	s.DNSErrors += other.DNSErrors
	s.TimeoutErrors += other.TimeoutErrors

	// For peak values, take the maximum
	if other.PeakConnections > s.PeakConnections {
		s.PeakConnections = other.PeakConnections
	}
	if other.PeakBytesPerSec > s.PeakBytesPerSec {
		s.PeakBytesPerSec = other.PeakBytesPerSec
	}

	// Current rates are not additive, they represent current state
	s.CurrentBytesIn = other.CurrentBytesIn
	s.CurrentBytesOut = other.CurrentBytesOut
	s.CurrentRequests = other.CurrentRequests
}

// RateStats represents rate-based statistics
type RateStats struct {
	BytesInPerSec  int64
	BytesOutPerSec int64
	RequestsPerSec int64
}

// GetEfficiency calculates efficiency metrics
func (s *StatisticsSnapshot) GetEfficiency() EfficiencyMetrics {
	if s.Requests == 0 {
		return EfficiencyMetrics{
			SuccessRate: 0,
			ErrorRate:   0,
			BlockRate:   0,
		}
	}

	errorRate := float64(s.Errors) / float64(s.Requests)
	blockRate := float64(s.BlockedRequests) / float64(s.Requests)
	successRate := 1.0 - errorRate

	return EfficiencyMetrics{
		SuccessRate: successRate,
		ErrorRate:   errorRate,
		BlockRate:   blockRate,
	}
}

// EfficiencyMetrics represents efficiency-related metrics
type EfficiencyMetrics struct {
	SuccessRate float64
	ErrorRate   float64
	BlockRate   float64
}
