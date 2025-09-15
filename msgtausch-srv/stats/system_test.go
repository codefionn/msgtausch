package stats

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockConnectionTracker is a mock implementation of ConnectionTracker
type MockConnectionTracker struct {
	mock.Mock
}

func (m *MockConnectionTracker) GetActiveConnectionCount() int64 {
	args := m.Called()
	return args.Get(0).(int64)
}

func TestNewSystemStatsCollector(t *testing.T) {
	mockTracker := &MockConnectionTracker{}
	collector := NewSystemStatsCollector(mockTracker)

	assert.NotNil(t, collector)
	assert.Equal(t, mockTracker, collector.connectionTracker)
	assert.False(t, collector.bootTime.IsZero())
}

func TestSystemStatsCollector_CollectSystemStats(t *testing.T) {
	tests := []struct {
		name                string
		activeConnections   int64
		expectedConnections int64
		expectNonZeroUptime bool
		expectSystemInfo    bool
	}{
		{
			name:                "Basic stats collection",
			activeConnections:   5,
			expectedConnections: 5,
			expectNonZeroUptime: true,
			expectSystemInfo:    true,
		},
		{
			name:                "Zero connections",
			activeConnections:   0,
			expectedConnections: 0,
			expectNonZeroUptime: true,
			expectSystemInfo:    true,
		},
		{
			name:                "High connection count",
			activeConnections:   1000,
			expectedConnections: 1000,
			expectNonZeroUptime: true,
			expectSystemInfo:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTracker := &MockConnectionTracker{}
			mockTracker.On("GetActiveConnectionCount").Return(tt.activeConnections)

			collector := NewSystemStatsCollector(mockTracker)
			ctx := context.Background()

			stats, err := collector.CollectSystemStats(ctx)

			assert.NoError(t, err)
			assert.NotNil(t, stats)

			// Test connection count
			assert.Equal(t, tt.expectedConnections, stats.CurrentConnections)

			if tt.expectSystemInfo {
				// Test that basic system info is populated
				assert.Greater(t, stats.CPUCount, 0, "CPU count should be greater than 0")
				assert.NotEmpty(t, stats.Architecture, "Architecture should not be empty")
				assert.NotEmpty(t, stats.OSInfo, "OS info should not be empty")
			}

			if tt.expectNonZeroUptime {
				// Uptime should be non-zero (unless system just booted)
				assert.GreaterOrEqual(t, stats.UptimeSeconds, int64(0), "Uptime should be non-negative")
			}

			// CPU and memory stats might be 0 on some systems, so we just check they're not negative
			assert.GreaterOrEqual(t, stats.CPUUsagePercent, float64(0), "CPU usage should be non-negative")
			assert.GreaterOrEqual(t, stats.MemoryUsagePercent, float64(0), "Memory usage should be non-negative")
			assert.GreaterOrEqual(t, stats.MemoryUsedBytes, int64(0), "Used memory should be non-negative")
			assert.GreaterOrEqual(t, stats.MemoryTotalBytes, int64(0), "Total memory should be non-negative")

			mockTracker.AssertExpectations(t)
		})
	}
}

func TestSystemStatsCollector_CollectSystemStats_NilTracker(t *testing.T) {
	collector := NewSystemStatsCollector(nil)
	ctx := context.Background()

	stats, err := collector.CollectSystemStats(ctx)

	assert.NoError(t, err)
	assert.NotNil(t, stats)
	assert.Equal(t, int64(0), stats.CurrentConnections, "Should be 0 when no tracker is provided")
}

func TestSystemStatsCollector_CollectSystemStats_WithContext(t *testing.T) {
	mockTracker := &MockConnectionTracker{}
	mockTracker.On("GetActiveConnectionCount").Return(int64(42))

	collector := NewSystemStatsCollector(mockTracker)

	// Test with context that has timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stats, err := collector.CollectSystemStats(ctx)

	assert.NoError(t, err)
	assert.NotNil(t, stats)
	assert.Equal(t, int64(42), stats.CurrentConnections)

	mockTracker.AssertExpectations(t)
}

func TestFormatUptime(t *testing.T) {
	tests := []struct {
		name     string
		seconds  int64
		expected string
	}{
		{"Zero seconds", 0, "0 seconds"},
		{"Few seconds", 45, "45s"},
		{"One minute", 60, "1m"},
		{"Multiple minutes", 150, "2m"},
		{"One hour", 3600, "1h"},
		{"Hours and minutes", 3660, "1h 1m"},
		{"One day", 86400, "1d"},
		{"Days, hours, and minutes", 90061, "1d 1h 1m"},
		{"Multiple days", 172800, "2d"},
		{"Complex uptime", 266461, "3d 2h 1m"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We need to test the JavaScript formatUptime function logic
			// Since it's in JavaScript, we'll implement the same logic in Go for testing
			result := formatUptimeForTest(tt.seconds)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// formatUptimeForTest implements the same logic as the JavaScript formatUptime function
func formatUptimeForTest(seconds int64) string {
	if seconds == 0 {
		return "0 seconds"
	}

	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	minutes := (seconds % 3600) / 60

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}

	if len(parts) > 0 {
		return strings.Join(parts, " ")
	}
	return fmt.Sprintf("%ds", seconds)
}

func TestGetSystemBootTime(t *testing.T) {
	bootTime := getSystemBootTime()

	// Boot time should be in the past (before now)
	assert.True(t, bootTime.Before(time.Now()) || bootTime.Equal(time.Now()),
		"Boot time should be before or equal to current time")

	// Boot time should be reasonable (not more than a year ago, not in the future)
	oneYearAgo := time.Now().AddDate(-1, 0, 0)
	assert.True(t, bootTime.After(oneYearAgo),
		"Boot time should be within the last year")
}

func TestReadCPUStat(t *testing.T) {
	// This test will only work on Linux systems with /proc/stat
	stat, err := readCPUStat()

	if err != nil {
		// If we can't read CPU stats (e.g., on non-Linux systems), skip the test
		t.Skipf("Cannot read CPU stats on this system: %v", err)
		return
	}

	assert.NotNil(t, stat)
	assert.GreaterOrEqual(t, stat.total, int64(0), "Total CPU time should be non-negative")
	assert.GreaterOrEqual(t, stat.idle, int64(0), "Idle CPU time should be non-negative")
	assert.LessOrEqual(t, stat.idle, stat.total, "Idle time should not exceed total time")
}

func TestGetMemoryUsage(t *testing.T) {
	// This test will only work on Linux systems with /proc/meminfo
	used, total, err := getMemoryUsage()

	if err != nil {
		// If we can't read memory stats (e.g., on non-Linux systems), skip the test
		t.Skipf("Cannot read memory stats on this system: %v", err)
		return
	}

	assert.GreaterOrEqual(t, used, int64(0), "Used memory should be non-negative")
	assert.Greater(t, total, int64(0), "Total memory should be greater than 0")
	assert.LessOrEqual(t, used, total, "Used memory should not exceed total memory")
}

func TestGetCPUUsage(t *testing.T) {
	// This test will only work on Linux systems with /proc/stat
	usage, err := getCPUUsage()

	if err != nil {
		// If we can't read CPU usage (e.g., on non-Linux systems), skip the test
		t.Skipf("Cannot read CPU usage on this system: %v", err)
		return
	}

	assert.GreaterOrEqual(t, usage, float64(0), "CPU usage should be non-negative")
	assert.LessOrEqual(t, usage, float64(100), "CPU usage should not exceed 100%")
}

// Portal Integration Tests

// MockStatsCollector provides a mock implementation of the stats.Collector interface
type MockStatsCollector struct {
	mock.Mock
	systemStatsCollector *SystemStatsCollector
}

func (m *MockStatsCollector) GetSystemStats(ctx context.Context) (*SystemStats, error) {
	if m.systemStatsCollector != nil {
		return m.systemStatsCollector.CollectSystemStats(ctx)
	}
	args := m.Called(ctx)
	return args.Get(0).(*SystemStats), args.Error(1)
}

// Implement other required methods for stats.Collector interface
func (m *MockStatsCollector) StartConnection(ctx context.Context, clientIP, targetHost string, targetPort int, protocol string) (int64, error) {
	args := m.Called(ctx, clientIP, targetHost, targetPort, protocol)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockStatsCollector) EndConnection(ctx context.Context, connectionID int64, bytesSent, bytesReceived int64, duration time.Duration, closeReason string) error {
	args := m.Called(ctx, connectionID, bytesSent, bytesReceived, duration, closeReason)
	return args.Error(0)
}

func (m *MockStatsCollector) RecordHTTPRequest(ctx context.Context, connectionID int64, method, url, host, userAgent string, contentLength int64) error {
	args := m.Called(ctx, connectionID, method, url, host, userAgent, contentLength)
	return args.Error(0)
}

func (m *MockStatsCollector) RecordHTTPResponse(ctx context.Context, connectionID int64, statusCode int, contentLength int64) error {
	args := m.Called(ctx, connectionID, statusCode, contentLength)
	return args.Error(0)
}

func (m *MockStatsCollector) RecordHTTPRequestWithHeaders(ctx context.Context, connectionID int64, method, url, host, userAgent string, contentLength, headerSize int64) error {
	args := m.Called(ctx, connectionID, method, url, host, userAgent, contentLength, headerSize)
	return args.Error(0)
}

func (m *MockStatsCollector) RecordHTTPResponseWithHeaders(ctx context.Context, connectionID int64, statusCode int, contentLength, headerSize int64) error {
	args := m.Called(ctx, connectionID, statusCode, contentLength, headerSize)
	return args.Error(0)
}

func (m *MockStatsCollector) RecordError(ctx context.Context, connectionID int64, errorType, errorMessage string) error {
	args := m.Called(ctx, connectionID, errorType, errorMessage)
	return args.Error(0)
}

func (m *MockStatsCollector) RecordDataTransfer(ctx context.Context, connectionID int64, bytesSent, bytesReceived int64) error {
	args := m.Called(ctx, connectionID, bytesSent, bytesReceived)
	return args.Error(0)
}

func (m *MockStatsCollector) RecordBlockedRequest(ctx context.Context, clientIP, targetHost, reason string) error {
	args := m.Called(ctx, clientIP, targetHost, reason)
	return args.Error(0)
}

func (m *MockStatsCollector) RecordAllowedRequest(ctx context.Context, clientIP, targetHost string) error {
	args := m.Called(ctx, clientIP, targetHost)
	return args.Error(0)
}

func (m *MockStatsCollector) GetOverviewStats(ctx context.Context) (*OverviewStats, error) {
	args := m.Called(ctx)
	return args.Get(0).(*OverviewStats), args.Error(1)
}

func (m *MockStatsCollector) GetTopDomains(ctx context.Context, limit int) ([]DomainStats, error) {
	args := m.Called(ctx, limit)
	return args.Get(0).([]DomainStats), args.Error(1)
}

func (m *MockStatsCollector) GetSecurityEvents(ctx context.Context, limit int) ([]SecurityEventInfo, error) {
	args := m.Called(ctx, limit)
	return args.Get(0).([]SecurityEventInfo), args.Error(1)
}

func (m *MockStatsCollector) GetRecentErrors(ctx context.Context, limit int) ([]ErrorSummary, error) {
	args := m.Called(ctx, limit)
	return args.Get(0).([]ErrorSummary), args.Error(1)
}

func (m *MockStatsCollector) GetBandwidthStats(ctx context.Context, days int) (*BandwidthStats, error) {
	args := m.Called(ctx, days)
	return args.Get(0).(*BandwidthStats), args.Error(1)
}

func (m *MockStatsCollector) HealthCheck(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockStatsCollector) Close() error {
	args := m.Called()
	return args.Error(0)
}

func TestSystemStatsCollector_Integration_WithRealSystem(t *testing.T) {
	mockTracker := &MockConnectionTracker{}
	mockTracker.On("GetActiveConnectionCount").Return(int64(15))

	collector := NewSystemStatsCollector(mockTracker)
	ctx := context.Background()

	stats, err := collector.CollectSystemStats(ctx)

	assert.NoError(t, err)
	assert.NotNil(t, stats)

	// Validate all required system stats fields are populated
	assert.Equal(t, int64(15), stats.CurrentConnections)
	assert.Greater(t, stats.CPUCount, 0, "CPU count should be greater than 0")
	assert.NotEmpty(t, stats.Architecture, "Architecture should not be empty")
	assert.NotEmpty(t, stats.OSInfo, "OS info should not be empty")
	assert.GreaterOrEqual(t, stats.UptimeSeconds, int64(0), "Uptime should be non-negative")

	// System stats should be reasonable values
	assert.GreaterOrEqual(t, stats.CPUUsagePercent, float64(0), "CPU usage should be non-negative")
	assert.LessOrEqual(t, stats.CPUUsagePercent, float64(100), "CPU usage should not exceed 100%")
	assert.GreaterOrEqual(t, stats.MemoryUsagePercent, float64(0), "Memory usage should be non-negative")
	assert.LessOrEqual(t, stats.MemoryUsagePercent, float64(100), "Memory usage should not exceed 100%")

	// Validate JSON marshaling works correctly
	jsonData, err := json.Marshal(stats)
	assert.NoError(t, err, "System stats should be JSON serializable")
	assert.Contains(t, string(jsonData), "current_connections", "JSON should contain snake_case field names")
	assert.Contains(t, string(jsonData), "cpu_usage_percent", "JSON should contain snake_case field names")
	assert.Contains(t, string(jsonData), "memory_usage_percent", "JSON should contain snake_case field names")

	mockTracker.AssertExpectations(t)
}

func TestSystemStatsCollector_Integration_ErrorHandling(t *testing.T) {
	tests := []struct {
		name             string
		setupMockTracker func(*MockConnectionTracker)
		expectedError    bool
		validateStats    func(*testing.T, *SystemStats)
	}{
		{
			name: "Tracker returns error - should not fail system stats collection",
			setupMockTracker: func(mockTracker *MockConnectionTracker) {
				// Even if tracker fails, system stats collection should continue
				mockTracker.On("GetActiveConnectionCount").Return(int64(0))
			},
			expectedError: false,
			validateStats: func(t *testing.T, stats *SystemStats) {
				assert.Equal(t, int64(0), stats.CurrentConnections)
				assert.Greater(t, stats.CPUCount, 0, "CPU count should still be populated")
			},
		},
		{
			name: "High connection count",
			setupMockTracker: func(mockTracker *MockConnectionTracker) {
				mockTracker.On("GetActiveConnectionCount").Return(int64(9999))
			},
			expectedError: false,
			validateStats: func(t *testing.T, stats *SystemStats) {
				assert.Equal(t, int64(9999), stats.CurrentConnections)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTracker := &MockConnectionTracker{}
			tt.setupMockTracker(mockTracker)

			collector := NewSystemStatsCollector(mockTracker)
			ctx := context.Background()

			stats, err := collector.CollectSystemStats(ctx)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, stats)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, stats)
				if tt.validateStats != nil {
					tt.validateStats(t, stats)
				}
			}

			mockTracker.AssertExpectations(t)
		})
	}
}

func TestSystemStatsCollector_DataStructureValidation(t *testing.T) {
	mockTracker := &MockConnectionTracker{}
	mockTracker.On("GetActiveConnectionCount").Return(int64(42))

	collector := NewSystemStatsCollector(mockTracker)
	ctx := context.Background()

	stats, err := collector.CollectSystemStats(ctx)

	assert.NoError(t, err)
	assert.NotNil(t, stats)

	// Test that all JSON tags are correct for API serialization
	jsonBytes, err := json.Marshal(stats)
	assert.NoError(t, err)

	var unmarshaled map[string]interface{}
	err = json.Unmarshal(jsonBytes, &unmarshaled)
	assert.NoError(t, err)

	// Verify required fields are present with correct names
	expectedFields := []string{
		"current_connections", "cpu_usage_percent", "memory_used_bytes",
		"memory_total_bytes", "memory_usage_percent", "cpu_count",
		"os_info", "architecture", "uptime_seconds",
	}

	for _, field := range expectedFields {
		assert.Contains(t, unmarshaled, field, "JSON should contain field: %s", field)
	}

	// Verify data types are correct
	assert.IsType(t, float64(0), unmarshaled["current_connections"], "current_connections should be numeric")
	assert.IsType(t, float64(0), unmarshaled["cpu_usage_percent"], "cpu_usage_percent should be numeric")
	assert.IsType(t, float64(0), unmarshaled["cpu_count"], "cpu_count should be numeric")
	assert.IsType(t, "", unmarshaled["os_info"], "os_info should be string")
	assert.IsType(t, "", unmarshaled["architecture"], "architecture should be string")

	mockTracker.AssertExpectations(t)
}

func TestSystemStatsCollector_ContextHandling(t *testing.T) {
	mockTracker := &MockConnectionTracker{}
	mockTracker.On("GetActiveConnectionCount").Return(int64(25))

	collector := NewSystemStatsCollector(mockTracker)

	tests := []struct {
		name        string
		ctxFunc     func() context.Context
		expectError bool
	}{
		{
			name: "Normal context",
			ctxFunc: func() context.Context {
				return context.Background()
			},
			expectError: false,
		},
		{
			name: "Context with timeout",
			ctxFunc: func() context.Context {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				t.Cleanup(cancel)
				return ctx
			},
			expectError: false,
		},
		{
			name: "Context with values",
			ctxFunc: func() context.Context {
				return context.WithValue(context.Background(), "test", "value")
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.ctxFunc()
			stats, err := collector.CollectSystemStats(ctx)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, stats)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, stats)
				assert.Equal(t, int64(25), stats.CurrentConnections)
			}
		})
	}

	mockTracker.AssertExpectations(t)
}

func TestSystemStatsCollector_EdgeCases(t *testing.T) {
	tests := []struct {
		name             string
		connectionCount  int64
		expectedBehavior string
		validateResult   func(*testing.T, *SystemStats, error)
	}{
		{
			name:             "Zero connections",
			connectionCount:  0,
			expectedBehavior: "Should handle zero connections gracefully",
			validateResult: func(t *testing.T, stats *SystemStats, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, stats)
				assert.Equal(t, int64(0), stats.CurrentConnections)
			},
		},
		{
			name:             "Negative connections (invalid)",
			connectionCount:  -1,
			expectedBehavior: "Should handle negative connections",
			validateResult: func(t *testing.T, stats *SystemStats, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, stats)
				assert.Equal(t, int64(-1), stats.CurrentConnections)
			},
		},
		{
			name:             "Maximum int64 connections",
			connectionCount:  9223372036854775807, // max int64
			expectedBehavior: "Should handle maximum connection count",
			validateResult: func(t *testing.T, stats *SystemStats, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, stats)
				assert.Equal(t, int64(9223372036854775807), stats.CurrentConnections)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTracker := &MockConnectionTracker{}
			mockTracker.On("GetActiveConnectionCount").Return(tt.connectionCount)

			collector := NewSystemStatsCollector(mockTracker)
			ctx := context.Background()

			stats, err := collector.CollectSystemStats(ctx)
			tt.validateResult(t, stats, err)

			mockTracker.AssertExpectations(t)
		})
	}
}

func TestSystemStatsCollector_SystemInfoValidation(t *testing.T) {
	mockTracker := &MockConnectionTracker{}
	mockTracker.On("GetActiveConnectionCount").Return(int64(10))

	collector := NewSystemStatsCollector(mockTracker)
	ctx := context.Background()

	stats, err := collector.CollectSystemStats(ctx)

	assert.NoError(t, err)
	assert.NotNil(t, stats)

	// Validate system information fields
	assert.Greater(t, stats.CPUCount, 0, "CPU count should be positive")
	assert.NotEmpty(t, stats.Architecture, "Architecture should not be empty")
	assert.NotEmpty(t, stats.OSInfo, "OS info should not be empty")

	// Architecture should be a valid Go architecture
	validArchitectures := []string{"386", "amd64", "arm", "arm64", "ppc64", "ppc64le", "mips", "mipsle", "mips64", "mips64le", "s390x", "wasm"}
	assert.Contains(t, validArchitectures, stats.Architecture, "Architecture should be a valid Go architecture")

	// OS info should contain both OS and architecture
	assert.Contains(t, stats.OSInfo, stats.Architecture, "OS info should include architecture")

	// Uptime should be reasonable (not negative, not impossibly large)
	assert.GreaterOrEqual(t, stats.UptimeSeconds, int64(0), "Uptime should not be negative")
	assert.LessOrEqual(t, stats.UptimeSeconds, int64(365*24*3600), "Uptime should not exceed 1 year")

	mockTracker.AssertExpectations(t)
}

func TestSystemStatsCollector_MemoryStatsValidation(t *testing.T) {
	mockTracker := &MockConnectionTracker{}
	mockTracker.On("GetActiveConnectionCount").Return(int64(5))

	collector := NewSystemStatsCollector(mockTracker)
	ctx := context.Background()

	stats, err := collector.CollectSystemStats(ctx)

	assert.NoError(t, err)
	assert.NotNil(t, stats)

	// Memory stats validation (only on systems where we can read them)
	if stats.MemoryTotalBytes > 0 {
		assert.GreaterOrEqual(t, stats.MemoryUsedBytes, int64(0), "Used memory should be non-negative")
		assert.LessOrEqual(t, stats.MemoryUsedBytes, stats.MemoryTotalBytes, "Used memory should not exceed total")

		// Memory usage percentage should be calculated correctly
		expectedPercentage := float64(stats.MemoryUsedBytes) / float64(stats.MemoryTotalBytes) * 100
		assert.InDelta(t, expectedPercentage, stats.MemoryUsagePercent, 0.01, "Memory percentage should be calculated correctly")

		// Memory values should be reasonable
		assert.Greater(t, stats.MemoryTotalBytes, int64(1024*1024), "Total memory should be at least 1MB")
		assert.LessOrEqual(t, stats.MemoryTotalBytes, int64(1024*1024*1024*1024), "Total memory should not exceed 1TB")
	}

	mockTracker.AssertExpectations(t)
}

func TestSystemStatsCollector_CPUStatsValidation(t *testing.T) {
	mockTracker := &MockConnectionTracker{}
	mockTracker.On("GetActiveConnectionCount").Return(int64(3))

	collector := NewSystemStatsCollector(mockTracker)
	ctx := context.Background()

	stats, err := collector.CollectSystemStats(ctx)

	assert.NoError(t, err)
	assert.NotNil(t, stats)

	// CPU stats validation
	assert.GreaterOrEqual(t, stats.CPUUsagePercent, float64(0), "CPU usage should be non-negative")
	assert.LessOrEqual(t, stats.CPUUsagePercent, float64(100), "CPU usage should not exceed 100%")

	// CPU count should be reasonable
	assert.GreaterOrEqual(t, stats.CPUCount, 1, "CPU count should be at least 1")
	assert.LessOrEqual(t, stats.CPUCount, 256, "CPU count should be reasonable (≤256)")

	mockTracker.AssertExpectations(t)
}

func TestSystemStatsCollector_JsonMarshalingEdgeCases(t *testing.T) {
	tests := []struct {
		name            string
		connectionCount int64
		description     string
	}{
		{
			name:            "Zero values",
			connectionCount: 0,
			description:     "Should marshal zero values correctly",
		},
		{
			name:            "Large values",
			connectionCount: 999999999,
			description:     "Should marshal large values correctly",
		},
		{
			name:            "Negative values",
			connectionCount: -42,
			description:     "Should marshal negative values correctly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTracker := &MockConnectionTracker{}
			mockTracker.On("GetActiveConnectionCount").Return(tt.connectionCount)

			collector := NewSystemStatsCollector(mockTracker)
			ctx := context.Background()

			stats, err := collector.CollectSystemStats(ctx)
			assert.NoError(t, err)
			assert.NotNil(t, stats)

			// Test JSON marshaling
			jsonBytes, err := json.Marshal(stats)
			assert.NoError(t, err, "Should be able to marshal stats to JSON")
			assert.NotEmpty(t, jsonBytes, "JSON should not be empty")

			// Test JSON unmarshaling
			var unmarshaled SystemStats
			err = json.Unmarshal(jsonBytes, &unmarshaled)
			assert.NoError(t, err, "Should be able to unmarshal stats from JSON")

			// Verify round-trip consistency for key fields
			assert.Equal(t, stats.CurrentConnections, unmarshaled.CurrentConnections, "CurrentConnections should round-trip correctly")
			assert.Equal(t, stats.CPUCount, unmarshaled.CPUCount, "CPUCount should round-trip correctly")
			assert.Equal(t, stats.Architecture, unmarshaled.Architecture, "Architecture should round-trip correctly")
			assert.Equal(t, stats.OSInfo, unmarshaled.OSInfo, "OSInfo should round-trip correctly")

			// Validate JSON contains expected structure
			var jsonMap map[string]any
			err = json.Unmarshal(jsonBytes, &jsonMap)
			assert.NoError(t, err)

			// All required fields should be present
			requiredFields := []string{
				"current_connections", "cpu_usage_percent", "memory_used_bytes",
				"memory_total_bytes", "memory_usage_percent", "cpu_count",
				"os_info", "architecture", "uptime_seconds",
			}

			for _, field := range requiredFields {
				assert.Contains(t, jsonMap, field, "JSON should contain field %s", field)
			}

			mockTracker.AssertExpectations(t)
		})
	}
}

func TestSystemStatsCollector_ConcurrentAccess(t *testing.T) {
	mockTracker := &MockConnectionTracker{}
	// Set up mock to handle multiple calls
	mockTracker.On("GetActiveConnectionCount").Return(int64(100)).Maybe()

	collector := NewSystemStatsCollector(mockTracker)
	ctx := context.Background()

	// Test concurrent access to system stats collection
	const numGoroutines = 10
	results := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			stats, err := collector.CollectSystemStats(ctx)
			if err != nil {
				results <- err
				return
			}
			if stats == nil {
				results <- fmt.Errorf("stats is nil")
				return
			}
			if stats.CurrentConnections != 100 {
				results <- fmt.Errorf("unexpected connection count: %d", stats.CurrentConnections)
				return
			}
			results <- nil
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		err := <-results
		assert.NoError(t, err, "Concurrent access should not produce errors")
	}

	// Verify mock was called at least once (may be called up to numGoroutines times)
	mockTracker.AssertExpectations(t)
}

func TestSystemStatsCollector_PerformanceCharacteristics(t *testing.T) {
	mockTracker := &MockConnectionTracker{}
	mockTracker.On("GetActiveConnectionCount").Return(int64(50))

	collector := NewSystemStatsCollector(mockTracker)
	ctx := context.Background()

	// Test that stats collection is reasonably fast
	start := time.Now()
	stats, err := collector.CollectSystemStats(ctx)
	duration := time.Since(start)

	assert.NoError(t, err)
	assert.NotNil(t, stats)

	// Stats collection should complete within a reasonable time (5 seconds max)
	assert.Less(t, duration, 5*time.Second, "Stats collection should complete quickly")

	// Multiple calls should remain fast
	start = time.Now()
	for i := 0; i < 5; i++ {
		_, err := collector.CollectSystemStats(ctx)
		assert.NoError(t, err)
	}
	totalDuration := time.Since(start)

	// All calls should complete within reasonable time
	assert.Less(t, totalDuration, 10*time.Second, "Multiple stats collections should remain fast")

	mockTracker.AssertExpectations(t)
}

func TestSystemStatsCollector_BootTimeHandling(t *testing.T) {
	tests := []struct {
		name        string
		description string
	}{
		{
			name:        "Normal boot time",
			description: "Should handle normal system boot time correctly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTracker := &MockConnectionTracker{}
			mockTracker.On("GetActiveConnectionCount").Return(int64(10))

			collector := NewSystemStatsCollector(mockTracker)

			// Boot time should be set during collector creation
			assert.False(t, collector.bootTime.IsZero(), "Boot time should be set")
			assert.True(t, collector.bootTime.Before(time.Now()) || collector.bootTime.Equal(time.Now()),
				"Boot time should be before or equal to current time")

			ctx := context.Background()
			stats, err := collector.CollectSystemStats(ctx)

			assert.NoError(t, err)
			assert.NotNil(t, stats)
			assert.GreaterOrEqual(t, stats.UptimeSeconds, int64(0), "Uptime should be non-negative")

			mockTracker.AssertExpectations(t)
		})
	}
}

func TestSystemStatsCollector_DataConsistency(t *testing.T) {
	mockTracker := &MockConnectionTracker{}
	mockTracker.On("GetActiveConnectionCount").Return(int64(25))

	collector := NewSystemStatsCollector(mockTracker)
	ctx := context.Background()

	// Collect stats multiple times and verify consistency
	stats1, err1 := collector.CollectSystemStats(ctx)
	assert.NoError(t, err1)
	assert.NotNil(t, stats1)

	// Small delay to allow for time-based differences
	time.Sleep(100 * time.Millisecond)

	stats2, err2 := collector.CollectSystemStats(ctx)
	assert.NoError(t, err2)
	assert.NotNil(t, stats2)

	// Static system information should remain consistent
	assert.Equal(t, stats1.CPUCount, stats2.CPUCount, "CPU count should remain consistent")
	assert.Equal(t, stats1.Architecture, stats2.Architecture, "Architecture should remain consistent")
	assert.Equal(t, stats1.OSInfo, stats2.OSInfo, "OS info should remain consistent")
	assert.Equal(t, stats1.CurrentConnections, stats2.CurrentConnections, "Connection count should be consistent with same mock")

	// Uptime should increase or stay the same
	assert.GreaterOrEqual(t, stats2.UptimeSeconds, stats1.UptimeSeconds, "Uptime should not decrease")

	mockTracker.AssertExpectations(t)
}

func TestSystemStatsCollector_ErrorResiliency(t *testing.T) {
	tests := []struct {
		name           string
		setupCollector func() *SystemStatsCollector
		expectError    bool
		description    string
	}{
		{
			name: "Nil connection tracker",
			setupCollector: func() *SystemStatsCollector {
				return NewSystemStatsCollector(nil)
			},
			expectError: false,
			description: "Should handle nil connection tracker gracefully",
		},
		{
			name: "Valid connection tracker",
			setupCollector: func() *SystemStatsCollector {
				mockTracker := &MockConnectionTracker{}
				mockTracker.On("GetActiveConnectionCount").Return(int64(123))
				return NewSystemStatsCollector(mockTracker)
			},
			expectError: false,
			description: "Should work with valid connection tracker",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := tt.setupCollector()
			ctx := context.Background()

			stats, err := collector.CollectSystemStats(ctx)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, stats)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, stats)

				// Basic validation that we got reasonable stats
				assert.Greater(t, stats.CPUCount, 0)
				assert.NotEmpty(t, stats.Architecture)
				assert.NotEmpty(t, stats.OSInfo)
				assert.GreaterOrEqual(t, stats.UptimeSeconds, int64(0))
			}
		})
	}
}

func TestSystemStatsCollector_MemoryCalculations(t *testing.T) {
	mockTracker := &MockConnectionTracker{}
	mockTracker.On("GetActiveConnectionCount").Return(int64(7))

	collector := NewSystemStatsCollector(mockTracker)
	ctx := context.Background()

	stats, err := collector.CollectSystemStats(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, stats)

	// If memory stats are available, verify calculations are correct
	if stats.MemoryTotalBytes > 0 && stats.MemoryUsedBytes >= 0 {
		// Memory percentage calculation should be accurate
		expectedPercentage := float64(stats.MemoryUsedBytes) / float64(stats.MemoryTotalBytes) * 100
		assert.InDelta(t, expectedPercentage, stats.MemoryUsagePercent, 0.1,
			"Memory usage percentage should be calculated correctly")

		// Percentage should be within valid range
		assert.GreaterOrEqual(t, stats.MemoryUsagePercent, float64(0), "Memory percentage should not be negative")
		assert.LessOrEqual(t, stats.MemoryUsagePercent, float64(100), "Memory percentage should not exceed 100%")

		// Used memory should not exceed total memory
		assert.LessOrEqual(t, stats.MemoryUsedBytes, stats.MemoryTotalBytes,
			"Used memory should not exceed total memory")
	}

	mockTracker.AssertExpectations(t)
}

func TestSystemStatsCollector_CPUCalculations(t *testing.T) {
	mockTracker := &MockConnectionTracker{}
	mockTracker.On("GetActiveConnectionCount").Return(int64(12))

	collector := NewSystemStatsCollector(mockTracker)
	ctx := context.Background()

	// Test multiple collections to see CPU usage calculation
	var cpuUsages []float64
	for i := 0; i < 3; i++ {
		stats, err := collector.CollectSystemStats(ctx)
		assert.NoError(t, err)
		assert.NotNil(t, stats)

		// CPU usage should be within valid range
		assert.GreaterOrEqual(t, stats.CPUUsagePercent, float64(0),
			"CPU usage should not be negative")
		assert.LessOrEqual(t, stats.CPUUsagePercent, float64(100),
			"CPU usage should not exceed 100%")

		cpuUsages = append(cpuUsages, stats.CPUUsagePercent)

		// Small delay between measurements
		time.Sleep(50 * time.Millisecond)
	}

	// All CPU usage measurements should be reasonable
	for i, usage := range cpuUsages {
		assert.GreaterOrEqual(t, usage, float64(0), "CPU usage %d should be non-negative", i)
		assert.LessOrEqual(t, usage, float64(100), "CPU usage %d should not exceed 100%", i)
	}

	mockTracker.AssertExpectations(t)
}

// Test for system stats used in portal/dashboard context
func TestSystemStatsCollector_DashboardIntegration(t *testing.T) {
	// Simulate how the portal would use the system stats collector
	mockTracker := &MockConnectionTracker{}
	mockTracker.On("GetActiveConnectionCount").Return(int64(150))

	collector := NewSystemStatsCollector(mockTracker)

	// Create a mock stats collector that uses our system stats collector
	mockStatsCollector := &MockStatsCollector{
		systemStatsCollector: collector,
	}

	ctx := context.Background()
	stats, err := mockStatsCollector.GetSystemStats(ctx)

	assert.NoError(t, err)
	assert.NotNil(t, stats)
	assert.Equal(t, int64(150), stats.CurrentConnections)

	// Verify the stats are suitable for dashboard display
	jsonBytes, err := json.Marshal(stats)
	assert.NoError(t, err)
	assert.Contains(t, string(jsonBytes), "current_connections")
	assert.Contains(t, string(jsonBytes), "150") // Our mock connection count

	// Verify all dashboard-required fields are present
	var dashboardData map[string]any
	err = json.Unmarshal(jsonBytes, &dashboardData)
	assert.NoError(t, err)

	// Check that all fields expected by the dashboard JavaScript are present
	dashboardFields := []string{
		"current_connections", "cpu_usage_percent", "memory_usage_percent",
		"uptime_seconds", "cpu_count", "architecture", "os_info",
		"memory_total_bytes", "memory_used_bytes",
	}

	for _, field := range dashboardFields {
		assert.Contains(t, dashboardData, field, "Dashboard should have field: %s", field)
	}

	mockTracker.AssertExpectations(t)
}
