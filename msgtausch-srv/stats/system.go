package stats

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
)

// SystemStatsCollector collects system information and current connection data
type SystemStatsCollector struct {
	connectionTracker ConnectionTracker
	bootTime          time.Time
}

// ConnectionTracker interface to get current connection count
type ConnectionTracker interface {
	GetActiveConnectionCount() int64
}

// NewSystemStatsCollector creates a new system stats collector
func NewSystemStatsCollector(tracker ConnectionTracker) *SystemStatsCollector {
	bootTime := getSystemBootTime()
	return &SystemStatsCollector{
		connectionTracker: tracker,
		bootTime:          bootTime,
	}
}

// CollectSystemStats collects current system statistics
func (s *SystemStatsCollector) CollectSystemStats(ctx context.Context) (*SystemStats, error) {
	stats := &SystemStats{
		CPUCount:     runtime.NumCPU(),
		Architecture: runtime.GOARCH,
		OSInfo:       fmt.Sprintf("%s %s", runtime.GOOS, runtime.GOARCH),
	}

	if s.connectionTracker != nil {
		stats.CurrentConnections = s.connectionTracker.GetActiveConnectionCount()
	}

	// Get memory usage
	memUsed, memTotal, err := getMemoryUsage()
	if err != nil {
		logger.Debug("Failed to get memory usage: %v", err)
	} else {
		stats.MemoryUsedBytes = memUsed
		stats.MemoryTotalBytes = memTotal
		if memTotal > 0 {
			stats.MemoryUsagePercent = float64(memUsed) / float64(memTotal) * 100
		}
	}

	// Get CPU usage (simplified version)
	cpuUsage, err := getCPUUsage()
	if err != nil {
		logger.Debug("Failed to get CPU usage: %v", err)
	} else {
		stats.CPUUsagePercent = cpuUsage
	}

	// Calculate uptime
	if !s.bootTime.IsZero() {
		stats.UptimeSeconds = int64(time.Since(s.bootTime).Seconds())
	}

	return stats, nil
}

// getMemoryUsage reads memory information from /proc/meminfo (Linux)
func getMemoryUsage() (used, total int64, err error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	var memTotal, memFree, buffers, cached int64

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		key := strings.TrimSuffix(fields[0], ":")
		value, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}

		// Convert from KB to bytes
		value *= 1024

		switch key {
		case "MemTotal":
			memTotal = value
		case "MemFree":
			memFree = value
		case "Buffers":
			buffers = value
		case "Cached":
			cached = value
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}

	used = memTotal - memFree - buffers - cached
	return used, memTotal, nil
}

// getCPUUsage provides a simplified CPU usage calculation
func getCPUUsage() (float64, error) {
	// Read /proc/stat twice with a small interval to calculate CPU usage
	stat1, err := readCPUStat()
	if err != nil {
		return 0, err
	}

	time.Sleep(100 * time.Millisecond)

	stat2, err := readCPUStat()
	if err != nil {
		return 0, err
	}

	// Calculate CPU usage percentage
	totalDiff := stat2.total - stat1.total
	idleDiff := stat2.idle - stat1.idle

	if totalDiff == 0 {
		return 0, nil
	}

	usage := float64(totalDiff-idleDiff) / float64(totalDiff) * 100
	return usage, nil
}

type cpuStat struct {
	total int64
	idle  int64
}

// readCPUStat reads CPU statistics from /proc/stat
func readCPUStat() (*cpuStat, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return nil, fmt.Errorf("failed to read /proc/stat")
	}

	line := scanner.Text()
	fields := strings.Fields(line)
	if len(fields) < 8 || fields[0] != "cpu" {
		return nil, fmt.Errorf("invalid /proc/stat format")
	}

	var values []int64
	for i := 1; i < len(fields) && i < 8; i++ {
		val, err := strconv.ParseInt(fields[i], 10, 64)
		if err != nil {
			return nil, err
		}
		values = append(values, val)
	}

	if len(values) < 4 {
		return nil, fmt.Errorf("insufficient CPU stat values")
	}

	var total int64
	for _, v := range values {
		total += v
	}

	return &cpuStat{
		total: total,
		idle:  values[3], // idle time is the 4th field
	}, nil
}

// getSystemBootTime tries to determine system boot time
func getSystemBootTime() time.Time {
	// Try to read from /proc/uptime
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		uptimeStr := strings.Fields(string(data))[0]
		if uptime, err := strconv.ParseFloat(uptimeStr, 64); err == nil {
			return time.Now().Add(-time.Duration(uptime * float64(time.Second)))
		}
	}

	// Fallback: assume boot time is current time (not accurate but better than zero)
	return time.Now()
}
