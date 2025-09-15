package stats

import (
	"context"
	"fmt"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
)

// CollectorFactory creates statistics collectors based on configuration
type CollectorFactory struct{}

// NewCollectorFactory creates a new collector factory
func NewCollectorFactory() *CollectorFactory {
	return &CollectorFactory{}
}

// CreateCollector creates a statistics collector based on the provided configuration
func (f *CollectorFactory) CreateCollector(cfg *config.StatisticsConfig) (Collector, error) {
	if !cfg.Enabled {
		return NewDummyCollector(), nil
	}

	var collector Collector
	var err error

	switch cfg.Backend {
	case "sqlite", "":
		sqlitePath := cfg.SQLitePath
		if sqlitePath == "" {
			sqlitePath = "msgtausch_stats.db"
		}
		collector, err = NewSQLiteCollector(sqlitePath)
	case "postgres":
		if cfg.PostgresDSN == "" {
			return nil, fmt.Errorf("postgres_dsn is required for postgres backend")
		}
		collector, err = NewPostgreSQLCollector(cfg.PostgresDSN)
	case "dummy":
		collector = NewDummyCollector()
	default:
		return nil, fmt.Errorf("unsupported stats backend: %s", cfg.Backend)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create %s collector: %w", cfg.Backend, err)
	}

	// Apply buffering if flush interval is specified
	flushInterval := time.Duration(cfg.FlushInterval) * time.Second
	if flushInterval <= 0 {
		flushInterval = 5 * time.Second
	}

	// Always use buffered collector for better performance
	return NewBufferedCollectorWithInterval(collector, flushInterval), nil
}

// CreateCollectorFromConfig creates a collector from the main configuration
func (f *CollectorFactory) CreateCollectorFromConfig(cfg *config.Config) (Collector, error) {
	return f.CreateCollector(&cfg.Statistics)
}

// MustCreateCollector creates a collector and panics on error
func (f *CollectorFactory) MustCreateCollector(cfg *config.StatisticsConfig) Collector {
	collector, err := f.CreateCollector(cfg)
	if err != nil {
		panic(fmt.Sprintf("failed to create stats collector: %v", err))
	}
	return collector
}

// HealthChecker provides health check functionality for collectors
type HealthChecker struct {
	collector Collector
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(collector Collector) *HealthChecker {
	return &HealthChecker{collector: collector}
}

// Check performs a health check on the collector
func (h *HealthChecker) Check(ctx context.Context) error {
	if h.collector == nil {
		return fmt.Errorf("no collector configured")
	}
	return h.collector.HealthCheck(ctx)
}

// Close safely closes the collector
func (h *HealthChecker) Close() error {
	if h.collector != nil {
		return h.collector.Close()
	}
	return nil
}
