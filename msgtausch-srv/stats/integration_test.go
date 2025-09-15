package stats

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
)

func TestDummyCollector(t *testing.T) {
	collector := NewDummyCollector()
	defer collector.Close()

	// Test basic operations
	ctx := context.Background()

	// Test connection tracking
	connID, err := collector.StartConnection(ctx, "127.0.0.1", "example.com", 80, "http")
	if err != nil {
		t.Fatalf("StartConnection failed: %v", err)
	}

	err = collector.EndConnection(ctx, connID, 1024, 2048, time.Second, "normal")
	if err != nil {
		t.Fatalf("EndConnection failed: %v", err)
	}

	// Test HTTP request/response
	err = collector.RecordHTTPRequest(ctx, connID, "GET", "/test", "example.com", "test-agent", 0)
	if err != nil {
		t.Fatalf("RecordHTTPRequest failed: %v", err)
	}

	err = collector.RecordHTTPResponse(ctx, connID, 200, 1024)
	if err != nil {
		t.Fatalf("RecordHTTPResponse failed: %v", err)
	}

	// Test security events
	err = collector.RecordBlockedRequest(ctx, "127.0.0.1", "blocked.com", "policy")
	if err != nil {
		t.Fatalf("RecordBlockedRequest failed: %v", err)
	}

	err = collector.RecordAllowedRequest(ctx, "127.0.0.1", "allowed.com")
	if err != nil {
		t.Fatalf("RecordAllowedRequest failed: %v", err)
	}

	// Test health check
	err = collector.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("HealthCheck failed: %v", err)
	}
}

func TestSQLiteCollector(t *testing.T) {
	// Create temporary database file
	dbPath := "test_stats.db"
	defer os.Remove(dbPath)

	collector, err := NewSQLiteCollector(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite collector: %v", err)
	}
	defer collector.Close()

	testCollector(t, collector)
}

func TestBufferedCollector(t *testing.T) {
	underlying := NewDummyCollector()
	collector := NewBufferedCollectorWithInterval(underlying, 1*time.Second)
	defer collector.Close()

	testCollector(t, collector)
}

func TestFactory(t *testing.T) {
	tests := []struct {
		name    string
		config  config.StatisticsConfig
		wantErr bool
	}{
		{
			name: "disabled",
			config: config.StatisticsConfig{
				Enabled: false,
			},
		},
		{
			name: "sqlite default",
			config: config.StatisticsConfig{
				Enabled:    true,
				Backend:    "sqlite",
				SQLitePath: "msgtausch_stats" + randomSuffix() + ".db",
			},
		},
		{
			name: "postgres missing dsn",
			config: config.StatisticsConfig{
				Enabled: true,
				Backend: "postgres",
			},
			wantErr: true,
		},
		{
			name: "invalid backend",
			config: config.StatisticsConfig{
				Enabled: true,
				Backend: "invalid",
			},
			wantErr: true,
		},
	}

	factory := NewCollectorFactory()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector, err := factory.CreateCollector(&tt.config)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if collector == nil {
				t.Fatal("Expected collector but got nil")
			}

			collector.Close()
		})
	}
}

func testCollector(t *testing.T, collector Collector) {
	ctx := context.Background()

	// Test connection tracking
	connID, err := collector.StartConnection(ctx, "127.0.0.1", "example.com", 80, "http")
	if err != nil {
		t.Fatalf("StartConnection failed: %v", err)
	}

	err = collector.RecordHTTPRequest(ctx, connID, "GET", "/test", "example.com", "test-agent", 0)
	if err != nil {
		t.Fatalf("RecordHTTPRequest failed: %v", err)
	}

	err = collector.RecordHTTPResponse(ctx, connID, 200, 1024)
	if err != nil {
		t.Fatalf("RecordHTTPResponse failed: %v", err)
	}

	err = collector.RecordDataTransfer(ctx, connID, 1024, 2048)
	if err != nil {
		t.Fatalf("RecordDataTransfer failed: %v", err)
	}

	err = collector.EndConnection(ctx, connID, 1024, 2048, 2*time.Second, "normal")
	if err != nil {
		t.Fatalf("EndConnection failed: %v", err)
	}

	// Test error recording
	err = collector.RecordError(ctx, connID, "timeout", "connection timeout")
	if err != nil {
		t.Fatalf("RecordError failed: %v", err)
	}

	// Test security events
	err = collector.RecordBlockedRequest(ctx, "127.0.0.1", "malicious.com", "blocklist")
	if err != nil {
		t.Fatalf("RecordBlockedRequest failed: %v", err)
	}

	err = collector.RecordAllowedRequest(ctx, "127.0.0.1", "safe.com")
	if err != nil {
		t.Fatalf("RecordAllowedRequest failed: %v", err)
	}

	// Test health check
	err = collector.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("HealthCheck failed: %v", err)
	}
}
func BenchmarkBufferedCollector(b *testing.B) {
	underlying := NewDummyCollector()
	collector := NewBufferedCollectorWithInterval(underlying, 1*time.Second)
	defer collector.Close()

	ctx := context.Background()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		connID := int64(i)
		collector.RecordHTTPRequest(ctx, connID, "GET", "/test", "example.com", "agent", 0)
		collector.RecordHTTPResponse(ctx, connID, 200, 1024)
	}
}

// randomSuffix generates a random hex string for use in temporary filenames.
func randomSuffix() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
