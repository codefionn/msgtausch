package stats

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"
)

// BenchmarkTrackedConn compares atomic vs original tracked connection operations
func BenchmarkTrackedConn(b *testing.B) {
	ctx := context.Background()
	collector := NewAtomicTestCollector()
	defer collector.Close()

	b.Run("Atomic_ConnectionOperations", func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				connID, _ := collector.StartConnection(ctx, "127.0.0.1", "example.com", 80, "http")
				collector.RecordDataTransfer(ctx, connID, 1024, 2048)
				collector.EndConnection(ctx, connID, 1024, 2048, 100*time.Millisecond, "normal")
			}
		})
	})
}

// BenchmarkAtomicCounters benchmarks atomic counter operations
func BenchmarkAtomicCounters(b *testing.B) {
	b.Run("Atomic_Add", func(b *testing.B) {
		var counter AtomicInt64Counter
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				counter.Add(1)
			}
		})
	})

	b.Run("Atomic_Load", func(b *testing.B) {
		var counter AtomicInt64Counter
		counter.Store(42)
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_ = counter.Load()
			}
		})
	})

	b.Run("Atomic_AddLoad", func(b *testing.B) {
		var counter AtomicInt64Counter
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				newVal := counter.Add(1)
				_ = newVal
			}
		})
	})
}

// BenchmarkCollectorOperations benchmarks collector operations with different implementations
func BenchmarkCollectorOperations(b *testing.B) {
	ctx := context.Background()

	// Test different collector types
	collectors := map[string]Collector{
		"AtomicTestCollector": NewAtomicTestCollector(),
	}

	for name, collector := range collectors {
		b.Run(name+"_StartConnection", func(b *testing.B) {
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					collector.StartConnection(ctx, "127.0.0.1", "example.com", 80, "http")
				}
			})
		})

		b.Run(name+"_RecordHTTPRequest", func(b *testing.B) {
			connID, _ := collector.StartConnection(ctx, "127.0.0.1", "example.com", 80, "http")
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					collector.RecordHTTPRequest(ctx, connID, "GET", "http://example.com/", "example.com", "test", 1024)
				}
			})
		})

		b.Run(name+"_RecordDataTransfer", func(b *testing.B) {
			connID, _ := collector.StartConnection(ctx, "127.0.0.1", "example.com", 80, "http")
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					collector.RecordDataTransfer(ctx, connID, 1024, 2048)
				}
			})
		})

		b.Run(name+"_MixedOperations", func(b *testing.B) {
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					switch i % 4 {
					case 0:
						collector.StartConnection(ctx, "127.0.0.1", "example.com", 80, "http")
					case 1:
						collector.RecordHTTPRequest(ctx, 1, "GET", "http://example.com/", "example.com", "test", 1024)
					case 2:
						collector.RecordHTTPResponse(ctx, 1, 200, 2048)
					case 3:
						collector.EndConnection(ctx, 1, 1024, 2048, 100*time.Millisecond, "normal")
					}
					i++
				}
			})
		})
	}
}

// BenchmarkConcurrentAccess benchmarks concurrent access patterns
func BenchmarkConcurrentAccess(b *testing.B) {
	const numGoroutines = 100
	const operationsPerGoroutine = 1000

	collector := NewAtomicTestCollector()
	defer collector.Close()

	ctx := context.Background()

	b.ResetTimer()

	var wg sync.WaitGroup
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			for j := 0; j < operationsPerGoroutine; j++ {
				// Start connection
				connID, err := collector.StartConnection(ctx, "127.0.0.1", "example.com", 80, "http")
				if err != nil {
					continue
				}

				// Record HTTP request/response
				collector.RecordHTTPRequest(ctx, connID, "GET", "http://example.com/", "example.com", "test", 1024)
				collector.RecordHTTPResponse(ctx, connID, 200, 2048)

				// Record data transfers
				collector.RecordDataTransfer(ctx, connID, 512, 1024)

				// End connection
				collector.EndConnection(ctx, connID, 1024, 2048, 50*time.Millisecond, "normal")
			}
		}(i)
	}

	wg.Wait()
}

// BenchmarkMemoryUsage benchmarks memory allocation patterns
func BenchmarkMemoryUsage(b *testing.B) {
	collector := NewAtomicTestCollector()
	defer collector.Close()

	ctx := context.Background()

	b.Run("With_GC", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			connID, _ := collector.StartConnection(ctx, "127.0.0.1", "example.com", 80, "http")
			collector.RecordHTTPRequest(ctx, connID, "GET", "http://example.com/", "example.com", "test", 1024)
			collector.RecordHTTPResponse(ctx, connID, 200, 2048)
			collector.EndConnection(ctx, connID, 1024, 2048, 50*time.Millisecond, "normal")

			// Force GC periodically to measure allocation impact
			if i%1000 == 0 {
				runtime.GC()
			}
		}
	})

	b.Run("Without_GC", func(b *testing.B) {
		runtime.GC() // Clean start
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			connID, _ := collector.StartConnection(ctx, "127.0.0.1", "example.com", 80, "http")
			collector.RecordHTTPRequest(ctx, connID, "GET", "http://example.com/", "example.com", "test", 1024)
			collector.RecordHTTPResponse(ctx, connID, 200, 2048)
			collector.EndConnection(ctx, connID, 1024, 2048, 50*time.Millisecond, "normal")
		}
	})
}

// BenchmarkAtomicVsMutex compares atomic vs mutex performance
func BenchmarkAtomicVsMutex(b *testing.B) {
	const numGoroutines = 50

	b.Run("Atomic_Counter", func(b *testing.B) {
		var counter AtomicInt64Counter
		b.ResetTimer()

		var wg sync.WaitGroup
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < b.N/numGoroutines; j++ {
					counter.Add(1)
				}
			}()
		}
		wg.Wait()
	})

	b.Run("Mutex_Counter", func(b *testing.B) {
		var counter int64
		var mu sync.Mutex
		b.ResetTimer()

		var wg sync.WaitGroup
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < b.N/numGoroutines; j++ {
					mu.Lock()
					counter++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
	})
}

// TestAtomicCounterCorrectness verifies atomic counter correctness
func TestAtomicCounterCorrectness(t *testing.T) {
	const numGoroutines = 100
	const incrementsPerGoroutine = 1000

	var counter AtomicInt64Counter
	var wg sync.WaitGroup

	// Increment from multiple goroutines
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < incrementsPerGoroutine; j++ {
				counter.Add(1)
			}
		}()
	}

	wg.Wait()

	expected := int64(numGoroutines * incrementsPerGoroutine)
	actual := counter.Load()

	if actual != expected {
		t.Errorf("Expected counter value %d, got %d", expected, actual)
	}

	t.Logf("Final counter value: %d (expected: %d)", actual, expected)
}

// TestAtomicTestCollectorCorrectness verifies the atomic test collector correctness
func TestAtomicTestCollectorCorrectness(t *testing.T) {
	collector := NewAtomicTestCollector()
	defer collector.Close()

	ctx := context.Background()

	// Test connection lifecycle
	connID, err := collector.StartConnection(ctx, "127.0.0.1", "example.com", 80, "http")
	if err != nil {
		t.Fatalf("StartConnection failed: %v", err)
	}

	// Record some data
	err = collector.RecordHTTPRequest(ctx, connID, "GET", "http://example.com/", "example.com", "test", 1024)
	if err != nil {
		t.Fatalf("RecordHTTPRequest failed: %v", err)
	}

	err = collector.RecordHTTPResponse(ctx, connID, 200, 2048)
	if err != nil {
		t.Fatalf("RecordHTTPResponse failed: %v", err)
	}

	err = collector.RecordDataTransfer(ctx, connID, 1024, 2048)
	if err != nil {
		t.Fatalf("RecordDataTransfer failed: %v", err)
	}

	err = collector.EndConnection(ctx, connID, 1024, 2048, 100*time.Millisecond, "normal")
	if err != nil {
		t.Fatalf("EndConnection failed: %v", err)
	}

	// Verify statistics
	stats, err := collector.GetOverviewStats(ctx)
	if err != nil {
		t.Fatalf("GetOverviewStats failed: %v", err)
	}

	if stats.TotalConnections != 1 {
		t.Errorf("Expected 1 total connection, got %d", stats.TotalConnections)
	}

	if stats.TotalRequests != 1 {
		t.Errorf("Expected 1 total request, got %d", stats.TotalRequests)
	}

	// Note: Bytes in include request content + data transfer bytes received
	// Bytes out include response content + data transfer bytes sent
	if stats.TotalBytesIn < 1024 {
		t.Errorf("Expected at least 1024 bytes in, got %d", stats.TotalBytesIn)
	}

	if stats.TotalBytesOut < 2048 {
		t.Errorf("Expected at least 2048 bytes out, got %d", stats.TotalBytesOut)
	}

	t.Logf("Statistics: %+v", stats)
}

// TestConcurrentAtomicOperations tests concurrent atomic operations
func TestConcurrentAtomicOperations(t *testing.T) {
	const numGoroutines = 50
	const operationsPerGoroutine = 100

	collector := NewAtomicTestCollector()
	defer collector.Close()

	ctx := context.Background()

	var wg sync.WaitGroup

	// Concurrent operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			for j := 0; j < operationsPerGoroutine; j++ {
				// Start connection
				connID, err := collector.StartConnection(ctx, "127.0.0.1", "example.com", 80, "http")
				if err != nil {
					continue
				}

				// Record request/response
				collector.RecordHTTPRequest(ctx, connID, "GET", "http://example.com/", "example.com", "test", 100)
				collector.RecordHTTPResponse(ctx, connID, 200, 200)

				// End connection
				collector.EndConnection(ctx, connID, 100, 200, 10*time.Millisecond, "normal")
			}
		}(i)
	}

	wg.Wait()

	// Verify final state
	snapshot := collector.GetAtomicSnapshot()
	expectedConnections := int64(numGoroutines * operationsPerGoroutine)
	expectedRequests := int64(numGoroutines * operationsPerGoroutine)
	// Bytes in: HTTP request (100) + data transfer received (200) = 300 per operation
	// Bytes out: HTTP response (200) + data transfer sent (100) = 300 per operation
	expectedBytesIn := int64(numGoroutines * operationsPerGoroutine * 300)
	expectedBytesOut := int64(numGoroutines * operationsPerGoroutine * 300)

	if snapshot.TotalConnections != expectedConnections {
		t.Errorf("Expected %d total connections, got %d", expectedConnections, snapshot.TotalConnections)
	}

	if snapshot.TotalRequests != expectedRequests {
		t.Errorf("Expected %d total requests, got %d", expectedRequests, snapshot.TotalRequests)
	}

	if snapshot.TotalBytesIn != expectedBytesIn {
		t.Errorf("Expected %d total bytes in, got %d", expectedBytesIn, snapshot.TotalBytesIn)
	}

	if snapshot.TotalBytesOut != expectedBytesOut {
		t.Errorf("Expected %d total bytes out, got %d", expectedBytesOut, snapshot.TotalBytesOut)
	}

	t.Logf("Final snapshot: TotalConnections=%d, TotalRequests=%d, TotalBytesIn=%d, TotalBytesOut=%d",
		snapshot.TotalConnections, snapshot.TotalRequests, snapshot.TotalBytesIn, snapshot.TotalBytesOut)
}
