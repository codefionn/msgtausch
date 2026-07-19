package msgtausch_simulation

import (
	"net/http"
	"sync"
	"testing"
)

func TestRandomSimulationTestCase(t *testing.T) {
	seeds := []int64{1, 42, 2025, 99999}
	for _, seed := range seeds {
		tc1 := RandomSimulationTestCase(seed)
		tc2 := RandomSimulationTestCase(seed)
		if tc1 != tc2 {
			t.Errorf("RandomSimulationTestCase not deterministic for seed %d: got %+v vs %+v", seed, tc1, tc2)
		}
		if tc1.Seed == 0 {
			t.Errorf("Seed should not be zero: %d", tc1.Seed)
		}
		// AllowTimeout should be a valid boolean (no range check needed)
	}
}

func TestCreateRandomSocks5Proxies(t *testing.T) {
	proxies := CreateRandomSocks5Proxies(3)
	if len(proxies) == 0 {
		t.Error("Expected at least one SOCKS5 proxy")
	}
	for _, p := range proxies {
		if p.Listener == nil {
			t.Error("SOCKS5 proxy has nil listener")
		}
		if p.Server == nil {
			t.Error("SOCKS5 proxy has nil server")
		}
		p.Listener.Close()
	}
}

func TestCreateRandomMsgtauschProxies(t *testing.T) {
	proxies := CreateRandomMsgtauschProxies(3)
	if len(proxies) == 0 {
		t.Error("Expected at least one msgtausch proxy")
	}
	for _, p := range proxies {
		if p.Listener == nil {
			t.Error("msgtausch proxy has nil listener")
		}
		if p.Proxy == nil {
			t.Error("msgtausch proxy has nil Proxy field")
		}
		if p.Config == nil {
			t.Error("msgtausch proxy has nil Config field")
		}
		p.Listener.Close()
	}
}

func TestRunSimulation_Smoke(t *testing.T) {
	seeds := []int64{789, 1748188811585837387, 12345, 1752168433430179533}
	for _, seed := range seeds {
		err := RunSimulation(seed, false)
		if err != nil {
			t.Errorf("RunSimulation failed with seed %d: %v", seed, err)
		}
	}
}

func TestRunSimulationFeatureCoverage(t *testing.T) {
	t.Setenv("SIM_TLS_ENABLE", "0")

	stats, err := RunSimulationWithStats(789, false)
	if err != nil {
		t.Fatalf("RunSimulationWithStats failed: %v", err)
	}

	for _, method := range []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodHead,
		http.MethodOptions,
	} {
		if stats.HTTPMethodCounts[method] == 0 {
			t.Errorf("HTTP method %s was not exercised", method)
		}
	}
	if stats.ValidatedHTTPResponses < 7 {
		t.Errorf("expected at least 7 validated HTTP responses, got %d", stats.ValidatedHTTPResponses)
	}
	if stats.WebSocketConnections == 0 {
		t.Error("expected at least one WebSocket connection")
	}
	if stats.WebSocketMessages != stats.WebSocketConnections*2 {
		t.Errorf("expected two validated messages per WebSocket, got %d messages over %d connections", stats.WebSocketMessages, stats.WebSocketConnections)
	}

	var protocolRequests int
	for _, count := range stats.ProtocolCounts {
		protocolRequests += count
	}
	if protocolRequests != stats.TotalRequests {
		t.Errorf("protocol counts total %d, want %d", protocolRequests, stats.TotalRequests)
	}
}

func TestRunSimulationForwardAndTLSCoverage(t *testing.T) {
	t.Setenv("SIM_TLS_ENABLE", "1")
	t.Setenv("SIM_TLS_PROBABILITY", "1")
	t.Setenv("SIM_TLS_CA_CERT_PEM", "")
	t.Setenv("SIM_TLS_SERVER_CERT_PEM", "")
	t.Setenv("SIM_TLS_SERVER_KEY_PEM", "")

	stats, err := RunSimulationWithStats(789, true)
	if err != nil {
		t.Fatalf("RunSimulationWithStats failed: %v", err)
	}
	if stats.ConfiguredForwards == 0 {
		t.Fatal("expected forwards to be configured")
	}
	if stats.ForwardsUsed != stats.ConfiguredForwards {
		t.Errorf("used %d of %d configured forwards", stats.ForwardsUsed, stats.ConfiguredForwards)
	}
	if stats.ForwardedRequests == 0 {
		t.Error("expected forwarded requests")
	}
	if stats.ForwardConnections["socks5"] == 0 {
		t.Error("expected SOCKS5 forward connections")
	}
	if stats.ForwardConnections["http-proxy"] == 0 {
		t.Error("expected HTTP proxy forward connections")
	}
	if stats.ProtocolCounts["http"] != 0 || stats.ProtocolCounts["ws"] != 0 {
		t.Errorf("expected all traffic to use TLS, got protocol counts %#v", stats.ProtocolCounts)
	}
	if stats.ProtocolCounts["https"]+stats.ProtocolCounts["wss"] != stats.TotalRequests {
		t.Errorf("TLS protocol counts do not cover all requests: %#v", stats.ProtocolCounts)
	}
}

func TestRunSimulationWithStatsConcurrent(t *testing.T) {
	t.Setenv("SIM_TLS_ENABLE", "0")

	seeds := []int64{101, 202, 303}
	type result struct {
		seed  int64
		stats *SimulationStats
		err   error
	}
	results := make(chan result, len(seeds))
	var wg sync.WaitGroup
	for _, seed := range seeds {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			stats, err := RunSimulationWithStats(seed, false)
			results <- result{seed: seed, stats: stats, err: err}
		}(seed)
	}
	wg.Wait()
	close(results)

	for result := range results {
		if result.err != nil {
			t.Errorf("seed %d failed: %v", result.seed, result.err)
			continue
		}
		if result.stats.Seed != result.seed {
			t.Errorf("seed %d received stats for seed %d", result.seed, result.stats.Seed)
		}
	}
}
