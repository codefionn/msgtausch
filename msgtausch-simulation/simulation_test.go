package msgtausch_simulation

import (
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
