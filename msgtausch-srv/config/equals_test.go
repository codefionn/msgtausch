package config

import (
	"os"
	"testing"
)

func TestHasChanged(t *testing.T) {
	t.Run("domains file classifier: same content, different files", func(t *testing.T) {
		f1, err := os.CreateTemp(t.TempDir(), "domains1-*.txt")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		f2, err := os.CreateTemp(t.TempDir(), "domains2-*.txt")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		domains := "example.com\nfoo.org\n"
		if _, err := f1.WriteString(domains); err != nil {
			t.Fatalf("failed to write to f1: %v", err)
		}
		if _, err := f2.WriteString(domains); err != nil {
			t.Fatalf("failed to write to f2: %v", err)
		}
		f1.Close()
		f2.Close()
		cfg1 := &Config{Classifiers: map[string]Classifier{"d": &ClassifierDomainsFile{FilePath: f1.Name()}}}
		cfg2 := &Config{Classifiers: map[string]Classifier{"d": &ClassifierDomainsFile{FilePath: f2.Name()}}}
		if HasChanged(cfg1, cfg2) {
			t.Errorf("HasChanged should be false for domains file classifiers with same content")
		}
	})

	t.Run("domains file classifier: different content", func(t *testing.T) {
		f1, err := os.CreateTemp(t.TempDir(), "domains1-*.txt")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		f2, err := os.CreateTemp(t.TempDir(), "domains2-*.txt")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		if _, err := f1.WriteString("example.com\n"); err != nil {
			t.Fatalf("failed to write to f1: %v", err)
		}
		if _, err := f2.WriteString("foo.org\n"); err != nil {
			t.Fatalf("failed to write to f2: %v", err)
		}
		f1.Close()
		f2.Close()
		cfg1 := &Config{Classifiers: map[string]Classifier{"d": &ClassifierDomainsFile{FilePath: f1.Name()}}}
		cfg2 := &Config{Classifiers: map[string]Classifier{"d": &ClassifierDomainsFile{FilePath: f2.Name()}}}
		if !HasChanged(cfg1, cfg2) {
			t.Errorf("HasChanged should be true for domains file classifiers with different content")
		}
	})

	t.Run("domains file classifier: same file", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "domains-*.txt")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		domains := "example.com\nfoo.org\n"
		if _, err := f.WriteString(domains); err != nil {
			t.Fatalf("failed to write to file: %v", err)
		}
		f.Close()
		cfg1 := &Config{Classifiers: map[string]Classifier{"d": &ClassifierDomainsFile{FilePath: f.Name()}}}
		cfg2 := &Config{Classifiers: map[string]Classifier{"d": &ClassifierDomainsFile{FilePath: f.Name()}}}
		if HasChanged(cfg1, cfg2) {
			t.Errorf("HasChanged should be false for domains file classifiers with same file")
		}
	})

	t.Run("domains file classifier: both empty", func(t *testing.T) {
		f1, err := os.CreateTemp(t.TempDir(), "domains1-*.txt")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		f2, err := os.CreateTemp(t.TempDir(), "domains2-*.txt")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		f1.Close()
		f2.Close()
		cfg1 := &Config{Classifiers: map[string]Classifier{"d": &ClassifierDomainsFile{FilePath: f1.Name()}}}
		cfg2 := &Config{Classifiers: map[string]Classifier{"d": &ClassifierDomainsFile{FilePath: f2.Name()}}}
		if HasChanged(cfg1, cfg2) {
			t.Errorf("HasChanged should be false for domains file classifiers with both files empty")
		}
	})

	portClassifier1 := &ClassifierPort{Port: 8080}
	portClassifier2 := &ClassifierPort{Port: 9090}
	andClassifier := &ClassifierAnd{Classifiers: []Classifier{portClassifier1}}
	orClassifier := &ClassifierOr{Classifiers: []Classifier{portClassifier2}}
	trueClassifier := &ClassifierTrue{}
	falseClassifier := &ClassifierFalse{}

	forward1 := &ForwardDefaultNetwork{ClassifierData: portClassifier1}
	forward2 := &ForwardSocks5{Address: "socks5.example", Username: strPtr("user"), Password: strPtr("pass"), ClassifierData: trueClassifier}
	forward3 := &ForwardProxy{Address: "proxy.example", Username: nil, Password: nil, ClassifierData: falseClassifier}

	tests := []struct {
		name        string
		a, b        *Config
		wantChanged bool
	}{
		{
			"identical configs (all nil)",
			&Config{}, &Config{}, false,
		},
		{
			"different Server ListenAddress",
			&Config{Servers: []ServerConfig{{Type: ProxyTypeStandard, ListenAddress: "a", Enabled: true}}},
			&Config{Servers: []ServerConfig{{Type: ProxyTypeStandard, ListenAddress: "b", Enabled: true}}},
			true,
		},
		{
			"different TimeoutSeconds",
			&Config{TimeoutSeconds: 1}, &Config{TimeoutSeconds: 2}, true,
		},
		{
			"different MaxConcurrentConnections",
			&Config{MaxConcurrentConnections: 1}, &Config{MaxConcurrentConnections: 2}, true,
		},
		{
			"different Classifiers map",
			&Config{Classifiers: map[string]Classifier{"a": portClassifier1}},
			&Config{Classifiers: map[string]Classifier{"a": portClassifier2}},
			true,
		},
		{
			"identical Classifiers map",
			&Config{Classifiers: map[string]Classifier{"a": portClassifier1}},
			&Config{Classifiers: map[string]Classifier{"a": portClassifier1}},
			false,
		},
		{
			"different Forwards slice",
			&Config{Forwards: []Forward{forward1}},
			&Config{Forwards: []Forward{forward2}},
			true,
		},
		{
			"identical Forwards slice",
			&Config{Forwards: []Forward{forward1}},
			&Config{Forwards: []Forward{forward1}},
			false,
		},
		{
			"different Allowlist",
			&Config{Allowlist: portClassifier1},
			&Config{Allowlist: portClassifier2},
			true,
		},
		{
			"identical Allowlist",
			&Config{Allowlist: portClassifier1},
			&Config{Allowlist: portClassifier1},
			false,
		},
		{
			"different Blocklist",
			&Config{Blocklist: portClassifier1},
			&Config{Blocklist: portClassifier2},
			true,
		},
		{
			"identical Blocklist",
			&Config{Blocklist: portClassifier1},
			&Config{Blocklist: portClassifier1},
			false,
		},
		{
			"nil vs non-nil Config",
			&Config{}, nil, true,
		},
		{
			"both nil Config",
			nil, nil, false,
		},
		{
			"complex classifiers equal",
			&Config{Classifiers: map[string]Classifier{"a": andClassifier, "b": orClassifier}},
			&Config{Classifiers: map[string]Classifier{"a": andClassifier, "b": orClassifier}},
			false,
		},
		{
			"complex classifiers not equal",
			&Config{Classifiers: map[string]Classifier{"a": andClassifier, "b": orClassifier}},
			&Config{Classifiers: map[string]Classifier{"a": andClassifier, "b": portClassifier1}},
			true,
		},
		{
			"forwards with username/password equal",
			&Config{Forwards: []Forward{forward2}},
			&Config{Forwards: []Forward{forward2}},
			false,
		},
		{
			"forwards with username/password not equal",
			&Config{Forwards: []Forward{forward2}},
			&Config{Forwards: []Forward{forward3}},
			true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			changed := HasChanged(tc.a, tc.b)
			if changed != tc.wantChanged {
				t.Errorf("HasChanged() = %v, want %v", changed, tc.wantChanged)
			}
		})
	}
}

func strPtr(s string) *string { return &s }
