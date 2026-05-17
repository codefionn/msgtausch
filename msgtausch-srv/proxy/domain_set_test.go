package proxy

import "testing"

func TestDomainSetMatch(t *testing.T) {
	ds := NewDomainSet([]string{
		"example.com",
		".ads.net",     // leading dot tolerated
		"*.tracker.io", // wildcard prefix tolerated
		"Foo.COM",      // case-insensitive
	})

	cases := []struct {
		host string
		want bool
	}{
		{"example.com", true},           // exact
		{"ads.example.com", true},       // subdomain
		{"a.b.c.example.com", true},     // deep subdomain
		{"EXAMPLE.COM", true},           // case-insensitive host
		{"ads.net", true},               // leading-dot entry, exact
		{"x.ads.net", true},             // leading-dot entry, subdomain
		{"deep.tracker.io", true},       // wildcard entry, subdomain
		{"tracker.io", true},            // wildcard entry, apex
		{"foo.com", true},               // case-insensitive entry
		{"notexample.com", false},       // not a label boundary
		{"example.com.evil.net", false}, // suffix-substring, not parent
		{"badexample.com", false},       // not a subdomain
		{"com", false},                  // parent of nothing listed
		{"", false},
	}
	for _, c := range cases {
		if got := ds.Match(c.host); got != c.want {
			t.Errorf("Match(%q) = %v, want %v", c.host, got, c.want)
		}
	}

	if ds.Len() != 4 {
		t.Errorf("Len() = %d, want 4", ds.Len())
	}
	var nilSet *DomainSet
	if nilSet.Match("anything") {
		t.Error("nil DomainSet should not match")
	}
}
