package proxy

import "strings"

// DomainSet is a memory-efficient matcher for domain blocklists.
//
// It replaces the Aho-Corasick / chunked-AC tries previously used for
// domains-url classifiers. Those built a double-array trie whose Build()
// allocated multiple GiB for lists of ~100k+ domains (confirmed via heap
// profiling: 99.7% of process heap). Domain blocklist matching only needs
// "is the host, or any parent domain of the host, present in the list?",
// which is an O(labels) hashset lookup with O(domains) memory — a few tens
// of MiB instead of several GiB for the same list.
type DomainSet struct {
	m map[string]struct{}
}

// NewDomainSet builds a DomainSet from a list of domains. Entries are
// lowercased and leading dots stripped so matching is case-insensitive and
// tolerant of ".example.com" style entries.
func NewDomainSet(domains []string) *DomainSet {
	m := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		d = strings.TrimPrefix(d, "*.")
		d = strings.Trim(d, ".")
		if d == "" {
			continue
		}
		m[d] = struct{}{}
	}
	return &DomainSet{m: m}
}

// Len returns the number of unique domains in the set.
func (d *DomainSet) Len() int { return len(d.m) }

// Match reports whether host exactly equals a listed domain or is a subdomain
// of one (i.e. host == domain or host ends with ".domain"). It walks the host
// label by label, so a single map lookup per label is all that is needed.
func (d *DomainSet) Match(host string) bool {
	if d == nil || len(d.m) == 0 {
		return false
	}
	h := strings.ToLower(strings.Trim(host, "."))
	for h != "" {
		if _, ok := d.m[h]; ok {
			return true
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
	}
	return false
}
