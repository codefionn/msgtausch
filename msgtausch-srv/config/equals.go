package config

import (
	"bytes"
	"os"

	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
)

// HasChanged returns true if the configuration has changed compared to another config.
// This implementation explicitly compares all fields without using reflection.
func HasChanged(a, b *Config) bool {
	if a == nil || b == nil {
		return a != b
	}
	// Compare server configurations
	if len(a.Servers) != len(b.Servers) {
		return true
	}

	for i := range a.Servers {
		if a.Servers[i].Type != b.Servers[i].Type ||
			a.Servers[i].ListenAddress != b.Servers[i].ListenAddress ||
			a.Servers[i].Enabled != b.Servers[i].Enabled ||
			a.Servers[i].InterceptorName != b.Servers[i].InterceptorName {
			return true
		}
	}
	if a.TimeoutSeconds != b.TimeoutSeconds {
		return true
	}
	if !classifiersMapEqual(a.Classifiers, b.Classifiers) {
		return true
	}
	if !forwardsSliceEqual(a.Forwards, b.Forwards) {
		return true
	}
	if !classifierEqual(a.Allowlist, b.Allowlist) {
		return true
	}
	if !classifierEqual(a.Blocklist, b.Blocklist) {
		return true
	}
	return false
}

// classifierEqual compares two Classifier interfaces for equality.
func classifierEqual(a, b Classifier) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Type() != b.Type() {
		return false
	}
	switch ta := a.(type) {
	case *ClassifierPort:
		tb, ok := b.(*ClassifierPort)
		return ok && ta.Port == tb.Port
	case *ClassifierDomainsFile:
		taContent, err := os.ReadFile(ta.FilePath)
		if err != nil {
			logger.Error("Failed to read domains file: %v (file: %s)", err, ta.FilePath)
			return false
		}
		tbContent, err := os.ReadFile(b.(*ClassifierDomainsFile).FilePath)
		if err != nil {
			logger.Error("Failed to read domains file: %v (file: %s)", err, b.(*ClassifierDomainsFile).FilePath)
			return false
		}
		return bytes.Equal(taContent, tbContent)
	case *ClassifierAnd:
		tb, ok := b.(*ClassifierAnd)
		if !ok || len(ta.Classifiers) != len(tb.Classifiers) {
			return false
		}
		for i := range ta.Classifiers {
			if !classifierEqual(ta.Classifiers[i], tb.Classifiers[i]) {
				return false
			}
		}
		return true
	case *ClassifierOr:
		tb, ok := b.(*ClassifierOr)
		if !ok || len(ta.Classifiers) != len(tb.Classifiers) {
			return false
		}
		for i := range ta.Classifiers {
			if !classifierEqual(ta.Classifiers[i], tb.Classifiers[i]) {
				return false
			}
		}
		return true
	case *ClassifierNot:
		tb, ok := b.(*ClassifierNot)
		if !ok {
			return false
		}
		return classifierEqual(ta.Classifier, tb.Classifier)
	case *ClassifierDomain:
		tb, ok := b.(*ClassifierDomain)
		return ok && ta.Op == tb.Op && ta.Domain == tb.Domain
	case *ClassifierRef:
		tb, ok := b.(*ClassifierRef)
		return ok && ta.Id == tb.Id
	case *ClassifierIP:
		tb, ok := b.(*ClassifierIP)
		return ok && ta.IP == tb.IP
	case *ClassifierNetwork:
		tb, ok := b.(*ClassifierNetwork)
		return ok && ta.CIDR == tb.CIDR
	case *ClassifierTrue:
		_, ok := b.(*ClassifierTrue)
		return ok
	case *ClassifierFalse:
		_, ok := b.(*ClassifierFalse)
		return ok
	default:
		return false
	}
}

// classifiersMapEqual compares two maps of Classifier for equality.
func classifiersMapEqual(a, b map[string]Classifier) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok || !classifierEqual(va, vb) {
			return false
		}
	}
	return true
}

// forwardsSliceEqual compares two slices of Forward for equality.
func forwardsSliceEqual(a, b []Forward) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !forwardEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}

// forwardEqual compares two Forward interfaces for equality.
func forwardEqual(a, b Forward) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Type() != b.Type() {
		return false
	}
	switch ta := a.(type) {
	case *ForwardDefaultNetwork:
		tb, ok := b.(*ForwardDefaultNetwork)
		return ok && classifierEqual(ta.ClassifierData, tb.ClassifierData)
	case *ForwardSocks5:
		tb, ok := b.(*ForwardSocks5)
		if !ok {
			return false
		}
		if ta.Address != tb.Address {
			return false
		}
		if !stringPtrEqual(ta.Username, tb.Username) {
			return false
		}
		if !stringPtrEqual(ta.Password, tb.Password) {
			return false
		}
		return classifierEqual(ta.ClassifierData, tb.ClassifierData)
	case *ForwardProxy:
		tb, ok := b.(*ForwardProxy)
		if !ok {
			return false
		}
		if ta.Address != tb.Address {
			return false
		}
		if !stringPtrEqual(ta.Username, tb.Username) {
			return false
		}
		if !stringPtrEqual(ta.Password, tb.Password) {
			return false
		}
		return classifierEqual(ta.ClassifierData, tb.ClassifierData)
	default:
		return false
	}
}

// stringPtrEqual compares two *string values for equality.
func stringPtrEqual(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
