package proxy

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
)

type ClassifierInput struct {
	host       string
	remoteIP   string
	remotePort uint16
}

type Classifier interface {
	Classify(input ClassifierInput) (bool, error)
}

type ClassifierAnd struct {
	Classifiers []Classifier
}

func (c *ClassifierAnd) Classify(input ClassifierInput) (bool, error) {
	for _, classifier := range c.Classifiers {
		result, err := classifier.Classify(input)
		if err != nil {
			return false, err
		}
		if !result {
			return false, nil
		}
	}
	return true, nil
}

type ClassifierOr struct {
	Classifiers []Classifier
}

func (c *ClassifierOr) Classify(input ClassifierInput) (bool, error) {
	for _, classifier := range c.Classifiers {
		result, err := classifier.Classify(input)
		if err != nil {
			return false, err
		}
		if result {
			return true, nil
		}
	}
	return false, nil
}

// ClassifierOrDomains is an optimized OR classifier for multiple domain/equal classifiers
// that uses Aho-Corasick for efficient pattern matching
type ClassifierOrDomains struct {
	Trie       *ahocorasick.Trie
	DomainList []string // Keep original domains for debugging
}

func (c *ClassifierOrDomains) Classify(input ClassifierInput) (bool, error) {
	// Use Aho-Corasick for efficient pattern matching
	if c.Trie != nil {
		matches := c.Trie.MatchString(input.host)
		for _, match := range matches {
			// Get the matched pattern (domain)
			matchedDomain := c.DomainList[match.Pattern()]

			// Check for exact match
			if input.host == matchedDomain {
				return true, nil
			}
		}
	}

	return false, nil
}

// ClassifierOrDomainsIs is an optimized OR classifier for multiple domain/is classifiers
// that uses Aho-Corasick for efficient pattern matching with subdomain support
type ClassifierOrDomainsIs struct {
	Trie       *ahocorasick.Trie
	DomainList []string // Keep original domains for debugging
}

func (c *ClassifierOrDomainsIs) Classify(input ClassifierInput) (bool, error) {
	// Use Aho-Corasick for efficient pattern matching
	if c.Trie != nil {
		matches := c.Trie.MatchString(input.host)
		for _, match := range matches {
			// Get the matched pattern (domain)
			matchedDomain := c.DomainList[match.Pattern()]

			// Check for exact match or subdomain match (like ClassifierStrIs)
			if input.host == matchedDomain || strings.HasSuffix(input.host, "."+matchedDomain) {
				return true, nil
			}
		}
	}

	return false, nil
}

type ClassifierNot struct {
	Classifier Classifier
}

func (c *ClassifierNot) Classify(input ClassifierInput) (bool, error) {
	result, err := c.Classifier.Classify(input)
	if err != nil {
		return false, err
	}
	return !result, nil
}

type ClassifierStrEq struct {
	Get func(input ClassifierInput) (string, error)
}

func (c *ClassifierStrEq) Classify(input ClassifierInput) (bool, error) {
	value, err := c.Get(input)
	if err != nil {
		return false, err
	}
	return value == input.host, nil
}

type ClassifierStrNotEq struct {
	Get func(input ClassifierInput) (string, error)
}

func (c *ClassifierStrNotEq) Classify(input ClassifierInput) (bool, error) {
	value, err := c.Get(input)
	if err != nil {
		return false, err
	}
	return value != input.host, nil
}

type ClassifierStrContains struct {
	Get func(input ClassifierInput) (string, error)
}

func (c *ClassifierStrContains) Classify(input ClassifierInput) (bool, error) {
	value, err := c.Get(input)
	if err != nil {
		return false, err
	}
	return strings.Contains(input.host, value), nil
}

type ClassifierStrNotContains struct {
	Get func(input ClassifierInput) (string, error)
}

func (c *ClassifierStrNotContains) Classify(input ClassifierInput) (bool, error) {
	value, err := c.Get(input)
	if err != nil {
		return false, err
	}
	return !strings.Contains(input.host, value), nil
}

type ClassifierStrIs struct {
	Get func(input ClassifierInput) (string, error)
}

func (c *ClassifierStrIs) Classify(input ClassifierInput) (bool, error) {
	value, err := c.Get(input)
	if err != nil {
		return false, err
	}
	return value == input.host || strings.HasSuffix(input.host, "."+value), nil
}

// ClassifierRef represents a reference to another classifier by ID
type ClassifierRef struct {
	Id          string
	Classifiers map[string]Classifier
}

// Classify looks up the referenced classifier by ID and delegates classification to it
func (c *ClassifierRef) Classify(input ClassifierInput) (bool, error) {
	classifier, ok := c.Classifiers[c.Id]
	if !ok {
		return false, fmt.Errorf("classifier with ID '%s' not found", c.Id)
	}
	return classifier.Classify(input)
}

// tryOptimizeOrClassifier attempts to optimize an OR classifier when all sub-classifiers
// are domain classifiers with the same operation by using Aho-Corasick for efficient pattern matching.
// Returns nil if optimization is not possible, the optimized classifier if successful,
// or an error if compilation fails.
func tryOptimizeOrClassifier(orClassifier *config.ClassifierOr) (Classifier, error) {
	// Check if all classifiers are domain/equal - if so, optimize with Aho-Corasick
	var domains []string
	allDomainEqual := true
	allDomainIs := true

detectOptimizations:
	for _, subClassifier := range orClassifier.Classifiers {
		if domainClassifier, ok := subClassifier.(*config.ClassifierDomain); ok {
			switch domainClassifier.Op {
			case config.ClassifierOpEqual:
				domains = append(domains, domainClassifier.Domain)
				allDomainIs = false // Mixed operations
			case config.ClassifierOpIs:
				domains = append(domains, domainClassifier.Domain)
				allDomainEqual = false // Mixed operations
			default:
				// Other operation - no optimization possible
				allDomainEqual = false
				allDomainIs = false
				break detectOptimizations
			}
		} else {
			// Not a domain classifier - no optimization possible
			allDomainEqual = false
			allDomainIs = false
			break
		}
	}

	// If all are domain/equal classifiers and we have more than one, use optimized version
	if allDomainEqual && len(domains) > 1 {
		var trie *ahocorasick.Trie
		if len(domains) > 0 {
			trie = ahocorasick.NewTrieBuilder().AddStrings(domains).Build()
			logger.Debug("Created optimized Aho-Corasick OR classifier with %d equal domains", len(domains))
		}

		return &ClassifierOrDomains{
			Trie:       trie,
			DomainList: domains,
		}, nil
	}

	// If all are domain/is classifiers and we have more than one, use optimized version
	if allDomainIs && len(domains) > 1 {
		var trie *ahocorasick.Trie
		if len(domains) > 0 {
			trie = ahocorasick.NewTrieBuilder().AddStrings(domains).Build()
			logger.Debug("Created optimized Aho-Corasick OR classifier with %d is domains", len(domains))
		}

		return &ClassifierOrDomainsIs{
			Trie:       trie,
			DomainList: domains,
		}, nil
	}

	// No optimization possible
	return nil, nil
}

func CompileClassifiersMap(classifiers map[string]config.Classifier) (map[string]Classifier, error) {
	// First pass: compile all classifiers
	result := make(map[string]Classifier)
	for name, classifier := range classifiers {
		c, err := CompileClassifier(classifier)
		if err != nil {
			return nil, err
		}
		result[name] = c
	}

	// Second pass: connect references to their targets
	for _, c := range result {
		if ref, ok := c.(*ClassifierRef); ok {
			// Update the Classifiers map in the reference
			ref.Classifiers = result
		}
	}

	return result, nil
}

func CompileClassifiers(classifiers []config.Classifier) ([]Classifier, error) {
	var result []Classifier
	for _, classifier := range classifiers {
		c, err := CompileClassifier(classifier)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, nil
}

type ClassifierPort struct {
	Port int
}

func (c *ClassifierPort) Classify(input ClassifierInput) (bool, error) {
	if input.remotePort == 0 {
		return false, fmt.Errorf("target port not provided in classifier input")
	}

	return input.remotePort == uint16(c.Port), nil
}

// ClassifierDomainsFile matches if the input host is in the loaded domains set.
// Uses Aho-Corasick algorithm for efficient domain matching.
type ClassifierDomainsFile struct {
	Trie       *ahocorasick.Trie
	DomainList []string // Keep original domains for debugging
}

func (c *ClassifierDomainsFile) Classify(input ClassifierInput) (bool, error) {
	// Check for subdomain matches using Aho-Corasick for efficient pattern matching
	if c.Trie != nil {
		matches := c.Trie.MatchString(input.host)
		for _, match := range matches {
			// Get the matched pattern (domain)
			matchedDomain := c.DomainList[match.Pattern()]

			hasSuffix := strings.HasSuffix(input.host, matchedDomain)
			if hasSuffix && len(input.host) == len(matchedDomain) {
				return true, nil
			}

			// Check if it's a valid subdomain match (host ends with ".domain")
			if hasSuffix && len(input.host) > len(matchedDomain) && input.host[len(input.host)-len(matchedDomain)-1] == '.' {
				return true, nil
			}
		}
	}

	return false, nil
}

func CompileClassifier(classifier config.Classifier) (Classifier, error) {
	// Check for nil classifier
	if classifier == nil {
		return nil, fmt.Errorf("nil classifier provided")
	}

	switch classifier.Type() {
	case config.ClassifierTypePort:
		portClassifier := classifier.(*config.ClassifierPort)
		return &ClassifierPort{
			Port: portClassifier.Port,
		}, nil
	case config.ClassifierTypeAnd:
		c, err := CompileClassifiers(classifier.(*config.ClassifierAnd).Classifiers)
		if err != nil {
			return nil, err
		}
		return &ClassifierAnd{
			Classifiers: c,
		}, nil
	case config.ClassifierTypeOr:
		orClassifier := classifier.(*config.ClassifierOr)

		// Try to optimize for domain/equal classifiers
		if optimized, err := tryOptimizeOrClassifier(orClassifier); optimized != nil || err != nil {
			return optimized, err
		}

		// Fall back to regular OR classifier
		c, err := CompileClassifiers(orClassifier.Classifiers)
		if err != nil {
			return nil, err
		}
		return &ClassifierOr{
			Classifiers: c,
		}, nil
	case config.ClassifierTypeNot:
		c, err := CompileClassifier(classifier.(*config.ClassifierNot).Classifier)
		if err != nil {
			return nil, err
		}
		return &ClassifierNot{
			Classifier: c,
		}, nil
	case config.ClassifierTypeDomain:
		domainClassifier := classifier.(*config.ClassifierDomain)

		// For domain classifiers, we need to reverse the usual comparison logic
		// The domain from the classifier should be compared against the host in the input
		switch domainClassifier.Op {
		case config.ClassifierOpEqual:
			return &ClassifierStrEq{
				Get: func(input ClassifierInput) (string, error) {
					return domainClassifier.Domain, nil
				},
			}, nil
		case config.ClassifierOpNotEqual:
			return &ClassifierStrNotEq{
				Get: func(input ClassifierInput) (string, error) {
					return domainClassifier.Domain, nil
				},
			}, nil
		case config.ClassifierOpContains:
			// For Contains, we need to check if the host contains the domain
			return &ClassifierStrContains{
				Get: func(input ClassifierInput) (string, error) {
					return input.host, nil
				},
			}, nil
		case config.ClassifierOpNotContains:
			// For NotContains, we need to check if the host doesn't contain the domain
			return &ClassifierStrNotContains{
				Get: func(input ClassifierInput) (string, error) {
					return input.host, nil
				},
			}, nil
		case config.ClassifierOpIs:
			return &ClassifierStrIs{
				Get: func(input ClassifierInput) (string, error) {
					return domainClassifier.Domain, nil
				},
			}, nil
		default:
			return nil, fmt.Errorf("unsupported domain classifier operation: %v", domainClassifier.Op)
		}
	case config.ClassifierTypeIP:
		ipClassifier := classifier.(*config.ClassifierIP)
		return &ClassifierIP{
			IP: ipClassifier.IP,
		}, nil
	case config.ClassifierTypeNetwork:
		networkClassifier := classifier.(*config.ClassifierNetwork)
		return &ClassifierNetwork{
			CIDR: networkClassifier.CIDR,
		}, nil
	case config.ClassifierTypeRef:
		// For reference classifiers, we need to return a placeholder that will be
		// populated with the actual classifiers map later
		return &ClassifierRef{
			Id:          classifier.(*config.ClassifierRef).Id,
			Classifiers: make(map[string]Classifier),
		}, nil
	case config.ClassifierTypeTrue:
		return &ClassifierTrue{}, nil
	case config.ClassifierTypeFalse:
		return &ClassifierFalse{}, nil
	case config.ClassifierTypeDomainsFile:
		domainsFile := classifier.(*config.ClassifierDomainsFile)
		clf, err := NewClassifierDomainsFile(domainsFile.FilePath)
		if err != nil {
			return nil, err
		}
		return clf, nil
	default:
		return nil, fmt.Errorf("unsupported classifier type: %v", classifier.Type())
	}
}

var rgComment = regexp.MustCompile(`\A(.*?)[ \t\v]*(?:[#;].*)?\z`)
var rgSplitDomains = regexp.MustCompile(`[ \t\v]+`)

// NewClassifierDomainsFile loads domains from the given file path and creates
// an Aho-Corasick trie for efficient pattern matching.
func NewClassifierDomainsFile(filePath string) (*ClassifierDomainsFile, error) {
	file, err := os.Open(filePath)
	if err != nil {
		logger.Error("Failed to open domains file: %v (file: %s)", err, filePath)
		return nil, fmt.Errorf("failed to open domains file: %w", err)
	}
	defer file.Close()

	var domainList []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		line = rgComment.FindStringSubmatch(line)[1]

		for _, domain := range rgSplitDomains.Split(line, -1) {
			if domain == "0.0.0.0" {
				continue
			}

			// We don't support wildcards, but we do support subdomains
			if strings.HasPrefix(domain, "*.") {
				domainList = append(domainList, domain[2:])
				continue
			}

			domainList = append(domainList, domain)
		}
	}
	if err := scanner.Err(); err != nil {
		logger.Error("Error reading domains file: %v (file: %s)", err, filePath)
		return nil, fmt.Errorf("error reading domains file: %w", err)
	}

	var trie *ahocorasick.Trie
	if len(domainList) > 0 {
		// Create Aho-Corasick trie for efficient pattern matching
		trie = ahocorasick.NewTrieBuilder().AddStrings(domainList).Build()
		logger.Debug("Created Aho-Corasick trie with %d domains from file: %s", len(domainList), filePath)
	} else {
		logger.Warn("No domains found in file: %s", filePath)
	}

	return &ClassifierDomainsFile{
		Trie:       trie,
		DomainList: domainList,
	}, nil
}

// ClassifierIP checks if the remote IP matches a specified IP address
type ClassifierIP struct {
	IP string
}

func (c *ClassifierIP) Classify(input ClassifierInput) (bool, error) {
	if input.remoteIP == "" {
		return false, fmt.Errorf("remote IP not provided in classifier input")
	}

	return input.remoteIP == c.IP, nil
}

// ClassifierNetwork checks if the remote IP is within a specified CIDR network range
type ClassifierNetwork struct {
	CIDR string
}

func (c *ClassifierNetwork) Classify(input ClassifierInput) (bool, error) {
	if input.remoteIP == "" {
		return false, fmt.Errorf("remote IP not provided in classifier input")
	}

	// Parse the CIDR
	_, ipNet, err := net.ParseCIDR(c.CIDR)
	if err != nil {
		return false, fmt.Errorf("invalid CIDR format '%s': %w", c.CIDR, err)
	}

	// Parse the remote IP
	remoteIP := net.ParseIP(input.remoteIP)
	if remoteIP == nil {
		return false, fmt.Errorf("invalid remote IP format '%s'", input.remoteIP)
	}

	// Check if the IP is in the CIDR range
	isInRange := ipNet.Contains(remoteIP)

	return isInRange, nil
}

// True/False Classifiers

type ClassifierTrue struct{}

func (c *ClassifierTrue) Classify(input ClassifierInput) (bool, error) { return true, nil }

type ClassifierFalse struct{}

func (c *ClassifierFalse) Classify(input ClassifierInput) (bool, error) { return false, nil }

func CreateOpClassifier(
	op config.ClassifierOp,
	getfn func(input ClassifierInput) (string, error),
) (Classifier, error) {
	switch op {
	case config.ClassifierOpEqual:
		return &ClassifierStrEq{
			Get: getfn,
		}, nil
	case config.ClassifierOpNotEqual:
		return &ClassifierStrNotEq{
			Get: getfn,
		}, nil
	case config.ClassifierOpContains:
		return &ClassifierStrContains{
			Get: getfn,
		}, nil
	case config.ClassifierOpNotContains:
		return &ClassifierStrNotContains{
			Get: getfn,
		}, nil
	case config.ClassifierOpIs:
		return &ClassifierStrIs{
			Get: getfn,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported classifier operation: %v", op)
	}
}
