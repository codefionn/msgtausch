package proxy

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"unsafe"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/codefionn/msgtausch/msgtausch-srv/logger"
)

// ClassifierInput contains the input data for classification decisions.
type ClassifierInput struct {
	host       string
	remoteIP   string
	remotePort uint16
}

// estimateTrieMemorySize estimates the memory usage of an Aho-Corasick trie
// by calculating the approximate size of the structure and its contents.
func estimateTrieMemorySize(trie *ahocorasick.Trie, domainCount int) int64 {
	if trie == nil {
		return 0
	}

	// Base estimate: the trie structure itself
	baseSize := int64(unsafe.Sizeof(*trie))

	// Get the value using reflection to access internal structure
	trieValue := reflect.ValueOf(trie).Elem()

	// Try to estimate internal data structures
	// The trie typically contains:
	// - States/nodes (each state has goto functions, failure links, outputs)
	// - Pattern strings
	var totalSize int64 = baseSize

	// Iterate through fields if accessible
	for i := 0; i < trieValue.NumField(); i++ {
		field := trieValue.Field(i)
		if field.CanInterface() {
			switch field.Kind() {
			case reflect.Slice, reflect.Array:
				// Estimate slice/array size
				elemSize := field.Type().Elem().Size()
				totalSize += int64(field.Len()) * int64(elemSize)
			case reflect.Map:
				// Estimate map size (rough approximation)
				totalSize += int64(field.Len()) * 48 // rough estimate per entry
			case reflect.String:
				totalSize += int64(field.Len())
			case reflect.Ptr:
				if !field.IsNil() {
					totalSize += int64(unsafe.Sizeof(field.Interface()))
				}
			}
		}
	}

	// Add estimate for stored patterns (domain strings)
	// Rough estimate: average domain length * number of domains
	const avgDomainLength = 20
	totalSize += int64(domainCount * avgDomainLength)

	// Add estimate for trie nodes (rough approximation)
	// Typically, the number of nodes is roughly proportional to total pattern length
	// Each node might have: goto map, fail link, output list
	estimatedNodes := domainCount * avgDomainLength / 4
	const nodeOverhead = 64 // rough estimate per node
	totalSize += int64(estimatedNodes * nodeOverhead)

	return totalSize
}

// formatMemorySize formats a byte count into a human-readable string
func formatMemorySize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d bytes", bytes)
	}
}

// Classifier defines the interface for all traffic classifiers.
type Classifier interface {
	Classify(input ClassifierInput) (bool, error)
}

// ClassifierAnd implements a logical AND operation across multiple classifiers.
type ClassifierAnd struct {
	Classifiers []Classifier
}

// Classify returns true if all classifiers in the AND group return true.
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

// ClassifierOr implements a logical OR operation across multiple classifiers.
type ClassifierOr struct {
	Classifiers []Classifier
}

// Classify returns true if any classifier in the OR group returns true.
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

// Classify returns true if the input host matches any domain in the list.
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

// Classify returns true if the input host exactly matches any domain in the list.
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

// ClassifierOrDomainsFile is an optimized OR classifier for multiple domains-file classifiers
// that combines all domain lists and uses Aho-Corasick for efficient pattern matching
type ClassifierOrDomainsFile struct {
	Trie       *ahocorasick.Trie
	DomainList []string // Combined domains from all files for debugging
}

// Classify returns true if the input host matches any domain from the combined domain files.
func (c *ClassifierOrDomainsFile) Classify(input ClassifierInput) (bool, error) {
	// Use Aho-Corasick for efficient pattern matching
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

// ClassifierNot negates the result of another classifier.
type ClassifierNot struct {
	Classifier Classifier
}

// Classify returns the negation of the underlying classifier's result.
func (c *ClassifierNot) Classify(input ClassifierInput) (bool, error) {
	result, err := c.Classifier.Classify(input)
	if err != nil {
		return false, err
	}
	return !result, nil
}

// ClassifierStrEq matches when a string field equals a specific value.
type ClassifierStrEq struct {
	Get func(input ClassifierInput) (string, error)
}

// Classify returns true if the specified field equals the given value.
func (c *ClassifierStrEq) Classify(input ClassifierInput) (bool, error) {
	value, err := c.Get(input)
	if err != nil {
		return false, err
	}
	return value == input.host, nil
}

// ClassifierStrNotEq matches when a string field does not equal a specific value.
type ClassifierStrNotEq struct {
	Get func(input ClassifierInput) (string, error)
}

// Classify returns true if the specified field does not equal the given value.
func (c *ClassifierStrNotEq) Classify(input ClassifierInput) (bool, error) {
	value, err := c.Get(input)
	if err != nil {
		return false, err
	}
	return value != input.host, nil
}

// ClassifierStrContains matches when a string field contains a specific substring.
type ClassifierStrContains struct {
	Get func(input ClassifierInput) (string, error)
}

// Classify returns true if the specified field contains the given substring.
func (c *ClassifierStrContains) Classify(input ClassifierInput) (bool, error) {
	value, err := c.Get(input)
	if err != nil {
		return false, err
	}
	return strings.Contains(input.host, value), nil
}

// ClassifierStrNotContains matches when a string field does not contain a specific substring.
type ClassifierStrNotContains struct {
	Get func(input ClassifierInput) (string, error)
}

// Classify returns true if the specified field does not contain the given substring.
func (c *ClassifierStrNotContains) Classify(input ClassifierInput) (bool, error) {
	value, err := c.Get(input)
	if err != nil {
		return false, err
	}
	return !strings.Contains(input.host, value), nil
}

// ClassifierStrIs matches when a string field exactly matches a specific value.
type ClassifierStrIs struct {
	Get func(input ClassifierInput) (string, error)
}

// Classify returns true if the specified field exactly matches the given value.
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
// Returns nil if optimization is not possible, the optimized classifier if successful.
func tryOptimizeOrClassifier(orClassifier *config.ClassifierOr) Classifier {
	// Check if all classifiers are domain/equal - if so, optimize with Aho-Corasick
	var domains []string
	var domainsFilePaths []string
	allDomainEqual := true
	allDomainIs := true
	allDomainsFile := true
	allDomainsIsOrFile := true

detectOptimizations:
	for _, subClassifier := range orClassifier.Classifiers {
		switch c := subClassifier.(type) {
		case *config.ClassifierDomain:
			switch c.Op {
			case config.ClassifierOpEqual:
				domains = append(domains, c.Domain)
				allDomainIs = false    // Mixed operations
				allDomainsFile = false // Mixed types
				allDomainsIsOrFile = false
			case config.ClassifierOpIs:
				domains = append(domains, c.Domain)
				allDomainEqual = false // Mixed operations
				allDomainsFile = false // Mixed types
			default:
				// Other operation - no optimization possible
				allDomainEqual = false
				allDomainIs = false
				allDomainsFile = false
				allDomainsIsOrFile = false
				break detectOptimizations
			}
		case *config.ClassifierDomainsFile:
			domainsFilePaths = append(domainsFilePaths, c.FilePath)
			allDomainEqual = false // Mixed types
			allDomainIs = false    // Mixed types
		default:
			// Not a domain or domains-file classifier - no optimization possible
			allDomainEqual = false
			allDomainIs = false
			allDomainsFile = false
			allDomainsIsOrFile = false
			break detectOptimizations
		}
	}

	// If all are domain/equal classifiers and we have more than one, use optimized version
	if allDomainEqual && len(domains) > 1 {
		var trie *ahocorasick.Trie
		if len(domains) > 0 {
			trie = ahocorasick.NewTrieBuilder().AddStrings(domains).Build()
			memSize := estimateTrieMemorySize(trie, len(domains))
			logger.Info("Created optimized Aho-Corasick OR classifier with %d equal domains (memory: %s)", len(domains), formatMemorySize(memSize))
		}

		return &ClassifierOrDomains{
			Trie:       trie,
			DomainList: domains,
		}
	}

	// If all are domain/is classifiers and we have more than one, use optimized version
	if allDomainIs && len(domains) > 1 {
		var trie *ahocorasick.Trie
		if len(domains) > 0 {
			trie = ahocorasick.NewTrieBuilder().AddStrings(domains).Build()
			memSize := estimateTrieMemorySize(trie, len(domains))
			logger.Info("Created optimized Aho-Corasick OR classifier with %d is domains (memory: %s)", len(domains), formatMemorySize(memSize))
		}

		return &ClassifierOrDomainsIs{
			Trie:       trie,
			DomainList: domains,
		}
	}

	// If all are domains-file classifiers and we have more than one, use optimized version
	if allDomainsFile && len(domainsFilePaths) > 1 {
		// Load and combine all domain lists from the files
		var combinedDomains []string
		for _, filePath := range domainsFilePaths {
			domainsFileClassifier, err := NewClassifierDomainsFile(filePath)
			if err != nil {
				logger.Error("Failed to load domains file for optimization: %v (file: %s)", err, filePath)
				// Fall back to regular OR classifier if we can't load any file
				return nil
			}
			combinedDomains = append(combinedDomains, domainsFileClassifier.DomainList...)
		}

		var trie *ahocorasick.Trie
		if len(combinedDomains) > 0 {
			trie = ahocorasick.NewTrieBuilder().AddStrings(combinedDomains).Build()
			memSize := estimateTrieMemorySize(trie, len(combinedDomains))
			logger.Info("Created optimized Aho-Corasick OR classifier with %d domains from %d files (memory: %s)", len(combinedDomains), len(domainsFilePaths), formatMemorySize(memSize))
		}

		return &ClassifierOrDomainsFile{
			Trie:       trie,
			DomainList: combinedDomains,
		}
	}

	// If all are domain/is classifiers and we have more than one, use optimized version
	if allDomainsIsOrFile && (len(domains) > 1 || len(domainsFilePaths) > 1) {
		// Load and combine all domain lists from the files
		var combinedDomains []string
		for _, filePath := range domainsFilePaths {
			domainsFileClassifier, err := NewClassifierDomainsFile(filePath)
			if err != nil {
				logger.Error("Failed to load domains file for optimization: %v (file: %s)", err, filePath)
				// Fall back to regular OR classifier if we can't load any file
				return nil
			}
			combinedDomains = append(combinedDomains, domainsFileClassifier.DomainList...)
		}

		var trieDomainFiles *ahocorasick.Trie
		if len(combinedDomains) > 0 {
			trieDomainFiles = ahocorasick.NewTrieBuilder().AddStrings(combinedDomains).Build()
			memSize := estimateTrieMemorySize(trieDomainFiles, len(combinedDomains))
			logger.Info("Created optimized Aho-Corasick OR classifier with %d domains from %d files (memory: %s)", len(combinedDomains), len(domainsFilePaths), formatMemorySize(memSize))
		}

		classifierOrDomainsFile := &ClassifierOrDomainsFile{
			Trie:       trieDomainFiles,
			DomainList: combinedDomains,
		}

		var trieDomains *ahocorasick.Trie
		if len(domains) > 0 {
			trieDomains = ahocorasick.NewTrieBuilder().AddStrings(domains).Build()
			memSize := estimateTrieMemorySize(trieDomains, len(domains))
			logger.Info("Created optimized Aho-Corasick OR classifier with %d is domains (memory: %s)", len(domains), formatMemorySize(memSize))
		}

		classifierOrDomains := &ClassifierOrDomainsIs{
			Trie:       trieDomains,
			DomainList: domains,
		}

		return &ClassifierOr{
			Classifiers: []Classifier{classifierOrDomainsFile, classifierOrDomains},
		}
	}

	// No optimization possible
	return nil
}

// CompileClassifiersMap compiles a map of config.Classifier into runtime Classifiers.
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

// CompileClassifiers compiles a slice of config.Classifier into runtime Classifiers.
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

// ClassifierPort matches traffic based on port numbers.
type ClassifierPort struct {
	Port int
}

// Classify returns true if the remote port matches the specified value.
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

// Classify returns true if the input host matches any domain loaded from the file.
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

// CompileClassifier compiles a config.Classifier into a runtime Classifier.
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
		if optimized := tryOptimizeOrClassifier(orClassifier); optimized != nil {
			return optimized, nil
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
			// For Contains, check if the host contains the configured domain substring
			return &ClassifierStrContains{
				Get: func(input ClassifierInput) (string, error) {
					return domainClassifier.Domain, nil
				},
			}, nil
		case config.ClassifierOpNotContains:
			// For NotContains, ensure the host does not contain the configured domain substring
			return &ClassifierStrNotContains{
				Get: func(input ClassifierInput) (string, error) {
					return domainClassifier.Domain, nil
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
	case config.ClassifierTypeRecord:
		recordClassifier := classifier.(*config.ClassifierRecord)
		wrappedClassifier, err := CompileClassifier(recordClassifier.Classifier)
		if err != nil {
			return nil, err
		}
		return &ClassifierRecord{WrappedClassifier: wrappedClassifier}, nil
	default:
		return nil, fmt.Errorf("unsupported classifier type: %v", classifier.Type())
	}
}

var rgComment = regexp.MustCompile(`\A(.*?)[ \t\v]*(?:[#;].*)?\z`)
var rgSplitDomains = regexp.MustCompile(`[ \t\v]+`)

// NewClassifierDomainsFile loads domains from the given file path and creates
// an Aho-Corasick trie for efficient pattern matching.
func NewClassifierDomainsFile(filePath string) (*ClassifierDomainsFile, error) {
	logger.Debug("NewClassifierDomainsFile called with path: %s", filePath)
	// Validate file path to prevent directory traversal
	cleanPath := filepath.Clean(filePath)
	if !filepath.IsAbs(cleanPath) {
		// If relative path, make it absolute relative to current working directory
		absPath, err := filepath.Abs(cleanPath)
		if err != nil {
			logger.Error("Invalid file path: %v (file: %s)", err, filePath)
			return nil, fmt.Errorf("invalid file path: %w", err)
		}
		cleanPath = absPath
	}

	file, err := os.Open(cleanPath)
	if err != nil {
		logger.Error("Failed to open domains file: %v (file: %s)", err, cleanPath)
		return nil, fmt.Errorf("failed to open domains file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			logger.Error("Error closing domains file: %v", closeErr)
		}
	}()

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
		memSize := estimateTrieMemorySize(trie, len(domainList))
		logger.Info("Created Aho-Corasick trie with %d domains from file: %s (memory: %s)", len(domainList), filePath, formatMemorySize(memSize))
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

// Classify returns true if the remote IP matches the specified IP address.
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

// Classify returns true if the remote IP is within the specified network range.
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

// ClassifierTrue always returns true.
type ClassifierTrue struct{}

// Classify always returns true.
func (c *ClassifierTrue) Classify(input ClassifierInput) (bool, error) { return true, nil }

// ClassifierFalse always returns false.
type ClassifierFalse struct{}

// Classify always returns false.
func (c *ClassifierFalse) Classify(input ClassifierInput) (bool, error) { return false, nil }

// ClassifierRecord wraps another classifier and marks matching traffic for recording
type ClassifierRecord struct {
	WrappedClassifier Classifier
}

// Classify returns the result of the wrapped classifier
func (c *ClassifierRecord) Classify(input ClassifierInput) (bool, error) {
	return c.WrappedClassifier.Classify(input)
}

// CreateOpClassifier creates a classifier based on the operation type and value.
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
