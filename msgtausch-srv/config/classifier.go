package config

// ClassifierType defines the type of classifier for traffic filtering.
type ClassifierType int

const (
	// ClassifierTypeAnd represents a logical AND operation across multiple classifiers.
	ClassifierTypeAnd ClassifierType = iota
	// ClassifierTypeOr represents a logical OR operation across multiple classifiers.
	ClassifierTypeOr
	// ClassifierTypeNot represents a logical NOT operation on a classifier.
	ClassifierTypeNot
	// ClassifierTypeDomain matches against domain names.
	ClassifierTypeDomain
	// ClassifierTypeRef references another classifier by name.
	ClassifierTypeRef
	// ClassifierTypeIP matches against IP addresses.
	ClassifierTypeIP
	// ClassifierTypeNetwork matches against network ranges.
	ClassifierTypeNetwork
	// ClassifierTypePort matches against port numbers.
	ClassifierTypePort
	// ClassifierTypeTrue always returns true.
	ClassifierTypeTrue
	// ClassifierTypeFalse always returns false.
	ClassifierTypeFalse
	// ClassifierTypeDomainsFile matches against domains loaded from a file.
	ClassifierTypeDomainsFile
)

// ClassifierOp defines the operation type for string comparisons.
type ClassifierOp int

// Classifier defines the interface for all classifier configurations.
type Classifier interface {
	Type() ClassifierType
}

// ClassifierDomainsFile holds the path to a file containing domains for matching.
// Actual loading and matching is handled in proxy/classifier.go.
type ClassifierDomainsFile struct {
	FilePath string
}

// Type returns the classifier type for this configuration.
func (c *ClassifierDomainsFile) Type() ClassifierType {
	return ClassifierTypeDomainsFile
}

// ClassifierPort matches traffic based on port numbers.
type ClassifierPort struct {
	Port int
}

// Type returns the classifier type for this configuration.
func (c *ClassifierPort) Type() ClassifierType {
	return ClassifierTypePort
}

// ClassifierAnd represents a logical AND operation across multiple classifiers.
type ClassifierAnd struct {
	Classifiers []Classifier
}

// Type returns the classifier type for this configuration.
func (c *ClassifierAnd) Type() ClassifierType {
	return ClassifierTypeAnd
}

// ClassifierOr represents a logical OR operation across multiple classifiers.
type ClassifierOr struct {
	Classifiers []Classifier
}

// Type returns the classifier type for this configuration.
func (c *ClassifierOr) Type() ClassifierType {
	return ClassifierTypeOr
}

// ClassifierNot negates the result of another classifier.
type ClassifierNot struct {
	Classifier Classifier
}

// Type returns the classifier type for this configuration.
func (c *ClassifierNot) Type() ClassifierType {
	return ClassifierTypeNot
}

const (
	// ClassifierOpEqual checks for equality.
	ClassifierOpEqual ClassifierOp = iota
	// ClassifierOpNotEqual checks for inequality.
	ClassifierOpNotEqual
	// ClassifierOpContains checks if string contains substring.
	ClassifierOpContains
	// ClassifierOpNotContains checks if string does not contain substring.
	ClassifierOpNotContains
	// ClassifierOpIs checks for exact string match.
	ClassifierOpIs
)

// ClassifierDomain matches traffic against specific domain names.
type ClassifierDomain struct {
	Op     ClassifierOp
	Domain string
}

// Type returns the classifier type for this configuration.
func (c *ClassifierDomain) Type() ClassifierType {
	return ClassifierTypeDomain
}

// ClassifierRef references another classifier by name.
type ClassifierRef struct {
	Id string
}

// Type returns the classifier type for this configuration.
func (c *ClassifierRef) Type() ClassifierType {
	return ClassifierTypeRef
}

// ClassifierIP matches traffic against specific IP addresses.
type ClassifierIP struct {
	IP string
}

// Type returns the classifier type for this configuration.
func (c *ClassifierIP) Type() ClassifierType {
	return ClassifierTypeIP
}

// ClassifierNetwork matches traffic against network ranges.
type ClassifierNetwork struct {
	CIDR string
}

// Type returns the classifier type for this configuration.
func (c *ClassifierNetwork) Type() ClassifierType {
	return ClassifierTypeNetwork
}

// ClassifierTrue always returns true for any traffic.
type ClassifierTrue struct{}

// Type returns the classifier type for this configuration.
func (c *ClassifierTrue) Type() ClassifierType {
	return ClassifierTypeTrue
}

// ClassifierFalse always returns false for any traffic.
type ClassifierFalse struct{}

// Type returns the classifier type for this configuration.
func (c *ClassifierFalse) Type() ClassifierType {
	return ClassifierTypeFalse
}
