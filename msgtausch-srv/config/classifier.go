package config

type ClassifierType int

const (
	ClassifierTypeAnd ClassifierType = iota
	ClassifierTypeOr
	ClassifierTypeNot
	ClassifierTypeDomain
	ClassifierTypeRef
	ClassifierTypeIP
	ClassifierTypeNetwork
	ClassifierTypePort        // Port classifier
	ClassifierTypeTrue        // Always true classifier
	ClassifierTypeFalse       // Always false classifier
	ClassifierTypeDomainsFile // Classifier for a file of domains
)

type ClassifierOp int

type Classifier interface {
	Type() ClassifierType
}

// ConfigClassifierDomainsFile holds the path to a file containing domains.
// Actual loading and matching is handled in proxy/classifier.go.
type ClassifierDomainsFile struct {
	FilePath string
}

func (c *ClassifierDomainsFile) Type() ClassifierType {
	return ClassifierTypeDomainsFile
}

type ClassifierPort struct {
	Port int
}

func (c *ClassifierPort) Type() ClassifierType {
	return ClassifierTypePort
}

type ClassifierAnd struct {
	Classifiers []Classifier
}

func (c *ClassifierAnd) Type() ClassifierType {
	return ClassifierTypeAnd
}

type ClassifierOr struct {
	Classifiers []Classifier
}

func (c *ClassifierOr) Type() ClassifierType {
	return ClassifierTypeOr
}

type ClassifierNot struct {
	Classifier Classifier
}

func (c *ClassifierNot) Type() ClassifierType {
	return ClassifierTypeNot
}

const (
	ClassifierOpEqual ClassifierOp = iota
	ClassifierOpNotEqual
	ClassifierOpIs
	ClassifierOpContains
	ClassifierOpNotContains
)

type ClassifierDomain struct {
	Op     ClassifierOp
	Domain string
}

func (c *ClassifierDomain) Type() ClassifierType {
	return ClassifierTypeDomain
}

type ClassifierRef struct {
	Id string
}

func (c *ClassifierRef) Type() ClassifierType {
	return ClassifierTypeRef
}

type ClassifierIP struct {
	IP string
}

func (c *ClassifierIP) Type() ClassifierType {
	return ClassifierTypeIP
}

type ClassifierNetwork struct {
	CIDR string
}

func (c *ClassifierNetwork) Type() ClassifierType {
	return ClassifierTypeNetwork
}

type ClassifierTrue struct{}

func (c *ClassifierTrue) Type() ClassifierType {
	return ClassifierTypeTrue
}

type ClassifierFalse struct{}

func (c *ClassifierFalse) Type() ClassifierType {
	return ClassifierTypeFalse
}
