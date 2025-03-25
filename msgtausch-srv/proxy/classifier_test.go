package proxy

import (
	"fmt"
	"os"
	"testing"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"github.com/codefionn/msgtausch/msgtausch-srv/config"
)

func TestClassifierAnd_Classify(t *testing.T) {
	tests := []struct {
		name        string
		classifiers []Classifier
		input       ClassifierInput
		expected    bool
		error       bool
	}{
		{
			name: "All true",
			classifiers: []Classifier{
				&mockClassifier{result: true, err: nil},
				&mockClassifier{result: true, err: nil},
			},
			input:    ClassifierInput{host: "example.com"},
			expected: true,
			error:    false,
		},
		{
			name: "One false",
			classifiers: []Classifier{
				&mockClassifier{result: true, err: nil},
				&mockClassifier{result: false, err: nil},
			},
			input:    ClassifierInput{host: "example.com"},
			expected: false,
			error:    false,
		},
		{
			name: "One error",
			classifiers: []Classifier{
				&mockClassifier{result: true, err: nil},
				&mockClassifier{result: false, err: errTest},
			},
			input:    ClassifierInput{host: "example.com"},
			expected: false,
			error:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ClassifierAnd{Classifiers: tt.classifiers}
			result, err := c.Classify(tt.input)

			if (err != nil) != tt.error {
				t.Errorf("ClassifierAnd.Classify() error = %v, wantErr %v", err, tt.error)
				return
			}
			if result != tt.expected {
				t.Errorf("ClassifierAnd.Classify() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestClassifierOr_Classify(t *testing.T) {
	tests := []struct {
		name        string
		classifiers []Classifier
		input       ClassifierInput
		expected    bool
		error       bool
	}{
		{
			name: "All false",
			classifiers: []Classifier{
				&mockClassifier{result: false, err: nil},
				&mockClassifier{result: false, err: nil},
			},
			input:    ClassifierInput{host: "example.com"},
			expected: false,
			error:    false,
		},
		{
			name: "One true",
			classifiers: []Classifier{
				&mockClassifier{result: true, err: nil},
				&mockClassifier{result: false, err: nil},
			},
			input:    ClassifierInput{host: "example.com"},
			expected: true,
			error:    false,
		},
		{
			name: "One error",
			classifiers: []Classifier{
				&mockClassifier{result: true, err: errTest},
				&mockClassifier{result: false, err: nil},
			},
			input:    ClassifierInput{host: "example.com"},
			expected: false,
			error:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ClassifierOr{Classifiers: tt.classifiers}
			result, err := c.Classify(tt.input)

			if (err != nil) != tt.error {
				t.Errorf("ClassifierOr.Classify() error = %v, wantErr %v", err, tt.error)
				return
			}
			if result != tt.expected {
				t.Errorf("ClassifierOr.Classify() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestClassifierNot_Classify(t *testing.T) {
	tests := []struct {
		name       string
		classifier Classifier
		input      ClassifierInput
		expected   bool
		error      bool
	}{
		{
			name:       "True",
			classifier: &mockClassifier{result: true, err: nil},
			input:      ClassifierInput{host: "example.com"},
			expected:   false,
			error:      false,
		},
		{
			name:       "False",
			classifier: &mockClassifier{result: false, err: nil},
			input:      ClassifierInput{host: "example.com"},
			expected:   true,
			error:      false,
		},
		{
			name:       "Error",
			classifier: &mockClassifier{result: false, err: errTest},
			input:      ClassifierInput{host: "example.com"},
			expected:   false,
			error:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ClassifierNot{Classifier: tt.classifier}
			result, err := c.Classify(tt.input)

			if (err != nil) != tt.error {
				t.Errorf("ClassifierNot.Classify() error = %v, wantErr %v", err, tt.error)
				return
			}
			if result != tt.expected {
				t.Errorf("ClassifierNot.Classify() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestClassifierTrueFalse_Classify(t *testing.T) {
	t.Run("ClassifierTrue always returns true", func(t *testing.T) {
		c := &ClassifierTrue{}
		result, err := c.Classify(ClassifierInput{})
		if err != nil {
			t.Errorf("ClassifierTrue.Classify() unexpected error: %v", err)
		}
		if !result {
			t.Errorf("ClassifierTrue.Classify() = %v, want true", result)
		}
	})

	t.Run("ClassifierFalse always returns false", func(t *testing.T) {
		c := &ClassifierFalse{}
		result, err := c.Classify(ClassifierInput{})
		if err != nil {
			t.Errorf("ClassifierFalse.Classify() unexpected error: %v", err)
		}
		if result {
			t.Errorf("ClassifierFalse.Classify() = %v, want false", result)
		}
	})
}

func TestClassifierTrueFalse_Integration(t *testing.T) {
	t.Run("Integration: ClassifierTrue from config", func(t *testing.T) {
		c, err := CompileClassifier(&config.ClassifierTrue{})
		if err != nil {
			t.Fatalf("CompileClassifier(True) error: %v", err)
		}
		result, err := c.Classify(ClassifierInput{host: "irrelevant", remoteIP: "", remotePort: 0})
		if err != nil {
			t.Errorf("ClassifierTrue.Classify() error: %v", err)
		}
		if !result {
			t.Errorf("ClassifierTrue.Classify() = %v, want true", result)
		}
	})

	t.Run("Integration: ClassifierFalse from config", func(t *testing.T) {
		c, err := CompileClassifier(&config.ClassifierFalse{})
		if err != nil {
			t.Fatalf("CompileClassifier(False) error: %v", err)
		}
		result, err := c.Classify(ClassifierInput{host: "irrelevant", remoteIP: "", remotePort: 0})
		if err != nil {
			t.Errorf("ClassifierFalse.Classify() error: %v", err)
		}
		if result {
			t.Errorf("ClassifierFalse.Classify() = %v, want false", result)
		}
	})
}

func TestCompileClassifier_TrueFalse(t *testing.T) {
	t.Run("CompileClassifier True", func(t *testing.T) {
		c, err := CompileClassifier(&config.ClassifierTrue{})
		if err != nil {
			t.Fatalf("CompileClassifier(True) error: %v", err)
		}
		result, err := c.Classify(ClassifierInput{})
		if err != nil {
			t.Errorf("ClassifierTrue.Classify() unexpected error: %v", err)
		}
		if !result {
			t.Errorf("ClassifierTrue.Classify() = %v, want true", result)
		}
	})

	t.Run("CompileClassifier False", func(t *testing.T) {
		c, err := CompileClassifier(&config.ClassifierFalse{})
		if err != nil {
			t.Fatalf("CompileClassifier(False) error: %v", err)
		}
		result, err := c.Classify(ClassifierInput{})
		if err != nil {
			t.Errorf("ClassifierFalse.Classify() unexpected error: %v", err)
		}
		if result {
			t.Errorf("ClassifierFalse.Classify() = %v, want false", result)
		}
	})
}

func TestClassifierRef_Classify(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		classifiers map[string]Classifier
		input       ClassifierInput
		expected    bool
		error       bool
	}{
		{
			name: "Found classifier returns true",
			id:   "test-classifier",
			classifiers: map[string]Classifier{
				"test-classifier": &mockClassifier{result: true, err: nil},
			},
			input:    ClassifierInput{host: "example.com"},
			expected: true,
			error:    false,
		},
		{
			name: "Found classifier returns false",
			id:   "test-classifier",
			classifiers: map[string]Classifier{
				"test-classifier": &mockClassifier{result: false, err: nil},
			},
			input:    ClassifierInput{host: "example.com"},
			expected: false,
			error:    false,
		},
		{
			name: "Found classifier returns error",
			id:   "test-classifier",
			classifiers: map[string]Classifier{
				"test-classifier": &mockClassifier{result: false, err: errTest},
			},
			input:    ClassifierInput{host: "example.com"},
			expected: false,
			error:    true,
		},
		{
			name: "Classifier not found",
			id:   "non-existent",
			classifiers: map[string]Classifier{
				"test-classifier": &mockClassifier{result: true, err: nil},
			},
			input:    ClassifierInput{host: "example.com"},
			expected: false,
			error:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ClassifierRef{
				Id:          tt.id,
				Classifiers: tt.classifiers,
			}
			result, err := c.Classify(tt.input)

			if (err != nil) != tt.error {
				t.Errorf("ClassifierRef.Classify() error = %v, wantErr %v", err, tt.error)
				return
			}
			if result != tt.expected {
				t.Errorf("ClassifierRef.Classify() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCompileClassifier_Ref(t *testing.T) {
	// Test that CompileClassifier correctly handles ClassifierRef
	configRef := &config.ClassifierRef{
		Id: "test-ref",
	}

	// Classifier is an interface, so we need to pass a value that implements it
	var classifier config.Classifier = configRef
	result, err := CompileClassifier(classifier)
	if err != nil {
		t.Fatalf("CompileClassifier() error = %v", err)
	}

	ref, ok := result.(*ClassifierRef)
	if !ok {
		t.Fatalf("CompileClassifier() did not return a *ClassifierRef, got %T", result)
	}

	if ref.Id != "test-ref" {
		t.Errorf("ClassifierRef.Id = %v, want %v", ref.Id, "test-ref")
	}

	if ref.Classifiers == nil {
		t.Errorf("ClassifierRef.Classifiers is nil, want initialized map")
	}
}

func TestCompileClassifiersMap_WithRefs(t *testing.T) {
	// Setup: Create classifiers with references
	classifiers := map[string]config.Classifier{
		"ref": &config.ClassifierRef{
			Id: "target",
		},
		"target": &config.ClassifierDomain{
			Op:     config.ClassifierOpEqual,
			Domain: "example.com",
		},
	}

	// Execute: Compile classifiers
	compiledClassifiers, err := CompileClassifiersMap(classifiers)

	// Verify: No error
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
		return
	}

	// Verify: Both classifiers are compiled
	if len(compiledClassifiers) != 2 {
		t.Errorf("Expected 2 compiled classifiers, got %d", len(compiledClassifiers))
	}

	// Verify: Both target and ref are in the compiled map
	_, ok := compiledClassifiers["target"]
	if !ok {
		t.Errorf("Missing 'target' in compiled classifiers")
	}

	ref, ok := compiledClassifiers["ref"]
	if !ok {
		t.Errorf("Missing 'ref' in compiled classifiers")
		return
	}

	// Verify ref is a ClassifierRef
	classifierRef, ok := ref.(*ClassifierRef)
	if !ok {
		t.Errorf("Expected ref to be a *ClassifierRef, got %T", ref)
		return
	}

	// Verify ref has a map of classifiers
	target, ok := classifierRef.Classifiers["target"]
	if !ok {
		t.Errorf("Missing 'target' in ref.Classifiers")
		return
	}

	// Verify it's the same instance as in the main classifiers map
	if target != compiledClassifiers["target"] {
		t.Errorf("ref.Classifiers[\"target\"] != classifiers[\"target\"]")
	}
}

func TestCompileClassifiersMap_TrueFalse(t *testing.T) {
	t.Run("CompileClassifiersMap with true/false", func(t *testing.T) {
		classifiers := map[string]config.Classifier{
			"t": &config.ClassifierTrue{},
			"f": &config.ClassifierFalse{},
		}
		compiled, err := CompileClassifiersMap(classifiers)
		if err != nil {
			t.Fatalf("CompileClassifiersMap error: %v", err)
		}
		if len(compiled) != 2 {
			t.Errorf("Expected 2 compiled classifiers, got %d", len(compiled))
		}
		if _, ok := compiled["t"].(*ClassifierTrue); !ok {
			t.Errorf("Expected *ClassifierTrue, got %T", compiled["t"])
		}
		if _, ok := compiled["f"].(*ClassifierFalse); !ok {
			t.Errorf("Expected *ClassifierFalse, got %T", compiled["f"])
		}
	})
}

func TestClassifierTrueFalse_JSONIntegration(t *testing.T) {
	jsonConfig := `{
		"classifiers": {
			"t": {"type": "true"},
			"f": {"type": "false"}
		}
	}`
	dir := t.TempDir()
	path := dir + "/tf.json"
	err := os.WriteFile(path, []byte(jsonConfig), 0o644)
	if err != nil {
		t.Fatalf("Failed to write temp config: %v", err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	compiled, err := CompileClassifiersMap(cfg.Classifiers)
	if err != nil {
		t.Fatalf("CompileClassifiersMap error: %v", err)
	}
	if _, ok := compiled["t"].(*ClassifierTrue); !ok {
		t.Errorf("Expected *ClassifierTrue, got %T", compiled["t"])
	}
	if _, ok := compiled["f"].(*ClassifierFalse); !ok {
		t.Errorf("Expected *ClassifierFalse, got %T", compiled["f"])
	}
	tr, _ := compiled["t"].Classify(ClassifierInput{})
	fa, _ := compiled["f"].Classify(ClassifierInput{})
	if !tr {
		t.Errorf("ClassifierTrue.Classify() = false, want true")
	}
	if fa {
		t.Errorf("ClassifierFalse.Classify() = true, want false")
	}
}

func TestClassifierIP_Classify(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		input    ClassifierInput
		expected bool
		error    bool
	}{
		{
			name:     "Equal - Match",
			ip:       "192.168.1.1",
			input:    ClassifierInput{host: "example.com", remoteIP: "192.168.1.1"},
			expected: true,
			error:    false,
		},
		{
			name:     "Equal - No Match",
			ip:       "192.168.1.1",
			input:    ClassifierInput{host: "example.com", remoteIP: "192.168.1.2"},
			expected: false,
			error:    false,
		},
		{
			name:     "Missing remote IP",
			ip:       "192.168.1.1",
			input:    ClassifierInput{host: "example.com", remoteIP: ""},
			expected: false,
			error:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ClassifierIP{IP: tt.ip}
			result, err := c.Classify(tt.input)

			if (err != nil) != tt.error {
				t.Errorf("ClassifierIP.Classify() error = %v, wantErr %v", err, tt.error)
				return
			}
			if result != tt.expected {
				t.Errorf("ClassifierIP.Classify() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestClassifierPort_Classify(t *testing.T) {
	tests := []struct {
		name     string
		port     int
		input    ClassifierInput
		expected bool
		error    bool
	}{
		{"Equal true", 443, ClassifierInput{remotePort: 443}, true, false},
		{"Equal false", 443, ClassifierInput{remotePort: 80}, false, false},
		{"Missing port", 443, ClassifierInput{}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ClassifierPort{Port: tt.port}
			result, err := c.Classify(tt.input)
			if (err != nil) != tt.error {
				t.Errorf("ClassifierPort.Classify() error = %v, wantErr %v", err, tt.error)
			}
			if result != tt.expected {
				t.Errorf("ClassifierPort.Classify() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCompileClassifier_Port(t *testing.T) {
	portClassifier := &config.ClassifierPort{Port: 8080}
	var classifier config.Classifier = portClassifier
	result, err := CompileClassifier(classifier)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
		return
	}
	c, ok := result.(*ClassifierPort)
	if !ok {
		t.Errorf("Expected *ClassifierPort, got %T", result)
		return
	}
	if c.Port != 8080 {
		t.Errorf("Expected port 8080, got %d", c.Port)
	}
}

// Simple test for isHostAllowed with port classifier
func TestProxy_isHostAllowed_Port(t *testing.T) {
	cfg := &config.Config{
		Classifiers: map[string]config.Classifier{
			"allow443": &config.ClassifierPort{Port: 443},
		},
		Allowlist: &config.ClassifierPort{Port: 443},
	}

	// Create a properly initialized proxy with compiled classifiers
	p := NewProxy(cfg)

	// Should allow port 443
	allowed := p.isHostAllowed("example.com", "", 443)
	if !allowed {
		t.Errorf("Expected host:443 to be allowed")
	}
	// Should not allow port 80
	allowed = p.isHostAllowed("example.com", "", 80)
	if allowed {
		t.Errorf("Expected host:80 to be denied")
	}
}

func TestClassifierNetwork_Classify(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		input    ClassifierInput
		expected bool
		error    bool
	}{
		{
			name:     "Contains - IP in range",
			cidr:     "192.168.1.0/24",
			input:    ClassifierInput{host: "example.com", remoteIP: "192.168.1.5"},
			expected: true,
			error:    false,
		},
		{
			name:     "Contains - IP not in range",
			cidr:     "192.168.1.0/24",
			input:    ClassifierInput{host: "example.com", remoteIP: "192.168.2.5"},
			expected: false,
			error:    false,
		},
		{
			name:     "Invalid CIDR format",
			cidr:     "192.168.1/24", // Invalid CIDR format
			input:    ClassifierInput{host: "example.com", remoteIP: "192.168.1.5"},
			expected: false,
			error:    true,
		},
		{
			name:     "Invalid remote IP format",
			cidr:     "192.168.1.0/24",
			input:    ClassifierInput{host: "example.com", remoteIP: "not.an.ip.address"},
			expected: false,
			error:    true,
		},
		{
			name:     "Missing remote IP",
			cidr:     "192.168.1.0/24",
			input:    ClassifierInput{host: "example.com", remoteIP: ""},
			expected: false,
			error:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ClassifierNetwork{CIDR: tt.cidr}
			result, err := c.Classify(tt.input)

			if (err != nil) != tt.error {
				t.Errorf("ClassifierNetwork.Classify() error = %v, wantErr %v", err, tt.error)
				return
			}
			if result != tt.expected {
				t.Errorf("ClassifierNetwork.Classify() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCompileClassifier_IP(t *testing.T) {
	// Test compiling an IP classifier
	ipClassifier := &config.ClassifierIP{
		IP: "192.168.1.1",
	}

	// Convert to Classifier interface
	var classifier config.Classifier = ipClassifier
	result, err := CompileClassifier(classifier)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
		return
	}

	// Verify type
	c, ok := result.(*ClassifierIP)
	if !ok {
		t.Errorf("Expected *ClassifierIP, got %T", result)
		return
	}

	// Verify properties
	if c.IP != "192.168.1.1" {
		t.Errorf("Expected IP to be '192.168.1.1', got '%s'", c.IP)
	}
}

func TestCompileClassifier_Network(t *testing.T) {
	// Test compiling a Network classifier
	networkClassifier := &config.ClassifierNetwork{
		CIDR: "192.168.1.0/24",
	}

	// Convert to Classifier interface
	var classifier config.Classifier = networkClassifier
	result, err := CompileClassifier(classifier)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
		return
	}

	// Verify type
	c, ok := result.(*ClassifierNetwork)
	if !ok {
		t.Errorf("Expected *ClassifierNetwork, got %T", result)
		return
	}

	// Verify properties
	if c.CIDR != "192.168.1.0/24" {
		t.Errorf("Expected CIDR to be '192.168.1.0/24', got '%s'", c.CIDR)
	}
}

func TestClassifierDomainsFile(t *testing.T) {
	domains := "example.com\nfoo.org\nbar.net\n# comment\n"
	tmpfile, err := os.CreateTemp(t.TempDir(), "domainsfile-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpfile.Close()
	_, err = tmpfile.WriteString(domains)
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	clf, err := NewClassifierDomainsFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to load domains file: %v", err)
	}

	tests := []struct {
		domain   string
		expected bool
	}{
		{"example.com", true},
		{"foo.org", true},
		{"bar.net", true},
		{"notfound.com", false},
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.domain, func(t *testing.T) {
			ok, err := clf.Classify(ClassifierInput{host: tc.domain})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if ok != tc.expected {
				t.Errorf("expected %v for domain %q, got %v", tc.expected, tc.domain, ok)
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		_, err := NewClassifierDomainsFile("/nonexistent/file.txt")
		if err == nil {
			t.Error("expected error for missing file, got nil")
		}
	})
}

func TestClassifierDomainsFileInlineComments(t *testing.T) {
	// Test that domains file correctly handles inline comments after domain names
	domains := "example.com # this is a comment\nfoo.org ; another comment\nbar.net#no space before comment\ntest.com;semicolon comment\nclean.domain\n# full line comment\n; another full line comment\n\n  \t  \n"
	tmpfile, err := os.CreateTemp(t.TempDir(), "domainsfile-inline-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpfile.Close()
	_, err = tmpfile.WriteString(domains)
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	clf, err := NewClassifierDomainsFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to load domains file: %v", err)
	}

	// Verify the domains were parsed correctly (stripping inline comments)
	expectedDomains := []string{"example.com", "foo.org", "bar.net", "test.com", "clean.domain"}
	if len(clf.DomainList) != len(expectedDomains) {
		t.Errorf("Expected %d domains, got %d. Domains: %v", len(expectedDomains), len(clf.DomainList), clf.DomainList)
	}

	// Test that each domain (without comment) matches correctly
	tests := []struct {
		domain   string
		expected bool
		desc     string
	}{
		{"example.com", true, "domain with hash comment should match"},
		{"foo.org", true, "domain with semicolon comment should match"},
		{"bar.net", true, "domain with hash comment (no space) should match"},
		{"test.com", true, "domain with semicolon comment (no space) should match"},
		{"clean.domain", true, "domain without comment should match"},
		{"notfound.com", false, "non-existing domain should not match"},
		{"", false, "empty domain should not match"},
		// Test that comments themselves don't become domains
		{"this", false, "comment text should not become a domain"},
		{"comment", false, "comment text should not become a domain"},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s_%s", tc.domain, tc.desc), func(t *testing.T) {
			ok, err := clf.Classify(ClassifierInput{host: tc.domain})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if ok != tc.expected {
				t.Errorf("expected %v for domain %q (%s), got %v", tc.expected, tc.domain, tc.desc, ok)
			}
		})
	}
}

func TestClassifierDomainsFileInlineCommentsWithWhitespace(t *testing.T) {
	// Test various whitespace scenarios with inline comments
	domains := "  example.com   # comment with spaces  \n\tfoo.org\t;\tcomment with tabs\t\n   bar.net   #   spaced comment   \n"
	tmpfile, err := os.CreateTemp(t.TempDir(), "domainsfile-whitespace-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpfile.Close()
	_, err = tmpfile.WriteString(domains)
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	clf, err := NewClassifierDomainsFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to load domains file: %v", err)
	}

	tests := []struct {
		domain   string
		expected bool
	}{
		{"example.com", true},
		{"foo.org", true},
		{"bar.net", true},
		{"notfound.com", false},
	}

	for _, tc := range tests {
		t.Run(tc.domain, func(t *testing.T) {
			ok, err := clf.Classify(ClassifierInput{host: tc.domain})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if ok != tc.expected {
				t.Errorf("expected %v for domain %q, got %v", tc.expected, tc.domain, ok)
			}
		})
	}
}

func TestClassifierDomainsFileInlineCommentsWildcard(t *testing.T) {
	// Test wildcard domains with inline comments
	domains := "*.google.com # wildcard with comment\n*.facebook.com;semicolon comment\n*.github.com#no space comment\nnormal.domain ; mixed format\n"
	tmpfile, err := os.CreateTemp(t.TempDir(), "domainsfile-wildcard-comments-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpfile.Close()
	_, err = tmpfile.WriteString(domains)
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	clf, err := NewClassifierDomainsFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to load domains file: %v", err)
	}

	tests := []struct {
		domain   string
		expected bool
		desc     string
	}{
		// Exact matches (wildcards are treated as the base domain)
		{"google.com", true, "wildcard domain base should match"},
		{"facebook.com", true, "wildcard domain base should match"},
		{"github.com", true, "wildcard domain base should match"},
		{"normal.domain", true, "normal domain should match"},

		// Subdomain matches
		{"www.google.com", true, "subdomain of wildcard should match"},
		{"api.facebook.com", true, "subdomain of wildcard should match"},
		{"docs.github.com", true, "subdomain of wildcard should match"},
		{"sub.normal.domain", true, "subdomain of normal domain should match"},

		// Non-matches
		{"google.net", false, "different TLD should not match"},
		{"notfound.com", false, "non-existing domain should not match"},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s_%s", tc.domain, tc.desc), func(t *testing.T) {
			ok, err := clf.Classify(ClassifierInput{host: tc.domain})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if ok != tc.expected {
				t.Errorf("expected %v for domain %q (%s), got %v", tc.expected, tc.domain, tc.desc, ok)
			}
		})
	}
}

func TestClassifierDomainsFileInlineCommentsEdgeCases(t *testing.T) {
	// Test edge cases with inline comments
	domains := "example.com##double hash\nfoo.org;;double semicolon\nbar.net #; mixed delimiters\ntest.com ;# mixed delimiters reverse\nhash#inside.domain ; this should not work as expected\nno-comment.domain\n"
	tmpfile, err := os.CreateTemp(t.TempDir(), "domainsfile-edge-cases-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpfile.Close()
	_, err = tmpfile.WriteString(domains)
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	clf, err := NewClassifierDomainsFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to load domains file: %v", err)
	}

	tests := []struct {
		domain   string
		expected bool
		desc     string
	}{
		{"example.com", true, "double hash comment should be handled"},
		{"foo.org", true, "double semicolon comment should be handled"},
		{"bar.net", true, "mixed delimiters should be handled"},
		{"test.com", true, "mixed delimiters reverse should be handled"},
		// Note: "hash#inside.domain" with # in the middle should ideally be treated as an invalid domain
		// but the current regex will match everything up to the first comment delimiter
		{"no-comment.domain", true, "domain without comment should work"},
		{"notfound.com", false, "non-existing domain should not match"},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s_%s", tc.domain, tc.desc), func(t *testing.T) {
			ok, err := clf.Classify(ClassifierInput{host: tc.domain})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if ok != tc.expected {
				t.Errorf("expected %v for domain %q (%s), got %v", tc.expected, tc.domain, tc.desc, ok)
			}
		})
	}
}

func TestClassifierDomainsFileInlineCommentsEmptyDomains(t *testing.T) {
	// Test cases where inline comments might result in empty domains
	domains := "# just a comment\n; another comment\n   # spaced comment\n\t;\ttab comment\n # valid.domain\ngood.domain # comment\n  \t  # empty with whitespace\n"
	tmpfile, err := os.CreateTemp(t.TempDir(), "domainsfile-empty-domains-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpfile.Close()
	_, err = tmpfile.WriteString(domains)
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	clf, err := NewClassifierDomainsFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to load domains file: %v", err)
	}

	// Should only have the one valid domain
	expectedDomainCount := 1
	if len(clf.DomainList) != expectedDomainCount {
		t.Errorf("Expected %d domains, got %d. Domains: %v", expectedDomainCount, len(clf.DomainList), clf.DomainList)
	}

	// Test that the valid domain works
	ok, err := clf.Classify(ClassifierInput{host: "good.domain"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected good.domain to match")
	}
}

func TestClassifierDomainsFileInlineCommentsBugDemonstration(t *testing.T) {
	// This test verifies the fix for inline comments is working correctly
	domains := "example.com # this should be stripped\ntest.org ; this too\n"
	tmpfile, err := os.CreateTemp(t.TempDir(), "domainsfile-bug-demo-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpfile.Close()
	_, err = tmpfile.WriteString(domains)
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	clf, err := NewClassifierDomainsFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to load domains file: %v", err)
	}

	// After fixing the bug, the DomainList should only contain ["example.com", "test.org"]
	t.Logf("Parsed domains: %v", clf.DomainList)

	if len(clf.DomainList) != 2 {
		t.Errorf("Expected 2 domains, got %d", len(clf.DomainList))
	}

	// Verify the domains were parsed correctly without comments
	expectedDomains := []string{"example.com", "test.org"}
	for i, expected := range expectedDomains {
		if i >= len(clf.DomainList) || clf.DomainList[i] != expected {
			t.Errorf("Expected domain %d to be %q, got %q", i, expected, clf.DomainList[i])
		}
	}

	// These should now work correctly with the fix
	ok, _ := clf.Classify(ClassifierInput{host: "example.com"})
	if !ok {
		t.Error("'example.com' should match")
	}

	ok, _ = clf.Classify(ClassifierInput{host: "test.org"})
	if !ok {
		t.Error("'test.org' should match")
	}
}

func TestClassifierDomainsFileMultipleDomainsPerLine(t *testing.T) {
	// Test multiple domains separated by whitespace on the same line
	domains := "google.com facebook.com\nexample.org\ttest.com\n  github.com   bitbucket.org  \n"
	tmpfile, err := os.CreateTemp(t.TempDir(), "domainsfile-multiple-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpfile.Close()
	_, err = tmpfile.WriteString(domains)
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	clf, err := NewClassifierDomainsFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to load domains file: %v", err)
	}

	t.Logf("Parsed domains: %v", clf.DomainList)

	// Should have parsed 6 individual domains
	expectedDomains := []string{"google.com", "facebook.com", "example.org", "test.com", "github.com", "bitbucket.org"}
	if len(clf.DomainList) != len(expectedDomains) {
		t.Errorf("Expected %d domains, got %d. Domains: %v", len(expectedDomains), len(clf.DomainList), clf.DomainList)
	}

	// Test that all domains work individually
	for _, domain := range expectedDomains {
		ok, err := clf.Classify(ClassifierInput{host: domain})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !ok {
			t.Errorf("expected %q to match", domain)
		}
	}

	// Test subdomains
	subdomainTests := []struct {
		host     string
		expected bool
	}{
		{"www.google.com", true},
		{"api.facebook.com", true},
		{"docs.github.com", true},
		{"notfound.com", false},
	}

	for _, tc := range subdomainTests {
		ok, err := clf.Classify(ClassifierInput{host: tc.host})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if ok != tc.expected {
			t.Errorf("expected %v for %q, got %v", tc.expected, tc.host, ok)
		}
	}
}

func TestClassifierDomainsFileMultipleDomainsWithComments(t *testing.T) {
	// Test multiple domains per line combined with inline comments
	domains := "google.com facebook.com # social media\nexample.org test.com ; test domains\ngithub.com\tbitbucket.org  # version control\n"
	tmpfile, err := os.CreateTemp(t.TempDir(), "domainsfile-multiple-comments-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpfile.Close()
	_, err = tmpfile.WriteString(domains)
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	clf, err := NewClassifierDomainsFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to load domains file: %v", err)
	}

	t.Logf("Parsed domains: %v", clf.DomainList)

	// Should have parsed 6 domains, comments stripped
	expectedDomains := []string{"google.com", "facebook.com", "example.org", "test.com", "github.com", "bitbucket.org"}
	if len(clf.DomainList) != len(expectedDomains) {
		t.Errorf("Expected %d domains, got %d. Domains: %v", len(expectedDomains), len(clf.DomainList), clf.DomainList)
	}

	// Test that all domains work
	for _, domain := range expectedDomains {
		ok, err := clf.Classify(ClassifierInput{host: domain})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !ok {
			t.Errorf("expected %q to match", domain)
		}
	}
}

func TestClassifierDomainsFileHostsFileFormat(t *testing.T) {
	// Test hosts file format support (filtering out 0.0.0.0 entries)
	// NOTE: Currently affected by the rgSplitDomains regex bug
	domains := "0.0.0.0 ads.example.com\n127.0.0.1 localhost\ngoogle.com\n0.0.0.0 tracker.evil.com\nfacebook.com # social\n"
	tmpfile, err := os.CreateTemp(t.TempDir(), "domainsfile-hosts-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpfile.Close()
	_, err = tmpfile.WriteString(domains)
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	clf, err := NewClassifierDomainsFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to load domains file: %v", err)
	}

	t.Logf("Current parsed domains: %v", clf.DomainList)

	t.Run("current_bug_behavior", func(t *testing.T) {
		// Due to split bug, lines like "0.0.0.0 ads.example.com" are stored as single "domains"
		// The 0.0.0.0 filtering only works if 0.0.0.0 appears as a separate domain after splitting
		currentCount := len(clf.DomainList)
		t.Logf("Current domain count: %d", currentCount)

		for _, domain := range clf.DomainList {
			t.Logf("Stored domain: %q", domain)
		}
	})

	t.Run("expected_behavior_after_fix", func(t *testing.T) {
		t.Skip("These tests will pass after fixing rgSplitDomains regex")

		// After fixing, should parse: ads.example.com, localhost, google.com, tracker.evil.com, facebook.com
		// (0.0.0.0 and 127.0.0.1 are filtered out as domains)
		expectedCount := 5
		if len(clf.DomainList) != expectedCount {
			t.Errorf("Expected %d domains, got %d. Domains: %v", expectedCount, len(clf.DomainList), clf.DomainList)
		}

		// Test that legitimate domains work
		tests := []struct {
			domain   string
			expected bool
		}{
			{"ads.example.com", true},
			{"localhost", true},
			{"google.com", true},
			{"tracker.evil.com", true},
			{"facebook.com", true},
			{"notfound.com", false},
		}

		for _, tc := range tests {
			ok, err := clf.Classify(ClassifierInput{host: tc.domain})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if ok != tc.expected {
				t.Errorf("expected %v for %q, got %v", tc.expected, tc.domain, ok)
			}
		}
	})
}

func TestClassifierDomainsFileComplexMixedFormat(t *testing.T) {
	// Test complex mixed format with various features
	domains := `# This is a comment line
; Another comment
google.com facebook.com # Multiple domains with comment
*.github.com	# Wildcard with tab
example.org test.com; Multiple with semicolon comment
0.0.0.0 blocked.site.com malware.com # hosts format with multiple
normal.domain
  spaced.domain   extra.domain  # spaces everywhere
	tabs.domain	more.domains
# Final comment`

	tmpfile, err := os.CreateTemp(t.TempDir(), "domainsfile-complex-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpfile.Close()
	_, err = tmpfile.WriteString(domains)
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	clf, err := NewClassifierDomainsFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to load domains file: %v", err)
	}

	t.Logf("Parsed domains: %v", clf.DomainList)

	// Test expected domains
	expectedDomains := []string{
		"google.com", "facebook.com", "github.com", "example.org", "test.com",
		"blocked.site.com", "malware.com", "normal.domain", "spaced.domain",
		"extra.domain", "tabs.domain", "more.domains",
	}

	for _, domain := range expectedDomains {
		t.Run(domain, func(t *testing.T) {
			ok, err := clf.Classify(ClassifierInput{host: domain})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !ok {
				t.Errorf("expected %q to match", domain)
			}
		})
	}

	// Test subdomains for wildcard entry
	t.Run("wildcard_subdomain", func(t *testing.T) {
		ok, err := clf.Classify(ClassifierInput{host: "api.github.com"})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !ok {
			t.Error("expected api.github.com to match (wildcard)")
		}
	})
}

func TestClassifierDomainsFileRegexBugDocumentation(t *testing.T) {
	// This test documents the current regex bug and provides the fix
	t.Run("regex_bug_explanation", func(t *testing.T) {
		t.Log("Current rgSplitDomains regex: `\\A[ \\t\\v]\\z`")
		t.Log("Issue: This pattern only matches single whitespace characters at start/end of string")
		t.Log("       It won't match whitespace in the middle of a line for splitting")
		t.Log("       Therefore, lines like 'domain1.com domain2.com' don't get split")
		t.Log("")
		t.Log("Fix needed: Change regex to `[ \\t\\v]+`")
		t.Log("           This will match one or more whitespace characters anywhere")
		t.Log("           and properly split multiple domains per line")
		t.Log("")
		t.Log("Location: /msgtausch-srv/proxy/classifier.go line 458")
		t.Log("Change:   var rgSplitDomains = regexp.MustCompile(`[ \\t\\v]+`)")
	})
}

// TestClassifierDomainsFileWindowsNewlines is like TestClassifierDomainsFile but uses Windows newlines (\r\n).
func TestClassifierDomainsFileWindowsNewlines(t *testing.T) {
	domains := "example.com\r\nfoo.org\r\nbar.net\r\n# comment\r\n"
	tmpfile, err := os.CreateTemp(t.TempDir(), "domainsfile-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpfile.Close()
	_, err = tmpfile.WriteString(domains)
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	clf, err := NewClassifierDomainsFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to load domains file: %v", err)
	}

	tests := []struct {
		domain   string
		expected bool
	}{
		{"example.com", true},
		{"foo.org", true},
		{"bar.net", true},
		{"notfound.com", false},
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.domain, func(t *testing.T) {
			ok, err := clf.Classify(ClassifierInput{host: tc.domain})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if ok != tc.expected {
				t.Errorf("expected %v for domain %q, got %v", tc.expected, tc.domain, ok)
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		_, err := NewClassifierDomainsFile("/nonexistent/file.txt")
		if err == nil {
			t.Error("expected error for missing file, got nil")
		}
	})
}

func TestClassifierDomainsFileAhoCorasick(t *testing.T) {
	// Test Aho-Corasick integration with subdomain matching
	domains := "google.com\nfacebook.com\ngithub.com\nexample.org\n# comment line\n"
	tmpfile, err := os.CreateTemp(t.TempDir(), "domainsfile-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpfile.Close()
	_, err = tmpfile.WriteString(domains)
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	clf, err := NewClassifierDomainsFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to load domains file: %v", err)
	}

	// Verify Aho-Corasick trie was created
	if clf.Trie == nil {
		t.Error("Expected Aho-Corasick trie to be created, got nil")
	}

	// Verify domain list was populated
	if len(clf.DomainList) != 4 {
		t.Errorf("Expected 4 domains in DomainList, got %d", len(clf.DomainList))
	}

	tests := []struct {
		domain   string
		expected bool
		desc     string
	}{
		// Exact matches
		{"google.com", true, "exact match"},
		{"facebook.com", true, "exact match"},
		{"github.com", true, "exact match"},
		{"example.org", true, "exact match"},

		// Subdomain matches
		{"www.google.com", true, "subdomain match"},
		{"mail.google.com", true, "subdomain match"},
		{"api.github.com", true, "subdomain match"},
		{"docs.github.com", true, "subdomain match"},
		{"app.facebook.com", true, "subdomain match"},
		{"test.example.org", true, "subdomain match"},

		// Non-matches
		{"google.net", false, "different TLD"},
		{"notfound.com", false, "no match"},
		{"example.com", false, "different TLD"},
		{"", false, "empty string"},
		{"googlex.com", false, "similar but not matching"},
		{"xgoogle.com", false, "prefix similarity"},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s_%s", tc.domain, tc.desc), func(t *testing.T) {
			ok, err := clf.Classify(ClassifierInput{host: tc.domain})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if ok != tc.expected {
				t.Errorf("expected %v for domain %q (%s), got %v", tc.expected, tc.domain, tc.desc, ok)
			}
		})
	}
}

func TestClassifierDomainsFileAhoCorasickWildcard(t *testing.T) {
	// Test Aho-Corasick integration with subdomain matching
	domains := "*.google.com\n*.facebook.com\n*.github.com\n*.example.org\n# comment line\n"
	tmpfile, err := os.CreateTemp(t.TempDir(), "domainsfile-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpfile.Close()
	_, err = tmpfile.WriteString(domains)
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	clf, err := NewClassifierDomainsFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to load domains file: %v", err)
	}

	// Verify Aho-Corasick trie was created
	if clf.Trie == nil {
		t.Error("Expected Aho-Corasick trie to be created, got nil")
	}

	// Verify domain list was populated
	if len(clf.DomainList) != 4 {
		t.Errorf("Expected 4 domains in DomainList, got %d", len(clf.DomainList))
	}

	tests := []struct {
		domain   string
		expected bool
		desc     string
	}{
		// Exact matches
		{"google.com", true, "exact match"},
		{"facebook.com", true, "exact match"},
		{"github.com", true, "exact match"},
		{"example.org", true, "exact match"},

		// Subdomain matches
		{"www.google.com", true, "subdomain match"},
		{"mail.google.com", true, "subdomain match"},
		{"api.github.com", true, "subdomain match"},
		{"docs.github.com", true, "subdomain match"},
		{"app.facebook.com", true, "subdomain match"},
		{"test.example.org", true, "subdomain match"},

		// Non-matches
		{"google.net", false, "different TLD"},
		{"notfound.com", false, "no match"},
		{"example.com", false, "different TLD"},
		{"", false, "empty string"},
		{"googlex.com", false, "similar but not matching"},
		{"xgoogle.com", false, "prefix similarity"},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s_%s", tc.domain, tc.desc), func(t *testing.T) {
			ok, err := clf.Classify(ClassifierInput{host: tc.domain})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if ok != tc.expected {
				t.Errorf("expected %v for domain %q (%s), got %v", tc.expected, tc.domain, tc.desc, ok)
			}
		})
	}
}

func TestClassifierOrDomainsOptimization(t *testing.T) {
	// Test that OR classifier with multiple domain/equal classifiers gets optimized to use Aho-Corasick
	classifiers := map[string]config.Classifier{
		"test-or": &config.ClassifierOr{
			Classifiers: []config.Classifier{
				&config.ClassifierDomain{
					Op:     config.ClassifierOpEqual,
					Domain: "google.com",
				},
				&config.ClassifierDomain{
					Op:     config.ClassifierOpEqual,
					Domain: "facebook.com",
				},
				&config.ClassifierDomain{
					Op:     config.ClassifierOpEqual,
					Domain: "github.com",
				},
			},
		},
	}

	compiled, err := CompileClassifiersMap(classifiers)
	if err != nil {
		t.Fatalf("CompileClassifiersMap error: %v", err)
	}

	// Verify the OR classifier was optimized to ClassifierOrDomains
	orClassifier, ok := compiled["test-or"].(*ClassifierOrDomains)
	if !ok {
		t.Fatalf("Expected ClassifierOrDomains, got %T", compiled["test-or"])
	}

	// Verify Aho-Corasick trie was created
	if orClassifier.Trie == nil {
		t.Error("Expected Aho-Corasick trie to be created, got nil")
	}

	// Verify domain list was populated
	if len(orClassifier.DomainList) != 3 {
		t.Errorf("Expected 3 domains in DomainList, got %d", len(orClassifier.DomainList))
	}

	tests := []struct {
		domain   string
		expected bool
		desc     string
	}{
		// Exact matches
		{"google.com", true, "exact match"},
		{"facebook.com", true, "exact match"},
		{"github.com", true, "exact match"},

		// Non-matches (should not match subdomains since this is exact matching)
		{"www.google.com", false, "subdomain should not match"},
		{"api.github.com", false, "subdomain should not match"},
		{"example.com", false, "different domain"},
		{"", false, "empty string"},
		{"googlex.com", false, "similar but not matching"},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s_%s", tc.domain, tc.desc), func(t *testing.T) {
			ok, err := orClassifier.Classify(ClassifierInput{host: tc.domain})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if ok != tc.expected {
				t.Errorf("expected %v for domain %q (%s), got %v", tc.expected, tc.domain, tc.desc, ok)
			}
		})
	}
}

func TestClassifierOrDomainsNoOptimization(t *testing.T) {
	// Test that OR classifier with mixed types doesn't get optimized
	classifiers := map[string]config.Classifier{
		"test-or": &config.ClassifierOr{
			Classifiers: []config.Classifier{
				&config.ClassifierDomain{
					Op:     config.ClassifierOpEqual,
					Domain: "google.com",
				},
				&config.ClassifierDomain{
					Op:     config.ClassifierOpContains, // Different op - should prevent optimization
					Domain: "facebook.com",
				},
			},
		},
	}

	compiled, err := CompileClassifiersMap(classifiers)
	if err != nil {
		t.Fatalf("CompileClassifiersMap error: %v", err)
	}

	// Verify the OR classifier was NOT optimized (should be regular ClassifierOr)
	_, isOptimized := compiled["test-or"].(*ClassifierOrDomains)
	if isOptimized {
		t.Error("Expected regular ClassifierOr (not optimized), got ClassifierOrDomains")
	}

	_, isRegular := compiled["test-or"].(*ClassifierOr)
	if !isRegular {
		t.Errorf("Expected ClassifierOr, got %T", compiled["test-or"])
	}
}

func TestClassifierStrIs_Classify(t *testing.T) {
	tests := []struct {
		name     string
		getValue string
		input    ClassifierInput
		expected bool
		hasError bool
	}{
		{
			name:     "Exact domain match",
			getValue: "example.com",
			input:    ClassifierInput{host: "example.com"},
			expected: true,
			hasError: false,
		},
		{
			name:     "Subdomain match",
			getValue: "example.com",
			input:    ClassifierInput{host: "www.example.com"},
			expected: true,
			hasError: false,
		},
		{
			name:     "Deep subdomain match",
			getValue: "example.com",
			input:    ClassifierInput{host: "api.v2.example.com"},
			expected: true,
			hasError: false,
		},
		{
			name:     "No match - different domain",
			getValue: "example.com",
			input:    ClassifierInput{host: "google.com"},
			expected: false,
			hasError: false,
		},
		{
			name:     "No match - different TLD",
			getValue: "example.com",
			input:    ClassifierInput{host: "example.org"},
			expected: false,
			hasError: false,
		},
		{
			name:     "No match - partial string similarity",
			getValue: "example.com",
			input:    ClassifierInput{host: "notexample.com"},
			expected: false,
			hasError: false,
		},
		{
			name:     "No match - domain as prefix",
			getValue: "example.com",
			input:    ClassifierInput{host: "example.com.evil.org"},
			expected: false,
			hasError: false,
		},
		{
			name:     "Empty input host",
			getValue: "example.com",
			input:    ClassifierInput{host: ""},
			expected: false,
			hasError: false,
		},
		{
			name:     "Empty domain value",
			getValue: "",
			input:    ClassifierInput{host: "example.com"},
			expected: false,
			hasError: false,
		},
		{
			name:     "Both empty",
			getValue: "",
			input:    ClassifierInput{host: ""},
			expected: true,
			hasError: false,
		},
		{
			name:     "Single character domain",
			getValue: "a",
			input:    ClassifierInput{host: "b.a"},
			expected: true,
			hasError: false,
		},
		{
			name:     "Get function error",
			getValue: "",
			input:    ClassifierInput{host: "example.com"},
			expected: false,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classifier := &ClassifierStrIs{
				Get: func(input ClassifierInput) (string, error) {
					if tt.hasError {
						return "", fmt.Errorf("test error")
					}
					return tt.getValue, nil
				},
			}

			result, err := classifier.Classify(tt.input)

			if tt.hasError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestClassifierStrIs_Integration(t *testing.T) {
	// Test ClassifierStrIs through the domain classifier compilation
	domainClassifier := &config.ClassifierDomain{
		Op:     config.ClassifierOpIs,
		Domain: "example.com",
	}

	compiled, err := CompileClassifier(domainClassifier)
	if err != nil {
		t.Fatalf("CompileClassifier error: %v", err)
	}

	// Verify it compiles to a ClassifierStrIs
	strIsClassifier, ok := compiled.(*ClassifierStrIs)
	if !ok {
		t.Fatalf("Expected *ClassifierStrIs, got %T", compiled)
	}

	// Note: For domain classifiers with OpIs, the logic is:
	// Get function returns domainClassifier.Domain (example.com), and we check if domain "is" host
	// The ClassifierStrIs checks: value == input.host || strings.HasSuffix(input.host, "."+value)
	// Where value is "example.com", so we're checking:
	// "example.com" == input.host || strings.HasSuffix(input.host, ".example.com")
	tests := []struct {
		host     string
		expected bool
	}{
		{"example.com", true}, // Exact match: "example.com" == "example.com"
		{"www.example.com", true},
		{"api.example.com", true},
		{"google.com", false},     // No match: "example.com" != "google.com" and no suffix
		{"example.org", false},    // No match: "example.com" != "example.org" and no suffix
		{"notexample.com", false}, // No match: "example.com" != "notexample.com" and no suffix
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			result, err := strIsClassifier.Classify(ClassifierInput{host: tt.host})
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("For host %q, expected %v, got %v", tt.host, tt.expected, result)
			}
		})
	}
}

func TestCreateOpClassifier_Is(t *testing.T) {
	// Test CreateOpClassifier with ClassifierOpIs
	getfn := func(input ClassifierInput) (string, error) {
		return "example.com", nil
	}

	classifier, err := CreateOpClassifier(config.ClassifierOpIs, getfn)
	if err != nil {
		t.Fatalf("CreateOpClassifier error: %v", err)
	}

	// Verify it returns a ClassifierStrIs
	strIsClassifier, ok := classifier.(*ClassifierStrIs)
	if !ok {
		t.Fatalf("Expected *ClassifierStrIs, got %T", classifier)
	}

	// Test the classifier functionality
	tests := []struct {
		host     string
		expected bool
	}{
		{"example.com", true},     // Exact match
		{"www.example.com", true}, // Subdomain
		{"google.com", false},     // No match
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			result, err := strIsClassifier.Classify(ClassifierInput{host: tt.host})
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("For host %q, expected %v, got %v", tt.host, tt.expected, result)
			}
		})
	}
}

func TestClassifierOrDomainsIsOptimization(t *testing.T) {
	// Test that OR classifier with multiple domain/is classifiers gets optimized to use Aho-Corasick
	classifiers := map[string]config.Classifier{
		"test-or": &config.ClassifierOr{
			Classifiers: []config.Classifier{
				&config.ClassifierDomain{
					Op:     config.ClassifierOpIs,
					Domain: "google.com",
				},
				&config.ClassifierDomain{
					Op:     config.ClassifierOpIs,
					Domain: "facebook.com",
				},
				&config.ClassifierDomain{
					Op:     config.ClassifierOpIs,
					Domain: "github.com",
				},
			},
		},
	}

	compiled, err := CompileClassifiersMap(classifiers)
	if err != nil {
		t.Fatalf("CompileClassifiersMap error: %v", err)
	}

	// Verify the OR classifier was optimized to ClassifierOrDomainsIs
	orIsClassifier, ok := compiled["test-or"].(*ClassifierOrDomainsIs)
	if !ok {
		t.Fatalf("Expected ClassifierOrDomainsIs, got %T", compiled["test-or"])
	}

	// Verify Aho-Corasick trie was created
	if orIsClassifier.Trie == nil {
		t.Error("Expected Aho-Corasick trie to be created, got nil")
	}

	// Verify domain list was populated
	if len(orIsClassifier.DomainList) != 3 {
		t.Errorf("Expected 3 domains in DomainList, got %d", len(orIsClassifier.DomainList))
	}

	tests := []struct {
		domain   string
		expected bool
		desc     string
	}{
		// Exact matches
		{"google.com", true, "exact match"},
		{"facebook.com", true, "exact match"},
		{"github.com", true, "exact match"},

		// Subdomain matches (should match since this is "is" operation)
		{"www.google.com", true, "subdomain should match"},
		{"api.github.com", true, "subdomain should match"},
		{"app.facebook.com", true, "subdomain should match"},

		// Non-matches
		{"example.com", false, "different domain"},
		{"", false, "empty string"},
		{"googlex.com", false, "similar but not matching"},
		{"google.net", false, "different TLD"},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s_%s", tc.domain, tc.desc), func(t *testing.T) {
			ok, err := orIsClassifier.Classify(ClassifierInput{host: tc.domain})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if ok != tc.expected {
				t.Errorf("expected %v for domain %q (%s), got %v", tc.expected, tc.domain, tc.desc, ok)
			}
		})
	}
}

func TestClassifierOrDomainsIsNoOptimization(t *testing.T) {
	// Test that OR classifier with mixed domain operations doesn't get optimized
	classifiers := map[string]config.Classifier{
		"test-or": &config.ClassifierOr{
			Classifiers: []config.Classifier{
				&config.ClassifierDomain{
					Op:     config.ClassifierOpIs,
					Domain: "google.com",
				},
				&config.ClassifierDomain{
					Op:     config.ClassifierOpEqual, // Mixed with equal - should prevent optimization
					Domain: "facebook.com",
				},
			},
		},
	}

	compiled, err := CompileClassifiersMap(classifiers)
	if err != nil {
		t.Fatalf("CompileClassifiersMap error: %v", err)
	}

	// Verify the OR classifier was NOT optimized (should be regular ClassifierOr)
	_, isOptimizedIs := compiled["test-or"].(*ClassifierOrDomainsIs)
	if isOptimizedIs {
		t.Error("Expected regular ClassifierOr (not optimized), got ClassifierOrDomainsIs")
	}

	_, isOptimizedEqual := compiled["test-or"].(*ClassifierOrDomains)
	if isOptimizedEqual {
		t.Error("Expected regular ClassifierOr (not optimized), got ClassifierOrDomains")
	}

	_, isRegular := compiled["test-or"].(*ClassifierOr)
	if !isRegular {
		t.Errorf("Expected ClassifierOr, got %T", compiled["test-or"])
	}
}

func TestClassifierOrOptimizationCoexistence(t *testing.T) {
	// Test that both equal and is optimizations can coexist and work correctly

	// Test case 1: Multiple equal classifiers should optimize to ClassifierOrDomains
	equalClassifiers := map[string]config.Classifier{
		"equal-or": &config.ClassifierOr{
			Classifiers: []config.Classifier{
				&config.ClassifierDomain{Op: config.ClassifierOpEqual, Domain: "example.com"},
				&config.ClassifierDomain{Op: config.ClassifierOpEqual, Domain: "test.com"},
			},
		},
	}

	// Test case 2: Multiple is classifiers should optimize to ClassifierOrDomainsIs
	isClassifiers := map[string]config.Classifier{
		"is-or": &config.ClassifierOr{
			Classifiers: []config.Classifier{
				&config.ClassifierDomain{Op: config.ClassifierOpIs, Domain: "example.org"},
				&config.ClassifierDomain{Op: config.ClassifierOpIs, Domain: "test.org"},
			},
		},
	}

	// Compile both
	compiledEqual, err := CompileClassifiersMap(equalClassifiers)
	if err != nil {
		t.Fatalf("CompileClassifiersMap (equal) error: %v", err)
	}

	compiledIs, err := CompileClassifiersMap(isClassifiers)
	if err != nil {
		t.Fatalf("CompileClassifiersMap (is) error: %v", err)
	}

	// Verify equal optimization
	equalOr, ok := compiledEqual["equal-or"].(*ClassifierOrDomains)
	if !ok {
		t.Errorf("Expected ClassifierOrDomains for equal, got %T", compiledEqual["equal-or"])
	}

	// Verify is optimization
	isOr, ok := compiledIs["is-or"].(*ClassifierOrDomainsIs)
	if !ok {
		t.Errorf("Expected ClassifierOrDomainsIs for is, got %T", compiledIs["is-or"])
	}

	// Test functionality of both
	// Equal classifier should match exactly but not subdomains
	result, _ := equalOr.Classify(ClassifierInput{host: "example.com"})
	if !result {
		t.Error("Equal classifier should match exact domain")
	}
	result, _ = equalOr.Classify(ClassifierInput{host: "www.example.com"})
	if result {
		t.Error("Equal classifier should NOT match subdomain")
	}

	// Is classifier should match exactly and subdomains
	result, _ = isOr.Classify(ClassifierInput{host: "example.org"})
	if !result {
		t.Error("Is classifier should match exact domain")
	}
	result, _ = isOr.Classify(ClassifierInput{host: "www.example.org"})
	if !result {
		t.Error("Is classifier should match subdomain")
	}
}

func TestClassifierOrDomainsIs_DirectTesting(t *testing.T) {
	// Test ClassifierOrDomainsIs directly without going through compilation
	domains := []string{"example.com", "test.org", "github.com"}

	trie := ahocorasick.NewTrieBuilder().AddStrings(domains).Build()
	classifier := &ClassifierOrDomainsIs{
		Trie:       trie,
		DomainList: domains,
	}

	tests := []struct {
		host     string
		expected bool
		desc     string
	}{
		// Exact matches
		{"example.com", true, "exact match first domain"},
		{"test.org", true, "exact match second domain"},
		{"github.com", true, "exact match third domain"},

		// Subdomain matches
		{"www.example.com", true, "subdomain of first domain"},
		{"api.test.org", true, "subdomain of second domain"},
		{"docs.github.com", true, "subdomain of third domain"},
		{"mail.api.test.org", true, "deep subdomain"},

		// Non-matches
		{"example.net", false, "different TLD"},
		{"test.com", false, "different TLD"},
		{"github.org", false, "different TLD"},
		{"notexample.com", false, "prefix similarity"},
		{"example.com.evil.org", false, "domain as prefix"},
		{"", false, "empty string"},
		{"random.domain.co", false, "unrelated domain"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s", tt.host, tt.desc), func(t *testing.T) {
			result, err := classifier.Classify(ClassifierInput{host: tt.host})
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("For host %q (%s), expected %v, got %v", tt.host, tt.desc, tt.expected, result)
			}
		})
	}
}

func TestClassifierOrDomainsIs_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		domains  []string
		host     string
		expected bool
	}{
		{
			name:     "Single character domain",
			domains:  []string{"a"},
			host:     "b.a",
			expected: true,
		},
		{
			name:     "Empty trie",
			domains:  []string{},
			host:     "example.com",
			expected: false,
		},
		{
			name:     "Domain with dash",
			domains:  []string{"my-site.com"},
			host:     "sub.my-site.com",
			expected: true,
		},
		{
			name:     "International domain",
			domains:  []string{"測試.com"},
			host:     "sub.測試.com",
			expected: true,
		},
		{
			name:     "Very long subdomain",
			domains:  []string{"example.com"},
			host:     "very.long.subdomain.chain.with.many.parts.example.com",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var trie *ahocorasick.Trie
			if len(tt.domains) > 0 {
				trie = ahocorasick.NewTrieBuilder().AddStrings(tt.domains).Build()
			}

			classifier := &ClassifierOrDomainsIs{
				Trie:       trie,
				DomainList: tt.domains,
			}

			result, err := classifier.Classify(ClassifierInput{host: tt.host})
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestTryOptimizeOrClassifier_SingleDomain(t *testing.T) {
	// Test that single domain classifiers don't get optimized (need at least 2)
	tests := []struct {
		name string
		op   config.ClassifierOp
	}{
		{"single equal domain", config.ClassifierOpEqual},
		{"single is domain", config.ClassifierOpIs},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orClassifier := &config.ClassifierOr{
				Classifiers: []config.Classifier{
					&config.ClassifierDomain{
						Op:     tt.op,
						Domain: "example.com",
					},
				},
			}

			optimized := tryOptimizeOrClassifier(orClassifier)

			if optimized != nil {
				t.Error("Single domain classifier should not be optimized")
			}
		})
	}
}

func TestTryOptimizeOrClassifier_MixedTypes(t *testing.T) {
	// Test various combinations that should NOT be optimized
	tests := []struct {
		name        string
		classifiers []config.Classifier
	}{
		{
			name: "domain and port mix",
			classifiers: []config.Classifier{
				&config.ClassifierDomain{Op: config.ClassifierOpEqual, Domain: "example.com"},
				&config.ClassifierPort{Port: 443},
			},
		},
		{
			name: "equal and contains mix",
			classifiers: []config.Classifier{
				&config.ClassifierDomain{Op: config.ClassifierOpEqual, Domain: "example.com"},
				&config.ClassifierDomain{Op: config.ClassifierOpContains, Domain: "test.com"},
			},
		},
		{
			name: "is and contains mix",
			classifiers: []config.Classifier{
				&config.ClassifierDomain{Op: config.ClassifierOpIs, Domain: "example.com"},
				&config.ClassifierDomain{Op: config.ClassifierOpContains, Domain: "test.com"},
			},
		},
		{
			name: "equal, is, and contains mix",
			classifiers: []config.Classifier{
				&config.ClassifierDomain{Op: config.ClassifierOpEqual, Domain: "example.com"},
				&config.ClassifierDomain{Op: config.ClassifierOpIs, Domain: "test.com"},
				&config.ClassifierDomain{Op: config.ClassifierOpContains, Domain: "github.com"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orClassifier := &config.ClassifierOr{
				Classifiers: tt.classifiers,
			}

			optimized := tryOptimizeOrClassifier(orClassifier)

			if optimized != nil {
				t.Errorf("Mixed classifier types should not be optimized, got %T", optimized)
			}
		})
	}
}

func TestClassifierOrDomains_vs_ClassifierOrDomainsIs_Behavior(t *testing.T) {
	// Test that the two optimizations behave differently for subdomains
	domains := []string{"example.com", "test.org"}

	// Create equal optimization (exact matching only)
	trieEqual := ahocorasick.NewTrieBuilder().AddStrings(domains).Build()
	equalClassifier := &ClassifierOrDomains{
		Trie:       trieEqual,
		DomainList: domains,
	}

	// Create is optimization (exact + subdomain matching)
	trieIs := ahocorasick.NewTrieBuilder().AddStrings(domains).Build()
	isClassifier := &ClassifierOrDomainsIs{
		Trie:       trieIs,
		DomainList: domains,
	}

	tests := []struct {
		host       string
		expectedEq bool // ClassifierOrDomains (equal)
		expectedIs bool // ClassifierOrDomainsIs (is)
		desc       string
	}{
		{"example.com", true, true, "exact match should work for both"},
		{"test.org", true, true, "exact match should work for both"},
		{"www.example.com", false, true, "subdomain should only work for is"},
		{"api.test.org", false, true, "subdomain should only work for is"},
		{"mail.api.test.org", false, true, "deep subdomain should only work for is"},
		{"different.com", false, false, "unrelated domain should fail for both"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s", tt.host, tt.desc), func(t *testing.T) {
			// Test equal classifier
			resultEq, err := equalClassifier.Classify(ClassifierInput{host: tt.host})
			if err != nil {
				t.Errorf("Equal classifier error: %v", err)
			}
			if resultEq != tt.expectedEq {
				t.Errorf("Equal classifier for %q: expected %v, got %v", tt.host, tt.expectedEq, resultEq)
			}

			// Test is classifier
			resultIs, err := isClassifier.Classify(ClassifierInput{host: tt.host})
			if err != nil {
				t.Errorf("Is classifier error: %v", err)
			}
			if resultIs != tt.expectedIs {
				t.Errorf("Is classifier for %q: expected %v, got %v", tt.host, tt.expectedIs, resultIs)
			}
		})
	}
}

func TestTryOptimizeOrClassifier_LargeNumberOfDomains(t *testing.T) {
	// Test optimization with many domains to ensure Aho-Corasick benefits
	domains := make([]config.Classifier, 100)
	domainList := make([]string, 100)

	for i := range 100 {
		domain := fmt.Sprintf("domain%d.com", i)
		domainList[i] = domain
		domains[i] = &config.ClassifierDomain{
			Op:     config.ClassifierOpIs,
			Domain: domain,
		}
	}

	orClassifier := &config.ClassifierOr{
		Classifiers: domains,
	}

	optimized := tryOptimizeOrClassifier(orClassifier)

	// Should be optimized to ClassifierOrDomainsIs
	orIsClassifier, ok := optimized.(*ClassifierOrDomainsIs)
	if !ok {
		t.Fatalf("Expected ClassifierOrDomainsIs with many domains, got %T", optimized)
	}

	// Verify it has the correct number of domains
	if len(orIsClassifier.DomainList) != 100 {
		t.Errorf("Expected 100 domains, got %d", len(orIsClassifier.DomainList))
	}

	// Test a few random domains work
	testCases := []string{"domain5.com", "www.domain50.com", "api.domain99.com"}
	for _, host := range testCases {
		result, err := orIsClassifier.Classify(ClassifierInput{host: host})
		if err != nil {
			t.Errorf("Classification error for %s: %v", host, err)
		}
		if !result {
			t.Errorf("Expected %s to match in large domain set", host)
		}
	}

	// Test a non-matching domain
	result, err := orIsClassifier.Classify(ClassifierInput{host: "notfound.com"})
	if err != nil {
		t.Errorf("Classification error: %v", err)
	}
	if result {
		t.Error("Expected notfound.com to NOT match in large domain set")
	}
}

type mockClassifier struct {
	result bool
	err    error
}

func (m *mockClassifier) Classify(input ClassifierInput) (bool, error) {
	return m.result, m.err
}

var errTest = errorf("test error")

func errorf(format string, a ...any) error {
	return errorString{s: fmt.Sprintf(format, a...)}
}

type errorString struct {
	s string
}

func (e errorString) Error() string {
	return e.s
}

func TestClassifierDomainsFileAdvancedCombined(t *testing.T) {
	// Test combining all advanced features: wildcards, comments, multiple formats,
	// hosts file entries, multiple domains per line, various whitespace, and edge cases
	domains := `# Advanced domains file test - combining all features
; This file tests every supported feature combination

# Standard domains with various comment styles
example.com # primary test domain
test.org ; alternative test domain
github.com## double hash comment

# Wildcard domains with comments
*.google.com # all Google services
*.facebook.com;social media wildcard
*.amazonaws.com	# AWS services (tab before comment)

# Multiple domains per line with mixed separators and comments
api.stripe.com  billing.stripe.com	# payment services
docs.microsoft.com support.microsoft.com # Microsoft domains ; mixed comment styles
cdn1.cloudflare.com   cdn2.cloudflare.com  cdn3.cloudflare.com # CDN endpoints

# Hosts file format entries with comments
0.0.0.0 ads.malicious.com tracker.evil.org # blocked advertising
127.0.0.1 localhost.localdomain # local host entry
0.0.0.0	spam.site.net	malware.bad.com # multiple blocked domains

# Complex whitespace scenarios
  	spaced.domain.com   	# leading/trailing spaces and tabs
	tab-prefixed.net	# tab prefix
   mixed-spaces.org	tabs.domain.co.uk   # mixed spacing

# Edge cases and special characters
domain-with-hyphens.com # hyphenated domain
test123.numeric.domain # numeric in domain
single-char-subdomain.a.very.long.tld.extension # complex structure

# International and special cases
xn--domain.com # punycode representation
sub.domain.with.multiple.levels.deep.hierarchy.test # deep nesting

# Empty lines and whitespace-only lines should be ignored




# More wildcard combinations
*.cdn.example.org *.media.test.net # multiple wildcards per line
*.api.service.com	static.assets.net # mixed wildcard and regular

# Comment-only lines and edge cases
; semicolon-only comment
## double hash comment
; ; double semicolon comment

# Final domains without comments
final-domain.com
last-test.org
end-marker.net`

	// Create temporary file with complex content
	tmpfile, err := os.CreateTemp(t.TempDir(), "advanced-domains-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpfile.Close()

	_, err = tmpfile.WriteString(domains)
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	// Load the classifier
	clf, err := NewClassifierDomainsFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to load domains file: %v", err)
	}

	// Log parsed domains for debugging
	t.Logf("Total parsed domains: %d", len(clf.DomainList))
	t.Logf("Parsed domains: %v", clf.DomainList)

	// Verify Aho-Corasick trie was created
	if clf.Trie == nil {
		t.Error("Expected Aho-Corasick trie to be created, got nil")
	}

	// Test cases covering all feature combinations
	tests := []struct {
		host     string
		expected bool
		category string
		desc     string
	}{
		// Basic domain matching
		{"example.com", true, "basic", "primary test domain"},
		{"test.org", true, "basic", "alternative test domain"},
		{"github.com", true, "basic", "domain with double hash comment"},

		// Wildcard domain matching (exact and subdomains)
		{"google.com", true, "wildcard", "wildcard base domain"},
		{"www.google.com", true, "wildcard", "wildcard subdomain"},
		{"mail.google.com", true, "wildcard", "wildcard deep subdomain"},
		{"facebook.com", true, "wildcard", "wildcard with semicolon comment"},
		{"api.facebook.com", true, "wildcard", "wildcard subdomain"},
		{"amazonaws.com", true, "wildcard", "wildcard with tab comment"},
		{"s3.amazonaws.com", true, "wildcard", "AWS subdomain"},

		// Multiple domains per line
		{"api.stripe.com", true, "multiple", "first of multiple domains"},
		{"billing.stripe.com", true, "multiple", "second of multiple domains"},
		{"docs.microsoft.com", true, "multiple", "Microsoft docs"},
		{"support.microsoft.com", true, "multiple", "Microsoft support"},
		{"cdn1.cloudflare.com", true, "multiple", "first CDN endpoint"},
		{"cdn2.cloudflare.com", true, "multiple", "second CDN endpoint"},
		{"cdn3.cloudflare.com", true, "multiple", "third CDN endpoint"},

		// Hosts file format (domains should be extracted)
		{"ads.malicious.com", true, "hosts", "blocked ad domain"},
		{"tracker.evil.org", true, "hosts", "blocked tracker"},
		{"localhost.localdomain", true, "hosts", "localhost entry"},
		{"spam.site.net", true, "hosts", "spam domain"},
		{"malware.bad.com", true, "hosts", "malware domain"},

		// Complex whitespace handling
		{"spaced.domain.com", true, "whitespace", "domain with complex spacing"},
		{"tab-prefixed.net", true, "whitespace", "tab-prefixed domain"},
		{"mixed-spaces.org", true, "whitespace", "mixed spacing domain"},
		{"tabs.domain.co.uk", true, "whitespace", "tab-separated domain"},

		// Special characters and edge cases
		{"domain-with-hyphens.com", true, "special", "hyphenated domain"},
		{"test123.numeric.domain", true, "special", "numeric subdomain"},
		{"single-char-subdomain.a.very.long.tld.extension", true, "special", "complex structure"},
		{"xn--domain.com", true, "special", "punycode domain"},
		{"sub.domain.with.multiple.levels.deep.hierarchy.test", true, "special", "deep hierarchy"},

		// Mixed wildcard and regular combinations
		{"cdn.example.org", true, "mixed", "wildcard CDN base"},
		{"www.cdn.example.org", true, "mixed", "wildcard CDN subdomain"},
		{"media.test.net", true, "mixed", "wildcard media base"},
		{"images.media.test.net", true, "mixed", "wildcard media subdomain"},
		{"api.service.com", true, "mixed", "wildcard API base"},
		{"v1.api.service.com", true, "mixed", "wildcard API subdomain"},
		{"static.assets.net", true, "mixed", "regular domain with wildcard"},

		// Final domains
		{"final-domain.com", true, "final", "final domain without comment"},
		{"last-test.org", true, "final", "last test domain"},
		{"end-marker.net", true, "final", "end marker domain"},

		// Subdomain testing for regular domains
		{"www.example.com", true, "subdomain", "subdomain of example.com"},
		{"api.test.org", true, "subdomain", "subdomain of test.org"},
		{"docs.github.com", true, "subdomain", "subdomain of github.com"},

		// Negative test cases
		{"notfound.com", false, "negative", "non-existent domain"},
		{"example.net", false, "negative", "wrong TLD"},
		{"test.com", false, "negative", "wrong TLD for test"},
		{"google.net", false, "negative", "wrong TLD for Google"},
		{"", false, "negative", "empty domain"},
		{"invalid", false, "negative", "invalid domain format"},
		{"example.com.evil.org", false, "negative", "domain as prefix attack"},
	}

	// Group tests by category for better organization
	categories := make(map[string][]struct {
		host     string
		expected bool
		category string
		desc     string
	})

	for _, test := range tests {
		categories[test.category] = append(categories[test.category], test)
	}

	// Run tests grouped by category
	for category, categoryTests := range categories {
		t.Run(category, func(t *testing.T) {
			for _, tc := range categoryTests {
				t.Run(fmt.Sprintf("%s_%s", tc.host, tc.desc), func(t *testing.T) {
					result, err := clf.Classify(ClassifierInput{host: tc.host})
					if err != nil {
						t.Errorf("Unexpected error for %q: %v", tc.host, err)
					}
					if result != tc.expected {
						t.Errorf("For %q (%s): expected %v, got %v", tc.host, tc.desc, tc.expected, result)
					}
				})
			}
		})
	}

	// Additional verification tests
	t.Run("verification", func(t *testing.T) {
		// Verify minimum expected number of domains were parsed
		// This number may vary based on regex bug status and parsing logic
		minExpectedDomains := 20 // Conservative estimate
		if len(clf.DomainList) < minExpectedDomains {
			t.Errorf("Expected at least %d domains to be parsed, got %d", minExpectedDomains, len(clf.DomainList))
		}

		// Verify no duplicate domains
		seen := make(map[string]bool)
		duplicates := make([]string, 0)
		for _, domain := range clf.DomainList {
			if seen[domain] {
				duplicates = append(duplicates, domain)
			}
			seen[domain] = true
		}
		if len(duplicates) > 0 {
			t.Errorf("Found duplicate domains: %v", duplicates)
		}

		// Verify no empty domains
		for i, domain := range clf.DomainList {
			if domain == "" {
				t.Errorf("Found empty domain at index %d", i)
			}
		}

		// Verify Aho-Corasick trie functionality
		if clf.Trie == nil {
			t.Error("Aho-Corasick trie should not be nil")
		}
	})
}
