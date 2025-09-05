package config

import (
	"testing"
)

func TestClassifierTrueFalse_Type(t *testing.T) {
	if (&ClassifierTrue{}).Type() != ClassifierTypeTrue {
		t.Errorf("ClassifierTrue.Type() = %v, want %v", (&ClassifierTrue{}).Type(), ClassifierTypeTrue)
	}
	if (&ClassifierFalse{}).Type() != ClassifierTypeFalse {
		t.Errorf("ClassifierFalse.Type() = %v, want %v", (&ClassifierFalse{}).Type(), ClassifierTypeFalse)
	}
}

func TestParseClassifier_TrueFalse(t *testing.T) {
	cases := []struct {
		name         string
		input        map[string]any
		expectedType ClassifierType
	}{
		{"true classifier", map[string]any{"type": "true"}, ClassifierTypeTrue},
		{"false classifier", map[string]any{"type": "false"}, ClassifierTypeFalse},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cl, err := parseClassifier(c.input)
			if err != nil {
				t.Fatalf("parseClassifier error: %v", err)
			}
			if cl.Type() != c.expectedType {
				t.Errorf("got type %v, want %v", cl.Type(), c.expectedType)
			}
		})
	}
}

func TestParseClassifier_OrClassifier(t *testing.T) {
	testCases := []struct {
		name        string
		input       map[string]any
		expectError bool
		validate    func(t *testing.T, classifier Classifier)
	}{
		{
			name: "OR classifier with domain and port sub-classifiers",
			input: map[string]any{
				"type": "or",
				"classifiers": []any{
					map[string]any{
						"type":   "domain",
						"domain": "example.com",
						"op":     "equal",
					},
					map[string]any{
						"type": "port",
						"port": float64(443),
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, classifier Classifier) {
				orClassifier, ok := classifier.(*ClassifierOr)
				if !ok {
					t.Fatalf("Expected *ClassifierOr, got %T", classifier)
				}
				if len(orClassifier.Classifiers) != 2 {
					t.Fatalf("Expected 2 sub-classifiers, got %d", len(orClassifier.Classifiers))
				}

				// Check first sub-classifier (domain)
				domainClassifier, ok := orClassifier.Classifiers[0].(*ClassifierDomain)
				if !ok {
					t.Errorf("Expected first sub-classifier to be *ClassifierDomain, got %T", orClassifier.Classifiers[0])
				} else {
					if domainClassifier.Domain != "example.com" {
						t.Errorf("Expected domain 'example.com', got '%s'", domainClassifier.Domain)
					}
					if domainClassifier.Op != ClassifierOpEqual {
						t.Errorf("Expected ClassifierOpEqual, got %v", domainClassifier.Op)
					}
				}

				// Check second sub-classifier (port)
				portClassifier, ok := orClassifier.Classifiers[1].(*ClassifierPort)
				if !ok {
					t.Errorf("Expected second sub-classifier to be *ClassifierPort, got %T", orClassifier.Classifiers[1])
				} else if portClassifier.Port != 443 {
					t.Errorf("Expected port 443, got %d", portClassifier.Port)
				}
			},
		},
		{
			name: "OR classifier with IP and network sub-classifiers",
			input: map[string]any{
				"type": "or",
				"classifiers": []any{
					map[string]any{
						"type": "ip",
						"ip":   "192.168.1.1",
					},
					map[string]any{
						"type": "network",
						"cidr": "10.0.0.0/8",
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, classifier Classifier) {
				orClassifier, ok := classifier.(*ClassifierOr)
				if !ok {
					t.Fatalf("Expected *ClassifierOr, got %T", classifier)
				}
				if len(orClassifier.Classifiers) != 2 {
					t.Fatalf("Expected 2 sub-classifiers, got %d", len(orClassifier.Classifiers))
				}

				// Check first sub-classifier (IP)
				ipClassifier, ok := orClassifier.Classifiers[0].(*ClassifierIP)
				if !ok {
					t.Errorf("Expected first sub-classifier to be *ClassifierIP, got %T", orClassifier.Classifiers[0])
				} else if ipClassifier.IP != "192.168.1.1" {
					t.Errorf("Expected IP '192.168.1.1', got '%s'", ipClassifier.IP)
				}

				// Check second sub-classifier (network)
				networkClassifier, ok := orClassifier.Classifiers[1].(*ClassifierNetwork)
				if !ok {
					t.Errorf("Expected second sub-classifier to be *ClassifierNetwork, got %T", orClassifier.Classifiers[1])
				} else if networkClassifier.CIDR != "10.0.0.0/8" {
					t.Errorf("Expected CIDR '10.0.0.0/8', got '%s'", networkClassifier.CIDR)
				}
			},
		},
		{
			name: "OR classifier with single true sub-classifier",
			input: map[string]any{
				"type": "or",
				"classifiers": []any{
					map[string]any{"type": "true"},
				},
			},
			expectError: false,
			validate: func(t *testing.T, classifier Classifier) {
				orClassifier, ok := classifier.(*ClassifierOr)
				if !ok {
					t.Fatalf("Expected *ClassifierOr, got %T", classifier)
				}
				if len(orClassifier.Classifiers) != 1 {
					t.Fatalf("Expected 1 sub-classifier, got %d", len(orClassifier.Classifiers))
				}

				if _, ok := orClassifier.Classifiers[0].(*ClassifierTrue); !ok {
					t.Errorf("Expected sub-classifier to be *ClassifierTrue, got %T", orClassifier.Classifiers[0])
				}
			},
		},
		{
			name: "OR classifier with empty sub-classifiers",
			input: map[string]any{
				"type":        "or",
				"classifiers": []any{},
			},
			expectError: false,
			validate: func(t *testing.T, classifier Classifier) {
				orClassifier, ok := classifier.(*ClassifierOr)
				if !ok {
					t.Fatalf("Expected *ClassifierOr, got %T", classifier)
				}
				if len(orClassifier.Classifiers) != 0 {
					t.Fatalf("Expected 0 sub-classifiers, got %d", len(orClassifier.Classifiers))
				}
			},
		},
		{
			name: "OR classifier without classifiers field",
			input: map[string]any{
				"type": "or",
			},
			expectError: false,
			validate: func(t *testing.T, classifier Classifier) {
				orClassifier, ok := classifier.(*ClassifierOr)
				if !ok {
					t.Fatalf("Expected *ClassifierOr, got %T", classifier)
				}
				if orClassifier.Classifiers != nil {
					t.Fatalf("Expected nil sub-classifiers slice, got %v", orClassifier.Classifiers)
				}
			},
		},
		{
			name: "OR classifier with invalid sub-classifier",
			input: map[string]any{
				"type": "or",
				"classifiers": []any{
					map[string]any{"type": "invalid-type"},
				},
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			classifier, err := parseClassifier(tc.input)

			if (err != nil) != tc.expectError {
				t.Fatalf("parseClassifier() error = %v, expectError %v", err, tc.expectError)
			}

			if !tc.expectError && tc.validate != nil {
				tc.validate(t, classifier)
			}
		})
	}
}

func TestParseClassifier_NotClassifier(t *testing.T) {
	testCases := []struct {
		name        string
		input       map[string]any
		expectError bool
		validate    func(t *testing.T, classifier Classifier)
	}{
		{
			name: "NOT classifier with domain sub-classifier",
			input: map[string]any{
				"type": "not",
				"classifier": map[string]any{
					"type":   "domain",
					"domain": "example.com",
					"op":     "equal",
				},
			},
			expectError: false,
			validate: func(t *testing.T, classifier Classifier) {
				notClassifier, ok := classifier.(*ClassifierNot)
				if !ok {
					t.Fatalf("Expected *ClassifierNot, got %T", classifier)
				}

				domainClassifier, ok := notClassifier.Classifier.(*ClassifierDomain)
				if !ok {
					t.Fatalf("Expected sub-classifier to be *ClassifierDomain, got %T", notClassifier.Classifier)
				}
				if domainClassifier.Domain != "example.com" {
					t.Errorf("Expected domain 'example.com', got '%s'", domainClassifier.Domain)
				}
				if domainClassifier.Op != ClassifierOpEqual {
					t.Errorf("Expected ClassifierOpEqual, got %v", domainClassifier.Op)
				}
			},
		},
		{
			name: "NOT classifier with port sub-classifier",
			input: map[string]any{
				"type": "not",
				"classifier": map[string]any{
					"type": "port",
					"port": float64(80),
				},
			},
			expectError: false,
			validate: func(t *testing.T, classifier Classifier) {
				notClassifier, ok := classifier.(*ClassifierNot)
				if !ok {
					t.Fatalf("Expected *ClassifierNot, got %T", classifier)
				}

				portClassifier, ok := notClassifier.Classifier.(*ClassifierPort)
				if !ok {
					t.Fatalf("Expected sub-classifier to be *ClassifierPort, got %T", notClassifier.Classifier)
				}
				if portClassifier.Port != 80 {
					t.Errorf("Expected port 80, got %d", portClassifier.Port)
				}
			},
		},
		{
			name: "NOT classifier with true sub-classifier",
			input: map[string]any{
				"type": "not",
				"classifier": map[string]any{
					"type": "true",
				},
			},
			expectError: false,
			validate: func(t *testing.T, classifier Classifier) {
				notClassifier, ok := classifier.(*ClassifierNot)
				if !ok {
					t.Fatalf("Expected *ClassifierNot, got %T", classifier)
				}

				if _, ok := notClassifier.Classifier.(*ClassifierTrue); !ok {
					t.Errorf("Expected sub-classifier to be *ClassifierTrue, got %T", notClassifier.Classifier)
				}
			},
		},
		{
			name: "NOT classifier without classifier field",
			input: map[string]any{
				"type": "not",
			},
			expectError: false,
			validate: func(t *testing.T, classifier Classifier) {
				notClassifier, ok := classifier.(*ClassifierNot)
				if !ok {
					t.Fatalf("Expected *ClassifierNot, got %T", classifier)
				}
				if notClassifier.Classifier != nil {
					t.Fatalf("Expected nil sub-classifier, got %v", notClassifier.Classifier)
				}
			},
		},
		{
			name: "NOT classifier with invalid sub-classifier",
			input: map[string]any{
				"type": "not",
				"classifier": map[string]any{
					"type": "invalid-type",
				},
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			classifier, err := parseClassifier(tc.input)

			if (err != nil) != tc.expectError {
				t.Fatalf("parseClassifier() error = %v, expectError %v", err, tc.expectError)
			}

			if !tc.expectError && tc.validate != nil {
				tc.validate(t, classifier)
			}
		})
	}
}

func TestParseClassifier_NestedClassifiers(t *testing.T) {
	testCases := []struct {
		name        string
		input       map[string]any
		expectError bool
		validate    func(t *testing.T, classifier Classifier)
	}{
		{
			name: "OR classifier containing AND classifier",
			input: map[string]any{
				"type": "or",
				"classifiers": []any{
					map[string]any{
						"type": "and",
						"classifiers": []any{
							map[string]any{
								"type":   "domain",
								"domain": "example.com",
								"op":     "equal",
							},
							map[string]any{
								"type": "port",
								"port": float64(443),
							},
						},
					},
					map[string]any{
						"type": "ip",
						"ip":   "192.168.1.1",
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, classifier Classifier) {
				orClassifier, ok := classifier.(*ClassifierOr)
				if !ok {
					t.Fatalf("Expected *ClassifierOr, got %T", classifier)
				}
				if len(orClassifier.Classifiers) != 2 {
					t.Fatalf("Expected 2 sub-classifiers, got %d", len(orClassifier.Classifiers))
				}

				// Check first sub-classifier (AND)
				andClassifier, ok := orClassifier.Classifiers[0].(*ClassifierAnd)
				if !ok {
					t.Fatalf("Expected first sub-classifier to be *ClassifierAnd, got %T", orClassifier.Classifiers[0])
				}
				if len(andClassifier.Classifiers) != 2 {
					t.Fatalf("Expected AND classifier to have 2 sub-classifiers, got %d", len(andClassifier.Classifiers))
				}

				// Check second sub-classifier (IP)
				ipClassifier, ok := orClassifier.Classifiers[1].(*ClassifierIP)
				if !ok {
					t.Fatalf("Expected second sub-classifier to be *ClassifierIP, got %T", orClassifier.Classifiers[1])
				}
				if ipClassifier.IP != "192.168.1.1" {
					t.Errorf("Expected IP '192.168.1.1', got '%s'", ipClassifier.IP)
				}
			},
		},
		{
			name: "NOT classifier containing OR classifier",
			input: map[string]any{
				"type": "not",
				"classifier": map[string]any{
					"type": "or",
					"classifiers": []any{
						map[string]any{
							"type": "port",
							"port": float64(80),
						},
						map[string]any{
							"type": "port",
							"port": float64(8080),
						},
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, classifier Classifier) {
				notClassifier, ok := classifier.(*ClassifierNot)
				if !ok {
					t.Fatalf("Expected *ClassifierNot, got %T", classifier)
				}

				orClassifier, ok := notClassifier.Classifier.(*ClassifierOr)
				if !ok {
					t.Fatalf("Expected sub-classifier to be *ClassifierOr, got %T", notClassifier.Classifier)
				}
				if len(orClassifier.Classifiers) != 2 {
					t.Fatalf("Expected OR classifier to have 2 sub-classifiers, got %d", len(orClassifier.Classifiers))
				}
			},
		},
		{
			name: "AND classifier containing NOT classifier",
			input: map[string]any{
				"type": "and",
				"classifiers": []any{
					map[string]any{
						"type":   "domain",
						"domain": "example.com",
						"op":     "contains",
					},
					map[string]any{
						"type": "not",
						"classifier": map[string]any{
							"type": "port",
							"port": float64(443),
						},
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, classifier Classifier) {
				andClassifier, ok := classifier.(*ClassifierAnd)
				if !ok {
					t.Fatalf("Expected *ClassifierAnd, got %T", classifier)
				}
				if len(andClassifier.Classifiers) != 2 {
					t.Fatalf("Expected 2 sub-classifiers, got %d", len(andClassifier.Classifiers))
				}

				// Check first sub-classifier (domain)
				domainClassifier, ok := andClassifier.Classifiers[0].(*ClassifierDomain)
				if !ok {
					t.Fatalf("Expected first sub-classifier to be *ClassifierDomain, got %T", andClassifier.Classifiers[0])
				}
				if domainClassifier.Domain != "example.com" {
					t.Errorf("Expected domain 'example.com', got '%s'", domainClassifier.Domain)
				}

				// Check second sub-classifier (NOT)
				notClassifier, ok := andClassifier.Classifiers[1].(*ClassifierNot)
				if !ok {
					t.Fatalf("Expected second sub-classifier to be *ClassifierNot, got %T", andClassifier.Classifiers[1])
				}

				// Check NOT's sub-classifier (port)
				portClassifier, ok := notClassifier.Classifier.(*ClassifierPort)
				if !ok {
					t.Fatalf("Expected NOT's sub-classifier to be *ClassifierPort, got %T", notClassifier.Classifier)
				}
				if portClassifier.Port != 443 {
					t.Errorf("Expected port 443, got %d", portClassifier.Port)
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			classifier, err := parseClassifier(tc.input)

			if (err != nil) != tc.expectError {
				t.Fatalf("parseClassifier() error = %v, expectError %v", err, tc.expectError)
			}

			if !tc.expectError && tc.validate != nil {
				tc.validate(t, classifier)
			}
		})
	}
}
