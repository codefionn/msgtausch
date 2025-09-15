package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifierRecord(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]any
		expected ClassifierType
		wantErr  bool
	}{
		{
			name: "valid record classifier with domain classifier",
			input: map[string]any{
				"type": "record",
				"classifier": map[string]any{
					"type":   "domain",
					"op":     "contains",
					"domain": "example.com",
				},
			},
			expected: ClassifierTypeRecord,
			wantErr:  false,
		},
		{
			name: "valid record classifier with true classifier",
			input: map[string]any{
				"type": "record",
				"classifier": map[string]any{
					"type": "true",
				},
			},
			expected: ClassifierTypeRecord,
			wantErr:  false,
		},
		{
			name: "record classifier missing classifier field",
			input: map[string]any{
				"type": "record",
			},
			expected: ClassifierTypeRecord,
			wantErr:  true,
		},
		{
			name: "record classifier with invalid nested classifier",
			input: map[string]any{
				"type": "record",
				"classifier": map[string]any{
					"type": "invalid",
				},
			},
			expected: ClassifierTypeRecord,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classifier, err := parseClassifier(tt.input)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, classifier.Type())

			recordClassifier, ok := classifier.(*ClassifierRecord)
			require.True(t, ok, "Expected ClassifierRecord type")
			require.NotNil(t, recordClassifier.Classifier, "Expected wrapped classifier to be set")
		})
	}
}

func TestClassifierRecordType(t *testing.T) {
	// Test that ClassifierRecord correctly returns its type
	record := &ClassifierRecord{
		Classifier: &ClassifierTrue{},
	}

	assert.Equal(t, ClassifierTypeRecord, record.Type())
}

func TestClassifierRecordNested(t *testing.T) {
	// Test nested record classifier with complex classifier
	input := map[string]any{
		"type": "record",
		"classifier": map[string]any{
			"type": "and",
			"classifiers": []any{
				map[string]any{
					"type":   "domain",
					"op":     "contains",
					"domain": "api",
				},
				map[string]any{
					"type": "port",
					"port": 443,
				},
			},
		},
	}

	classifier, err := parseClassifier(input)
	require.NoError(t, err)

	recordClassifier, ok := classifier.(*ClassifierRecord)
	require.True(t, ok)

	andClassifier, ok := recordClassifier.Classifier.(*ClassifierAnd)
	require.True(t, ok)
	assert.Len(t, andClassifier.Classifiers, 2)
}

func TestParseClassifierWithRecord(t *testing.T) {
	// Test that record classifier is properly recognized in parsing
	testCases := []struct {
		name        string
		input       map[string]any
		expectType  ClassifierType
		expectError bool
	}{
		{
			name: "record with domain",
			input: map[string]any{
				"type": "record",
				"classifier": map[string]any{
					"type":   "domain",
					"op":     "equal",
					"domain": "test.com",
				},
			},
			expectType:  ClassifierTypeRecord,
			expectError: false,
		},
		{
			name: "record with network",
			input: map[string]any{
				"type": "record",
				"classifier": map[string]any{
					"type": "network",
					"cidr": "192.168.1.0/24",
				},
			},
			expectType:  ClassifierTypeRecord,
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parseClassifier(tc.input)

			if tc.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expectType, result.Type())

			if tc.expectType == ClassifierTypeRecord {
				recordClassifier, ok := result.(*ClassifierRecord)
				require.True(t, ok)
				assert.NotNil(t, recordClassifier.Classifier)
			}
		})
	}
}
