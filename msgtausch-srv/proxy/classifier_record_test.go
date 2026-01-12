package proxy

import (
	"testing"

	"github.com/codefionn/msgtausch/msgtausch-srv/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifierRecordCompilation(t *testing.T) {
	tests := []struct {
		name             string
		configClassifier config.Classifier
		expectError      bool
		testInput        ClassifierInput
		expectedResult   bool
	}{
		{
			name: "record classifier with domain classifier",
			configClassifier: &config.ClassifierRecord{
				Classifier: &config.ClassifierDomain{
					Op:     config.ClassifierOpContains,
					Domain: "example",
				},
			},
			expectError: false,
			testInput: ClassifierInput{
				host:       "api.example.com",
				remotePort: 80,
			},
			expectedResult: true,
		},
		{
			name: "record classifier with domain classifier - no match",
			configClassifier: &config.ClassifierRecord{
				Classifier: &config.ClassifierDomain{
					Op:     config.ClassifierOpContains,
					Domain: "example",
				},
			},
			expectError: false,
			testInput: ClassifierInput{
				host:       "google.com",
				remotePort: 80,
			},
			expectedResult: false,
		},
		{
			name: "record classifier with port classifier",
			configClassifier: &config.ClassifierRecord{
				Classifier: &config.ClassifierPort{
					Port: 443,
				},
			},
			expectError: false,
			testInput: ClassifierInput{
				host:       "any.com",
				remotePort: 443,
			},
			expectedResult: true,
		},
		{
			name: "record classifier with true classifier",
			configClassifier: &config.ClassifierRecord{
				Classifier: &config.ClassifierTrue{},
			},
			expectError: false,
			testInput: ClassifierInput{
				host:       "any.com",
				remotePort: 80,
			},
			expectedResult: true,
		},
		{
			name: "record classifier with false classifier",
			configClassifier: &config.ClassifierRecord{
				Classifier: &config.ClassifierFalse{},
			},
			expectError: false,
			testInput: ClassifierInput{
				host:       "any.com",
				remotePort: 80,
			},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiledClassifier, err := CompileClassifier(tt.configClassifier, nil)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, compiledClassifier)

			// Verify it's a ClassifierRecord
			recordClassifier, ok := compiledClassifier.(*ClassifierRecord)
			require.True(t, ok, "Expected ClassifierRecord type")
			require.NotNil(t, recordClassifier.WrappedClassifier)

			// Test classification
			result, err := recordClassifier.Classify(tt.testInput)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestClassifierRecordWithComplexClassifier(t *testing.T) {
	// Test record classifier with AND logic
	configClassifier := &config.ClassifierRecord{
		Classifier: &config.ClassifierAnd{
			Classifiers: []config.Classifier{
				&config.ClassifierDomain{
					Op:     config.ClassifierOpContains,
					Domain: "api",
				},
				&config.ClassifierPort{
					Port: 443,
				},
			},
		},
	}

	compiledClassifier, err := CompileClassifier(configClassifier, nil)
	require.NoError(t, err)

	recordClassifier, ok := compiledClassifier.(*ClassifierRecord)
	require.True(t, ok)

	// Test cases
	testCases := []struct {
		name     string
		input    ClassifierInput
		expected bool
	}{
		{
			name: "matches both conditions",
			input: ClassifierInput{
				host:       "api.example.com",
				remotePort: 443,
			},
			expected: true,
		},
		{
			name: "matches domain but not port",
			input: ClassifierInput{
				host:       "api.example.com",
				remotePort: 80,
			},
			expected: false,
		},
		{
			name: "matches port but not domain",
			input: ClassifierInput{
				host:       "web.example.com",
				remotePort: 443,
			},
			expected: false,
		},
		{
			name: "matches neither",
			input: ClassifierInput{
				host:       "web.example.com",
				remotePort: 80,
			},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := recordClassifier.Classify(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestClassifierRecordWithOrClassifier(t *testing.T) {
	// Test record classifier with OR logic
	configClassifier := &config.ClassifierRecord{
		Classifier: &config.ClassifierOr{
			Classifiers: []config.Classifier{
				&config.ClassifierDomain{
					Op:     config.ClassifierOpEqual,
					Domain: "test.com",
				},
				&config.ClassifierPort{
					Port: 8080,
				},
			},
		},
	}

	compiledClassifier, err := CompileClassifier(configClassifier, nil)
	require.NoError(t, err)

	recordClassifier, ok := compiledClassifier.(*ClassifierRecord)
	require.True(t, ok)

	testCases := []struct {
		name     string
		input    ClassifierInput
		expected bool
	}{
		{
			name: "matches domain condition",
			input: ClassifierInput{
				host:       "test.com",
				remotePort: 80,
			},
			expected: true,
		},
		{
			name: "matches port condition",
			input: ClassifierInput{
				host:       "other.com",
				remotePort: 8080,
			},
			expected: true,
		},
		{
			name: "matches both conditions",
			input: ClassifierInput{
				host:       "test.com",
				remotePort: 8080,
			},
			expected: true,
		},
		{
			name: "matches neither",
			input: ClassifierInput{
				host:       "other.com",
				remotePort: 80,
			},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := recordClassifier.Classify(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestClassifierRecordWithNotClassifier(t *testing.T) {
	// Test record classifier with NOT logic
	configClassifier := &config.ClassifierRecord{
		Classifier: &config.ClassifierNot{
			Classifier: &config.ClassifierDomain{
				Op:     config.ClassifierOpContains,
				Domain: "internal",
			},
		},
	}

	compiledClassifier, err := CompileClassifier(configClassifier, nil)
	require.NoError(t, err)

	recordClassifier, ok := compiledClassifier.(*ClassifierRecord)
	require.True(t, ok)

	testCases := []struct {
		name     string
		input    ClassifierInput
		expected bool
	}{
		{
			name: "does not contain 'internal'",
			input: ClassifierInput{
				host:       "api.example.com",
				remotePort: 80,
			},
			expected: true,
		},
		{
			name: "contains 'internal'",
			input: ClassifierInput{
				host:       "internal.example.com",
				remotePort: 80,
			},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := recordClassifier.Classify(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestClassifierRecordDirectClassify(t *testing.T) {
	// Test the Classify method directly
	wrappedClassifier := &ClassifierTrue{}
	recordClassifier := &ClassifierRecord{
		WrappedClassifier: wrappedClassifier,
	}

	input := ClassifierInput{
		host:       "test.com",
		remotePort: 80,
	}

	result, err := recordClassifier.Classify(input)
	require.NoError(t, err)
	assert.True(t, result)

	// Test with false classifier
	recordClassifier.WrappedClassifier = &ClassifierFalse{}
	result, err = recordClassifier.Classify(input)
	require.NoError(t, err)
	assert.False(t, result)
}
