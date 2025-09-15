package logger

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
)

// captureOutput captures log output during test execution
func captureOutput(f func()) string {
	// Create a pipe to capture the output
	oldOutput := stdLogger.Writer()
	r, w, _ := os.Pipe()
	stdLogger.SetOutput(w)

	// Run the function that produces output
	f()

	// Restore the original output and read the captured output
	w.Close()
	stdLogger.SetOutput(oldOutput)

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	return buf.String()
}

func TestSetLevel(t *testing.T) {
	tests := []struct {
		name          string
		level         LogLevel
		expectedLevel LogLevel
	}{
		{"set debug level", DEBUG, DEBUG},
		{"set info level", INFO, INFO},
		{"set warn level", WARN, WARN},
		{"set error level", ERROR, ERROR},
		{"set fatal level", FATAL, FATAL},
	}

	// Save the original level to restore it after the test
	originalLevel := GetLevel()
	defer func() {
		SetLevel(originalLevel)
	}()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetLevel(tt.level)
			if GetLevel() != tt.expectedLevel {
				t.Errorf("SetLevel() = %v, want %v", GetLevel(), tt.expectedLevel)
			}
		})
	}
}

func TestGetLevelFromString(t *testing.T) {
	tests := []struct {
		name          string
		levelStr      string
		expectedLevel LogLevel
	}{
		{"debug level", "DEBUG", DEBUG},
		{"info level", "INFO", INFO},
		{"warn level", "WARN", WARN},
		{"error level", "ERROR", ERROR},
		{"fatal level", "FATAL", FATAL},
		{"lowercase debug", "debug", DEBUG},
		{"mixed case warn", "WaRn", WARN},
		{"unknown level", "UNKNOWN", INFO}, // Default is INFO
		{"empty string", "", INFO},         // Default is INFO
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetLevelFromString(tt.levelStr); got != tt.expectedLevel {
				t.Errorf("GetLevelFromString(%q) = %v, want %v", tt.levelStr, got, tt.expectedLevel)
			}
		})
	}
}

func TestLevelToString(t *testing.T) {
	tests := []struct {
		name           string
		level          LogLevel
		expectedString string
	}{
		{"debug level", DEBUG, "DEBUG"},
		{"info level", INFO, "INFO"},
		{"warn level", WARN, "WARN"},
		{"error level", ERROR, "ERROR"},
		{"fatal level", FATAL, "FATAL"},
		{"unknown level", LogLevel(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := levelToString(tt.level); got != tt.expectedString {
				t.Errorf("levelToString(%v) = %q, want %q", tt.level, got, tt.expectedString)
			}
		})
	}
}

func TestLogLevelFiltering(t *testing.T) {
	tests := []struct {
		name            string
		currentLevel    LogLevel
		logLevel        LogLevel
		shouldBePrinted bool
	}{
		{"debug with debug level", DEBUG, DEBUG, true},
		{"info with debug level", DEBUG, INFO, true},
		{"warn with debug level", DEBUG, WARN, true},
		{"error with debug level", DEBUG, ERROR, true},
		{"fatal with debug level", DEBUG, FATAL, true},

		{"debug with info level", INFO, DEBUG, false},
		{"info with info level", INFO, INFO, true},
		{"warn with info level", INFO, WARN, true},
		{"error with info level", INFO, ERROR, true},
		{"fatal with info level", INFO, FATAL, true},

		{"debug with warn level", WARN, DEBUG, false},
		{"info with warn level", WARN, INFO, false},
		{"warn with warn level", WARN, WARN, true},
		{"error with warn level", WARN, ERROR, true},
		{"fatal with warn level", WARN, FATAL, true},

		{"debug with error level", ERROR, DEBUG, false},
		{"info with error level", ERROR, INFO, false},
		{"warn with error level", ERROR, WARN, false},
		{"error with error level", ERROR, ERROR, true},
		{"fatal with error level", ERROR, FATAL, true},
	}

	// Save the original level to restore it after the test
	originalLevel := GetLevel()
	defer func() {
		SetLevel(originalLevel)
	}()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set the current log level
			SetLevel(tt.currentLevel)

			// Capture the output
			output := captureOutput(func() {
				// Call the appropriate log function based on level
				switch tt.logLevel {
				case DEBUG:
					Debug("test message")
				case INFO:
					Info("test message")
				case WARN:
					Warn("test message")
				case ERROR:
					Error("test message")
				case FATAL:
					// Special case for FATAL to avoid os.Exit
					// We're just testing the filtering logic, not the exit behavior
					if IsLevelEnabled(FATAL) {
						stdLogger.Printf("[%s] %s", levelToString(FATAL), "test message")
					}
				}
			})

			if tt.shouldBePrinted && output == "" {
				t.Errorf("Expected log output but got none for level %s with current level %s",
					levelToString(tt.logLevel), levelToString(tt.currentLevel))
			}

			if !tt.shouldBePrinted && output != "" {
				t.Errorf("Expected no log output but got %q for level %s with current level %s",
					output, levelToString(tt.logLevel), levelToString(tt.currentLevel))
			}
		})
	}
}

func TestLogFormatting(t *testing.T) {
	tests := []struct {
		name           string
		logFunc        func(string, ...interface{})
		level          string
		format         string
		args           []interface{}
		expectedOutput string
	}{
		{
			name:    "debug with no args",
			logFunc: Debug,
			level:   "DEBUG",
			format:  "simple message",
			args:    nil,
		},
		{
			name:    "info with string arg",
			logFunc: Info,
			level:   "INFO",
			format:  "message with %s",
			args:    []interface{}{"argument"},
		},
		{
			name:    "warn with multiple args",
			logFunc: Warn,
			level:   "WARN",
			format:  "message with %s and %d",
			args:    []interface{}{"string", 42},
		},
		{
			name:    "error with complex args",
			logFunc: Error,
			level:   "ERROR",
			format:  "error: %v, code: %d",
			args:    []interface{}{fmt.Errorf("test error"), 500},
		},
	}

	// Save the original level to restore it after the test
	originalLevel := GetLevel()
	defer func() {
		SetLevel(originalLevel)
	}()

	// Set level to DEBUG to ensure all messages are logged
	SetLevel(DEBUG)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureOutput(func() {
				tt.logFunc(tt.format, tt.args...)
			})

			// Check that output contains the expected level
			if !strings.Contains(output, tt.level) {
				t.Errorf("Output does not contain expected level. Got: %s, Want to contain: %s", output, tt.level)
			}

			// Check that output contains the formatted message
			expectedContent := fmt.Sprintf(tt.format, tt.args...)
			if !strings.Contains(output, expectedContent) {
				t.Errorf("Output does not contain expected content. Got: %s, Want to contain: %s", output, expectedContent)
			}
		})
	}
}

// TestFatalBehavior tests the formatting of Fatal messages without actually calling os.Exit
func TestFatalBehavior(t *testing.T) {
	// Save the original level to restore it after the test
	originalLevel := GetLevel()
	defer func() {
		SetLevel(originalLevel)
	}()

	// Set level to DEBUG to ensure the message is logged
	SetLevel(DEBUG)

	// Create a custom logger for this test
	oldLogger := stdLogger
	var buf bytes.Buffer
	stdLogger = log.New(&buf, "", log.LstdFlags)

	// Restore the original logger after the test
	defer func() {
		stdLogger = oldLogger
	}()

	// We can't directly call logMessage with FATAL as it would call os.Exit
	// Instead, we'll format the message ourselves to test the formatting
	msg := fmt.Sprintf("Fatal error: %s", "test")
	stdLogger.Printf("[%s] %s", levelToString(FATAL), msg)

	// Check the output
	output := buf.String()
	if !strings.Contains(output, "FATAL") {
		t.Errorf("Output does not contain FATAL level. Got: %s", output)
	}
	if !strings.Contains(output, "Fatal error: test") {
		t.Errorf("Output does not contain expected message. Got: %s", output)
	}
}

func TestWithRequestID(t *testing.T) {
	tests := []struct {
		name           string
		requestID      string
		format         string
		args           []any
		expectedOutput string
	}{
		{
			name:           "with request ID",
			requestID:      "12345",
			format:         "Test message %s",
			args:           []any{"arg"},
			expectedOutput: "[12345] Test message arg",
		},
		{
			name:           "empty request ID",
			requestID:      "",
			format:         "Test message %s",
			args:           []any{"arg"},
			expectedOutput: "[] Test message arg",
		},
		{
			name:           "multiple format args",
			requestID:      "12345",
			format:         "Test %s %d %s",
			args:           []any{"message", 42, "args"},
			expectedOutput: "[12345] Test message 42 args",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := WithRequestID(tt.requestID, tt.format, tt.args...)
			if output != tt.expectedOutput {
				t.Errorf("WithRequestID() = %q, want %q", output, tt.expectedOutput)
			}
		})
	}
}
