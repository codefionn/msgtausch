package logger

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// LogLevel represents the severity of a log message
type LogLevel int

const (
	// DEBUG level for detailed troubleshooting information
	TRACE LogLevel = iota
	DEBUG
	// INFO level for general operational information
	INFO
	// WARN level for non-critical issues
	WARN
	// ERROR level for error conditions
	ERROR
	// FATAL level for critical errors that prevent operation
	FATAL
)

var (
	// currentLevel is the current logging level
	currentLevel LogLevel = INFO
	// stdLogger is the standard logger instance
	stdLogger = log.New(os.Stdout, "", log.LstdFlags)
)

// SetLevel sets the current logging level
func SetLevel(level LogLevel) {
	currentLevel = level
}

func IsLevelEnabled(level LogLevel) bool {
	return level >= currentLevel
}

// GetLevelFromString converts a string level to LogLevel
func GetLevelFromString(level string) LogLevel {
	switch strings.ToUpper(level) {
	case "TRACE":
		return TRACE
	case "DEBUG":
		return DEBUG
	case "INFO":
		return INFO
	case "WARN":
		return WARN
	case "ERROR":
		return ERROR
	case "FATAL":
		return FATAL
	default:
		return INFO
	}
}

// levelToString converts a LogLevel to its string representation
func levelToString(level LogLevel) string {
	switch level {
	case TRACE:
		return "TRACE"
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	case FATAL:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// logMessage logs a message at the specified level with optional context
func logMessage(level LogLevel, format string, v ...any) {
	if level < currentLevel {
		return
	}

	msg := fmt.Sprintf(format, v...)
	stdLogger.Printf("[%s] %s", levelToString(level), msg)
}

// Debug logs a debug message
// Arguments are handled in the manner of [fmt.Printf].
func Trace(format string, v ...any) {
	logMessage(TRACE, format, v...)
}

// Debug logs a debug message
// Arguments are handled in the manner of [fmt.Printf].
func Debug(format string, v ...any) {
	logMessage(DEBUG, format, v...)
}

// Info logs an informational message
// Arguments are handled in the manner of [fmt.Printf].
func Info(format string, v ...any) {
	logMessage(INFO, format, v...)
}

// Warn logs a warning message
// Arguments are handled in the manner of [fmt.Printf].
func Warn(format string, v ...any) {
	logMessage(WARN, format, v...)
}

// Error logs an error message
// Arguments are handled in the manner of [fmt.Printf].
func Error(format string, v ...any) {
	logMessage(ERROR, format, v...)
}

// Fatal logs a fatal message and exits
// Arguments are handled in the manner of [fmt.Printf].
func Fatal(format string, v ...any) {
	logMessage(FATAL, format, v...)
	os.Exit(1)
}

// WithRequestID adds a request ID to the log message
// Arguments are handled in the manner of [fmt.Printf].
func WithRequestID(requestID, format string, v ...any) string {
	return fmt.Sprintf("[%s] %s", requestID, fmt.Sprintf(format, v...))
}
