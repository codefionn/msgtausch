package logger

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync/atomic"
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
	// currentLevel holds the current logging level atomically
	currentLevel atomic.Int32
	// stdLogger is the standard logger instance
	stdLogger = log.New(os.Stdout, "", log.LstdFlags)
)

func init() {
	currentLevel.Store(int32(INFO))
}

// SetLevel sets the current logging level
func SetLevel(level LogLevel) {
	currentLevel.Store(int32(level))
}

func IsLevelEnabled(level LogLevel) bool {
	return level >= LogLevel(currentLevel.Load())
}

// GetLevel returns the current logging level.
func GetLevel() LogLevel {
	return LogLevel(currentLevel.Load())
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
	if level < LogLevel(currentLevel.Load()) {
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

// ConnectionUUIDFromContext extracts the connection UUID from context.
// This function should be implemented to match the proxy's context key structure.
// We'll create a simple interface that allows the proxy to provide UUID extraction.
var ConnectionUUIDExtractor func(context.Context) (string, bool)

// getUUIDFromContext extracts UUID from context if available
func getUUIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}

	// Use the extractor function if available (set by proxy initialization)
	if ConnectionUUIDExtractor != nil {
		if uuid, ok := ConnectionUUIDExtractor(ctx); ok {
			return uuid
		}
	}

	return ""
}

// formatWithUUID formats a message with UUID prefix if available
func formatWithUUID(ctx context.Context, format string, v ...any) string {
	msg := fmt.Sprintf(format, v...)
	if uuid := getUUIDFromContext(ctx); uuid != "" {
		return fmt.Sprintf("[%s] %s", uuid, msg)
	}
	return msg
}

// Context-aware logging functions that include UUID when available

// TraceCtx logs a trace message with UUID context if available
func TraceCtx(ctx context.Context, format string, v ...any) {
	if TRACE < LogLevel(currentLevel.Load()) {
		return
	}
	msg := formatWithUUID(ctx, format, v...)
	stdLogger.Printf("[%s] %s", levelToString(TRACE), msg)
}

// DebugCtx logs a debug message with UUID context if available
func DebugCtx(ctx context.Context, format string, v ...any) {
	if DEBUG < LogLevel(currentLevel.Load()) {
		return
	}
	msg := formatWithUUID(ctx, format, v...)
	stdLogger.Printf("[%s] %s", levelToString(DEBUG), msg)
}

// InfoCtx logs an info message with UUID context if available
func InfoCtx(ctx context.Context, format string, v ...any) {
	if INFO < LogLevel(currentLevel.Load()) {
		return
	}
	msg := formatWithUUID(ctx, format, v...)
	stdLogger.Printf("[%s] %s", levelToString(INFO), msg)
}

// WarnCtx logs a warning message with UUID context if available
func WarnCtx(ctx context.Context, format string, v ...any) {
	if WARN < LogLevel(currentLevel.Load()) {
		return
	}
	msg := formatWithUUID(ctx, format, v...)
	stdLogger.Printf("[%s] %s", levelToString(WARN), msg)
}

// ErrorCtx logs an error message with UUID context if available
func ErrorCtx(ctx context.Context, format string, v ...any) {
	if ERROR < LogLevel(currentLevel.Load()) {
		return
	}
	msg := formatWithUUID(ctx, format, v...)
	stdLogger.Printf("[%s] %s", levelToString(ERROR), msg)
}
