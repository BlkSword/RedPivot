package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

// LogLevel represents log severity
type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
)

func (l LogLevel) String() string {
	switch l {
	case LogLevelDebug:
		return "DEBUG"
	case LogLevelInfo:
		return "INFO"
	case LogLevelWarn:
		return "WARN"
	case LogLevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Logger provides structured logging
type Logger struct {
	mu       sync.Mutex
	output   io.Writer
	level    LogLevel
	format   string // "json" or "text"
	prefix   string
}

// NewLogger creates a new logger
func NewLogger(level, format, output string) *Logger {
	l := &Logger{
		level:  parseLogLevel(level),
		format: format,
	}

	switch output {
	case "stdout":
		l.output = os.Stdout
	case "stderr":
		l.output = os.Stderr
	default:
		file, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Printf("Failed to open log file: %v, using stdout", err)
			l.output = os.Stdout
		} else {
			l.output = file
		}
	}

	return l
}

// SetPrefix sets the logger prefix
func (l *Logger) SetPrefix(prefix string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prefix = prefix
}

// SetLevel sets the log level
func (l *Logger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, fields ...Field) {
	l.log(LogLevelDebug, msg, fields...)
}

// Info logs an info message
func (l *Logger) Info(msg string, fields ...Field) {
	l.log(LogLevelInfo, msg, fields...)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, fields ...Field) {
	l.log(LogLevelWarn, msg, fields...)
}

// Error logs an error message
func (l *Logger) Error(msg string, fields ...Field) {
	l.log(LogLevelError, msg, fields...)
}

// Fatal logs an error and exits
func (l *Logger) Fatal(msg string, fields ...Field) {
	l.log(LogLevelError, msg, fields...)
	os.Exit(1)
}

// WithFields returns a logger with preset fields
func (l *Logger) WithFields(fields ...Field) *FieldLogger {
	return &FieldLogger{
		logger: l,
		fields: fields,
	}
}

func (l *Logger) log(level LogLevel, msg string, fields ...Field) {
	if level < l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	entry := logEntry{
		Time:    time.Now().Format(time.RFC3339),
		Level:   level.String(),
		Message: msg,
	}

	if l.prefix != "" {
		entry.Component = l.prefix
	}

	for _, f := range fields {
		entry.Fields = append(entry.Fields, f)
	}

	var output string
	if l.format == "json" {
		data, _ := json.Marshal(entry)
		output = string(data)
	} else {
		output = l.formatText(entry)
	}

	fmt.Fprintln(l.output, output)
}

func (l *Logger) formatText(entry logEntry) string {
	var fieldsStr string
	for _, f := range entry.Fields {
		fieldsStr += fmt.Sprintf(" %s=%v", f.Key, f.Value)
	}

	if entry.Component != "" {
		return fmt.Sprintf("[%s] [%s] [%s] %s%s",
			entry.Time, entry.Level, entry.Component, entry.Message, fieldsStr)
	}
	return fmt.Sprintf("[%s] [%s] %s%s",
		entry.Time, entry.Level, entry.Message, fieldsStr)
}

type logEntry struct {
	Time      string  `json:"time"`
	Level     string  `json:"level"`
	Component string  `json:"component,omitempty"`
	Message   string  `json:"msg"`
	Fields    []Field `json:"fields,omitempty"`
}

// Field represents a log field
type Field struct {
	Key   string      `json:"key"`
	Value interface{} `json:"value"`
}

// F creates a log field
func F(key string, value interface{}) Field {
	return Field{Key: key, Value: value}
}

// String creates a string field
func String(key, value string) Field {
	return F(key, value)
}

// Int creates an int field
func Int(key string, value int) Field {
	return F(key, value)
}

// Int64 creates an int64 field
func Int64(key string, value int64) Field {
	return F(key, value)
}

// Err creates an error field
func Err(err error) Field {
	return F("error", err.Error())
}

// Duration creates a duration field
func Duration(key string, d time.Duration) Field {
	return F(key, d.String())
}

// Any creates a field with any value
func Any(key string, value interface{}) Field {
	return F(key, value)
}

// FieldLogger is a logger with preset fields
type FieldLogger struct {
	logger *Logger
	fields []Field
}

// Debug logs a debug message
func (l *FieldLogger) Debug(msg string, fields ...Field) {
	l.logger.Debug(msg, append(l.fields, fields...)...)
}

// Info logs an info message
func (l *FieldLogger) Info(msg string, fields ...Field) {
	l.logger.Info(msg, append(l.fields, fields...)...)
}

// Warn logs a warning message
func (l *FieldLogger) Warn(msg string, fields ...Field) {
	l.logger.Warn(msg, append(l.fields, fields...)...)
}

// Error logs an error message
func (l *FieldLogger) Error(msg string, fields ...Field) {
	l.logger.Error(msg, append(l.fields, fields...)...)
}

func parseLogLevel(s string) LogLevel {
	switch s {
	case "debug":
		return LogLevelDebug
	case "info":
		return LogLevelInfo
	case "warn":
		return LogLevelWarn
	case "error":
		return LogLevelError
	default:
		return LogLevelInfo
	}
}

// DefaultLogger is the default global logger
var DefaultLogger = NewLogger("info", "text", "stdout")
