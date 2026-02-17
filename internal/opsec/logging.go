package opsec

import (
	"sync"
	"time"
)

// LogMode controls logging behavior
type LogMode int

const (
	LogModeNormal   LogMode = iota // Normal logging
	LogModeQuiet                    // Suppress all output
	LogModeMemory                   // In-memory logs only
	LogModeSecure                   // Encrypted in-memory logs
)

// SecureLogger provides OPSEC-aware logging
type SecureLogger struct {
	mode      LogMode
	buffer    []*LogEntry
	maxSize   int
	mu        sync.Mutex
	onAdd     func(entry *LogEntry)
}

// LogEntry represents a single log entry
type LogEntry struct {
	Time    time.Time
	Level   string
	Message string
	Fields  map[string]interface{}
}

// NewSecureLogger creates a new secure logger
func NewSecureLogger(mode LogMode, maxSize int) *SecureLogger {
	return &SecureLogger{
		mode:    mode,
		buffer:  make([]*LogEntry, 0, maxSize),
		maxSize: maxSize,
	}
}

// SetOnAdd sets a callback for new entries
func (l *SecureLogger) SetOnAdd(fn func(entry *LogEntry)) {
	l.onAdd = fn
}

// Info logs an info message
func (l *SecureLogger) Info(msg string, fields ...interface{}) {
	l.log("INFO", msg, fields...)
}

// Debug logs a debug message
func (l *SecureLogger) Debug(msg string, fields ...interface{}) {
	l.log("DEBUG", msg, fields...)
}

// Warn logs a warning message
func (l *SecureLogger) Warn(msg string, fields ...interface{}) {
	l.log("WARN", msg, fields...)
}

// Error logs an error message
func (l *SecureLogger) Error(msg string, fields ...interface{}) {
	l.log("ERROR", msg, fields...)
}

func (l *SecureLogger) log(level, msg string, fields ...interface{}) {
	if l.mode == LogModeQuiet {
		return
	}

	entry := &LogEntry{
		Time:    time.Now(),
		Level:   level,
		Message: msg,
		Fields:  make(map[string]interface{}),
	}

	// Parse fields (key-value pairs)
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			entry.Fields[key] = fields[i+1]
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.mode == LogModeMemory || l.mode == LogModeSecure {
		l.buffer = append(l.buffer, entry)
		if len(l.buffer) > l.maxSize {
			l.buffer = l.buffer[1:]
		}
	}

	if l.onAdd != nil {
		l.onAdd(entry)
	}
}

// Purge clears all log entries from memory
func (l *SecureLogger) Purge() {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, entry := range l.buffer {
		MemzeroString(entry.Message)
		MemzeroString(entry.Level)
		for k, v := range entry.Fields {
			MemzeroString(k)
			if vs, ok := v.(string); ok {
				MemzeroString(vs)
			}
			delete(entry.Fields, k)
		}
	}

	l.buffer = l.buffer[:0]
}

// Export exports logs (for debugging only)
func (l *SecureLogger) Export() []*LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()

	result := make([]*LogEntry, len(l.buffer))
	copy(result, l.buffer)
	return result
}

// Size returns the number of buffered entries
func (l *SecureLogger) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buffer)
}

// AuditLog provides audit logging with automatic cleanup
type AuditLog struct {
	logger   *SecureLogger
	retention time.Duration
	entries  []*AuditEntry
	mu       sync.Mutex
}

// AuditEntry represents an audit log entry
type AuditEntry struct {
	Time     time.Time
	Action   string
	Resource string
	Result   string
	Metadata map[string]string
}

// NewAuditLog creates a new audit log
func NewAuditLog(retention time.Duration) *AuditLog {
	al := &AuditLog{
		logger:   NewSecureLogger(LogModeMemory, 1000),
		retention: retention,
		entries:  make([]*AuditEntry, 0),
	}
	go al.cleanupLoop()
	return al
}

// Record records an audit event
func (a *AuditLog) Record(action, resource, result string, metadata map[string]string) {
	entry := &AuditEntry{
		Time:     time.Now(),
		Action:   action,
		Resource: resource,
		Result:   result,
		Metadata: metadata,
	}

	a.mu.Lock()
	a.entries = append(a.entries, entry)
	a.mu.Unlock()

	a.logger.Info(action,
		"resource", resource,
		"result", result,
	)
}

// cleanupLoop periodically removes old entries
func (a *AuditLog) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		a.cleanup()
	}
}

func (a *AuditLog) cleanup() {
	a.mu.Lock()
	defer a.mu.Unlock()

	cutoff := time.Now().Add(-a.retention)
	newEntries := make([]*AuditEntry, 0)

	for _, entry := range a.entries {
		if entry.Time.After(cutoff) {
			newEntries = append(newEntries, entry)
		} else {
			// Securely clear the entry
			MemzeroString(entry.Action)
			MemzeroString(entry.Resource)
			MemzeroString(entry.Result)
			SrubStringMap(&entry.Metadata)
		}
	}

	a.entries = newEntries
}

// Clear clears all audit entries
func (a *AuditLog) Clear() {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, entry := range a.entries {
		MemzeroString(entry.Action)
		MemzeroString(entry.Resource)
		MemzeroString(entry.Result)
		SrubStringMap(&entry.Metadata)
	}

	a.entries = a.entries[:0]
	a.logger.Purge()
}

// SrubStringMap clears a string map
func SrubStringMap(m *map[string]string) {
	if m == nil || *m == nil {
		return
	}
	for k, v := range *m {
		MemzeroString(k)
		MemzeroString(v)
	}
	*m = nil
}
