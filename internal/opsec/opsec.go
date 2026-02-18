// Package opsec provides comprehensive operational security features
package opsec

import (
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

// Config holds OPSEC configuration
type Config struct {
	// Memory protection
	EnableMemoryProtection bool

	// Anti-debug
	EnableAntiDebug     bool
	DebugDetectionLevel DebuggerDetectionLevel
	OnDebugDetected     func()

	// Diskless
	DisklessMode   bool
	ConfigFromStdin bool
	ConfigFromEnv   bool

	// Logging
	LogMode   LogMode
	LogMaxSize int

	// Cleanup
	EnableCleanup bool
	CleanupOnExit bool
}

// DefaultConfig returns default OPSEC configuration
func DefaultConfig() *Config {
	return &Config{
		EnableMemoryProtection: true,
		EnableAntiDebug:        false,
		DebugDetectionLevel:    DetectionBasic,
		DisklessMode:           false,
		LogMode:               LogModeNormal,
		LogMaxSize:            1000,
		EnableCleanup:         true,
		CleanupOnExit:         true,
	}
}

// Manager coordinates all OPSEC features
type Manager struct {
	config      *Config
	antiDebug   *AntiDebug
	diskless    *DisklessMode
	logger      *SecureLogger
	secureCfg   *SecureConfig

	cleanupFns  []func()
}

// NewManager creates a new OPSEC manager
func NewManager(cfg *Config) *Manager {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	m := &Manager{
		config:     cfg,
		cleanupFns: make([]func(), 0),
	}

	// Initialize components
	if cfg.EnableAntiDebug {
		m.antiDebug = NewAntiDebug(cfg.DebugDetectionLevel)
	}

	if cfg.DisklessMode {
		m.diskless = NewDisklessMode()
		if cfg.ConfigFromStdin {
			m.diskless.UseStdin()
		}
		if cfg.ConfigFromEnv {
			m.diskless.UseEnv()
		}
	}

	m.logger = NewSecureLogger(cfg.LogMode, cfg.LogMaxSize)

	return m
}

// Initialize sets up all OPSEC protections
func (m *Manager) Initialize() error {
	// Start anti-debug monitoring
	if m.config.EnableAntiDebug && m.antiDebug != nil {
		m.antiDebug.Start(func() {
			if m.config.OnDebugDetected != nil {
				m.config.OnDebugDetected()
			}
		})
	}

	// Setup cleanup handlers
	if m.config.CleanupOnExit {
		m.setupCleanupHandlers()
	}

	return nil
}

// LoadDisklessConfig loads configuration in diskless mode
func (m *Manager) LoadDisklessConfig() (*SecureConfig, error) {
	if m.diskless == nil {
		return nil, ErrNoConfig
	}

	raw, err := m.diskless.LoadConfig()
	if err != nil {
		return nil, err
	}

	m.secureCfg = raw.ToSecureConfig()
	return m.secureCfg, nil
}

// Logger returns the secure logger
func (m *Manager) Logger() *SecureLogger {
	return m.logger
}

// SecureConfig returns the secure configuration
func (m *Manager) SecureConfig() *SecureConfig {
	return m.secureCfg
}

// RegisterCleanup registers a cleanup function
func (m *Manager) RegisterCleanup(fn func()) {
	m.cleanupFns = append(m.cleanupFns, fn)
}

// Cleanup performs all cleanup operations
func (m *Manager) Cleanup() {
	// Run registered cleanup functions
	for _, fn := range m.cleanupFns {
		func() {
			defer func() { recover() }()
			fn()
		}()
	}

	// Stop anti-debug
	if m.antiDebug != nil {
		m.antiDebug.Stop()
	}

	// Purge logs
	if m.logger != nil {
		m.logger.Purge()
	}

	// Destroy secure config
	if m.secureCfg != nil {
		m.secureCfg.Destroy()
	}

	// Force garbage collection
	runtime.GC()
}

// setupCleanupHandlers sets up signal handlers for cleanup
func (m *Manager) setupCleanupHandlers() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		<-sigChan
		m.Cleanup()
		os.Exit(0)
	}()
}

// IsSecure returns true if all security checks pass
func (m *Manager) IsSecure() bool {
	if m.antiDebug != nil && m.antiDebug.IsDetected() {
		return false
	}
	return true
}

// CreateSecureString creates a secure string that will be auto-cleaned
func (m *Manager) CreateSecureString(s string) *SecureString {
	ss := NewSecureString(s)
	m.RegisterCleanup(func() {
		ss.Destroy()
	})
	return ss
}

// CreateSecureBytes creates secure bytes that will be auto-cleaned
func (m *Manager) CreateSecureBytes(b []byte) *SecureBytes {
	sb := NewSecureBytes(b)
	m.RegisterCleanup(func() {
		sb.Destroy()
	})
	return sb
}
