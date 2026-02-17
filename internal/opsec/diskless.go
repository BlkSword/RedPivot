package opsec

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
)

var (
	ErrNoConfig = errors.New("no configuration provided")
)

// DisklessMode enables running without disk persistence
type DisklessMode struct {
	configSource string
	stdinConfig  bool
	envConfig    bool
}

// NewDisklessMode creates a new diskless mode handler
func NewDisklessMode() *DisklessMode {
	return &DisklessMode{}
}

// UseStdin configures reading from stdin
func (d *DisklessMode) UseStdin() *DisklessMode {
	d.stdinConfig = true
	return d
}

// UseEnv configures reading from environment
func (d *DisklessMode) UseEnv() *DisklessMode {
	d.envConfig = true
	return d
}

// LoadConfig loads configuration from configured sources
func (d *DisklessMode) LoadConfig() (*RawConfig, error) {
	// Priority: stdin > env > error

	if d.stdinConfig {
		cfg, err := d.loadFromStdin()
		if err == nil {
			return cfg, nil
		}
	}

	if d.envConfig {
		cfg, err := d.loadFromEnv()
		if err == nil {
			return cfg, nil
		}
	}

	return nil, ErrNoConfig
}

// loadFromStdin reads base64-encoded JSON config from stdin
func (d *DisklessMode) loadFromStdin() (*RawConfig, error) {
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		return nil, errors.New("stdin is not piped")
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, err
	}

	// Try base64 decode first
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		// Not base64, try raw JSON
		decoded = data
	}

	var cfg RawConfig
	if err := json.Unmarshal(decoded, &cfg); err != nil {
		return nil, err
	}

	// Clear the decoded data from memory
	Memzero(decoded)
	Memzero(data)

	return &cfg, nil
}

// loadFromEnv loads configuration from environment variables
func (d *DisklessMode) loadFromEnv() (*RawConfig, error) {
	cfg := &RawConfig{}

	// Server configuration
	if server := os.Getenv("REDPIVOT_SERVER"); server != "" {
		cfg.Server = server
	}
	if token := os.Getenv("REDPIVOT_TOKEN"); token != "" {
		cfg.Token = token
	}

	// Proxy configuration via env
	// Format: REDPIVOT_PROXY_1="tcp:local:port"
	// Example: REDPIVOT_PROXY_1="tcp:127.0.0.1:22:6022"
	for i := 1; ; i++ {
		proxy := os.Getenv("REDPIVOT_PROXY_" + itoa(i))
		if proxy == "" {
			break
		}
		cfg.Proxies = append(cfg.Proxies, proxy)
	}

	if cfg.Server == "" {
		return nil, ErrNoConfig
	}

	return cfg, nil
}

// RawConfig holds raw configuration data
type RawConfig struct {
	Server string   `json:"server"`
	Token  string   `json:"token"`
	Proxies []string `json:"proxies"`
}

// ToSecureConfig converts to secure config and wipes raw data
func (r *RawConfig) ToSecureConfig() *SecureConfig {
	cfg := NewSecureConfig()
	cfg.SetServer(r.Server)
	cfg.SetToken(r.Token)

	for _, p := range r.Proxies {
		cfg.AddProxySpec([]byte(p))
	}

	// Wipe raw config
	r.Server = ""
	r.Token = ""
	r.Proxies = nil

	return cfg
}

// CleanupRegistry removes any registry traces (Windows)
func CleanupRegistry() error {
	// Placeholder for Windows registry cleanup
	// In production, this would remove Run keys, etc.
	return nil
}

// CleanupArtifacts removes any disk artifacts
func CleanupArtifacts(patterns []string) error {
	for _, pattern := range patterns {
		files, _ := filepathGlob(pattern)
		for _, f := range files {
			SecureDelete(f)
		}
	}
	return nil
}

// SecureDelete securely deletes a file
func SecureDelete(path string) error {
	// Get file size
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	// Open for writing
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	// Overwrite with random data 3 times
	size := info.Size()
	for i := 0; i < 3; i++ {
		random := make([]byte, size)
		rand.Read(random)
		f.WriteAt(random, 0)
		Memzero(random)
		f.Sync()
	}

	// Overwrite with zeros
	zeros := make([]byte, size)
	f.WriteAt(zeros, 0)
	f.Sync()

	// Truncate and close
	f.Truncate(0)
	f.Close()

	// Remove the file
	return os.Remove(path)
}

// itoa converts int to string without allocation
func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return itoa(i/10) + string(rune('0'+i%10))
}

// filepathGlob is a minimal glob implementation
func filepathGlob(pattern string) ([]string, error) {
	// Simple implementation - just check if file exists
	if _, err := os.Stat(pattern); err == nil {
		return []string{pattern}, nil
	}
	return nil, nil
}
