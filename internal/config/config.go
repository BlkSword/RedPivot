// Package config handles configuration management
package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// ServerConfig represents server-side configuration
type ServerConfig struct {
	Server   ServerSection   `yaml:"server"`
	Auth     AuthSection     `yaml:"auth"`
	Transport TransportSection `yaml:"transport"`
	Obfuscation ObfuscationSection `yaml:"obfuscation"`
	Logging  LoggingSection  `yaml:"logging"`
}

// ClientConfig represents client-side configuration
type ClientConfig struct {
	Client   ClientSection   `yaml:"client"`
	Proxies  []ProxyConfig   `yaml:"proxies"`
	Logging  LoggingSection  `yaml:"logging"`
}

// ServerSection contains server binding configuration
type ServerSection struct {
	Bind         string `yaml:"bind"`
	Domain       string `yaml:"domain"`
	ReadTimeout  int    `yaml:"read_timeout"`
	WriteTimeout int    `yaml:"write_timeout"`
}

// ClientSection contains client connection configuration
type ClientSection struct {
	Server    string        `yaml:"server"`
	Token     string        `yaml:"token"`
	Reconnect ReconnectConfig `yaml:"reconnect"`
}

// ReconnectConfig controls reconnection behavior
type ReconnectConfig struct {
	Enabled      bool          `yaml:"enabled"`
	MaxAttempts  int           `yaml:"max_attempts"`
	InitialDelay time.Duration `yaml:"initial_delay"`
	MaxDelay     time.Duration `yaml:"max_delay"`
}

// AuthSection contains authentication settings
type AuthSection struct {
	Method string   `yaml:"method"` // token, mtls
	Tokens []string `yaml:"tokens"`
}

// TransportSection contains transport layer settings
type TransportSection struct {
	Type      string    `yaml:"type"` // websocket, quic, grpc
	Path      string    `yaml:"path"`
	TLS       TLSConfig `yaml:"tls"`
	WebSocket WSConfig  `yaml:"websocket"`
	QUIC      QUICConfig `yaml:"quic"`
}

// TLSConfig contains TLS settings
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Cert     string `yaml:"cert"`
	Key      string `yaml:"key"`
	CA       string `yaml:"ca"`
	Insecure bool   `yaml:"insecure"` // Skip verification (client)
}

// WSConfig contains WebSocket-specific settings
type WSConfig struct {
	Path            string `yaml:"path"`
	ReadBufferSize  int    `yaml:"read_buffer_size"`
	WriteBufferSize int    `yaml:"write_buffer_size"`
}

// QUICConfig contains QUIC-specific settings
type QUICConfig struct {
	MaxStreams      int `yaml:"max_streams"`
	MaxIdleTimeout  int `yaml:"max_idle_timeout"`
	KeepAlivePeriod int `yaml:"keep_alive_period"`
}

// ObfuscationSection contains anti-traffic-analysis settings
type ObfuscationSection struct {
	Enabled           bool    `yaml:"enabled"`
	PaddingProbability float64 `yaml:"padding_probability"`
	TimingJitterMs    int     `yaml:"timing_jitter_ms"`
	ChunkMinSize      int     `yaml:"chunk_min_size"`
	ChunkMaxSize      int     `yaml:"chunk_max_size"`
}

// LoggingSection contains logging configuration
type LoggingSection struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // json, text
	Output string `yaml:"output"` // stdout, file path
}

// ProxyConfig represents a single proxy configuration
type ProxyConfig struct {
	Name       string `yaml:"name"`
	Type       string `yaml:"type"` // tcp, udp, http, https, stcp
	Local      string `yaml:"local"`
	RemotePort int    `yaml:"remote_port"`
	Subdomain  string `yaml:"subdomain"`
	SecretKey  string `yaml:"secret_key"` // For STCP
}

// DefaultServerConfig returns default server configuration
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Server: ServerSection{
			Bind:         "0.0.0.0:443",
			ReadTimeout:  30,
			WriteTimeout: 30,
		},
		Auth: AuthSection{
			Method: "token",
			Tokens: []string{},
		},
		Transport: TransportSection{
			Type: "websocket",
			Path: "/ws",
			TLS: TLSConfig{
				Enabled: true,
			},
			WebSocket: WSConfig{
				Path:            "/ws",
				ReadBufferSize:  64 * 1024,
				WriteBufferSize: 64 * 1024,
			},
			QUIC: QUICConfig{
				MaxStreams:      1000,
				MaxIdleTimeout:  60,
				KeepAlivePeriod: 15,
			},
		},
		Obfuscation: ObfuscationSection{
			Enabled:           true,
			PaddingProbability: 0.3,
			TimingJitterMs:    50,
			ChunkMinSize:      64,
			ChunkMaxSize:      1500,
		},
		Logging: LoggingSection{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		},
	}
}

// DefaultClientConfig returns default client configuration
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		Client: ClientSection{
			Reconnect: ReconnectConfig{
				Enabled:      true,
				MaxAttempts:  10,
				InitialDelay: 1 * time.Second,
				MaxDelay:     60 * time.Second,
			},
		},
		Logging: LoggingSection{
			Level:  "info",
			Format: "text",
			Output: "stdout",
		},
	}
}

// LoadServerConfig loads server configuration from file
func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	config := DefaultServerConfig()
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, err
	}

	return config, nil
}

// LoadClientConfig loads client configuration from file
func LoadClientConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	config := DefaultClientConfig()
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, err
	}

	return config, nil
}

// SaveServerConfig saves server configuration to file
func SaveServerConfig(config *ServerConfig, path string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// SaveClientConfig saves client configuration to file
func SaveClientConfig(config *ClientConfig, path string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
