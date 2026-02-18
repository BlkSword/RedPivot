// Package config handles configuration management
package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
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
	Server             string          `yaml:"server"`
	Token              string          `yaml:"token"`
	InsecureSkipVerify bool            `yaml:"insecure_skip_verify"`
	Reconnect          ReconnectConfig `yaml:"reconnect"`
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
	CertFile   string `yaml:"cert_file"`  // For HTTPS
	KeyFile    string `yaml:"key_file"`   // For HTTPS
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

// LoadClientConfigFromEnv loads client configuration from environment variables
func LoadClientConfigFromEnv() (*ClientConfig, error) {
	cfg := DefaultClientConfig()

	// Server URL
	if server := os.Getenv("REDPIVOT_SERVER"); server != "" {
		cfg.Client.Server = server
	} else {
		return nil, fmt.Errorf("REDPIVOT_SERVER environment variable is required")
	}

	// Token
	if token := os.Getenv("REDPIVOT_TOKEN"); token != "" {
		cfg.Client.Token = token
	} else {
		return nil, fmt.Errorf("REDPIVOT_TOKEN environment variable is required")
	}

	// Parse proxy configs from environment
	// Format: REDPIVOT_PROXY_1="tcp:127.0.0.1:22:6022"
	// Format: REDPIVOT_PROXY_2="http:127.0.0.1:8080:subdomain"
	// Format: REDPIVOT_PROXY_3="stcp:127.0.0.1:9000:secret_key"
	for i := 1; ; i++ {
		proxyEnv := os.Getenv(fmt.Sprintf("REDPIVOT_PROXY_%d", i))
		if proxyEnv == "" {
			break
		}

		proxyCfg, err := parseProxyEnv(proxyEnv)
		if err != nil {
			return nil, fmt.Errorf("invalid REDPIVOT_PROXY_%d: %w", i, err)
		}
		cfg.Proxies = append(cfg.Proxies, proxyCfg)
	}

	return cfg, nil
}

// parseProxyEnv parses a proxy definition from environment variable
// Format: type:local_addr:remote_port_or_subdomain[:secret_key]
func parseProxyEnv(s string) (ProxyConfig, error) {
	parts := strings.Split(s, ":")
	if len(parts) < 3 {
		return ProxyConfig{}, fmt.Errorf("invalid format, expected type:local:port_or_subdomain")
	}

	proxyCfg := ProxyConfig{
		Type:  parts[0],
		Local: parts[1],
	}

	switch parts[0] {
	case "tcp", "udp", "stcp":
		if len(parts) < 3 {
			return ProxyConfig{}, fmt.Errorf("missing remote port for %s proxy", parts[0])
		}
		port, err := strconv.Atoi(parts[2])
		if err != nil {
			return ProxyConfig{}, fmt.Errorf("invalid remote port: %s", parts[2])
		}
		proxyCfg.RemotePort = port
		proxyCfg.Name = fmt.Sprintf("%s-%d", parts[0], port)

		if parts[0] == "stcp" && len(parts) > 3 {
			proxyCfg.SecretKey = parts[3]
		}

	case "http", "https":
		proxyCfg.Subdomain = parts[2]
		proxyCfg.Name = fmt.Sprintf("%s-%s", parts[0], parts[2])

	default:
		return ProxyConfig{}, fmt.Errorf("unknown proxy type: %s", parts[0])
	}

	return proxyCfg, nil
}

// LoadClientConfigFromStdin reads base64 encoded JSON/YAML configuration from stdin
func LoadClientConfigFromStdin() (*ClientConfig, error) {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("failed to read stdin: %w", err)
	}

	// Trim whitespace
	input := strings.TrimSpace(string(data))
	if input == "" {
		return nil, fmt.Errorf("stdin is empty")
	}

	// Try base64 decode first
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		// Not base64, try raw JSON/YAML
		decoded = []byte(input)
	}

	cfg := DefaultClientConfig()

	// Try JSON first
	if err := json.Unmarshal(decoded, cfg); err == nil {
		return cfg, nil
	}

	// Try YAML
	if err := yaml.Unmarshal(decoded, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config as JSON or YAML: %w", err)
	}

	return cfg, nil
}

// Validate validates the proxy configuration
func (p *ProxyConfig) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("proxy name is required")
	}
	if p.Type == "" {
		return fmt.Errorf("proxy type is required")
	}

	switch p.Type {
	case "tcp", "udp", "stcp":
		if p.Local == "" {
			return fmt.Errorf("local address is required for %s proxy", p.Type)
		}
		if p.RemotePort <= 0 || p.RemotePort > 65535 {
			return fmt.Errorf("invalid remote port: %d", p.RemotePort)
		}
		if p.Type == "stcp" && p.SecretKey == "" {
			return fmt.Errorf("secret_key is required for stcp proxy")
		}

	case "http":
		if p.Local == "" {
			return fmt.Errorf("local address is required for http proxy")
		}

	case "https":
		if p.Local == "" {
			return fmt.Errorf("local address is required for https proxy")
		}
		if p.CertFile == "" {
			return fmt.Errorf("cert_file is required for https proxy")
		}
		if p.KeyFile == "" {
			return fmt.Errorf("key_file is required for https proxy")
		}

	default:
		return fmt.Errorf("unknown proxy type: %s", p.Type)
	}

	return nil
}
