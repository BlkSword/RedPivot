// Package main is the client entry point
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/redpivot/redpivot/internal/config"
	"github.com/redpivot/redpivot/internal/countermeasure"
	"github.com/redpivot/redpivot/internal/proxy"
	"github.com/redpivot/redpivot/internal/transport"
	"github.com/redpivot/redpivot/internal/tunnel"
	"github.com/redpivot/redpivot/pkg/utils"
)

var (
	configPath  = flag.String("config", "configs/redctl.yaml", "Path to configuration file")
	showVersion = flag.Bool("version", false, "Show version information")
	showHelp    = flag.Bool("help", false, "Show help information")
	verify      = flag.Bool("verify", false, "Verify configuration file")
	diskless    = flag.Bool("diskless", false, "Run in diskless mode (no config file)")
	envConfig   = flag.Bool("env", false, "Read configuration from environment variables")
	stdinConfig = flag.Bool("stdin", false, "Read configuration from stdin (base64 JSON)")
	version     = "dev"
)

const helpText = `redctl - RedPivot Client

Usage:
  redctl [options]

Options:
  -config <path>   Path to configuration file (default: configs/redctl.yaml)
  -version         Show version information
  -help            Show this help message
  -verify          Verify configuration file and exit
  -diskless        Run in diskless mode (no config file on disk)
  -env             Read configuration from environment variables (use with -diskless)
  -stdin           Read configuration from stdin as base64 JSON (use with -diskless)

Diskless Mode Environment Variables:
  REDPIVOT_SERVER  Server URL (e.g., wss://server:443/ws)
  REDPIVOT_TOKEN   Authentication token
  REDPIVOT_PROXY_1 Proxy definition (e.g., tcp:127.0.0.1:22:6022)

Examples:
  redctl -config configs/redctl.yaml
  redctl -verify -config configs/redctl.yaml
  redctl -diskless -env
  echo "base64-config" | redctl -diskless -stdin
`

func main() {
	flag.Parse()

	// Handle help flag
	if *showHelp {
		fmt.Print(helpText)
		os.Exit(0)
	}

	// Handle version flag
	if *showVersion {
		fmt.Printf("redctl version %s\n", version)
		os.Exit(0)
	}

	// Load configuration based on mode
	var cfg *config.ClientConfig
	var err error

	if *diskless {
		if *stdinConfig {
			cfg, err = config.LoadClientConfigFromStdin()
		} else if *envConfig {
			cfg, err = config.LoadClientConfigFromEnv()
		} else {
			fmt.Println("Diskless mode requires -env or -stdin flag")
			os.Exit(1)
		}
	} else {
		cfg, err = config.LoadClientConfig(*configPath)
	}

	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Handle verify flag
	if *verify {
		fmt.Printf("Configuration is valid\n")
		fmt.Printf("  Server: %s\n", cfg.Client.Server)
		fmt.Printf("  Proxies: %d\n", len(cfg.Proxies))
		for _, p := range cfg.Proxies {
			fmt.Printf("    - %s (%s): %s\n", p.Name, p.Type, p.Local)
		}
		os.Exit(0)
	}

	// Initialize logger
	logger := utils.NewLogger(cfg.Logging.Level, cfg.Logging.Format, cfg.Logging.Output)
	logger.SetPrefix("redctl")

	logger.Info("Starting RedPivot Client",
		utils.String("version", version),
		utils.String("server", cfg.Client.Server),
	)

	// Initialize obfuscator
	obfuscator := countermeasure.NewObfuscator(
		true, // Enable obfuscation on client
		0.3,  // 30% padding probability
		50,   // 50ms timing jitter
		64,   // Min chunk size
		1500, // Max chunk size
	)

	// Create client
	client := NewClient(cfg, obfuscator, logger)

	// Start proxies
	if err := client.Start(); err != nil {
		logger.Fatal("Failed to start client", utils.Err(err))
	}

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutting down client...")
	client.Stop()
	logger.Info("Client stopped")
}

// Client represents the RedPivot client
type Client struct {
	cfg        *config.ClientConfig
	obfuscator *countermeasure.Obfuscator
	logger     *utils.Logger

	mux      *tunnel.Mux
	ws       *transport.WebSocketTransport
	proxies  []Proxy
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
}

// Proxy interface for different proxy types
type Proxy interface {
	Start() error
	Close() error
	Name() string
	Type() string
}

// MuxAdapter adapts tunnel.Mux to implement proxy.StreamPool
type MuxAdapter struct {
	mux *tunnel.Mux
}

// NewMuxAdapter creates a new mux adapter
func NewMuxAdapter(mux *tunnel.Mux) *MuxAdapter {
	return &MuxAdapter{mux: mux}
}

// OpenStream implements proxy.StreamPool
func (a *MuxAdapter) OpenStream() (io.ReadWriteCloser, error) {
	return a.mux.OpenStream()
}

// NewClient creates a new client
func NewClient(cfg *config.ClientConfig, obfuscator *countermeasure.Obfuscator, logger *utils.Logger) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		cfg:        cfg,
		obfuscator: obfuscator,
		logger:     logger,
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start starts the client and connects to server
func (c *Client) Start() error {
	// Connect to server with retry
	var lastErr error
	for attempt := 0; attempt < c.cfg.Client.Reconnect.MaxAttempts; attempt++ {
		if attempt > 0 {
			delay := c.cfg.Client.Reconnect.InitialDelay * time.Duration(1<<uint(attempt-1))
			if delay > c.cfg.Client.Reconnect.MaxDelay {
				delay = c.cfg.Client.Reconnect.MaxDelay
			}
			c.logger.Info("Reconnecting...",
				utils.Int("attempt", attempt+1),
				utils.Duration("delay", delay),
			)
			time.Sleep(delay)
		}

		if err := c.connect(); err != nil {
			lastErr = err
			c.logger.Warn("Connection failed", utils.Err(err))
			continue
		}

		// Connection successful
		return c.startProxies()
	}

	return fmt.Errorf("failed to connect after %d attempts: %v",
		c.cfg.Client.Reconnect.MaxAttempts, lastErr)
}

// connect establishes connection to the server
func (c *Client) connect() error {
	// WebSocket configuration
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // In production, verify certificate
	}

	wsConfig := &transport.WSConfig{
		URL:       c.cfg.Client.Server,
		TLSConfig: tlsConfig,
	}

	// Connect
	ws, err := transport.NewWebSocketClient(wsConfig)
	if err != nil {
		return err
	}

	c.ws = ws

	// Wrap as ReadWriteCloser
	rwc := transport.NewWSReadWriteCloser(ws)

	// Create encrypted connection
	key := make([]byte, 32)
	copy(key, []byte("temporary-key-for-demo-purposes!"))

	crypto, err := tunnel.NewCryptoLayer(key)
	if err != nil {
		ws.Close()
		return err
	}

	encryptedConn := tunnel.NewEncryptedConn(rwc, crypto)

	// Create multiplexer
	c.mux = tunnel.NewMux(encryptedConn)

	// Set up reconnection handler
	ws.OnClose(func() {
		c.logger.Warn("Connection lost, reconnecting...")
		go c.reconnect()
	})

	c.logger.Info("Connected to server")
	return nil
}

// reconnect handles reconnection
func (c *Client) reconnect() {
	c.mu.Lock()
	c.stopProxies()
	c.mu.Unlock()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		if err := c.connect(); err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		// Restart proxies
		if err := c.startProxies(); err != nil {
			c.logger.Error("Failed to restart proxies", utils.Err(err))
			continue
		}

		c.logger.Info("Reconnected successfully")
		return
	}
}

// startProxies starts all configured proxies
func (c *Client) startProxies() error {
	muxAdapter := NewMuxAdapter(c.mux)

	for _, proxyCfg := range c.cfg.Proxies {
		var p Proxy

		switch proxyCfg.Type {
		case "tcp":
			p = proxy.NewTCPProxy(
				proxyCfg.Name,
				proxyCfg.Local,
				uint16(proxyCfg.RemotePort),
			)
			p.(*proxy.TCPProxy).SetStreamPool(muxAdapter)

		case "udp":
			p = proxy.NewUDPProxy(
				proxyCfg.Name,
				proxyCfg.Local,
				uint16(proxyCfg.RemotePort),
			)
			p.(*proxy.UDPProxy).SetStreamPool(muxAdapter)

		case "http":
			p = proxy.NewHTTPProxy(
				proxyCfg.Name,
				proxyCfg.Subdomain,
				"", // Domain from server
			)

		case "https":
			p = proxy.NewHTTPSProxy(
				proxyCfg.Name,
				proxyCfg.Subdomain,
				proxyCfg.Local,
				proxyCfg.CertFile,
				proxyCfg.KeyFile,
			)
			p.(*proxy.HTTPSProxy).SetStreamPool(muxAdapter)

		case "stcp":
			p = proxy.NewTCPProxy(
				proxyCfg.Name,
				proxyCfg.Local,
				uint16(proxyCfg.RemotePort),
			)
			p.(*proxy.TCPProxy).SetStreamPool(muxAdapter)
			c.logger.Info("STCP proxy configured",
				utils.String("name", proxyCfg.Name),
				utils.Any("has_secret", proxyCfg.SecretKey != ""),
			)

		default:
			c.logger.Warn("Unknown proxy type",
				utils.String("name", proxyCfg.Name),
				utils.String("type", proxyCfg.Type),
			)
			continue
		}

		if err := p.Start(); err != nil {
			c.logger.Error("Failed to start proxy",
				utils.String("name", proxyCfg.Name),
				utils.Err(err),
			)
			continue
		}

		c.proxies = append(c.proxies, p)
		c.logger.Info("Proxy started",
			utils.String("name", proxyCfg.Name),
			utils.String("type", proxyCfg.Type),
			utils.String("local", proxyCfg.Local),
		)
	}

	return nil
}

// stopProxies stops all proxies
func (c *Client) stopProxies() {
	for _, p := range c.proxies {
		p.Close()
		c.logger.Info("Proxy stopped", utils.String("name", p.Name()))
	}
	c.proxies = nil
}

// Stop stops the client
func (c *Client) Stop() {
	c.cancel()
	c.mu.Lock()
	defer c.mu.Unlock()

	c.stopProxies()

	if c.mux != nil {
		c.mux.Close()
	}
	if c.ws != nil {
		c.ws.Close()
	}
}
