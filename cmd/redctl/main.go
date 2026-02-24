// Package main is the client entry point
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/redpivot/redpivot/internal/client"
	"github.com/redpivot/redpivot/internal/config"
	"github.com/redpivot/redpivot/internal/config/wizard"
	"github.com/redpivot/redpivot/internal/transport"
	"github.com/redpivot/redpivot/internal/tunnel"
	"github.com/redpivot/redpivot/pkg/protocol"
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
  redctl [command] [options]

Commands:
  (default)     启动客户端
  config init   交互式生成配置文件
  help          显示帮助信息

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
  redctl config init
`

// runConfigInit runs the interactive configuration wizard
func runConfigInit() {
	cfg, savePath, err := wizard.RunClientWizard()
	if err != nil {
		fmt.Printf("\n配置生成失败: %v\n", err)
		os.Exit(1)
	}

	if err := config.SaveClientConfig(cfg, savePath); err != nil {
		fmt.Printf("\n保存配置失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n✓ 配置已保存到 %s\n", savePath)
	wizard.PrintClientSummary(cfg)
}

func main() {
	// Check for subcommands before flag parsing
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "config":
			if len(os.Args) > 2 && os.Args[2] == "init" {
				runConfigInit()
				return
			}
			fmt.Println("用法: redctl config init")
			fmt.Println("  交互式生成客户端配置文件")
			os.Exit(1)
		case "help", "-help", "--help":
			fmt.Print(helpText)
			os.Exit(0)
		}
	}

	flag.Parse()

	if *showHelp {
		fmt.Print(helpText)
		os.Exit(0)
	}

	if *showVersion {
		fmt.Printf("redctl version %s\n", version)
		os.Exit(0)
	}

	// Load configuration
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

	// Create client
	c := NewClient(cfg, logger)

	// Start
	if err := c.Start(); err != nil {
		logger.Fatal("Failed to start client", utils.Err(err))
	}

	// Wait for shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutting down client...")
	c.Stop()
	logger.Info("Client stopped")
}

// Client represents the RedPivot client
type Client struct {
	cfg    *config.ClientConfig
	logger *utils.Logger

	mu           sync.Mutex
	ctx          context.Context
	cancel       context.CancelFunc
	ws           *transport.WebSocketTransport
	mux          *tunnel.Mux
	proxyHandler *client.ProxyHandler
}

// NewClient creates a new client
func NewClient(cfg *config.ClientConfig, logger *utils.Logger) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		cfg:    cfg,
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start starts the client and connects to server
func (c *Client) Start() error {
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

		return nil
	}

	return fmt.Errorf("failed to connect after %d attempts: %v",
		c.cfg.Client.Reconnect.MaxAttempts, lastErr)
}

// connect establishes connection to the server
func (c *Client) connect() error {
	// WebSocket configuration
	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.cfg.Client.InsecureSkipVerify,
	}
	if tlsConfig.InsecureSkipVerify == false && os.Getenv("REDPIVOT_INSECURE") != "" {
		tlsConfig.InsecureSkipVerify = true
	}

	// Build headers with HTTP appearance if enabled
	var headers http.Header
	if c.cfg.Client.HttpAppearance.Enabled {
		appearance := transport.NewHttpAppearance(c.logger)
		appearance.Enabled = c.cfg.Client.HttpAppearance.Enabled

		// Set User-Agent based on browser type or custom UA
		if c.cfg.Client.HttpAppearance.UserAgent != "" {
			appearance.UserAgent = c.cfg.Client.HttpAppearance.UserAgent
		} else if c.cfg.Client.HttpAppearance.Browser != "" {
			appearance.UserAgent = transport.GetUAByBrowser(c.cfg.Client.HttpAppearance.Browser)
		}

		// Set extra headers
		if len(c.cfg.Client.HttpAppearance.ExtraHeaders) > 0 {
			appearance.ExtraHeaders = c.cfg.Client.HttpAppearance.ExtraHeaders
		}

		// Set URI template (stored for future use)
		if c.cfg.Client.HttpAppearance.UriTemplate != "" {
			appearance.UriTemplate = c.cfg.Client.HttpAppearance.UriTemplate
		}

		headers = appearance.BuildHeaders(c.cfg.Client.Server)
		c.logger.Info("HTTP appearance enabled",
			utils.String("browser", c.cfg.Client.HttpAppearance.Browser))
	}

	wsConfig := &transport.WSConfig{
		URL:       c.cfg.Client.Server,
		TLSConfig: tlsConfig,
		Header:    headers,
	}

	// Connect
	ws, err := transport.NewWebSocketClient(wsConfig)
	if err != nil {
		return err
	}

	c.ws = ws

	// Wrap as ReadWriteCloser
	rwc := transport.NewWSReadWriteCloser(ws)

	// Send authentication frame
	authFrame := protocol.NewFrame(protocol.FrameAuth, 0, []byte(c.cfg.Client.Token))
	if _, err := rwc.Write(authFrame.Encode()); err != nil {
		ws.Close()
		return fmt.Errorf("failed to send auth frame: %w", err)
	}

	// Wait for auth response
	respFrame, err := protocol.DecodeFrame(rwc)
	if err != nil {
		ws.Close()
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if respFrame.Type != protocol.FrameAuthResp {
		ws.Close()
		return fmt.Errorf("expected auth response, got %d", respFrame.Type)
	}

	// Check if authentication succeeded
	if len(respFrame.Payload) < 32 {
		// Authentication failed - payload contains error message
		errMsg := string(respFrame.Payload)
		ws.Close()
		return fmt.Errorf("authentication failed: %s", errMsg)
	}

	// Extract session key
	sessionKey := respFrame.Payload[:32]
	c.logger.Info("Authenticated successfully")

	// Create encrypted connection with session key
	crypto, err := tunnel.NewCryptoLayer(sessionKey)
	if err != nil {
		ws.Close()
		return fmt.Errorf("failed to create crypto layer: %w", err)
	}

	encryptedConn := tunnel.NewEncryptedConn(rwc, crypto)

	// Create multiplexer with stream handler for incoming connections
	muxAdapter := &muxStreamOpener{}
	c.mux = tunnel.NewMuxWithHandler(encryptedConn, func(stream *tunnel.Stream) {
		c.handleStream(stream)
	})
	muxAdapter.mux = c.mux

	// Create proxy handler
	c.proxyHandler = client.NewProxyHandler(muxAdapter, c.logger)

	// Register proxies with server
	if err := c.proxyHandler.RegisterProxies(c.cfg.Proxies); err != nil {
		c.mux.Close()
		ws.Close()
		return fmt.Errorf("failed to register proxies: %w", err)
	}

	// Set up reconnection handler
	ws.OnClose(func() {
		c.logger.Warn("Connection lost, reconnecting...")
		go c.reconnect()
	})

	c.logger.Info("Connected to server")
	return nil
}

// handleStream handles an incoming stream from server
func (c *Client) handleStream(stream *tunnel.Stream) {
	c.proxyHandler.HandleStream(stream)
}

// reconnect handles reconnection
func (c *Client) reconnect() {
	c.mu.Lock()
	if c.proxyHandler != nil {
		c.proxyHandler.Close()
	}
	if c.mux != nil {
		c.mux.Close()
	}
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

		c.logger.Info("Reconnected successfully")
		return
	}
}

// Stop stops the client
func (c *Client) Stop() {
	c.cancel()
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.proxyHandler != nil {
		c.proxyHandler.Close()
	}
	if c.mux != nil {
		c.mux.Close()
	}
	if c.ws != nil {
		c.ws.Close()
	}
}

// muxStreamOpener adapts Mux to implement StreamOpener
type muxStreamOpener struct {
	mux *tunnel.Mux
}

func (m *muxStreamOpener) OpenStream() (client.Stream, error) {
	if m.mux == nil {
		return nil, fmt.Errorf("mux not initialized")
	}
	return m.mux.OpenStream()
}
