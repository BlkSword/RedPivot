// Package main is the server entry point
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/redpivot/redpivot/internal/auth"
	"github.com/redpivot/redpivot/internal/config"
	"github.com/redpivot/redpivot/internal/config/wizard"
	"github.com/redpivot/redpivot/internal/countermeasure"
	"github.com/redpivot/redpivot/internal/server"
	"github.com/redpivot/redpivot/internal/transport"
	"github.com/redpivot/redpivot/internal/tunnel"
	"github.com/redpivot/redpivot/pkg/protocol"
	"github.com/redpivot/redpivot/pkg/utils"
)

var (
	configPath  = flag.String("config", "configs/redd.yaml", "Path to configuration file")
	showVersion = flag.Bool("version", false, "Show version information")
	showHelp    = flag.Bool("help", false, "Show help information")
	verify      = flag.Bool("verify", false, "Verify configuration file")
	version     = "dev"
)

const helpText = `redd - RedPivot Server

Usage:
  redd [command] [options]

Commands:
  (default)     启动服务端
  config init   交互式生成配置文件
  help          显示帮助信息

Options:
  -config <path>   Path to configuration file (default: configs/redd.yaml)
  -version         Show version information
  -help            Show this help message
  -verify          Verify configuration file and exit

Examples:
  redd -config /etc/redd/config.yaml
  redd -verify -config configs/redd.yaml
  redd config init
`

// runConfigInit runs the interactive configuration wizard
func runConfigInit() {
	cfg, savePath, err := wizard.RunServerWizard()
	if err != nil {
		fmt.Printf("\n配置生成失败: %v\n", err)
		os.Exit(1)
	}

	if err := config.SaveServerConfig(cfg, savePath); err != nil {
		fmt.Printf("\n保存配置失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n✓ 配置已保存到 %s\n", savePath)
	wizard.PrintServerSummary(cfg)
}

// Server represents the RedPivot server
type Server struct {
	cfg         *config.ServerConfig
	logger      *utils.Logger
	auth        *auth.CompositeAuth
	obfuscator  *countermeasure.Obfuscator
	httpServer  *http.Server
	proxyMgr    *server.ProxyManager
	mu          sync.RWMutex
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
			fmt.Println("用法: redd config init")
			fmt.Println("  交互式生成服务端配置文件")
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
		fmt.Printf("redd version %s\n", version)
		os.Exit(0)
	}

	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		os.Exit(1)
	}

	if *verify {
		fmt.Printf("Configuration file '%s' is valid\n", *configPath)
		fmt.Printf("  Server bind: %s\n", cfg.Server.Bind)
		fmt.Printf("  Domain: %s\n", cfg.Server.Domain)
		fmt.Printf("  TLS enabled: %v\n", cfg.Transport.TLS.Enabled)
		fmt.Printf("  Auth method: %s\n", cfg.Auth.Method)
		fmt.Printf("  Obfuscation enabled: %v\n", cfg.Obfuscation.Enabled)
		os.Exit(0)
	}

	logger := utils.NewLogger(cfg.Logging.Level, cfg.Logging.Format, cfg.Logging.Output)
	logger.SetPrefix("redd")

	logger.Info("Starting RedPivot Server",
		utils.String("version", version),
		utils.String("bind", cfg.Server.Bind),
	)

	// Initialize server
	srv := &Server{
		cfg:        cfg,
		logger:     logger,
		auth:       auth.NewCompositeAuth(auth.NewTokenAuth(cfg.Auth.Tokens), auth.NewRateLimiter(10, 60, 300)),
		obfuscator: countermeasure.NewObfuscator(cfg.Obfuscation.Enabled, cfg.Obfuscation.PaddingProbability, cfg.Obfuscation.TimingJitterMs, cfg.Obfuscation.ChunkMinSize, cfg.Obfuscation.ChunkMaxSize),
	}

	if err := srv.Start(); err != nil {
		logger.Fatal("Failed to start server", utils.Err(err))
	}

	// Wait for shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutting down server...")
	srv.Stop()
	logger.Info("Server stopped")
}

// Start starts the server
func (s *Server) Start() error {
	s.httpServer = &http.Server{Addr: s.cfg.Server.Bind}

	// Create proxy manager (will be set when first client connects)
	// We need a stream opener that can create streams to clients
	// For now, each client connection has its own proxy manager

	// WebSocket upgrader
	wsUpgrader := transport.NewWebSocketUpgrader(s.cfg.Transport.WebSocket.Path, func(ws *transport.WebSocketTransport) {
		s.handleConnection(ws)
	})

	// Configure TLS
	if s.cfg.Transport.TLS.Enabled {
		cert, err := tls.LoadX509KeyPair(s.cfg.Transport.TLS.Cert, s.cfg.Transport.TLS.Key)
		if err != nil {
			return fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		s.httpServer.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	// Set up handlers
	http.Handle(s.cfg.Transport.WebSocket.Path, wsUpgrader)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Start HTTP server
	go func() {
		var err error
		if s.cfg.Transport.TLS.Enabled {
			err = s.httpServer.ListenAndServeTLS("", "")
		} else {
			err = s.httpServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			s.logger.Fatal("Server error", utils.Err(err))
		}
	}()

	s.logger.Info("Server started",
		utils.String("address", s.cfg.Server.Bind),
		utils.Any("tls", s.cfg.Transport.TLS.Enabled),
	)

	return nil
}

// Stop stops the server
func (s *Server) Stop() {
	s.mu.Lock()
	if s.proxyMgr != nil {
		s.proxyMgr.Close()
	}
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s.httpServer.Shutdown(ctx)
}

// handleConnection handles a new WebSocket connection
func (s *Server) handleConnection(ws *transport.WebSocketTransport) {
	defer ws.Close()

	s.logger.Debug("New connection established")

	// Wrap WebSocket as ReadWriteCloser
	rwc := transport.NewWSReadWriteCloser(ws)

	// Wait for authentication frame
	authFrame, err := protocol.DecodeFrame(rwc)
	if err != nil {
		s.logger.Error("Failed to read auth frame", utils.Err(err))
		return
	}

	if authFrame.Type != protocol.FrameAuth {
		s.logger.Error("Expected auth frame", utils.Any("got", authFrame.Type))
		return
	}

	// Validate token
	token := string(authFrame.Payload)
	authInfo, err := s.auth.Authenticate("unknown", []byte(token))
	if err != nil {
		s.logger.Warn("Authentication failed", utils.String("token", token[:min(8, len(token))]+"..."))
		// Send auth failure response
		resp := protocol.NewFrame(protocol.FrameAuthResp, 0, []byte("authentication failed"))
		rwc.Write(resp.Encode())
		return
	}
	_ = authInfo // Session info available if needed

	// Generate session key
	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		s.logger.Error("Failed to generate session key", utils.Err(err))
		return
	}

	// Send auth success with session key
	resp := protocol.NewFrame(protocol.FrameAuthResp, 0, sessionKey)
	if _, err := rwc.Write(resp.Encode()); err != nil {
		s.logger.Error("Failed to send auth response", utils.Err(err))
		return
	}

	s.logger.Info("Client authenticated")

	// Create encrypted connection with session key
	crypto, err := tunnel.NewCryptoLayer(sessionKey)
	if err != nil {
		s.logger.Error("Failed to create crypto layer", utils.Err(err))
		return
	}

	encryptedConn := tunnel.NewEncryptedConn(rwc, crypto)

	// Create stream opener adapter for proxy manager
	streamOpener := &muxStreamOpener{encryptedConn: encryptedConn}

	// Create proxy manager for this client
	s.mu.Lock()
	s.proxyMgr = server.NewProxyManager(streamOpener, s.logger)
	proxyMgr := s.proxyMgr
	s.mu.Unlock()

	defer proxyMgr.Close()

	// Create multiplexer with stream handler
	mux := tunnel.NewMuxWithHandler(encryptedConn, func(stream *tunnel.Stream) {
		s.handleStream(stream, proxyMgr)
	})
	defer mux.Close()

	// Store mux for stream opener
	streamOpener.mux = mux

	// Keep connection alive
	<-mux.Done()
	s.logger.Debug("Connection closed")
}

// handleStream handles a new multiplexed stream
func (s *Server) handleStream(stream *tunnel.Stream, proxyMgr *server.ProxyManager) {
	s.logger.Info("New stream created", utils.Int("stream_id", int(stream.ID())))

	// Read first message to determine stream type
	buf := make([]byte, 64*1024)
	n, err := stream.Read(buf)
	if err != nil {
		s.logger.Error("Failed to read from stream", utils.Err(err))
		stream.Close()
		return
	}

	s.logger.Debug("Received message", utils.Int("bytes", n))

	// Try to decode as proxy message
	msg, err := protocol.DecodeProxyControlMessage(buf[:n])
	if err != nil {
		s.logger.Error("Failed to decode proxy message", utils.Err(err))
		stream.Close()
		return
	}

	s.logger.Debug("Decoded proxy message", utils.String("action", string(msg.Action)), utils.String("name", msg.Name))

	// Handle based on action
	switch msg.Action {
	case protocol.ProxyActionRegister:
		if err := proxyMgr.RegisterProxy(msg); err != nil {
			s.logger.Error("Failed to register proxy",
				utils.String("name", msg.Name),
				utils.Err(err),
			)
			resp := protocol.NewErrorMessage(msg.Name, err.Error())
			data, _ := resp.EncodeJSON()
			stream.Write(data)
			stream.Close()
			return
		}
		s.logger.Info("Proxy registered", utils.String("name", msg.Name))
		resp := protocol.NewSuccessMessage(msg.Name)
		data, _ := resp.EncodeJSON()
		if _, err := stream.Write(data); err != nil {
			s.logger.Error("Failed to write response", utils.Err(err))
		}
		stream.Close()

	case protocol.ProxyActionUnregister:
		if err := proxyMgr.UnregisterProxy(msg.Name); err != nil {
			s.logger.Error("Failed to unregister proxy",
				utils.String("name", msg.Name),
				utils.Err(err),
			)
		}
		stream.Close()

	default:
		// Let proxy manager handle data/close messages
		// But we need to put the read data back somehow
		// For now, just close
		stream.Close()
	}
}

// muxStreamOpener adapts Mux to implement StreamOpener
type muxStreamOpener struct {
	mux           *tunnel.Mux
	encryptedConn *tunnel.EncryptedConn
}

func (m *muxStreamOpener) OpenStream() (server.Stream, error) {
	if m.mux == nil {
		return nil, fmt.Errorf("mux not initialized")
	}
	return m.mux.OpenStream()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
