// Package main is the server entry point
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redpivot/redpivot/internal/auth"
	"github.com/redpivot/redpivot/internal/config"
	"github.com/redpivot/redpivot/internal/countermeasure"
	"github.com/redpivot/redpivot/internal/transport"
	"github.com/redpivot/redpivot/internal/tunnel"
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
  redd [options]

Options:
  -config <path>   Path to configuration file (default: configs/redd.yaml)
  -version         Show version information
  -help            Show this help message
  -verify          Verify configuration file and exit

Examples:
  redd -config /etc/redd/config.yaml
  redd -verify -config configs/redd.yaml
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
		fmt.Printf("redd version %s\n", version)
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Handle verify flag
	if *verify {
		fmt.Printf("Configuration file '%s' is valid\n", *configPath)
		fmt.Printf("  Server bind: %s\n", cfg.Server.Bind)
		fmt.Printf("  Domain: %s\n", cfg.Server.Domain)
		fmt.Printf("  TLS enabled: %v\n", cfg.Transport.TLS.Enabled)
		fmt.Printf("  Auth method: %s\n", cfg.Auth.Method)
		fmt.Printf("  Obfuscation enabled: %v\n", cfg.Obfuscation.Enabled)
		os.Exit(0)
	}

	// Initialize logger
	logger := utils.NewLogger(cfg.Logging.Level, cfg.Logging.Format, cfg.Logging.Output)
	logger.SetPrefix("redd")

	logger.Info("Starting RedPivot Server",
		utils.String("version", version),
		utils.String("bind", cfg.Server.Bind),
	)

	// Initialize authenticator
	authenticator := auth.NewTokenAuth(cfg.Auth.Tokens)
	rateLimiter := auth.NewRateLimiter(10, 60, 300) // 10 attempts per minute, 5 min ban
	compositeAuth := auth.NewCompositeAuth(authenticator, rateLimiter)

	// Initialize obfuscator
	obfuscator := countermeasure.NewObfuscator(
		cfg.Obfuscation.Enabled,
		cfg.Obfuscation.PaddingProbability,
		cfg.Obfuscation.TimingJitterMs,
		cfg.Obfuscation.ChunkMinSize,
		cfg.Obfuscation.ChunkMaxSize,
	)

	// Initialize HTTP server for WebSocket upgrade
	httpServer := &http.Server{
		Addr: cfg.Server.Bind,
	}

	// WebSocket upgrader
	wsUpgrader := transport.NewWebSocketUpgrader(cfg.Transport.WebSocket.Path, func(ws *transport.WebSocketTransport) {
		handleConnection(ws, compositeAuth, obfuscator, logger)
	})

	// Configure TLS if enabled
	if cfg.Transport.TLS.Enabled {
		cert, err := tls.LoadX509KeyPair(cfg.Transport.TLS.Cert, cfg.Transport.TLS.Key)
		if err != nil {
			logger.Fatal("Failed to load TLS certificate", utils.Err(err))
		}

		httpServer.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	// Set up HTTP handlers
	http.Handle(cfg.Transport.WebSocket.Path, wsUpgrader)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Start server
	go func() {
		var err error
		if cfg.Transport.TLS.Enabled {
			err = httpServer.ListenAndServeTLS("", "")
		} else {
			err = httpServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			logger.Fatal("Server error", utils.Err(err))
		}
	}()

	logger.Info("Server started",
		utils.String("address", cfg.Server.Bind),
		utils.Any("tls", cfg.Transport.TLS.Enabled),
	)

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("Shutdown error", utils.Err(err))
	}

	logger.Info("Server stopped")
}

// handleConnection handles a new WebSocket connection
func handleConnection(ws *transport.WebSocketTransport, authenticator *auth.CompositeAuth, obfuscator *countermeasure.Obfuscator, logger *utils.Logger) {
	defer ws.Close()

	logger.Debug("New connection established")

	// Wrap WebSocket as ReadWriteCloser
	rwc := transport.NewWSReadWriteCloser(ws)

	// Wait for authentication frame
	// Simplified - in production, you'd read and verify auth frame first

	// Create encrypted connection
	// In production, key would be exchanged during handshake
	key := make([]byte, 32)
	copy(key, []byte("temporary-key-for-demo-purposes!"))

	crypto, err := tunnel.NewCryptoLayer(key)
	if err != nil {
		logger.Error("Failed to create crypto layer", utils.Err(err))
		return
	}

	encryptedConn := tunnel.NewEncryptedConn(rwc, crypto)

	// Create multiplexer with stream handler
	mux := tunnel.NewMuxWithHandler(encryptedConn, func(stream *tunnel.Stream) {
		handleStream(stream, obfuscator, logger)
	})
	defer mux.Close()

	// Keep connection alive
	<-mux.Done()
	logger.Debug("Connection closed")
}

// handleStream handles a new multiplexed stream
func handleStream(stream *tunnel.Stream, obfuscator *countermeasure.Obfuscator, logger *utils.Logger) {
	defer stream.Close()

	logger.Debug("New stream created", utils.Int("stream_id", int(stream.ID())))

	// In a full implementation, this would:
	// 1. Read proxy registration message
	// 2. Set up appropriate proxy (TCP/UDP/HTTP)
	// 3. Forward traffic between stream and local service

	// For demo, just echo data back
	buf := make([]byte, 32*1024)
	for {
		n, err := stream.Read(buf)
		if err != nil {
			return
		}

		// Deobfuscate
		data, err := obfuscator.Deobfuscate(buf[:n])
		if err != nil {
			logger.Error("Deobfuscation error", utils.Err(err))
			continue
		}

		logger.Debug("Received data", utils.Int("bytes", len(data)))

		// Echo back (in production, forward to local service)
		obfuscated := obfuscator.Obfuscate(data)
		_, err = stream.Write(obfuscated)
		if err != nil {
			return
		}
	}
}
