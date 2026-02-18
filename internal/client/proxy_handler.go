// Package client provides client-side proxy handling
package client

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redpivot/redpivot/internal/config"
	"github.com/redpivot/redpivot/pkg/protocol"
	"github.com/redpivot/redpivot/pkg/utils"
)

// Stream represents a multiplexed stream
type Stream interface {
	ID() uint32
	Read(p []byte) (n int, err error)
	Write(p []byte) (n int, err error)
	Close() error
}

// StreamOpener opens new streams
type StreamOpener interface {
	OpenStream() (Stream, error)
}

// ClientConn represents a single client-side proxy connection
type ClientConn struct {
	ID        uint32
	ProxyName string
	LocalConn net.Conn
	Stream    Stream
	closed    atomic.Bool
}

// ProxyHandler handles client-side proxy operations
type ProxyHandler struct {
	streamOpener StreamOpener
	proxies      map[string]*config.ProxyConfig
	conns        map[uint32]*ClientConn
	mu           sync.RWMutex
	logger       *utils.Logger
}

// NewProxyHandler creates a new proxy handler
func NewProxyHandler(streamOpener StreamOpener, logger *utils.Logger) *ProxyHandler {
	return &ProxyHandler{
		streamOpener: streamOpener,
		proxies:      make(map[string]*config.ProxyConfig),
		conns:        make(map[uint32]*ClientConn),
		logger:       logger,
	}
}

// RegisterProxies registers all proxies with the server
func (ph *ProxyHandler) RegisterProxies(proxies []config.ProxyConfig) error {
	ph.mu.Lock()
	defer ph.mu.Unlock()

	for i := range proxies {
		cfg := &proxies[i]
		ph.proxies[cfg.Name] = cfg

		stream, err := ph.streamOpener.OpenStream()
		if err != nil {
			return fmt.Errorf("failed to open stream for proxy %s: %w", cfg.Name, err)
		}

		proxyType := protocol.ProxyMessageType(cfg.Type)
		registerMsg := protocol.NewRegisterMessage(
			cfg.Name,
			proxyType,
			uint16(cfg.RemotePort),
			cfg.Local,
			cfg.Subdomain,
			cfg.SecretKey,
		)

		if err := ph.sendProxyMessage(stream, registerMsg); err != nil {
			stream.Close()
			return fmt.Errorf("failed to register proxy %s: %w", cfg.Name, err)
		}

		response, err := ph.readProxyMessage(stream)
		if err != nil {
			stream.Close()
			return fmt.Errorf("failed to read response for proxy %s: %w", cfg.Name, err)
		}

		if response.Action == protocol.ProxyActionError {
			stream.Close()
			return fmt.Errorf("proxy %s registration failed: %s", cfg.Name, response.Error)
		}

		stream.Close()

		ph.logger.Info("Proxy registered with server",
			utils.String("name", cfg.Name),
			utils.String("type", cfg.Type),
			utils.Int("remote_port", cfg.RemotePort),
		)
	}

	return nil
}

// HandleStream handles an incoming stream from server
func (ph *ProxyHandler) HandleStream(stream Stream) {
	msg, err := ph.readProxyMessage(stream)
	if err != nil {
		ph.logger.Error("Failed to read proxy message", utils.Err(err))
		stream.Close()
		return
	}

	switch msg.Action {
	case protocol.ProxyActionConnect:
		// handleConnect takes ownership of the stream and will close it
		ph.handleConnect(stream, msg)
	case protocol.ProxyActionData:
		ph.handleData(msg)
		stream.Close()
	case protocol.ProxyActionClose:
		ph.handleClose(msg)
		stream.Close()
	default:
		ph.logger.Warn("Unknown proxy action", utils.Any("action", msg.Action))
		stream.Close()
	}
}

// handleConnect handles a new connection from server
func (ph *ProxyHandler) handleConnect(stream Stream, msg *protocol.ProxyControlMessage) {
	ph.mu.RLock()
	cfg, exists := ph.proxies[msg.Name]
	ph.mu.RUnlock()

	if !exists {
		ph.logger.Error("Unknown proxy", utils.String("name", msg.Name))
		return
	}

	localConn, err := net.DialTimeout("tcp", cfg.Local, 10*time.Second)
	if err != nil {
		ph.logger.Error("Failed to connect to local service",
			utils.String("proxy", msg.Name),
			utils.String("local", cfg.Local),
			utils.Err(err),
		)
		closeMsg := protocol.NewCloseMessage(msg.Name, msg.ConnID)
		ph.sendProxyMessage(stream, closeMsg)
		return
	}

	clientConn := &ClientConn{
		ID:        msg.ConnID,
		ProxyName: msg.Name,
		LocalConn: localConn,
		Stream:    stream,
	}

	ph.mu.Lock()
	ph.conns[msg.ConnID] = clientConn
	ph.mu.Unlock()

	ph.logger.Debug("New proxy connection",
		utils.String("proxy", msg.Name),
		utils.Uint32("conn_id", msg.ConnID),
		utils.String("local", cfg.Local),
	)

	go ph.copyLocalToStream(clientConn)
	go ph.copyStreamToLocal(clientConn)
}

// handleData handles incoming data from server
func (ph *ProxyHandler) handleData(msg *protocol.ProxyControlMessage) {
	ph.mu.RLock()
	conn, exists := ph.conns[msg.ConnID]
	ph.mu.RUnlock()

	if !exists {
		ph.logger.Warn("Unknown connection for data", utils.Uint32("conn_id", msg.ConnID))
		return
	}

	if _, err := conn.LocalConn.Write(msg.Data); err != nil {
		ph.logger.Debug("Failed to write to local connection",
			utils.Uint32("conn_id", msg.ConnID),
			utils.Err(err),
		)
		conn.Close()
		ph.removeConnection(msg.ConnID)
	}
}

// handleClose handles close message from server
func (ph *ProxyHandler) handleClose(msg *protocol.ProxyControlMessage) {
	ph.mu.RLock()
	conn, exists := ph.conns[msg.ConnID]
	ph.mu.RUnlock()

	if exists {
		conn.Close()
		ph.removeConnection(msg.ConnID)
	}
}

// copyLocalToStream copies data from local connection to stream
func (ph *ProxyHandler) copyLocalToStream(conn *ClientConn) {
	defer func() {
		conn.Close()
		ph.removeConnection(conn.ID)
	}()

	buf := make([]byte, 32*1024)
	for {
		n, err := conn.LocalConn.Read(buf)
		if err != nil {
			if err != io.EOF {
				ph.logger.Debug("Local connection read error",
					utils.String("proxy", conn.ProxyName),
					utils.Uint32("conn_id", conn.ID),
					utils.Err(err),
				)
			}
			return
		}

		dataMsg := protocol.NewDataMessage(conn.ProxyName, conn.ID, buf[:n])
		if err := ph.sendProxyMessage(conn.Stream, dataMsg); err != nil {
			ph.logger.Debug("Failed to send data to server",
				utils.String("proxy", conn.ProxyName),
				utils.Uint32("conn_id", conn.ID),
				utils.Err(err),
			)
			return
		}
	}
}

// copyStreamToLocal copies data from stream to local connection
func (ph *ProxyHandler) copyStreamToLocal(conn *ClientConn) {
	defer func() {
		conn.Close()
		ph.removeConnection(conn.ID)
	}()

	buf := make([]byte, 32*1024)
	for {
		n, err := conn.Stream.Read(buf)
		if err != nil {
			if err != io.EOF {
				ph.logger.Debug("Stream read error",
					utils.String("proxy", conn.ProxyName),
					utils.Uint32("conn_id", conn.ID),
					utils.Err(err),
				)
			}
			return
		}

		msg, err := protocol.DecodeProxyControlMessage(buf[:n])
		if err != nil {
			ph.logger.Debug("Failed to decode message",
				utils.String("proxy", conn.ProxyName),
				utils.Uint32("conn_id", conn.ID),
				utils.Err(err),
			)
			continue
		}

		switch msg.Action {
		case protocol.ProxyActionData:
			if _, err := conn.LocalConn.Write(msg.Data); err != nil {
				ph.logger.Debug("Failed to write to local connection",
					utils.String("proxy", conn.ProxyName),
					utils.Uint32("conn_id", conn.ID),
					utils.Err(err),
				)
				return
			}
		case protocol.ProxyActionClose:
			return
		default:
			ph.logger.Debug("Unexpected message action", utils.Any("action", msg.Action))
		}
	}
}

// sendProxyMessage sends a proxy message over stream
func (ph *ProxyHandler) sendProxyMessage(stream Stream, msg *protocol.ProxyControlMessage) error {
	data, err := msg.EncodeJSON()
	if err != nil {
		return err
	}
	_, err = stream.Write(data)
	return err
}

// readProxyMessage reads a proxy message from stream
func (ph *ProxyHandler) readProxyMessage(stream Stream) (*protocol.ProxyControlMessage, error) {
	buf := make([]byte, 64*1024)
	n, err := stream.Read(buf)
	if err != nil {
		return nil, err
	}
	return protocol.DecodeProxyControlMessage(buf[:n])
}

// removeConnection removes a connection from the map
func (ph *ProxyHandler) removeConnection(connID uint32) {
	ph.mu.Lock()
	delete(ph.conns, connID)
	ph.mu.Unlock()
}

// Close closes all connections
func (ph *ProxyHandler) Close() {
	ph.mu.Lock()
	defer ph.mu.Unlock()

	for _, conn := range ph.conns {
		conn.Close()
	}
	ph.conns = make(map[uint32]*ClientConn)
}

// Close closes a client connection
func (cc *ClientConn) Close() {
	if cc.closed.CompareAndSwap(false, true) {
		if cc.LocalConn != nil {
			cc.LocalConn.Close()
		}
		if cc.Stream != nil {
			cc.Stream.Close()
		}
	}
}

// UnregisterProxy unregisters a proxy from server
func (ph *ProxyHandler) UnregisterProxy(name string) error {
	ph.mu.Lock()
	defer ph.mu.Unlock()

	delete(ph.proxies, name)

	for id, conn := range ph.conns {
		if conn.ProxyName == name {
			conn.Close()
			delete(ph.conns, id)
		}
	}

	ph.logger.Info("Proxy unregistered", utils.String("name", name))
	return nil
}
