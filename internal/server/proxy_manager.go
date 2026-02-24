// Package server provides server-side proxy management
package server

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/redpivot/redpivot/pkg/protocol"
	"github.com/redpivot/redpivot/pkg/utils"
)

// Stream represents a multiplexed stream for sending/receiving data
type Stream interface {
	ID() uint32
	Read(p []byte) (n int, err error)
	Write(p []byte) (n int, err error)
	Close() error
}

// StreamOpener opens new streams to send proxy control messages
type StreamOpener interface {
	OpenStream() (Stream, error)
}

// ServerProxy represents a proxy on the server side
type ServerProxy struct {
	Name       string
	Type       protocol.ProxyMessageType
	RemotePort uint16
	Subdomain  string
	SecretKey  string
	LocalAddr  string

	listener  net.Listener
	connCount uint64
	conns     map[uint32]*ProxyConn
	mu        sync.RWMutex
	closed    bool
	logger    *utils.Logger
}

// ProxyConn represents a single proxy connection
type ProxyConn struct {
	ID       uint32
	Proxy    *ServerProxy
	Conn     net.Conn
	Stream   Stream
	RemoteIP string
	closed   atomic.Bool
}

// ProxyManager manages all server-side proxies
type ProxyManager struct {
	proxies      map[string]*ServerProxy
	streamOpener StreamOpener
	mu           sync.RWMutex
	connID       uint64
	logger       *utils.Logger
}

// NewProxyManager creates a new proxy manager
func NewProxyManager(streamOpener StreamOpener, logger *utils.Logger) *ProxyManager {
	return &ProxyManager{
		proxies:      make(map[string]*ServerProxy),
		streamOpener: streamOpener,
		logger:       logger,
	}
}

// RegisterProxy registers and starts a new proxy
func (pm *ProxyManager) RegisterProxy(msg *protocol.ProxyControlMessage) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, exists := pm.proxies[msg.Name]; exists {
		return fmt.Errorf("proxy %s already exists", msg.Name)
	}

	proxy := &ServerProxy{
		Name:       msg.Name,
		Type:       msg.Type,
		RemotePort: msg.RemotePort,
		Subdomain:  msg.Subdomain,
		SecretKey:  msg.SecretKey,
		LocalAddr:  msg.LocalAddr,
		conns:      make(map[uint32]*ProxyConn),
		logger:     pm.logger,
	}

	switch msg.Type {
	case protocol.ProxyMessageTypeTCP, protocol.ProxyMessageTypeSTCP:
		addr := fmt.Sprintf("0.0.0.0:%d", msg.RemotePort)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %w", addr, err)
		}
		proxy.listener = listener
		go pm.acceptLoop(proxy)

	case protocol.ProxyMessageTypeSOCKS5, protocol.ProxyMessageTypeRSOCKS:
		addr := fmt.Sprintf("0.0.0.0:%d", msg.RemotePort)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %w", addr, err)
		}
		proxy.listener = listener
		go pm.acceptLoop(proxy)

	default:
		return fmt.Errorf("unsupported proxy type: %s", msg.Type)
	}

	pm.proxies[msg.Name] = proxy
	pm.logger.Info("Proxy registered",
		utils.String("name", msg.Name),
		utils.String("type", string(msg.Type)),
		utils.Int("port", int(msg.RemotePort)),
	)

	return nil
}

// UnregisterProxy stops and removes a proxy
func (pm *ProxyManager) UnregisterProxy(name string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	proxy, exists := pm.proxies[name]
	if !exists {
		return fmt.Errorf("proxy %s not found", name)
	}

	proxy.mu.Lock()
	proxy.closed = true
	for _, conn := range proxy.conns {
		conn.Close()
	}
	proxy.mu.Unlock()

	if proxy.listener != nil {
		proxy.listener.Close()
	}

	delete(pm.proxies, name)
	pm.logger.Info("Proxy unregistered", utils.String("name", name))
	return nil
}

// acceptLoop accepts incoming connections for a proxy
func (pm *ProxyManager) acceptLoop(proxy *ServerProxy) {
	for {
		conn, err := proxy.listener.Accept()
		if err != nil {
			proxy.mu.RLock()
			closed := proxy.closed
			proxy.mu.RUnlock()
			if closed {
				return
			}
			pm.logger.Error("Accept error",
				utils.String("proxy", proxy.Name),
				utils.Err(err),
			)
			continue
		}

		go pm.handleNewConnection(proxy, conn)
	}
}

// handleNewConnection handles a new incoming connection
func (pm *ProxyManager) handleNewConnection(proxy *ServerProxy, conn net.Conn) {
	connID := uint32(atomic.AddUint64(&pm.connID, 1))

	stream, err := pm.streamOpener.OpenStream()
	if err != nil {
		pm.logger.Error("Failed to open stream",
			utils.String("proxy", proxy.Name),
			utils.Err(err),
		)
		conn.Close()
		return
	}

	proxyConn := &ProxyConn{
		ID:       connID,
		Proxy:    proxy,
		Conn:     conn,
		Stream:   stream,
		RemoteIP: conn.RemoteAddr().String(),
	}

	proxy.mu.Lock()
	proxy.conns[connID] = proxyConn
	proxy.mu.Unlock()

	connectMsg := protocol.NewConnectMessage(proxy.Name, connID, conn.RemoteAddr().String())
	if err := pm.sendProxyMessage(stream, connectMsg); err != nil {
		pm.logger.Error("Failed to send connect message",
			utils.String("proxy", proxy.Name),
			utils.Err(err),
		)
		proxyConn.Close()
		return
	}

	pm.logger.Debug("New proxy connection",
		utils.String("proxy", proxy.Name),
		utils.Uint32("conn_id", connID),
		utils.String("remote", conn.RemoteAddr().String()),
	)

	go pm.proxyCopyLocalToStream(proxyConn)
	go pm.proxyCopyStreamToLocal(proxyConn)
}

// proxyCopyLocalToStream copies data from local connection to stream
func (pm *ProxyManager) proxyCopyLocalToStream(pc *ProxyConn) {
	defer pc.Close()

	buf := make([]byte, 32*1024)
	for {
		n, err := pc.Conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				pm.logger.Debug("Connection read error",
					utils.String("proxy", pc.Proxy.Name),
					utils.Uint32("conn_id", pc.ID),
					utils.Err(err),
				)
			}
			return
		}

		dataMsg := protocol.NewDataMessage(pc.Proxy.Name, pc.ID, buf[:n])
		if err := pm.sendProxyMessage(pc.Stream, dataMsg); err != nil {
			pm.logger.Debug("Failed to send data message",
				utils.String("proxy", pc.Proxy.Name),
				utils.Uint32("conn_id", pc.ID),
				utils.Err(err),
			)
			return
		}
	}
}

// proxyCopyStreamToLocal copies data from stream to local connection
func (pm *ProxyManager) proxyCopyStreamToLocal(pc *ProxyConn) {
	defer pc.Close()

	buf := make([]byte, 32*1024)
	for {
		n, err := pc.Stream.Read(buf)
		if err != nil {
			if err != io.EOF {
				pm.logger.Debug("Stream read error",
					utils.String("proxy", pc.Proxy.Name),
					utils.Uint32("conn_id", pc.ID),
					utils.Err(err),
				)
			}
			return
		}

		msg, err := protocol.DecodeProxyControlMessage(buf[:n])
		if err != nil {
			pm.logger.Debug("Failed to decode message",
				utils.String("proxy", pc.Proxy.Name),
				utils.Uint32("conn_id", pc.ID),
				utils.Err(err),
			)
			continue
		}

		switch msg.Action {
		case protocol.ProxyActionData:
			if _, err := pc.Conn.Write(msg.Data); err != nil {
				pm.logger.Debug("Failed to write to connection",
					utils.String("proxy", pc.Proxy.Name),
					utils.Uint32("conn_id", pc.ID),
					utils.Err(err),
				)
				return
			}

		case protocol.ProxyActionClose:
			return

		default:
			pm.logger.Debug("Unexpected message action",
				utils.String("proxy", pc.Proxy.Name),
				utils.Uint32("conn_id", pc.ID),
				utils.Any("action", msg.Action),
			)
		}
	}
}

// sendProxyMessage sends a proxy message over stream
func (pm *ProxyManager) sendProxyMessage(stream Stream, msg *protocol.ProxyControlMessage) error {
	data, err := msg.EncodeJSON()
	if err != nil {
		return err
	}
	_, err = stream.Write(data)
	return err
}

// HandleClientMessage handles a message from client (for data/close)
func (pm *ProxyManager) HandleClientMessage(msg *protocol.ProxyControlMessage) error {
	pm.mu.RLock()
	proxy, exists := pm.proxies[msg.Name]
	pm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("proxy %s not found", msg.Name)
	}

	switch msg.Action {
	case protocol.ProxyActionData:
		proxy.mu.RLock()
		conn, exists := proxy.conns[msg.ConnID]
		proxy.mu.RUnlock()

		if !exists {
			return fmt.Errorf("connection %d not found", msg.ConnID)
		}

		if _, err := conn.Conn.Write(msg.Data); err != nil {
			conn.Close()
			return err
		}

	case protocol.ProxyActionClose:
		proxy.mu.RLock()
		conn, exists := proxy.conns[msg.ConnID]
		proxy.mu.RUnlock()

		if exists {
			conn.Close()
		}
	}

	return nil
}

// Close closes all proxies
func (pm *ProxyManager) Close() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for name, proxy := range pm.proxies {
		proxy.mu.Lock()
		proxy.closed = true
		for _, conn := range proxy.conns {
			conn.Close()
		}
		if proxy.listener != nil {
			proxy.listener.Close()
		}
		proxy.mu.Unlock()
		delete(pm.proxies, name)
	}
}

// Close closes a proxy connection
func (pc *ProxyConn) Close() {
	if pc.closed.CompareAndSwap(false, true) {
		if pc.Conn != nil {
			pc.Conn.Close()
		}
		if pc.Stream != nil {
			closeMsg := protocol.NewCloseMessage(pc.Proxy.Name, pc.ID)
			data, _ := closeMsg.EncodeJSON()
			pc.Stream.Write(data)
			pc.Stream.Close()
		}

		pc.Proxy.mu.Lock()
		delete(pc.Proxy.conns, pc.ID)
		pc.Proxy.mu.Unlock()
	}
}

// ListProxies returns list of registered proxies
func (pm *ProxyManager) ListProxies() []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	names := make([]string, 0, len(pm.proxies))
	for name := range pm.proxies {
		names = append(names, name)
	}
	return names
}

// HandleProxyStream handles incoming stream from client for proxy registration
func (pm *ProxyManager) HandleProxyStream(stream Stream) {
	defer stream.Close()

	buf := make([]byte, 64*1024)
	for {
		n, err := stream.Read(buf)
		if err != nil {
			return
		}

		msg, err := protocol.DecodeProxyControlMessage(buf[:n])
		if err != nil {
			pm.logger.Error("Failed to decode proxy message", utils.Err(err))
			continue
		}

		var response *protocol.ProxyControlMessage
		switch msg.Action {
		case protocol.ProxyActionRegister:
			if err := pm.RegisterProxy(msg); err != nil {
				response = protocol.NewErrorMessage(msg.Name, err.Error())
			} else {
				response = protocol.NewSuccessMessage(msg.Name)
			}

		case protocol.ProxyActionUnregister:
			if err := pm.UnregisterProxy(msg.Name); err != nil {
				response = protocol.NewErrorMessage(msg.Name, err.Error())
			} else {
				response = protocol.NewSuccessMessage(msg.Name)
			}

		case protocol.ProxyActionData, protocol.ProxyActionClose:
			if err := pm.HandleClientMessage(msg); err != nil {
				pm.logger.Error("Failed to handle client message",
					utils.String("action", string(msg.Action)),
					utils.Err(err),
				)
			}
			continue

		default:
			response = protocol.NewErrorMessage(msg.Name, "unknown action")
		}

		if response != nil {
			data, err := response.EncodeJSON()
			if err != nil {
				pm.logger.Error("Failed to encode response", utils.Err(err))
				continue
			}
			if _, err := stream.Write(data); err != nil {
				pm.logger.Error("Failed to send response", utils.Err(err))
				return
			}
		}
	}
}
