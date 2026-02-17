// Package proxy provides proxy implementations
package proxy

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redpivot/redpivot/pkg/protocol"
)

var (
	ErrProxyClosed    = errors.New("proxy closed")
	ErrBindFailed     = errors.New("bind failed")
	ErrAcceptFailed   = errors.New("accept failed")
	ErrConnectFailed  = errors.New("connect failed")
)

// TCPProxy represents a TCP proxy
type TCPProxy struct {
	name       string
	localAddr  string
	remotePort uint16

	listener   net.Listener
	streamPool StreamPool
	closed     atomic.Bool
	conns      sync.Map
	onConnect  func(net.Conn)
}

// StreamPool provides streams for proxying
type StreamPool interface {
	OpenStream() (io.ReadWriteCloser, error)
}

// NewTCPProxy creates a new TCP proxy
func NewTCPProxy(name, localAddr string, remotePort uint16) *TCPProxy {
	return &TCPProxy{
		name:       name,
		localAddr:  localAddr,
		remotePort: remotePort,
	}
}

// SetStreamPool sets the stream pool for creating new streams
func (p *TCPProxy) SetStreamPool(pool StreamPool) {
	p.streamPool = pool
}

// OnConnect sets a callback for new connections
func (p *TCPProxy) OnConnect(callback func(net.Conn)) {
	p.onConnect = callback
}

// Start starts the TCP proxy
func (p *TCPProxy) Start() error {
	if p.streamPool == nil {
		return errors.New("stream pool not set")
	}

	listener, err := net.Listen("tcp", p.localAddr)
	if err != nil {
		return ErrBindFailed
	}

	p.listener = listener

	// Accept loop
	go p.acceptLoop()

	return nil
}

// acceptLoop accepts incoming connections
func (p *TCPProxy) acceptLoop() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			if p.closed.Load() {
				return
			}
			continue
		}

		go p.handleConnection(conn)
	}
}

// handleConnection handles a single connection
func (p *TCPProxy) handleConnection(conn net.Conn) {
	defer conn.Close()

	if p.onConnect != nil {
		p.onConnect(conn)
	}

	// Open a stream through the tunnel
	stream, err := p.streamPool.OpenStream()
	if err != nil {
		return
	}
	defer stream.Close()

	// Store connection
	connID := conn.RemoteAddr().String()
	p.conns.Store(connID, conn)
	defer p.conns.Delete(connID)

	// Notify remote about new connection
	proxyMsg := &protocol.ProxyMessage{
		Name:       p.name,
		Type:       protocol.ProxyTypeTCP,
		LocalAddr:  conn.RemoteAddr().String(),
		RemotePort: p.remotePort,
	}
	_ = proxyMsg // Used in production to notify remote

	// Bidirectional copy
	go func() {
		io.Copy(stream, conn)
		conn.Close()
		stream.Close()
	}()

	io.Copy(conn, stream)
}

// Close closes the TCP proxy
func (p *TCPProxy) Close() error {
	if p.closed.CompareAndSwap(false, true) {
		if p.listener != nil {
			p.listener.Close()
		}

		// Close all connections
		p.conns.Range(func(key, value interface{}) bool {
			conn := value.(net.Conn)
			conn.Close()
			return true
		})
	}
	return nil
}

// Name returns the proxy name
func (p *TCPProxy) Name() string {
	return p.name
}

// Type returns the proxy type
func (p *TCPProxy) Type() string {
	return "tcp"
}

// LocalAddr returns the local address
func (p *TCPProxy) LocalAddr() string {
	return p.localAddr
}

// RemotePort returns the remote port
func (p *TCPProxy) RemotePort() uint16 {
	return p.remotePort
}

// TCPVisitor visits a remote TCP proxy (for STCP)
type TCPVisitor struct {
	name      string
	bindAddr  string
	secretKey string

	listener  net.Listener
	dialer    func() (io.ReadWriteCloser, error)
	closed    atomic.Bool
	conns     sync.Map
}

// NewTCPVisitor creates a new TCP visitor
func NewTCPVisitor(name, bindAddr, secretKey string) *TCPVisitor {
	return &TCPVisitor{
		name:      name,
		bindAddr:  bindAddr,
		secretKey: secretKey,
	}
}

// SetDialer sets the dialer function for creating streams
func (v *TCPVisitor) SetDialer(dialer func() (io.ReadWriteCloser, error)) {
	v.dialer = dialer
}

// Start starts the visitor
func (v *TCPVisitor) Start() error {
	if v.dialer == nil {
		return errors.New("dialer not set")
	}

	listener, err := net.Listen("tcp", v.bindAddr)
	if err != nil {
		return ErrBindFailed
	}

	v.listener = listener

	go v.acceptLoop()

	return nil
}

func (v *TCPVisitor) acceptLoop() {
	for {
		conn, err := v.listener.Accept()
		if err != nil {
			if v.closed.Load() {
				return
			}
			continue
		}

		go v.handleConnection(conn)
	}
}

func (v *TCPVisitor) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Dial stream to remote
	stream, err := v.dialer()
	if err != nil {
		return
	}
	defer stream.Close()

	// Store connection
	connID := conn.RemoteAddr().String()
	v.conns.Store(connID, conn)
	defer v.conns.Delete(connID)

	// Bidirectional copy
	go func() {
		io.Copy(stream, conn)
		conn.Close()
		stream.Close()
	}()

	io.Copy(conn, stream)
}

// Close closes the visitor
func (v *TCPVisitor) Close() error {
	if v.closed.CompareAndSwap(false, true) {
		if v.listener != nil {
			v.listener.Close()
		}

		v.conns.Range(func(key, value interface{}) bool {
			conn := value.(net.Conn)
			conn.Close()
			return true
		})
	}
	return nil
}

// ConnTracker tracks active connections
type ConnTracker struct {
	conns sync.Map
	count int64
}

// Add adds a connection
func (t *ConnTracker) Add(id string, conn net.Conn) {
	t.conns.Store(id, conn)
	atomic.AddInt64(&t.count, 1)
}

// Remove removes a connection
func (t *ConnTracker) Remove(id string) {
	t.conns.Delete(id)
	atomic.AddInt64(&t.count, -1)
}

// Count returns the number of connections
func (t *ConnTracker) Count() int64 {
	return atomic.LoadInt64(&t.count)
}

// CloseAll closes all connections
func (t *ConnTracker) CloseAll() {
	t.conns.Range(func(key, value interface{}) bool {
		conn := value.(net.Conn)
		conn.Close()
		return true
	})
}

// SetKeepAlive sets keepalive on a connection
func SetKeepAlive(conn net.Conn, keepalive bool, interval time.Duration) error {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return errors.New("not a TCP connection")
	}

	if err := tcpConn.SetKeepAlive(keepalive); err != nil {
		return err
	}

	if keepalive && interval > 0 {
		return tcpConn.SetKeepAlivePeriod(interval)
	}

	return nil
}

// SetTimeouts sets read/write timeouts on a connection
func SetTimeouts(conn net.Conn, readTimeout, writeTimeout time.Duration) error {
	if readTimeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			return err
		}
	}
	if writeTimeout > 0 {
		if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
			return err
		}
	}
	return nil
}
