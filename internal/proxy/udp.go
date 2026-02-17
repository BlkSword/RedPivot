package proxy

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrUDPBroadcast   = errors.New("broadcast not supported")
	ErrUDPPacketLarge = errors.New("packet too large")
)

const (
	MaxUDPPacketSize = 64 * 1024
	UDPTimeout       = 60 * time.Second
)

// UDPProxy represents a UDP proxy
type UDPProxy struct {
	name       string
	localAddr  string
	remotePort uint16

	conn       *net.UDPConn
	streamPool StreamPool
	closed     atomic.Bool
	sessions   sync.Map // addr -> *UDPSession
}

// UDPSession represents a UDP session
type UDPSession struct {
	remoteAddr *net.UDPAddr
	stream     io.ReadWriteCloser
	lastSeen   time.Time
}

// NewUDPProxy creates a new UDP proxy
func NewUDPProxy(name, localAddr string, remotePort uint16) *UDPProxy {
	return &UDPProxy{
		name:       name,
		localAddr:  localAddr,
		remotePort: remotePort,
	}
}

// SetStreamPool sets the stream pool
func (p *UDPProxy) SetStreamPool(pool StreamPool) {
	p.streamPool = pool
}

// Start starts the UDP proxy
func (p *UDPProxy) Start() error {
	if p.streamPool == nil {
		return errors.New("stream pool not set")
	}

	addr, err := net.ResolveUDPAddr("udp", p.localAddr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return ErrBindFailed
	}

	p.conn = conn

	// Start read loop
	go p.readLoop()

	// Start session cleanup
	go p.cleanupSessions()

	return nil
}

// readLoop reads UDP packets
func (p *UDPProxy) readLoop() {
	buf := make([]byte, MaxUDPPacketSize)

	for {
		n, remoteAddr, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			if p.closed.Load() {
				return
			}
			continue
		}

		// Copy packet data
		data := make([]byte, n)
		copy(data, buf[:n])

		go p.handlePacket(remoteAddr, data)
	}
}

// handlePacket handles a UDP packet
func (p *UDPProxy) handlePacket(remoteAddr *net.UDPAddr, data []byte) {
	// Find or create session
	session := p.getOrCreateSession(remoteAddr)
	if session == nil {
		return
	}

	// Update last seen
	session.lastSeen = time.Now()

	// Forward to tunnel
	_, err := session.stream.Write(data)
	if err != nil {
		p.sessions.Delete(remoteAddr.String())
		session.stream.Close()
	}
}

// getOrCreateSession gets or creates a UDP session
func (p *UDPProxy) getOrCreateSession(remoteAddr *net.UDPAddr) *UDPSession {
	key := remoteAddr.String()

	if val, ok := p.sessions.Load(key); ok {
		return val.(*UDPSession)
	}

	// Create new session
	stream, err := p.streamPool.OpenStream()
	if err != nil {
		return nil
	}

	session := &UDPSession{
		remoteAddr: remoteAddr,
		stream:     stream,
		lastSeen:   time.Now(),
	}

	// Start response handler
	go p.handleResponses(session)

	val, loaded := p.sessions.LoadOrStore(key, session)
	if loaded {
		stream.Close()
		return val.(*UDPSession)
	}

	return session
}

// handleResponses handles responses from the tunnel
func (p *UDPProxy) handleResponses(session *UDPSession) {
	buf := make([]byte, MaxUDPPacketSize)

	for {
		n, err := session.stream.Read(buf)
		if err != nil {
			return
		}

		if p.closed.Load() {
			return
		}

		// Send response back to client
		_, err = p.conn.WriteToUDP(buf[:n], session.remoteAddr)
		if err != nil {
			return
		}
	}
}

// cleanupSessions cleans up idle sessions
func (p *UDPProxy) cleanupSessions() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if p.closed.Load() {
			return
		}

		now := time.Now()
		p.sessions.Range(func(key, value interface{}) bool {
			session := value.(*UDPSession)
			if now.Sub(session.lastSeen) > UDPTimeout {
				p.sessions.Delete(key)
				session.stream.Close()
			}
			return true
		})
	}
}

// Close closes the UDP proxy
func (p *UDPProxy) Close() error {
	if p.closed.CompareAndSwap(false, true) {
		if p.conn != nil {
			p.conn.Close()
		}

		// Close all sessions
		p.sessions.Range(func(key, value interface{}) bool {
			session := value.(*UDPSession)
			session.stream.Close()
			return true
		})
	}
	return nil
}

// Name returns the proxy name
func (p *UDPProxy) Name() string {
	return p.name
}

// Type returns the proxy type
func (p *UDPProxy) Type() string {
	return "udp"
}

// LocalAddr returns the local address
func (p *UDPProxy) LocalAddr() string {
	return p.localAddr
}

// RemotePort returns the remote port
func (p *UDPProxy) RemotePort() uint16 {
	return p.remotePort
}

// UDPConnTrack tracks UDP connections with timeout
type UDPConnTrack struct {
	conns  sync.Map
	ttl    time.Duration
	closed atomic.Bool
}

// NewUDPConnTrack creates a new connection tracker
func NewUDPConnTrack(ttl time.Duration) *UDPConnTrack {
	return &UDPConnTrack{
		ttl: ttl,
	}
}

// Track tracks a connection
func (t *UDPConnTrack) Track(id string, conn io.Closer) {
	t.conns.Store(id, &trackedConn{
		conn:     conn,
		lastSeen: time.Now(),
	})
}

// Update updates the last seen time
func (t *UDPConnTrack) Update(id string) {
	if val, ok := t.conns.Load(id); ok {
		tc := val.(*trackedConn)
		tc.lastSeen = time.Now()
	}
}

// Remove removes a connection
func (t *UDPConnTrack) Remove(id string) {
	t.conns.Delete(id)
}

// Cleanup removes expired connections
func (t *UDPConnTrack) Cleanup() {
	now := time.Now()
	t.conns.Range(func(key, value interface{}) bool {
		tc := value.(*trackedConn)
		if now.Sub(tc.lastSeen) > t.ttl {
			tc.conn.Close()
			t.conns.Delete(key)
		}
		return true
	})
}

type trackedConn struct {
	conn     io.Closer
	lastSeen time.Time
}
