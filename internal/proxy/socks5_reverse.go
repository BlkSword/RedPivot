// Package proxy provides SOCKS5 reverse proxy implementation
package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redpivot/redpivot/pkg/protocol"
	"github.com/redpivot/redpivot/pkg/utils"
)

var (
	// ErrRSOCKS5NoStreamPool indicates no stream pool is configured
	ErrRSOCKS5NoStreamPool = errors.New("rsocks5: stream pool not configured")
)

// RSOCKS5Proxy represents a reverse SOCKS5 proxy (accepts connections from remote side)
type RSOCKS5Proxy struct {
	name       string
	localAddr  string
	remotePort uint16
	timeout    time.Duration
	allowAuth  bool

	listener   net.Listener
	streamPool StreamPool
	closed     atomic.Bool
	conns      *ConnTracker
	logger     *utils.FieldLogger

	onConnect   func(net.Conn, string)
	onEstablish func(net.Conn, string, string)
}

// NewRSOCKS5Proxy creates a new reverse SOCKS5 proxy
func NewRSOCKS5Proxy(name, localAddr string, remotePort uint16) *RSOCKS5Proxy {
	return &RSOCKS5Proxy{
		name:       name,
		localAddr:  localAddr,
		remotePort: remotePort,
		timeout:    30 * time.Second,
		conns:      &ConnTracker{},
		logger:     utils.DefaultLogger.WithFields(utils.String("proxy", "rsocks5"), utils.String("name", name)),
	}
}

// SetTimeout sets the connection timeout
func (p *RSOCKS5Proxy) SetTimeout(timeout time.Duration) {
	p.timeout = timeout
}

// SetAllowAuth sets whether to allow username/password authentication
func (p *RSOCKS5Proxy) SetAllowAuth(allow bool) {
	p.allowAuth = allow
}

// SetStreamPool sets the stream pool for creating tunnel streams
func (p *RSOCKS5Proxy) SetStreamPool(pool StreamPool) {
	p.streamPool = pool
}

// OnConnect sets a callback for new connections
func (p *RSOCKS5Proxy) OnConnect(callback func(net.Conn, string)) {
	p.onConnect = callback
}

// OnEstablish sets a callback when connection is established
func (p *RSOCKS5Proxy) OnEstablish(callback func(net.Conn, string, string)) {
	p.onEstablish = callback
}

// Start starts the reverse SOCKS5 proxy
func (p *RSOCKS5Proxy) Start() error {
	if p.streamPool == nil {
		p.logger.Error("Stream pool not configured")
		return ErrRSOCKS5NoStreamPool
	}

	listener, err := net.Listen("tcp", p.localAddr)
	if err != nil {
		p.logger.Error("Failed to listen", utils.Err(err), utils.String("addr", p.localAddr))
		return ErrBindFailed
	}

	p.listener = listener
	p.logger.Info("Reverse SOCKS5 proxy started", utils.String("addr", p.localAddr))

	go p.acceptLoop()

	return nil
}

// acceptLoop accepts incoming connections
func (p *RSOCKS5Proxy) acceptLoop() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			if p.closed.Load() {
				return
			}
			p.logger.Error("Accept failed", utils.Err(err))
			continue
		}

		go p.handleConnection(conn)
	}
}

// handleConnection handles a single reverse SOCKS5 connection
func (p *RSOCKS5Proxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	clientAddr := clientConn.RemoteAddr().String()
	p.logger.Debug("New reverse connection", utils.String("client", clientAddr))

	// Set timeout
	if p.timeout > 0 {
		clientConn.SetDeadline(time.Now().Add(p.timeout))
	}

	// Perform SOCKS5 handshake
	if err := p.handshake(clientConn); err != nil {
		p.logger.Debug("Handshake failed", utils.Err(err), utils.String("client", clientAddr))
		return
	}

	// Read and process SOCKS5 request
	targetAddr, err := p.handleRequest(clientConn)
	if err != nil {
		p.logger.Debug("Request failed", utils.Err(err), utils.String("client", clientAddr))
		p.sendErrorReply(clientConn, protocol.ReplyGeneralFailure)
		return
	}

	p.logger.Debug("Connecting through tunnel", utils.String("target", targetAddr), utils.String("client", clientAddr))

	// Call onConnect callback
	if p.onConnect != nil {
		p.onConnect(clientConn, targetAddr)
	}

	// Open a tunnel stream to the remote side
	stream, err := p.streamPool.OpenStream()
	if err != nil {
		p.logger.Debug("Tunnel stream open failed", utils.Err(err), utils.String("target", targetAddr))
		p.sendErrorReply(clientConn, protocol.ReplyGeneralFailure)
		return
	}
	defer stream.Close()

	// Send connection info through the tunnel
	connInfo := &protocol.ProxyMessage{
		Name:       p.name,
		Type:       protocol.ProxyTypeRSOCKS5,
		LocalAddr:  clientAddr,
		RemotePort: p.remotePort,
	}
	infoData := connInfo.Encode()

	// Write connection info to stream
	if _, err := stream.Write(infoData); err != nil {
		p.logger.Debug("Failed to write connection info", utils.Err(err))
		return
	}

	// Send success reply to client with a dummy binding address
	dummyIP := net.ParseIP("0.0.0.0")
	p.sendSuccessReply(clientConn, &net.TCPAddr{IP: dummyIP, Port: 0})

	p.logger.Debug("Connection established through tunnel", utils.String("client", clientAddr), utils.String("target", targetAddr))

	// Track connection
	connID := clientAddr + "->" + targetAddr
	p.conns.Add(connID, clientConn)
	defer p.conns.Remove(connID)

	// Call onEstablish callback
	if p.onEstablish != nil {
		p.onEstablish(clientConn, targetAddr, "0.0.0.0:0")
	}

	// Disable deadline for data transfer
	if p.timeout > 0 {
		clientConn.SetDeadline(time.Time{})
	}

	// Bidirectional data transfer through tunnel
	p.relay(clientConn, stream)
}

// handshake performs SOCKS5 handshake (method selection)
func (p *RSOCKS5Proxy) handshake(conn net.Conn) error {
	// Read handshake request
	buf := make([]byte, 256)
	_, err := io.ReadFull(conn, buf[:2])
	if err != nil {
		return fmt.Errorf("read version/method count: %w", err)
	}

	if buf[0] != protocol.SOCKS5Version {
		conn.Write([]byte{protocol.SOCKS5Version, byte(protocol.AuthNoAcceptable)})
		return ErrInvalidSOCKS5Version
	}

	methodCount := int(buf[1])
	if methodCount == 0 || methodCount > 255 {
		conn.Write([]byte{protocol.SOCKS5Version, byte(protocol.AuthNoAcceptable)})
		return ErrNoAcceptableMethod
	}

	// Read methods
	_, err = io.ReadFull(conn, buf[:methodCount])
	if err != nil {
		return fmt.Errorf("read methods: %w", err)
	}

	// Check if AUTH_NONE is supported
	methods := buf[:methodCount]
	hasNone := false
	hasUserPass := false

	for _, m := range methods {
		switch protocol.AuthMethod(m) {
		case protocol.AuthNone:
			hasNone = true
		case protocol.AuthUserPass:
			hasUserPass = true
		}
	}

	// Select method
	var selectedMethod protocol.AuthMethod
	if hasNone {
		selectedMethod = protocol.AuthNone
	} else if hasUserPass && p.allowAuth {
		selectedMethod = protocol.AuthUserPass
	} else {
		selectedMethod = protocol.AuthNoAcceptable
	}

	// Send method selection response
	resp := protocol.NewHandshakeResponse(selectedMethod)
	if _, err := conn.Write(resp.Encode()); err != nil {
		return fmt.Errorf("write method response: %w", err)
	}

	if selectedMethod == protocol.AuthNoAcceptable {
		return ErrNoAcceptableMethod
	}

	// Handle username/password authentication if selected
	if selectedMethod == protocol.AuthUserPass {
		return p.handleUserPassAuth(conn)
	}

	return nil
}

// handleUserPassAuth handles username/password authentication (RFC 1929)
func (p *RSOCKS5Proxy) handleUserPassAuth(conn net.Conn) error {
	buf := make([]byte, 256)

	// Read auth version
	if _, err := io.ReadFull(conn, buf[:1]); err != nil {
		return fmt.Errorf("read auth version: %w", err)
	}

	if buf[0] != 0x01 {
		return ErrSOCKS5AuthFailed
	}

	// Read username length
	if _, err := io.ReadFull(conn, buf[:1]); err != nil {
		return fmt.Errorf("read username length: %w", err)
	}

	ulen := int(buf[0])

	// Read username
	if _, err := io.ReadFull(conn, buf[:ulen]); err != nil {
		return fmt.Errorf("read username: %w", err)
	}
	username := string(buf[:ulen])

	// Read password length
	if _, err := io.ReadFull(conn, buf[:1]); err != nil {
		return fmt.Errorf("read password length: %w", err)
	}

	plen := int(buf[0])

	// Read password
	if _, err := io.ReadFull(conn, buf[:plen]); err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	password := string(buf[:plen])

	p.logger.Debug("Auth attempt", utils.String("user", username))

	// For now, accept any credentials (in production, validate against a database)
	_ = password // TODO: Implement proper authentication

	// Send auth response (0x01 = version, 0x00 = success)
	resp := []byte{0x01, 0x00}
	if _, err := conn.Write(resp); err != nil {
		return fmt.Errorf("write auth response: %w", err)
	}

	return nil
}

// handleRequest reads and processes SOCKS5 CONNECT request
func (p *RSOCKS5Proxy) handleRequest(conn net.Conn) (string, error) {
	// Read request header (4 bytes)
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("read request header: %w", err)
	}

	if header[0] != protocol.SOCKS5Version {
		return "", ErrInvalidSOCKS5Version
	}

	cmd := protocol.Command(header[1])
	if cmd != protocol.CmdConnect {
		// Only CONNECT is supported
		p.sendErrorReply(conn, protocol.ReplyCommandNotSupported)
		return "", fmt.Errorf("%w: %s", ErrInvalidSOCKS5Command, cmd)
	}

	addrType := protocol.AddressType(header[3])

	// Read address based on type
	var host string
	switch addrType {
	case protocol.AddrIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", fmt.Errorf("read IPv4: %w", err)
		}
		host = net.IP(addr).String()

	case protocol.AddrIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", fmt.Errorf("read IPv6: %w", err)
		}
		host = net.IP(addr).String()

	case protocol.AddrDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", fmt.Errorf("read domain length: %w", err)
		}
		domainLen := int(lenBuf[0])
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", fmt.Errorf("read domain: %w", err)
		}
		host = string(domain)

	default:
		p.sendErrorReply(conn, protocol.ReplyAddressNotSupported)
		return "", fmt.Errorf("%w: 0x%02x", ErrInvalidSOCKS5Address, addrType)
	}

	// Read port
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", fmt.Errorf("read port: %w", err)
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])

	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// sendSuccessReply sends a successful SOCKS5 reply
func (p *RSOCKS5Proxy) sendSuccessReply(conn net.Conn, localAddr *net.TCPAddr) {
	resp := protocol.NewSuccessResponse(localAddr.IP, uint16(localAddr.Port))
	if _, err := conn.Write(resp.Encode()); err != nil {
		p.logger.Error("Failed to send success reply", utils.Err(err))
	}
}

// sendErrorReply sends an error SOCKS5 reply
func (p *RSOCKS5Proxy) sendErrorReply(conn net.Conn, code protocol.ReplyCode) {
	resp := protocol.NewErrorResponse(code)
	if _, err := conn.Write(resp.Encode()); err != nil {
		p.logger.Error("Failed to send error reply", utils.Err(err))
	}
}

// relay performs bidirectional data transfer through tunnel
func (p *RSOCKS5Proxy) relay(client net.Conn, stream io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Stream (Tunnel)
	go func() {
		defer wg.Done()
		io.Copy(stream, client)
		stream.Close()
	}()

	// Stream (Tunnel) -> Client
	go func() {
		defer wg.Done()
		io.Copy(client, stream)
		client.Close()
	}()

	wg.Wait()
}

// Close closes the reverse SOCKS5 proxy
func (p *RSOCKS5Proxy) Close() error {
	if p.closed.CompareAndSwap(false, true) {
		if p.listener != nil {
			p.listener.Close()
		}
		p.conns.CloseAll()
		p.logger.Info("Reverse SOCKS5 proxy closed")
	}
	return nil
}

// Name returns the proxy name
func (p *RSOCKS5Proxy) Name() string {
	return p.name
}

// Type returns the proxy type
func (p *RSOCKS5Proxy) Type() string {
	return "rsocks5"
}

// LocalAddr returns the local address
func (p *RSOCKS5Proxy) LocalAddr() string {
	return p.localAddr
}

// RemotePort returns the remote port
func (p *RSOCKS5Proxy) RemotePort() uint16 {
	return p.remotePort
}

// ConnCount returns the number of active connections
func (p *RSOCKS5Proxy) ConnCount() int64 {
	return p.conns.Count()
}

// RSOCKS5Visitor visits a remote reverse SOCKS5 proxy
type RSOCKS5Visitor struct {
	name      string
	bindAddr  string
	secretKey string

	listener net.Listener
	dialer   func() (io.ReadWriteCloser, error)
	closed   atomic.Bool
	conns    sync.Map
	logger   *utils.FieldLogger
}

// NewRSOCKS5Visitor creates a new RSOCKS5 visitor
func NewRSOCKS5Visitor(name, bindAddr, secretKey string) *RSOCKS5Visitor {
	return &RSOCKS5Visitor{
		name:      name,
		bindAddr:  bindAddr,
		secretKey: secretKey,
		logger:    utils.DefaultLogger.WithFields(utils.String("proxy", "rsocks5_visitor"), utils.String("name", name)),
	}
}

// SetDialer sets the dialer function for creating streams
func (v *RSOCKS5Visitor) SetDialer(dialer func() (io.ReadWriteCloser, error)) {
	v.dialer = dialer
}

// Start starts the visitor
func (v *RSOCKS5Visitor) Start() error {
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

func (v *RSOCKS5Visitor) acceptLoop() {
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

func (v *RSOCKS5Visitor) handleConnection(conn net.Conn) {
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
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(stream, conn)
		stream.Close()
	}()

	go func() {
		defer wg.Done()
		io.Copy(conn, stream)
		conn.Close()
	}()

	wg.Wait()
}

// Close closes the visitor
func (v *RSOCKS5Visitor) Close() error {
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
