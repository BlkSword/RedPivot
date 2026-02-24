// Package proxy provides SOCKS5 forward proxy implementation
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
	// ErrSOCKS5HandshakeFailed indicates SOCKS5 handshake failed
	ErrSOCKS5HandshakeFailed = errors.New("socks5 handshake failed")
	// ErrSOCKS5AuthFailed indicates SOCKS5 authentication failed
	ErrSOCKS5AuthFailed = errors.New("socks5 authentication failed")
	// ErrSOCKS5CommandFailed indicates SOCKS5 command failed
	ErrSOCKS5CommandFailed = errors.New("socks5 command failed")
	// ErrInvalidSOCKS5Version indicates invalid SOCKS5 version
	ErrInvalidSOCKS5Version = errors.New("invalid socks5 version")
	// ErrNoAcceptableMethod indicates no acceptable authentication method
	ErrNoAcceptableMethod = errors.New("no acceptable socks5 method")
	// ErrInvalidSOCKS5Command indicates invalid SOCKS5 command
	ErrInvalidSOCKS5Command = errors.New("invalid socks5 command")
	// ErrInvalidSOCKS5Address indicates invalid SOCKS5 address
	ErrInvalidSOCKS5Address = errors.New("invalid socks5 address")
)

// SOCKS5Proxy represents a SOCKS5 forward proxy
type SOCKS5Proxy struct {
	name      string
	bindAddr  string
	timeout   time.Duration
	allowAuth bool // Allow username/password auth

	listener net.Listener
	closed   atomic.Bool
	conns    *ConnTracker
	logger   *utils.FieldLogger

	// Callbacks
	onConnect   func(net.Conn, string) // Called when new connection arrives
	onEstablish func(net.Conn, string, string)
}

// NewSOCKS5Proxy creates a new SOCKS5 proxy
func NewSOCKS5Proxy(name, bindAddr string) *SOCKS5Proxy {
	return &SOCKS5Proxy{
		name:     name,
		bindAddr: bindAddr,
		timeout:  30 * time.Second,
		conns:    &ConnTracker{},
		logger:   utils.DefaultLogger.WithFields(utils.String("proxy", "socks5"), utils.String("name", name)),
	}
}

// SetTimeout sets the connection timeout
func (p *SOCKS5Proxy) SetTimeout(timeout time.Duration) {
	p.timeout = timeout
}

// SetAllowAuth sets whether to allow username/password authentication
func (p *SOCKS5Proxy) SetAllowAuth(allow bool) {
	p.allowAuth = allow
}

// SetStreamPool is not used for SOCKS5 forward proxy
func (p *SOCKS5Proxy) SetStreamPool(pool StreamPool) {
	// SOCKS5 forward proxy doesn't use stream pool
}

// OnConnect sets a callback for new connections
func (p *SOCKS5Proxy) OnConnect(callback func(net.Conn, string)) {
	p.onConnect = callback
}

// OnEstablish sets a callback when connection is established
func (p *SOCKS5Proxy) OnEstablish(callback func(net.Conn, string, string)) {
	p.onEstablish = callback
}

// Start starts the SOCKS5 proxy
func (p *SOCKS5Proxy) Start() error {
	listener, err := net.Listen("tcp", p.bindAddr)
	if err != nil {
		p.logger.Error("Failed to listen", utils.Err(err), utils.String("addr", p.bindAddr))
		return ErrBindFailed
	}

	p.listener = listener
	p.logger.Info("SOCKS5 proxy started", utils.String("addr", p.bindAddr))

	go p.acceptLoop()

	return nil
}

// acceptLoop accepts incoming connections
func (p *SOCKS5Proxy) acceptLoop() {
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

// handleConnection handles a single SOCKS5 connection
func (p *SOCKS5Proxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	clientAddr := clientConn.RemoteAddr().String()
	p.logger.Debug("New connection", utils.String("client", clientAddr))

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
		// Send error response if not already sent
		p.sendErrorReply(clientConn, protocol.ReplyGeneralFailure)
		return
	}

	p.logger.Debug("Connecting to target", utils.String("target", targetAddr), utils.String("client", clientAddr))

	// Call onConnect callback
	if p.onConnect != nil {
		p.onConnect(clientConn, targetAddr)
	}

	// Connect to target
	targetConn, err := net.DialTimeout("tcp", targetAddr, p.timeout)
	if err != nil {
		p.logger.Debug("Target connection failed", utils.Err(err), utils.String("target", targetAddr))
		p.sendErrorReply(clientConn, protocol.ReplyHostUnreachable)
		return
	}
	defer targetConn.Close()

	// Get local address for binding
	localAddr := targetConn.LocalAddr().(*net.TCPAddr)
	p.sendSuccessReply(clientConn, localAddr)

	p.logger.Debug("Connection established", utils.String("client", clientAddr), utils.String("target", targetAddr))

	// Track connection
	connID := clientAddr + "->" + targetAddr
	p.conns.Add(connID, clientConn)
	defer p.conns.Remove(connID)

	// Call onEstablish callback
	if p.onEstablish != nil {
		p.onEstablish(clientConn, targetAddr, localAddr.String())
	}

	// Disable deadline for data transfer
	if p.timeout > 0 {
		clientConn.SetDeadline(time.Time{})
		targetConn.SetDeadline(time.Time{})
	}

	// Bidirectional data transfer
	p.relay(clientConn, targetConn)
}

// handshake performs SOCKS5 handshake (method selection)
func (p *SOCKS5Proxy) handshake(conn net.Conn) error {
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
func (p *SOCKS5Proxy) handleUserPassAuth(conn net.Conn) error {
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
func (p *SOCKS5Proxy) handleRequest(conn net.Conn) (string, error) {
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
func (p *SOCKS5Proxy) sendSuccessReply(conn net.Conn, localAddr *net.TCPAddr) {
	resp := protocol.NewSuccessResponse(localAddr.IP, uint16(localAddr.Port))
	if _, err := conn.Write(resp.Encode()); err != nil {
		p.logger.Error("Failed to send success reply", utils.Err(err))
	}
}

// sendErrorReply sends an error SOCKS5 reply
func (p *SOCKS5Proxy) sendErrorReply(conn net.Conn, code protocol.ReplyCode) {
	resp := protocol.NewErrorResponse(code)
	if _, err := conn.Write(resp.Encode()); err != nil {
		p.logger.Error("Failed to send error reply", utils.Err(err))
	}
}

// relay performs bidirectional data transfer
func (p *SOCKS5Proxy) relay(client, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Target
	go func() {
		defer wg.Done()
		io.Copy(target, client)
		target.Close()
	}()

	// Target -> Client
	go func() {
		defer wg.Done()
		io.Copy(client, target)
		client.Close()
	}()

	wg.Wait()
}

// Close closes the SOCKS5 proxy
func (p *SOCKS5Proxy) Close() error {
	if p.closed.CompareAndSwap(false, true) {
		if p.listener != nil {
			p.listener.Close()
		}
		p.conns.CloseAll()
		p.logger.Info("SOCKS5 proxy closed")
	}
	return nil
}

// Name returns the proxy name
func (p *SOCKS5Proxy) Name() string {
	return p.name
}

// Type returns the proxy type
func (p *SOCKS5Proxy) Type() string {
	return "socks5"
}

// BindAddr returns the bind address
func (p *SOCKS5Proxy) BindAddr() string {
	return p.bindAddr
}

// ConnCount returns the number of active connections
func (p *SOCKS5Proxy) ConnCount() int64 {
	return p.conns.Count()
}
