package proxy

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

var (
	ErrCertRequired = errors.New("certificate file is required for HTTPS proxy")
	ErrKeyRequired  = errors.New("key file is required for HTTPS proxy")
	ErrCertLoad     = errors.New("failed to load certificate")
)

// HTTPSProxy represents an HTTPS proxy with TLS termination
type HTTPSProxy struct {
	name      string
	subdomain string
	localAddr string
	certFile  string
	keyFile   string

	listener   net.Listener
	streamPool StreamPool
	domain     string
	tlsConfig  *tls.Config
	closed     atomic.Bool
	conns      *ConnTracker
}

// NewHTTPSProxy creates a new HTTPS proxy
func NewHTTPSProxy(name, subdomain, localAddr, certFile, keyFile string) *HTTPSProxy {
	return &HTTPSProxy{
		name:       name,
		subdomain:  subdomain,
		localAddr:  localAddr,
		certFile:   certFile,
		keyFile:    keyFile,
		conns:      &ConnTracker{},
	}
}

// SetStreamPool sets the stream pool
func (p *HTTPSProxy) SetStreamPool(pool StreamPool) {
	p.streamPool = pool
}

// SetDomain sets the domain
func (p *HTTPSProxy) SetDomain(domain string) {
	p.domain = domain
}

// Subdomain returns the subdomain
func (p *HTTPSProxy) Subdomain() string {
	return p.subdomain
}

// FullHost returns the full host (subdomain.domain)
func (p *HTTPSProxy) FullHost() string {
	if p.subdomain == "" {
		return p.domain
	}
	return p.subdomain + "." + p.domain
}

// Start starts the HTTPS proxy
func (p *HTTPSProxy) Start() error {
	if p.streamPool == nil {
		return errors.New("stream pool not set")
	}

	// Load TLS certificate
	cert, err := tls.LoadX509KeyPair(p.certFile, p.keyFile)
	if err != nil {
		return ErrCertLoad
	}

	p.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Start TLS listener
	listener, err := tls.Listen("tcp", p.localAddr, p.tlsConfig)
	if err != nil {
		return ErrBindFailed
	}

	p.listener = listener

	go p.acceptLoop()

	return nil
}

// acceptLoop accepts incoming TLS connections
func (p *HTTPSProxy) acceptLoop() {
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

// handleConnection handles a single HTTPS connection
func (p *HTTPSProxy) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Store connection
	connID := conn.RemoteAddr().String()
	p.conns.Add(connID, conn)
	defer p.conns.Remove(connID)

	// Read the Host header to verify routing
	reader := bufio.NewReader(conn)

	// Peek at the request to get the Host header
	reqBytes, err := reader.Peek(1024)
	if err != nil && err != io.EOF {
		return
	}

	// Parse the Host header for logging/validation
	host := p.parseHost(reqBytes)
	_ = host // Used for routing in production

	// Open a stream through the tunnel
	stream, err := p.streamPool.OpenStream()
	if err != nil {
		return
	}
	defer stream.Close()

	// Bidirectional copy
	go func() {
		io.Copy(stream, reader)
		stream.Close()
		conn.Close()
	}()

	io.Copy(conn, stream)
}

// parseHost extracts the Host header from HTTP request bytes
func (p *HTTPSProxy) parseHost(data []byte) string {
	lines := strings.Split(string(data), "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Host:"))
		}
	}
	return ""
}

// Close closes the HTTPS proxy
func (p *HTTPSProxy) Close() error {
	if p.closed.CompareAndSwap(false, true) {
		if p.listener != nil {
			p.listener.Close()
		}
		p.conns.CloseAll()
	}
	return nil
}

// Name returns the proxy name
func (p *HTTPSProxy) Name() string {
	return p.name
}

// Type returns the proxy type
func (p *HTTPSProxy) Type() string {
	return "https"
}

// HTTPSServer handles HTTPS routing for multiple HTTPS proxies
type HTTPSServer struct {
	domain     string
	listener   net.Listener
	proxies    sync.Map // name -> *HTTPSProxy
	routes     sync.Map // host -> *HTTPSProxy
	certFile   string
	keyFile    string
	tlsConfig  *tls.Config
	streamPool StreamPool
	closed     atomic.Bool
}

// NewHTTPSServer creates a new HTTPS server
func NewHTTPSServer(domain, certFile, keyFile string, pool StreamPool) *HTTPSServer {
	return &HTTPSServer{
		domain:     domain,
		certFile:   certFile,
		keyFile:    keyFile,
		streamPool: pool,
	}
}

// AddProxy adds an HTTPS proxy
func (s *HTTPSServer) AddProxy(proxy *HTTPSProxy) {
	s.proxies.Store(proxy.Name(), proxy)
	if proxy.Subdomain() != "" {
		s.routes.Store(proxy.FullHost(), proxy)
	}
}

// RemoveProxy removes an HTTPS proxy
func (s *HTTPSServer) RemoveProxy(name string) {
	if val, ok := s.proxies.Load(name); ok {
		proxy := val.(*HTTPSProxy)
		s.routes.Delete(proxy.FullHost())
		s.proxies.Delete(name)
	}
}

// Start starts the HTTPS server
func (s *HTTPSServer) Start(addr string) error {
	// Load TLS certificate
	cert, err := tls.LoadX509KeyPair(s.certFile, s.keyFile)
	if err != nil {
		return ErrCertLoad
	}

	s.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", addr, s.tlsConfig)
	if err != nil {
		return err
	}

	s.listener = listener

	go s.acceptLoop()

	return nil
}

func (s *HTTPSServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.closed.Load() {
				return
			}
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *HTTPSServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read the Host header to determine routing
	reader := bufio.NewReader(conn)

	// Peek at the request to get the Host header
	reqBytes, err := reader.Peek(1024)
	if err != nil {
		return
	}

	// Parse the Host header
	host := s.parseHost(reqBytes)
	if host == "" {
		s.writeErrorResponse(conn, http.StatusBadRequest, "Bad Request")
		return
	}

	// Find the proxy for this host
	val, ok := s.routes.Load(host)
	if !ok {
		// Try without port
		hostWithoutPort := strings.Split(host, ":")[0]
		val, ok = s.routes.Load(hostWithoutPort)
		if !ok {
			s.writeErrorResponse(conn, http.StatusNotFound, "Not Found")
			return
		}
	}

	_ = val.(*HTTPSProxy) // Used for routing in production

	// Open a stream to the client
	stream, err := s.streamPool.OpenStream()
	if err != nil {
		return
	}
	defer stream.Close()

	// Forward the connection
	go func() {
		io.Copy(stream, reader)
		stream.Close()
		conn.Close()
	}()

	io.Copy(conn, stream)
}

func (s *HTTPSServer) parseHost(data []byte) string {
	lines := strings.Split(string(data), "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Host:"))
		}
	}
	return ""
}

func (s *HTTPSServer) writeErrorResponse(conn net.Conn, statusCode int, message string) {
	statusText := http.StatusText(statusCode)
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s",
		statusCode, statusText, message)
	conn.Write([]byte(response))
}

// Close closes the HTTPS server
func (s *HTTPSServer) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		if s.listener != nil {
			s.listener.Close()
		}
	}
	return nil
}
