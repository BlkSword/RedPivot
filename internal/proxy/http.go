package proxy

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

var (
	ErrInvalidHost = errors.New("invalid host header")
)

// HTTPProxy represents an HTTP proxy
type HTTPProxy struct {
	name      string
	subdomain string

	listener   net.Listener
	streamPool StreamPool
	domain     string
	closed     atomic.Bool
	conns      *ConnTracker
	routes     sync.Map // subdomain -> proxy name
}

// NewHTTPProxy creates a new HTTP proxy
func NewHTTPProxy(name, subdomain, domain string) *HTTPProxy {
	return &HTTPProxy{
		name:       name,
		subdomain:  subdomain,
		domain:     domain,
		conns:      &ConnTracker{},
	}
}

// SetStreamPool sets the stream pool
func (p *HTTPProxy) SetStreamPool(pool StreamPool) {
	p.streamPool = pool
}

// Subdomain returns the subdomain
func (p *HTTPProxy) Subdomain() string {
	return p.subdomain
}

// FullHost returns the full host (subdomain.domain)
func (p *HTTPProxy) FullHost() string {
	if p.subdomain == "" {
		return p.domain
	}
	return p.subdomain + "." + p.domain
}

// Start starts listening (HTTP proxies are handled by HTTPServer)
func (p *HTTPProxy) Start() error {
	// HTTP proxies don't listen directly - they're routed by HTTPServer
	return nil
}

// Close closes the proxy
func (p *HTTPProxy) Close() error {
	p.closed.Store(true)
	p.conns.CloseAll()
	return nil
}

// Name returns the proxy name
func (p *HTTPProxy) Name() string {
	return p.name
}

// Type returns the proxy type
func (p *HTTPProxy) Type() string {
	return "http"
}

// HTTPServer handles HTTP routing for multiple HTTP proxies
type HTTPServer struct {
	domain     string
	listener   net.Listener
	proxies    sync.Map // name -> *HTTPProxy
	routes     sync.Map // host -> *HTTPProxy
	streamPool StreamPool
	closed     atomic.Bool
}

// NewHTTPServer creates a new HTTP server
func NewHTTPServer(domain string, pool StreamPool) *HTTPServer {
	return &HTTPServer{
		domain:     domain,
		streamPool: pool,
	}
}

// AddProxy adds an HTTP proxy
func (s *HTTPServer) AddProxy(proxy *HTTPProxy) {
	s.proxies.Store(proxy.Name(), proxy)
	if proxy.Subdomain() != "" {
		s.routes.Store(proxy.FullHost(), proxy)
	}
}

// RemoveProxy removes an HTTP proxy
func (s *HTTPServer) RemoveProxy(name string) {
	if val, ok := s.proxies.Load(name); ok {
		proxy := val.(*HTTPProxy)
		s.routes.Delete(proxy.FullHost())
		s.proxies.Delete(name)
	}
}

// Start starts the HTTP server
func (s *HTTPServer) Start(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	s.listener = listener

	go s.acceptLoop()

	return nil
}

func (s *HTTPServer) acceptLoop() {
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

func (s *HTTPServer) handleConnection(conn net.Conn) {
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
		http.Error(
			&responseWriter{conn: conn},
			"Bad Request",
			http.StatusBadRequest,
		)
		return
	}

	// Find the proxy for this host
	val, ok := s.routes.Load(host)
	if !ok {
		// Try without port
		hostWithoutPort := strings.Split(host, ":")[0]
		val, ok = s.routes.Load(hostWithoutPort)
		if !ok {
			http.Error(
				&responseWriter{conn: conn},
				"Not Found",
				http.StatusNotFound,
			)
			return
		}
	}

	_ = val.(*HTTPProxy) // Used for routing in production

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

func (s *HTTPServer) parseHost(data []byte) string {
	// Simple Host header parsing
	lines := strings.Split(string(data), "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Host:"))
		}
	}
	return ""
}

// Close closes the HTTP server
func (s *HTTPServer) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		if s.listener != nil {
			s.listener.Close()
		}
	}
	return nil
}

// responseWriter is a minimal http.ResponseWriter implementation
type responseWriter struct {
	conn    net.Conn
	headers http.Header
	status  int
	written bool
}

func (w *responseWriter) Header() http.Header {
	if w.headers == nil {
		w.headers = make(http.Header)
	}
	return w.headers
}

func (w *responseWriter) Write(data []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.conn.Write(data)
}

func (w *responseWriter) WriteHeader(statusCode int) {
	if w.written {
		return
	}
	w.status = statusCode
	w.written = true

	// Write status line
	statusText := http.StatusText(statusCode)
	w.conn.Write([]byte("HTTP/1.1 "))
	w.conn.Write([]byte(statusText))
	w.conn.Write([]byte("\r\n"))

	// Write headers
	for key, values := range w.headers {
		for _, value := range values {
			w.conn.Write([]byte(key))
			w.conn.Write([]byte(": "))
			w.conn.Write([]byte(value))
			w.conn.Write([]byte("\r\n"))
		}
	}
	w.conn.Write([]byte("\r\n"))
}
