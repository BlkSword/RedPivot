// Package transport provides different transport implementations
package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var (
	ErrConnectionClosed = errors.New("connection closed")
	ErrInvalidMessage   = errors.New("invalid message type")
	ErrDialFailed       = errors.New("dial failed")
)

// WebSocketTransport implements transport over WebSocket
type WebSocketTransport struct {
	conn          *websocket.Conn
	writeMu       sync.Mutex
	readMu        sync.Mutex
	closed        bool
	closeMu       sync.Mutex
	onClose       func()
	messageBuffer int
}

// WSConfig contains WebSocket configuration
type WSConfig struct {
	URL            string
	Header         http.Header
	TLSConfig      *tls.Config
	ReadBufferSize int
	WriteBufferSize int
	PingInterval   time.Duration
	PongWait       time.Duration
}

// DefaultWSConfig returns default WebSocket configuration
func DefaultWSConfig(url string) *WSConfig {
	return &WSConfig{
		URL:            url,
		ReadBufferSize: 64 * 1024,
		WriteBufferSize: 64 * 1024,
		PingInterval:   30 * time.Second,
		PongWait:       60 * time.Second,
	}
}

// NewWebSocketClient creates a WebSocket client transport
func NewWebSocketClient(config *WSConfig) (*WebSocketTransport, error) {
	// Apply defaults for zero values
	if config.PingInterval == 0 {
		config.PingInterval = 30 * time.Second
	}
	if config.PongWait == 0 {
		config.PongWait = 60 * time.Second
	}
	if config.WriteBufferSize == 0 {
		config.WriteBufferSize = 4096
	}
	if config.ReadBufferSize == 0 {
		config.ReadBufferSize = 4096
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		ReadBufferSize:   config.ReadBufferSize,
		WriteBufferSize:  config.WriteBufferSize,
		TLSClientConfig:  config.TLSConfig,
		Subprotocols:     []string{"redpivot-1"},
	}

	conn, _, err := dialer.Dial(config.URL, config.Header)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDialFailed, err)
	}

	transport := &WebSocketTransport{
		conn:          conn,
		messageBuffer: 256,
	}

	// Start ping loop
	go transport.pingLoop(config.PingInterval)

	return transport, nil
}

// NewWebSocketServer creates a WebSocket server transport from an upgraded connection
func NewWebSocketServer(conn *websocket.Conn) *WebSocketTransport {
	return &WebSocketTransport{
		conn:          conn,
		messageBuffer: 256,
	}
}

// Write writes binary data to the WebSocket
func (t *WebSocketTransport) Write(data []byte) (int, error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	if t.isClosed() {
		return 0, ErrConnectionClosed
	}

	err := t.conn.WriteMessage(websocket.BinaryMessage, data)
	if err != nil {
		return 0, err
	}

	return len(data), nil
}

// Read reads binary data from the WebSocket
func (t *WebSocketTransport) Read() ([]byte, error) {
	t.readMu.Lock()
	defer t.readMu.Unlock()

	if t.isClosed() {
		return nil, ErrConnectionClosed
	}

	messageType, data, err := t.conn.ReadMessage()
	if err != nil {
		if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
			t.Close()
		}
		return nil, err
	}

	if messageType != websocket.BinaryMessage {
		return nil, ErrInvalidMessage
	}

	return data, nil
}

// ReadChan returns a channel for reading messages
func (t *WebSocketTransport) ReadChan() <-chan []byte {
	ch := make(chan []byte, t.messageBuffer)

	go func() {
		defer close(ch)

		for {
			data, err := t.Read()
			if err != nil {
				return
			}

			select {
			case ch <- data:
			default:
				// Buffer full, drop oldest message
				select {
				case <-ch:
					ch <- data
				default:
				}
			}
		}
	}()

	return ch
}

// WriteChan writes messages from a channel
func (t *WebSocketTransport) WriteChan(ctx context.Context, ch <-chan []byte) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case data, ok := <-ch:
			if !ok {
				return nil
			}
			if _, err := t.Write(data); err != nil {
				return err
			}
		}
	}
}

// Close closes the WebSocket connection
func (t *WebSocketTransport) Close() error {
	t.closeMu.Lock()
	defer t.closeMu.Unlock()

	if t.closed {
		return nil
	}

	t.closed = true

	// Send close message with write lock to avoid concurrent write
	t.writeMu.Lock()
	err := t.conn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	t.writeMu.Unlock()

	if err != nil {
		// Log but continue closing
	}

	err = t.conn.Close()

	if t.onClose != nil {
		t.onClose()
	}

	return err
}

// OnClose sets a callback for when the connection closes
func (t *WebSocketTransport) OnClose(callback func()) {
	t.onClose = callback
}

// IsClosed returns whether the connection is closed
func (t *WebSocketTransport) IsClosed() bool {
	return t.isClosed()
}

func (t *WebSocketTransport) isClosed() bool {
	t.closeMu.Lock()
	defer t.closeMu.Unlock()
	return t.closed
}

// pingLoop sends periodic pings to keep the connection alive
func (t *WebSocketTransport) pingLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		if t.isClosed() {
			return
		}

		t.writeMu.Lock()
		err := t.conn.WriteMessage(websocket.PingMessage, nil)
		t.writeMu.Unlock()

		if err != nil {
			t.Close()
			return
		}
	}
}

// SetPingHandler sets a custom ping handler
func (t *WebSocketTransport) SetPingHandler(handler func(appData string) error) {
	t.conn.SetPingHandler(handler)
}

// SetPongHandler sets a custom pong handler
func (t *WebSocketTransport) SetPongHandler(handler func(appData string) error) {
	t.conn.SetPongHandler(handler)
}

// WebSocketUpgrader provides HTTP to WebSocket upgrade functionality
type WebSocketUpgrader struct {
	upgrader    websocket.Upgrader
	onConnect   func(*WebSocketTransport)
	onError     func(http.ResponseWriter, *http.Request, error)
	path        string
}

// NewWebSocketUpgrader creates a new WebSocket upgrader
func NewWebSocketUpgrader(path string, onConnect func(*WebSocketTransport)) *WebSocketUpgrader {
	return &WebSocketUpgrader{
		upgrader: websocket.Upgrader{
			ReadBufferSize:  64 * 1024,
			WriteBufferSize: 64 * 1024,
			CheckOrigin: func(r *http.Request) bool {
				return true // In production, validate origin
			},
			Subprotocols: []string{"redpivot-1"},
		},
		onConnect: onConnect,
		path:      path,
	}
}

// WithOriginCheck sets a custom origin check function
func (u *WebSocketUpgrader) WithOriginCheck(check func(r *http.Request) bool) *WebSocketUpgrader {
	u.upgrader.CheckOrigin = check
	return u
}

// WithErrorHandler sets an error handler
func (u *WebSocketUpgrader) WithErrorHandler(handler func(http.ResponseWriter, *http.Request, error)) *WebSocketUpgrader {
	u.onError = handler
	return u
}

// ServeHTTP implements http.Handler
func (u *WebSocketUpgrader) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != u.path {
		http.NotFound(w, r)
		return
	}

	conn, err := u.upgrader.Upgrade(w, r, nil)
	if err != nil {
		if u.onError != nil {
			u.onError(w, r, err)
		}
		return
	}

	transport := NewWebSocketServer(conn)
	if u.onConnect != nil {
		u.onConnect(transport)
	}
}

// WrapReadWriteCloser wraps WebSocket transport as io.ReadWriteCloser
type WSReadWriteCloser struct {
	transport *WebSocketTransport
	readBuf   []byte
	readPos   int
}

// NewWSReadWriteCloser creates an io.ReadWriteCloser wrapper
func NewWSReadWriteCloser(transport *WebSocketTransport) *WSReadWriteCloser {
	return &WSReadWriteCloser{
		transport: transport,
	}
}

func (w *WSReadWriteCloser) Read(p []byte) (n int, err error) {
	// If we have buffered data, return it
	if w.readBuf != nil && w.readPos < len(w.readBuf) {
		n = copy(p, w.readBuf[w.readPos:])
		w.readPos += n
		if w.readPos >= len(w.readBuf) {
			w.readBuf = nil
			w.readPos = 0
		}
		return n, nil
	}

	// Read new message
	data, err := w.transport.Read()
	if err != nil {
		return 0, err
	}

	n = copy(p, data)
	if n < len(data) {
		// Buffer the rest
		w.readBuf = data[n:]
		w.readPos = 0
	}

	return n, nil
}

func (w *WSReadWriteCloser) Write(p []byte) (n int, err error) {
	return w.transport.Write(p)
}

func (w *WSReadWriteCloser) Close() error {
	return w.transport.Close()
}

// Ensure interface implementations
var (
	_ io.ReadWriteCloser = (*WSReadWriteCloser)(nil)
)
