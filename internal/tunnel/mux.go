package tunnel

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redpivot/redpivot/pkg/protocol"
)

var (
	ErrMuxClosed      = errors.New("multiplexer closed")
	ErrStreamClosed   = errors.New("stream closed")
	ErrStreamNotFound = errors.New("stream not found")
	ErrWriteFailed    = errors.New("write failed")
)

// Stream represents a multiplexed stream
type Stream struct {
	id        uint32
	mux       *Mux
	recvBuf   [][]byte
	recvMu    sync.Mutex
	recvCond  *sync.Cond
	closed    atomic.Bool
	closeChan chan struct{}
}

// Mux handles connection multiplexing
type Mux struct {
	conn        io.ReadWriteCloser
	streams     sync.Map // map[uint32]*Stream
	nextID      uint32
	writeMu     sync.Mutex
	closed      atomic.Bool
	onStream    func(*Stream) // Callback for new streams (server-side)
	closeChan   chan struct{}
}

// NewMux creates a new multiplexer
func NewMux(conn io.ReadWriteCloser) *Mux {
	m := &Mux{
		conn:      conn,
		closeChan: make(chan struct{}),
	}
	go m.readLoop()
	go m.heartbeatLoop()
	return m
}

// NewMuxWithHandler creates a multiplexer with a stream handler
func NewMuxWithHandler(conn io.ReadWriteCloser, handler func(*Stream)) *Mux {
	m := &Mux{
		conn:      conn,
		onStream:  handler,
		closeChan: make(chan struct{}),
	}
	go m.readLoop()
	go m.heartbeatLoop()
	return m
}

// OpenStream opens a new stream
func (m *Mux) OpenStream() (*Stream, error) {
	if m.closed.Load() {
		return nil, ErrMuxClosed
	}

	id := atomic.AddUint32(&m.nextID, 1)
	// Use odd numbers for client-initiated streams
	if id%2 == 0 {
		id = atomic.AddUint32(&m.nextID, 1)
	}

	stream := &Stream{
		id:        id,
		mux:       m,
		recvBuf:   make([][]byte, 0),
		closeChan: make(chan struct{}),
	}
	stream.recvCond = sync.NewCond(&stream.recvMu)

	m.streams.Store(id, stream)

	// Send OpenStream frame
	frame := protocol.NewFrame(protocol.FrameOpenStream, id, nil)
	if err := m.writeFrame(frame); err != nil {
		m.streams.Delete(id)
		return nil, err
	}

	return stream, nil
}

// AcceptStream accepts an incoming stream (server-side)
func (m *Mux) AcceptStream() (*Stream, error) {
	// This would block until a new stream arrives
	// For now, streams are handled via onStream callback
	return nil, errors.New("use onStream handler instead")
}

// readLoop reads frames from the connection
func (m *Mux) readLoop() {
	defer m.Close()

	for {
		frame, err := protocol.DecodeFrame(m.conn)
		if err != nil {
			if err == io.EOF {
				return
			}
			// Non-EOF error, close the mux
			return
		}

		m.handleFrame(frame)
	}
}

// handleFrame processes an incoming frame
func (m *Mux) handleFrame(frame *protocol.Frame) {
	switch frame.Type {
	case protocol.FrameOpenStream:
		// Server-side: new stream from client
		stream := &Stream{
			id:        frame.StreamID,
			mux:       m,
			recvBuf:   make([][]byte, 0),
			closeChan: make(chan struct{}),
		}
		stream.recvCond = sync.NewCond(&stream.recvMu)

		m.streams.Store(frame.StreamID, stream)

		// Send ACK
		ackFrame := protocol.NewFrame(protocol.FrameAck, frame.StreamID, nil)
		m.writeFrame(ackFrame)

		// Notify handler
		if m.onStream != nil {
			go m.onStream(stream)
		}

	case protocol.FrameData:
		if val, ok := m.streams.Load(frame.StreamID); ok {
			stream := val.(*Stream)
			stream.addData(frame.Payload)
		}
		// Note: if stream not found, data is silently dropped
		// This could happen if the stream was closed before data arrived

	case protocol.FrameCloseStream:
		if val, ok := m.streams.Load(frame.StreamID); ok {
			stream := val.(*Stream)
			stream.Close()
		}

	case protocol.FrameHeartbeat, protocol.FramePing:
		// Respond with pong
		pongFrame := protocol.NewFrame(protocol.FramePong, 0, nil)
		m.writeFrame(pongFrame)

	case protocol.FrameAck:
		// Acknowledgment received, could track for flow control
	}
}

// writeFrame writes a frame to the connection
func (m *Mux) writeFrame(frame *protocol.Frame) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	if m.closed.Load() {
		return ErrMuxClosed
	}

	_, err := m.conn.Write(frame.Encode())
	return err
}

// heartbeatLoop sends periodic heartbeats
func (m *Mux) heartbeatLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.closeChan:
			return
		case <-ticker.C:
			if m.closed.Load() {
				return
			}
			frame := protocol.NewFrame(protocol.FrameHeartbeat, 0, nil)
			m.writeFrame(frame)
		}
	}
}

// Close closes the multiplexer and all streams
func (m *Mux) Close() error {
	if m.closed.CompareAndSwap(false, true) {
		close(m.closeChan)
		m.conn.Close()

		// Close all streams
		m.streams.Range(func(key, value interface{}) bool {
			stream := value.(*Stream)
			stream.Close()
			return true
		})
	}
	return nil
}

// Done returns a channel that's closed when the mux is closed
func (m *Mux) Done() <-chan struct{} {
	return m.closeChan
}

// IsClosed returns whether the mux is closed
func (m *Mux) IsClosed() bool {
	return m.closed.Load()
}

// addData adds data to the stream's receive buffer
func (s *Stream) addData(data []byte) {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()

	if s.closed.Load() {
		return
	}

	s.recvBuf = append(s.recvBuf, data)
	s.recvCond.Signal()
}

// Write writes data to the stream
func (s *Stream) Write(data []byte) (int, error) {
	if s.closed.Load() {
		return 0, ErrStreamClosed
	}

	// Split large data into chunks
	chunkSize := int(protocol.MaxPayloadSize) - protocol.HeaderSize
	sent := 0

	for sent < len(data) {
		end := sent + chunkSize
		if end > len(data) {
			end = len(data)
		}

		chunk := data[sent:end]
		frame := protocol.NewFrame(protocol.FrameData, s.id, chunk)

		if err := s.mux.writeFrame(frame); err != nil {
			return sent, err
		}

		sent = end
	}

	return sent, nil
}

// Read reads data from the stream
func (s *Stream) Read(data []byte) (int, error) {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()

	// Wait for data
	for len(s.recvBuf) == 0 {
		if s.closed.Load() {
			return 0, io.EOF
		}
		s.recvCond.Wait()
	}

	// Copy from first buffer
	first := s.recvBuf[0]
	n := copy(data, first)

	if n >= len(first) {
		// Consumed entire buffer
		s.recvBuf = s.recvBuf[1:]
	} else {
		// Partial consumption
		s.recvBuf[0] = first[n:]
	}

	return n, nil
}

// ReadChan returns a channel for reading data
func (s *Stream) ReadChan() <-chan []byte {
	ch := make(chan []byte, 64)

	go func() {
		defer close(ch)
		buf := make([]byte, 32*1024)

		for {
			n, err := s.Read(buf)
			if err != nil {
				return
			}

			data := make([]byte, n)
			copy(data, buf[:n])

			select {
			case ch <- data:
			case <-s.closeChan:
				return
			}
		}
	}()

	return ch
}

// Close closes the stream
func (s *Stream) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		close(s.closeChan)
		s.recvCond.Broadcast()

		// Notify remote
		frame := protocol.NewFrame(protocol.FrameCloseStream, s.id, nil)
		s.mux.writeFrame(frame)

		// Remove from mux
		s.mux.streams.Delete(s.id)
	}
	return nil
}

// ID returns the stream ID
func (s *Stream) ID() uint32 {
	return s.id
}

// IsClosed returns whether the stream is closed
func (s *Stream) IsClosed() bool {
	return s.closed.Load()
}
