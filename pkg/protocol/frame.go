// Package protocol defines the wire protocol for RedPivot
package protocol

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	MagicNumber    uint32 = 0x52454450 // "REDP"
	Version        byte   = 1
	HeaderSize     int    = 12
	MaxPayloadSize uint16 = 32 * 1024 // 32KB - fits in uint16
)

// FrameType represents the type of frame
type FrameType byte

const (
	FrameHandshake   FrameType = 0x01
	FrameHeartbeat   FrameType = 0x02
	FrameData        FrameType = 0x03
	FrameOpenStream  FrameType = 0x04
	FrameCloseStream FrameType = 0x05
	FrameAck         FrameType = 0x06
	FramePing        FrameType = 0x07
	FramePong        FrameType = 0x08
	FrameAuth        FrameType = 0x09
	FrameAuthResp    FrameType = 0x0A
	FrameNewProxy    FrameType = 0x0B
	FrameDelProxy    FrameType = 0x0C
)

var (
	ErrInvalidMagic     = errors.New("invalid magic number")
	ErrInvalidVersion   = errors.New("invalid version")
	ErrPayloadTooLarge  = errors.New("payload too large")
	ErrInvalidFrameType = errors.New("invalid frame type")
)

// Frame represents a single protocol frame
type Frame struct {
	Version  byte
	Type     FrameType
	Flags    byte
	StreamID uint32
	Length   uint16
	Payload  []byte
}

// NewFrame creates a new frame
func NewFrame(frameType FrameType, streamID uint32, payload []byte) *Frame {
	return &Frame{
		Version:  Version,
		Type:     frameType,
		Flags:    0,
		StreamID: streamID,
		Length:   uint16(len(payload)),
		Payload:  payload,
	}
}

// Encode serializes the frame to bytes
func (f *Frame) Encode() []byte {
	buf := make([]byte, HeaderSize+len(f.Payload))

	// Magic number (4 bytes)
	binary.BigEndian.PutUint32(buf[0:4], MagicNumber)
	// Version (1 byte)
	buf[4] = f.Version
	// Type (1 byte)
	buf[5] = byte(f.Type)
	// Flags (1 byte)
	buf[6] = f.Flags
	// Reserved (1 byte)
	buf[7] = 0
	// Stream ID (4 bytes)
	binary.BigEndian.PutUint32(buf[8:12], f.StreamID)
	// Length (2 bytes) - we overwrite bytes 10-11

	// Rebuild with proper length position
	buf = make([]byte, HeaderSize+len(f.Payload))
	binary.BigEndian.PutUint32(buf[0:4], MagicNumber)
	buf[4] = f.Version
	buf[5] = byte(f.Type)
	buf[6] = f.Flags
	buf[7] = 0
	binary.BigEndian.PutUint32(buf[8:12], f.StreamID)
	binary.BigEndian.PutUint16(buf[10:12], f.Length)

	// Payload
	if len(f.Payload) > 0 {
		copy(buf[HeaderSize:], f.Payload)
	}

	return buf
}

// DecodeFrame reads and decodes a frame from the reader
func DecodeFrame(r io.Reader) (*Frame, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	// Validate magic number
	magic := binary.BigEndian.Uint32(header[0:4])
	if magic != MagicNumber {
		return nil, ErrInvalidMagic
	}

	frame := &Frame{
		Version:  header[4],
		Type:     FrameType(header[5]),
		Flags:    header[6],
		StreamID: binary.BigEndian.Uint32(header[8:12]),
		Length:   binary.BigEndian.Uint16(header[10:12]),
	}

	// Validate version
	if frame.Version != Version {
		return nil, ErrInvalidVersion
	}

	// Validate frame type
	if !isValidFrameType(frame.Type) {
		return nil, ErrInvalidFrameType
	}

	// Read payload
	if frame.Length > 0 {
		if frame.Length > MaxPayloadSize {
			return nil, ErrPayloadTooLarge
		}
		frame.Payload = make([]byte, frame.Length)
		if _, err := io.ReadFull(r, frame.Payload); err != nil {
			return nil, err
		}
	}

	return frame, nil
}

// DecodeFrameFromBytes decodes a frame from a byte slice
func DecodeFrameFromBytes(data []byte) (*Frame, error) {
	if len(data) < HeaderSize {
		return nil, errors.New("data too short")
	}

	magic := binary.BigEndian.Uint32(data[0:4])
	if magic != MagicNumber {
		return nil, ErrInvalidMagic
	}

	frame := &Frame{
		Version:  data[4],
		Type:     FrameType(data[5]),
		Flags:    data[6],
		StreamID: binary.BigEndian.Uint32(data[8:12]),
		Length:   binary.BigEndian.Uint16(data[10:12]),
	}

	if frame.Version != Version {
		return nil, ErrInvalidVersion
	}

	if frame.Length > 0 {
		if int(frame.Length) > len(data)-HeaderSize {
			return nil, errors.New("payload length mismatch")
		}
		frame.Payload = make([]byte, frame.Length)
		copy(frame.Payload, data[HeaderSize:HeaderSize+int(frame.Length)])
	}

	return frame, nil
}

func isValidFrameType(t FrameType) bool {
	switch t {
	case FrameHandshake, FrameHeartbeat, FrameData,
		FrameOpenStream, FrameCloseStream, FrameAck,
		FramePing, FramePong, FrameAuth, FrameAuthResp,
		FrameNewProxy, FrameDelProxy:
		return true
	default:
		return false
	}
}
