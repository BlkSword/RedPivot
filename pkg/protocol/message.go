package protocol

import (
	"encoding/binary"
	"errors"
)

// Message types for control plane
type MessageType byte

const (
	MsgTypeHandshake  MessageType = 0x01
	MsgTypeAuth       MessageType = 0x02
	MsgTypeAuthResp   MessageType = 0x03
	MsgTypeHeartbeat  MessageType = 0x04
	MsgTypeProxyReq   MessageType = 0x05
	MsgTypeProxyResp  MessageType = 0x06
	MsgTypeProxyClose MessageType = 0x07
)

var (
	ErrInvalidMessage = errors.New("invalid message")
)

// HandshakeMessage represents handshake payload
type HandshakeMessage struct {
	Version    byte
	Features   uint16
	Extensions []byte
}

// Encode encodes handshake message
func (m *HandshakeMessage) Encode() []byte {
	buf := make([]byte, 3+len(m.Extensions))
	buf[0] = m.Version
	binary.BigEndian.PutUint16(buf[1:3], m.Features)
	if len(m.Extensions) > 0 {
		copy(buf[3:], m.Extensions)
	}
	return buf
}

// DecodeHandshake decodes handshake message
func DecodeHandshake(data []byte) (*HandshakeMessage, error) {
	if len(data) < 3 {
		return nil, ErrInvalidMessage
	}
	m := &HandshakeMessage{
		Version:  data[0],
		Features: binary.BigEndian.Uint16(data[1:3]),
	}
	if len(data) > 3 {
		m.Extensions = make([]byte, len(data)-3)
		copy(m.Extensions, data[3:])
	}
	return m, nil
}

// AuthMessage represents authentication payload
type AuthMessage struct {
	Method   byte   // 0x01 = token, 0x02 = mtls
	Token    []byte // Token or certificate hash
	Metadata []byte // Additional metadata
}

// Encode encodes auth message
func (m *AuthMessage) Encode() []byte {
	buf := make([]byte, 3+len(m.Token)+len(m.Metadata))
	buf[0] = m.Method
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(m.Token)))
	copy(buf[3:], m.Token)
	if len(m.Metadata) > 0 {
		copy(buf[3+len(m.Token):], m.Metadata)
	}
	return buf
}

// DecodeAuth decodes auth message
func DecodeAuth(data []byte) (*AuthMessage, error) {
	if len(data) < 3 {
		return nil, ErrInvalidMessage
	}
	tokenLen := int(binary.BigEndian.Uint16(data[1:3]))
	if len(data) < 3+tokenLen {
		return nil, ErrInvalidMessage
	}
	m := &AuthMessage{
		Method: data[0],
		Token:  make([]byte, tokenLen),
	}
	copy(m.Token, data[3:3+tokenLen])
	if len(data) > 3+tokenLen {
		m.Metadata = make([]byte, len(data)-3-tokenLen)
		copy(m.Metadata, data[3+tokenLen:])
	}
	return m, nil
}

// ProxyType defines the type of proxy
type ProxyType byte

const (
	ProxyTypeTCP   ProxyType = 0x01
	ProxyTypeUDP   ProxyType = 0x02
	ProxyTypeHTTP  ProxyType = 0x03
	ProxyTypeHTTPS ProxyType = 0x04
	ProxyTypeSTCP  ProxyType = 0x05 // Secret TCP (requires visitor)
)

// ProxyMessage represents proxy registration
type ProxyMessage struct {
	Name       string
	Type       ProxyType
	LocalAddr  string
	RemotePort uint16
	Subdomain  string
	SecretKey  string // For STCP
}

// Encode encodes proxy message
func (m *ProxyMessage) Encode() []byte {
	nameBytes := []byte(m.Name)
	localBytes := []byte(m.LocalAddr)
	subBytes := []byte(m.Subdomain)
	secretBytes := []byte(m.SecretKey)

	buf := make([]byte, 1+2+len(nameBytes)+1+2+len(localBytes)+2+2+len(subBytes)+2+len(secretBytes))
	offset := 0

	// Name
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(nameBytes)))
	offset += 2
	copy(buf[offset:], nameBytes)
	offset += len(nameBytes)

	// Type
	buf[offset] = byte(m.Type)
	offset += 1

	// Local address
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(localBytes)))
	offset += 2
	copy(buf[offset:], localBytes)
	offset += len(localBytes)

	// Remote port
	binary.BigEndian.PutUint16(buf[offset:offset+2], m.RemotePort)
	offset += 2

	// Subdomain
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(subBytes)))
	offset += 2
	copy(buf[offset:], subBytes)
	offset += len(subBytes)

	// Secret key
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(secretBytes)))
	offset += 2
	copy(buf[offset:], secretBytes)

	return buf[0 : offset+len(secretBytes)]
}

// DecodeProxy decodes proxy message
func DecodeProxy(data []byte) (*ProxyMessage, error) {
	if len(data) < 2 {
		return nil, ErrInvalidMessage
	}

	m := &ProxyMessage{}
	offset := 0

	// Name
	nameLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if len(data) < offset+nameLen {
		return nil, ErrInvalidMessage
	}
	m.Name = string(data[offset : offset+nameLen])
	offset += nameLen

	// Type
	m.Type = ProxyType(data[offset])
	offset += 1

	// Local address
	localLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if len(data) < offset+localLen {
		return nil, ErrInvalidMessage
	}
	m.LocalAddr = string(data[offset : offset+localLen])
	offset += localLen

	// Remote port
	m.RemotePort = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Subdomain
	if len(data) >= offset+2 {
		subLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if len(data) >= offset+subLen {
			m.Subdomain = string(data[offset : offset+subLen])
			offset += subLen
		}
	}

	// Secret key
	if len(data) >= offset+2 {
		secretLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if len(data) >= offset+secretLen {
			m.SecretKey = string(data[offset : offset+secretLen])
		}
	}

	return m, nil
}
