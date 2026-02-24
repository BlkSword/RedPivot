// Package protocol provides SOCKS5 protocol definitions (RFC 1928)
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
)

const (
	// SOCKS5Version is the SOCKS5 protocol version
	SOCKS5Version = 0x05
)

var (
	// ErrInvalidSOCKS5Version is returned when the SOCKS5 version is invalid
	ErrInvalidSOCKS5Version = errors.New("invalid SOCKS5 version")
	// ErrInvalidSOCKS5Command is returned when the SOCKS5 command is invalid
	ErrInvalidSOCKS5Command = errors.New("invalid SOCKS5 command")
	// ErrInvalidSOCKS5Address is returned when the SOCKS5 address is invalid
	ErrInvalidSOCKS5Address = errors.New("invalid SOCKS5 address")
	// ErrNoAcceptableMethod is returned when no acceptable authentication method is found
	ErrNoAcceptableMethod = errors.New("no acceptable authentication method")
)

// Command represents SOCKS5 command type
type Command byte

const (
	// CmdConnect establishes a TCP connection
	CmdConnect Command = 0x01
	// CmdBind establishes a TCP binding
	CmdBind Command = 0x02
	// CmdUdpAssociate establishes a UDP association
	CmdUdpAssociate Command = 0x03
)

func (c Command) String() string {
	switch c {
	case CmdConnect:
		return "CONNECT"
	case CmdBind:
		return "BIND"
	case CmdUdpAssociate:
		return "UDP_ASSOCIATE"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", byte(c))
	}
}

// AddressType represents SOCKS5 address type
type AddressType byte

const (
	// AddrIPv4 represents an IPv4 address
	AddrIPv4 AddressType = 0x01
	// AddrDomain represents a domain name
	AddrDomain AddressType = 0x03
	// AddrIPv6 represents an IPv6 address
	AddrIPv6 AddressType = 0x04
)

// AuthMethod represents SOCKS5 authentication method
type AuthMethod byte

const (
	// AuthNone represents no authentication
	AuthNone AuthMethod = 0x00
	// AuthUserPass represents username/password authentication (RFC 1929)
	AuthUserPass AuthMethod = 0x02
	// AuthNoAcceptable represents no acceptable methods
	AuthNoAcceptable AuthMethod = 0xFF
)

func (m AuthMethod) String() string {
	switch m {
	case AuthNone:
		return "NONE"
	case AuthUserPass:
		return "USER_PASS"
	case AuthNoAcceptable:
		return "NO_ACCEPTABLE"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", byte(m))
	}
}

// ReplyCode represents SOCKS5 reply code
type ReplyCode byte

const (
	// ReplySuccess indicates successful request
	ReplySuccess ReplyCode = 0x00
	// ReplyGeneralFailure indicates general SOCKS server failure
	ReplyGeneralFailure ReplyCode = 0x01
	// ReplyNotAllowed indicates connection not allowed by ruleset
	ReplyNotAllowed ReplyCode = 0x02
	// ReplyNetworkUnreachable indicates network unreachable
	ReplyNetworkUnreachable ReplyCode = 0x03
	// ReplyHostUnreachable indicates host unreachable
	ReplyHostUnreachable ReplyCode = 0x04
	// ReplyConnectionRefused indicates connection refused
	ReplyConnectionRefused ReplyCode = 0x05
	// ReplyTTLExpired indicates TTL expired
	ReplyTTLExpired ReplyCode = 0x06
	// ReplyCommandNotSupported indicates command not supported
	ReplyCommandNotSupported ReplyCode = 0x07
	// ReplyAddressNotSupported indicates address type not supported
	ReplyAddressNotSupported ReplyCode = 0x08
)

func (r ReplyCode) String() string {
	switch r {
	case ReplySuccess:
		return "SUCCESS"
	case ReplyGeneralFailure:
		return "GENERAL_FAILURE"
	case ReplyNotAllowed:
		return "NOT_ALLOWED"
	case ReplyNetworkUnreachable:
		return "NETWORK_UNREACHABLE"
	case ReplyHostUnreachable:
		return "HOST_UNREACHABLE"
	case ReplyConnectionRefused:
		return "CONNECTION_REFUSED"
	case ReplyTTLExpired:
		return "TTL_EXPIRED"
	case ReplyCommandNotSupported:
		return "COMMAND_NOT_SUPPORTED"
	case ReplyAddressNotSupported:
		return "ADDRESS_NOT_SUPPORTED"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", byte(r))
	}
}

// Error returns the error associated with a reply code
func (r ReplyCode) Error() error {
	if r == ReplySuccess {
		return nil
	}
	return &SOCKS5Error{Code: r}
}

// SOCKS5Error represents a SOCKS5 protocol error
type SOCKS5Error struct {
	Code ReplyCode
}

func (e *SOCKS5Error) Error() string {
	return fmt.Sprintf("socks5: %s", e.Code.String())
}

// HandshakeRequest represents a SOCKS5 handshake request
type HandshakeRequest struct {
	Version  byte
	Methods  []AuthMethod
}

// DecodeHandshakeRequest decodes a SOCKS5 handshake request
func DecodeHandshakeRequest(data []byte) (*HandshakeRequest, error) {
	if len(data) < 3 {
		return nil, errors.New("handshake request too short")
	}

	if data[0] != SOCKS5Version {
		return nil, ErrInvalidSOCKS5Version
	}

	methodCount := int(data[1])
	if len(data) < 2+methodCount {
		return nil, errors.New("handshake request methods truncated")
	}

	req := &HandshakeRequest{
		Version: SOCKS5Version,
		Methods: make([]AuthMethod, methodCount),
	}

	for i := 0; i < methodCount; i++ {
		req.Methods[i] = AuthMethod(data[2+i])
	}

	return req, nil
}

// HandshakeResponse represents a SOCKS5 handshake response
type HandshakeResponse struct {
	Version byte
	Method  AuthMethod
}

// Encode encodes a SOCKS5 handshake response
func (r *HandshakeResponse) Encode() []byte {
	return []byte{SOCKS5Version, byte(r.Method)}
}

// NewHandshakeResponse creates a new handshake response
func NewHandshakeResponse(method AuthMethod) *HandshakeResponse {
	return &HandshakeResponse{
		Version: SOCKS5Version,
		Method:  method,
	}
}

// Request represents a SOCKS5 request
type Request struct {
	Version  byte
	Command  Command
	Reserved byte
	AddrType AddressType
	DstAddr  string
	DstPort  uint16
}

// DecodeRequest decodes a SOCKS5 request
func DecodeRequest(data []byte) (*Request, error) {
	if len(data) < 4 {
		return nil, errors.New("request too short")
	}

	if data[0] != SOCKS5Version {
		return nil, ErrInvalidSOCKS5Version
	}

	req := &Request{
		Version:  data[0],
		Command:  Command(data[1]),
		Reserved: data[2],
		AddrType: AddressType(data[3]),
	}

	offset := 4

	switch req.AddrType {
	case AddrIPv4:
		if len(data) < offset+4+2 {
			return nil, errors.New("IPv4 address truncated")
		}
		ip := net.IP(data[offset : offset+4])
		req.DstAddr = ip.String()
		offset += 4

	case AddrIPv6:
		if len(data) < offset+16+2 {
			return nil, errors.New("IPv6 address truncated")
		}
		ip := net.IP(data[offset : offset+16])
		req.DstAddr = ip.String()
		offset += 16

	case AddrDomain:
		if len(data) < offset+1 {
			return nil, errors.New("domain length truncated")
		}
		domainLen := int(data[offset])
		offset++
		if len(data) < offset+domainLen+2 {
			return nil, errors.New("domain name truncated")
		}
		req.DstAddr = string(data[offset : offset+domainLen])
		offset += domainLen

	default:
		return nil, fmt.Errorf("unsupported address type: 0x%02x", req.AddrType)
	}

	if len(data) < offset+2 {
		return nil, errors.New("port truncated")
	}

	req.DstPort = binary.BigEndian.Uint16(data[offset : offset+2])

	return req, nil
}

// Response represents a SOCKS5 response
type Response struct {
	Version  byte
	Reply    ReplyCode
	Reserved byte
	AddrType AddressType
	BndAddr  net.IP
	BndPort  uint16
}

// Encode encodes a SOCKS5 response
func (r *Response) Encode() []byte {
	buf := make([]byte, 4)

	buf[0] = SOCKS5Version
	buf[1] = byte(r.Reply)
	buf[2] = r.Reserved

	switch {
	case r.BndAddr == nil:
		// Use IPv4 0.0.0.0 for no binding address
		buf[3] = byte(AddrIPv4)
		buf = append(buf, 0, 0, 0, 0)

	case r.BndAddr.To4() != nil:
		// IPv4
		buf[3] = byte(AddrIPv4)
		buf = append(buf, r.BndAddr.To4()...)

	default:
		// IPv6
		buf[3] = byte(AddrIPv6)
		buf = append(buf, r.BndAddr.To16()...)
	}

	// Port
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, r.BndPort)
	buf = append(buf, portBytes...)

	return buf
}

// NewSuccessResponse creates a success response with binding address
func NewSuccessResponse(bndAddr net.IP, bndPort uint16) *Response {
	return &Response{
		Version:  SOCKS5Version,
		Reply:    ReplySuccess,
		Reserved: 0x00,
		BndAddr:  bndAddr,
		BndPort:  bndPort,
	}
}

// NewErrorResponse creates an error response
func NewErrorResponse(reply ReplyCode) *Response {
	return &Response{
		Version:  SOCKS5Version,
		Reply:    reply,
		Reserved: 0x00,
		BndAddr:  nil,
		BndPort:  0,
	}
}

// Address represents a SOCKS5 address
type Address struct {
	Type AddressType
	Host string
	Port uint16
}

// Encode encodes a SOCKS5 address
func (a *Address) Encode() []byte {
	var buf []byte

	switch a.Type {
	case AddrIPv4:
		ip := net.ParseIP(a.Host)
		if ip == nil {
			return nil
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil
		}
		buf = make([]byte, 7)
		buf[0] = byte(AddrIPv4)
		copy(buf[1:5], ip4)

	case AddrDomain:
		buf = make([]byte, 2+len(a.Host)+2)
		buf[0] = byte(AddrDomain)
		buf[1] = byte(len(a.Host))
		copy(buf[2:], a.Host)

	case AddrIPv6:
		ip := net.ParseIP(a.Host)
		if ip == nil {
			return nil
		}
		ip6 := ip.To16()
		if ip6 == nil {
			return nil
		}
		buf = make([]byte, 19)
		buf[0] = byte(AddrIPv6)
		copy(buf[1:17], ip6)
	}

	// Add port
	binary.BigEndian.PutUint16(buf[len(buf)-2:], a.Port)

	return buf
}

// ParseAddress parses a host:port string into a SOCKS5 address
func ParseAddress(addr string) (*Address, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	result := &Address{
		Port: uint16(port),
	}

	ip := net.ParseIP(host)
	switch {
	case ip == nil:
		result.Type = AddrDomain
		result.Host = host
	case ip.To4() != nil:
		result.Type = AddrIPv4
		result.Host = ip.To4().String()
	default:
		result.Type = AddrIPv6
		result.Host = ip.To16().String()
	}

	return result, nil
}

// String returns the string representation of the address
func (a *Address) String() string {
	return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port)))
}
