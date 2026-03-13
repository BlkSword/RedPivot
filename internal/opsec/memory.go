// Package opsec provides operational security features
package opsec

import (
	"crypto/rand"
	"crypto/subtle"
	"runtime"
	"unsafe"
)

// SecureBytes holds sensitive data with automatic zeroing
type SecureBytes struct {
	data []byte
}

// NewSecureBytes creates a secure byte slice
func NewSecureBytes(data []byte) *SecureBytes {
	sb := &SecureBytes{
		data: make([]byte, len(data)),
	}
	copy(sb.data, data)
	return sb
}

// Bytes returns the underlying bytes (use with caution)
func (sb *SecureBytes) Bytes() []byte {
	return sb.data
}

// Equal compares with another byte slice in constant time
func (sb *SecureBytes) Equal(other []byte) bool {
	return subtle.ConstantTimeCompare(sb.data, other) == 1
}

// Destroy zeros and releases the memory
func (sb *SecureBytes) Destroy() {
	if sb.data != nil {
		Memzero(sb.data)
		sb.data = nil
		runtime.GC()
	}
}

// Len returns the length
func (sb *SecureBytes) Len() int {
	return len(sb.data)
}

// SecureString holds a sensitive string
type SecureString struct {
	sb *SecureBytes
}

// NewSecureString creates a secure string
func NewSecureString(s string) *SecureString {
	return &SecureString{
		sb: NewSecureBytes([]byte(s)),
	}
}

// String returns the string value
func (s *SecureString) String() string {
	return string(s.sb.Bytes())
}

// Equal compares in constant time
func (s *SecureString) Equal(other string) bool {
	return s.sb.Equal([]byte(other))
}

// Destroy zeros the memory
func (s *SecureString) Destroy() {
	s.sb.Destroy()
}

// Memzero securely zeros a byte slice
func Memzero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	// Prevent compiler optimization
	runtime.KeepAlive(b)
}

// MemzeroString securely zeros a string's backing array
func MemzeroString(s string) {
	if len(s) == 0 {
		return
	}
	// Access the underlying bytes of the string using unsafe.Slice (Go 1.17+)
	// This is safer than direct pointer arithmetic
	ptr := unsafe.StringData(s)
	sl := unsafe.Slice(ptr, len(s))
	Memzero(sl)
}

// SecureConfig holds configuration with memory protection
type SecureConfig struct {
	Token     *SecureString
	Server    *SecureString
	ProxySpecs []*SecureBytes
	obfuscated []byte
}

// NewSecureConfig creates a secure config from environment variables
func NewSecureConfig() *SecureConfig {
	return &SecureConfig{
		obfuscated: make([]byte, 0),
	}
}

// SetToken sets the token securely
func (c *SecureConfig) SetToken(token string) {
	if c.Token != nil {
		c.Token.Destroy()
	}
	c.Token = NewSecureString(token)
}

// SetServer sets the server address securely
func (c *SecureConfig) SetServer(server string) {
	if c.Server != nil {
		c.Server.Destroy()
	}
	c.Server = NewSecureString(server)
}

// AddProxySpec adds a proxy specification
func (c *SecureConfig) AddProxySpec(spec []byte) {
	c.ProxySpecs = append(c.ProxySpecs, NewSecureBytes(spec))
}

// Destroy clears all sensitive data
func (c *SecureConfig) Destroy() {
	if c.Token != nil {
		c.Token.Destroy()
	}
	if c.Server != nil {
		c.Server.Destroy()
	}
	for _, spec := range c.ProxySpecs {
		spec.Destroy()
	}
	Memzero(c.obfuscated)
}

// RandomPadding generates random padding bytes
func RandomPadding(minSize, maxSize int) []byte {
	size := minSize
	if maxSize > minSize {
		b := make([]byte, 1)
		rand.Read(b)
		size = minSize + int(b[0])%(maxSize-minSize)
	}
	padding := make([]byte, size)
	rand.Read(padding)
	return padding
}

// ScrubSlice removes all references to a slice
func ScrubSlice(s *[]byte) {
	if s == nil || *s == nil {
		return
	}
	Memzero(*s)
	*s = nil
}

// ScrubMap removes all entries from a string map
func ScrubMap(m *map[string]string) {
	if m == nil || *m == nil {
		return
	}
	for k, v := range *m {
		MemzeroString(k)
		MemzeroString(v)
	}
	// Clear the map
	for k := range *m {
		delete(*m, k)
	}
	*m = nil
}
