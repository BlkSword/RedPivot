package wizard

import (
	"crypto/rand"
	"encoding/hex"
	"net"
)

// GenerateSecureToken generates a cryptographically secure random token
func GenerateSecureToken(length int) string {
	if length <= 0 {
		length = 32
	}
	bytes := make([]byte, length)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)[:length]
}

// DetectLocalIP attempts to detect the local IP address
func DetectLocalIP() string {
	// Try to connect to a public DNS server to detect local IP
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// DefaultServerBind returns the default server bind address
func DefaultServerBind() string {
	return "0.0.0.0:443"
}

// DefaultWebSocketPath returns the default WebSocket path
func DefaultWebSocketPath() string {
	return "/ws"
}

// DefaultReadTimeout returns the default read timeout in seconds
func DefaultReadTimeout() int {
	return 30
}

// DefaultWriteTimeout returns the default write timeout in seconds
func DefaultWriteTimeout() int {
	return 30
}

// DefaultPaddingProbability returns the default padding probability
func DefaultPaddingProbability() float64 {
	return 0.3
}

// DefaultTimingJitterMs returns the default timing jitter in milliseconds
func DefaultTimingJitterMs() int {
	return 50
}

// DefaultChunkMinSize returns the default minimum chunk size
func DefaultChunkMinSize() int {
	return 64
}

// DefaultChunkMaxSize returns the default maximum chunk size
func DefaultChunkMaxSize() int {
	return 1500
}

// DefaultMaxReconnectAttempts returns the default max reconnect attempts
func DefaultMaxReconnectAttempts() int {
	return 10
}
