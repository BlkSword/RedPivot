// Package auth provides authentication mechanisms
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/redpivot/redpivot/pkg/utils"
)

var (
	ErrInvalidKnock      = errors.New("invalid port knock")
	ErrKnockExpired      = errors.New("port knock expired")
	ErrKnockAlreadyUsed  = errors.New("port knock already used")
	ErrIPNotWhitelisted  = errors.New("IP not whitelisted")
)

// PortKnock implements Single Packet Authorization (SPA) using HMAC-SHA256
type PortKnock struct {
	secret    []byte
	enabled   bool
	whitelist sync.Map // IP -> expiration time
	usedKnocks sync.Map // signature -> time (used to prevent replay attacks)
	logger    *utils.Logger
	ttl       time.Duration // How long a knock is valid
	replayTTL time.Duration // How long to track used knocks
}

// PortKnockConfig represents the port knock configuration
type PortKnockConfig struct {
	Enabled   bool          `yaml:"enabled"`
	Secret    string        `yaml:"secret"`         // HMAC secret key
	TTL       time.Duration `yaml:"ttl"`            // Default: 5 minutes
	ReplayTTL time.Duration `yaml:"replay_ttl"`     // How long to track used knocks (default: 10 minutes)
}

// KnockMessage represents the SPA message format
type KnockMessage struct {
	Timestamp int64  `json:"ts"`    // Unix timestamp
	IP        string `json:"ip"`    // Client IP (optional validation)
	Nonce     string `json:"nonce"` // Random nonce to prevent replay
	Signature string `json:"sig"`   // HMAC-SHA256 signature
}

// NewPortKnock creates a new port knock validator
func NewPortKnock(config *PortKnockConfig, logger *utils.Logger) (*PortKnock, error) {
	if !config.Enabled {
		return &PortKnock{
			enabled: false,
			logger:  logger,
			ttl:     5 * time.Minute,
		}, nil
	}

	if config.Secret == "" {
		return nil, errors.New("port_knock secret is required when enabled")
	}

	secret, err := base64.StdEncoding.DecodeString(config.Secret)
	if err != nil {
		// Try raw string if base64 decoding fails
		secret = []byte(config.Secret)
	}

	ttl := config.TTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}

	replayTTL := config.ReplayTTL
	if replayTTL == 0 {
		replayTTL = 10 * time.Minute
	}

	return &PortKnock{
		secret:    secret,
		enabled:   true,
		logger:    logger,
		ttl:       ttl,
		replayTTL: replayTTL,
	}, nil
}

// ValidateKnock validates a port knock message
func (p *PortKnock) ValidateKnock(data []byte, remoteAddr string) bool {
	if !p.enabled {
		return true // Port knock disabled, allow all
	}

	// Parse the knock message
	var msg KnockMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		p.logger.Debug("Failed to parse port knock message", utils.Err(err))
		return false
	}

	// Check timestamp
	now := time.Now().Unix()
	msgTime := msg.Timestamp

	if abs64(now-msgTime) > int64(p.ttl.Seconds()) {
		p.logger.Warn("Port knock expired",
			utils.String("ip", remoteAddr),
			utils.Int64("msg_ts", msgTime),
			utils.Int64("now", now),
		)
		return false
	}

	// Verify IP matches (if provided in message)
	clientIP, _, _ := net.SplitHostPort(remoteAddr)
	if msg.IP != "" && msg.IP != clientIP {
		p.logger.Warn("Port knock IP mismatch",
			utils.String("expected", clientIP),
			utils.String("got", msg.IP),
		)
		return false
	}

	// Check if knock was already used (replay protection)
	if _, exists := p.usedKnocks.Load(msg.Signature); exists {
		p.logger.Warn("Port knock replay detected",
			utils.String("ip", remoteAddr),
			utils.String("signature", msg.Signature[:min(16, len(msg.Signature))]+"..."),
		)
		return false
	}

	// Verify signature
	expectedSig := p.calculateSignature(&msg)
	if !hmac.Equal([]byte(msg.Signature), expectedSig) {
		p.logger.Warn("Port knock signature invalid",
			utils.String("ip", remoteAddr),
		)
		return false
	}

	// Mark knock as used
	p.usedKnocks.Store(msg.Signature, time.Now())

	// Add IP to whitelist with TTL
	p.whitelist.Store(clientIP, time.Now().Add(p.ttl))

	p.logger.Info("Port knock validated, IP whitelisted",
		utils.String("ip", clientIP),
		utils.Duration("ttl", p.ttl),
	)

	// Clean up old entries periodically
	p.cleanup()

	return true
}

// IsWhitelisted checks if an IP is in the whitelist
func (p *PortKnock) IsWhitelisted(remoteAddr string) bool {
	if !p.enabled {
		return true
	}

	clientIP, _, _ := net.SplitHostPort(remoteAddr)

	val, ok := p.whitelist.Load(clientIP)
	if !ok {
		return false
	}

	expiry, ok := val.(time.Time)
	if !ok {
		return false
	}

	if time.Now().After(expiry) {
		p.whitelist.Delete(clientIP)
		return false
	}

	return true
}

// CreateKnock creates a port knock message for a client
func (p *PortKnock) CreateKnock(clientIP string) ([]byte, error) {
	nonce := randomString(16)
	timestamp := time.Now().Unix()

	msg := KnockMessage{
		Timestamp: timestamp,
		IP:        clientIP,
		Nonce:     nonce,
	}

	// Calculate signature
	sig := p.calculateSignature(&msg)
	msg.Signature = base64.StdEncoding.EncodeToString(sig)

	return json.Marshal(&msg)
}

// calculateSignature calculates the HMAC-SHA256 signature
func (p *PortKnock) calculateSignature(msg *KnockMessage) []byte {
	h := hmac.New(sha256.New, p.secret)

	// Sign: timestamp + IP + nonce
	data := fmt.Sprintf("%d|%s|%s", msg.Timestamp, msg.IP, msg.Nonce)
	h.Write([]byte(data))

	return h.Sum(nil)
}

// cleanup removes expired entries from whitelist and used knocks
func (p *PortKnock) cleanup() {
	now := time.Now()

	// Clean whitelist
	p.whitelist.Range(func(key, value interface{}) bool {
		expiry, ok := value.(time.Time)
		if !ok || now.After(expiry) {
			p.whitelist.Delete(key)
		}
		return true
	})

	// Clean used knocks
	p.usedKnocks.Range(func(key, value interface{}) bool {
		usedTime, ok := value.(time.Time)
		if !ok || now.Sub(usedTime) > p.replayTTL {
			p.usedKnocks.Delete(key)
		}
		return true
	})
}

// AddToWhitelist manually adds an IP to the whitelist
func (p *PortKnock) AddToWhitelist(ip string, ttl time.Duration) {
	if !p.enabled {
		return
	}

	expiry := time.Now().Add(ttl)
	if ttl == 0 {
		expiry = time.Now().Add(p.ttl)
	}

	p.whitelist.Store(ip, expiry)
	p.logger.Info("IP manually added to whitelist",
		utils.String("ip", ip),
		utils.Duration("ttl", ttl),
	)
}

// RemoveFromWhitelist removes an IP from the whitelist
func (p *PortKnock) RemoveFromWhitelist(ip string) {
	p.whitelist.Delete(ip)
	p.logger.Info("IP removed from whitelist", utils.String("ip", ip))
}

// IsEnabled returns whether port knock is enabled
func (p *PortKnock) IsEnabled() bool {
	return p.enabled
}

// GenerateClientSecret generates a random secret for client configuration
func GenerateClientSecret() string {
	b := make([]byte, 32)
	if _, err := randRead(b); err != nil {
		// Fallback to time-based
		binary.BigEndian.PutUint64(b, uint64(time.Now().UnixNano()))
	}
	return base64.StdEncoding.EncodeToString(b)
}

// randRead wraps crypto/rand.Read for compatibility
func randRead(b []byte) (int, error) {
	// Simple fallback using time and nanos
	n := time.Now().UnixNano()
	for i := 0; i < len(b); i += 8 {
		binary.BigEndian.PutUint64(b[i:min(i+8, len(b))], uint64(n))
		n = int64(n>>31) ^ n
	}
	return len(b), nil
}

// Helper functions

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// ExtractIPFromAddr extracts IP from remote address string
func ExtractIPFromAddr(remoteAddr string) string {
	// Handle IPv6
	if strings.Contains(remoteAddr, "[") {
		host, _, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			return remoteAddr
		}
		return host
	}

	// Handle IPv4
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// ValidateIP validates an IP address string
func ValidateIP(ip string) bool {
	return net.ParseIP(ip) != nil
}
