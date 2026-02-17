// Package auth provides authentication mechanisms
package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var (
	ErrInvalidToken    = errors.New("invalid token")
	ErrTokenExpired    = errors.New("token expired")
	ErrAuthFailed      = errors.New("authentication failed")
	ErrInvalidMethod   = errors.New("invalid auth method")
)

// Authenticator defines the authentication interface
type Authenticator interface {
	Authenticate(credentials []byte) (*AuthInfo, error)
	Method() string
}

// AuthInfo contains authenticated user information
type AuthInfo struct {
	Token     string
	SessionID string
	ExpiresAt time.Time
	Metadata  map[string]string
}

// TokenAuth implements token-based authentication
type TokenAuth struct {
	tokens    sync.Map // token -> bool
	sessions  sync.Map // sessionID -> *Session
	sessionTTL time.Duration
}

// NewTokenAuth creates a new token authenticator
func NewTokenAuth(tokens []string) *TokenAuth {
	auth := &TokenAuth{
		sessionTTL: 24 * time.Hour,
	}

	for _, token := range tokens {
		auth.tokens.Store(hashToken(token), true)
	}

	return auth
}

// Authenticate validates a token
func (a *TokenAuth) Authenticate(credentials []byte) (*AuthInfo, error) {
	token := string(credentials)

	// Check if token is valid
	if !a.isValidToken(token) {
		return nil, ErrInvalidToken
	}

	// Create session
	sessionID := generateSessionID()
	session := &Session{
		ID:        sessionID,
		Token:     token,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(a.sessionTTL),
	}

	a.sessions.Store(sessionID, session)

	return &AuthInfo{
		Token:     token,
		SessionID: sessionID,
		ExpiresAt: session.ExpiresAt,
	}, nil
}

// Method returns the auth method name
func (a *TokenAuth) Method() string {
	return "token"
}

// isValidToken checks if a token is valid
func (a *TokenAuth) isValidToken(token string) bool {
	hashed := hashToken(token)
	_, ok := a.tokens.Load(hashed)
	return ok
}

// ValidateSession validates an existing session
func (a *TokenAuth) ValidateSession(sessionID string) (*Session, error) {
	val, ok := a.sessions.Load(sessionID)
	if !ok {
		return nil, ErrAuthFailed
	}

	session := val.(*Session)
	if time.Now().After(session.ExpiresAt) {
		a.sessions.Delete(sessionID)
		return nil, ErrTokenExpired
	}

	return session, nil
}

// RevokeSession revokes a session
func (a *TokenAuth) RevokeSession(sessionID string) {
	a.sessions.Delete(sessionID)
}

// AddToken adds a new token
func (a *TokenAuth) AddToken(token string) {
	a.tokens.Store(hashToken(token), true)
}

// RemoveToken removes a token
func (a *TokenAuth) RemoveToken(token string) {
	a.tokens.Delete(hashToken(token))
}

// Session represents an authenticated session
type Session struct {
	ID        string
	Token     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// hashToken hashes a token for storage
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// generateSessionID generates a random session ID
func generateSessionID() string {
	return randomString(32)
}

// randomString generates a random string of the given length
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[i%len(charset)]
	}
	return string(b)
}

// MultiAuth supports multiple authentication methods
type MultiAuth struct {
	methods map[string]Authenticator
}

// NewMultiAuth creates a multi-method authenticator
func NewMultiAuth() *MultiAuth {
	return &MultiAuth{
		methods: make(map[string]Authenticator),
	}
}

// AddMethod adds an authentication method
func (m *MultiAuth) AddMethod(auth Authenticator) {
	m.methods[auth.Method()] = auth
}

// Authenticate authenticates using the specified method
func (m *MultiAuth) Authenticate(method string, credentials []byte) (*AuthInfo, error) {
	auth, ok := m.methods[method]
	if !ok {
		return nil, ErrInvalidMethod
	}
	return auth.Authenticate(credentials)
}

// HasMethod checks if a method is available
func (m *MultiAuth) HasMethod(method string) bool {
	_, ok := m.methods[method]
	return ok
}

// RateLimiter provides rate limiting for authentication attempts
type RateLimiter struct {
	attempts sync.Map // IP -> *AttemptInfo
	maxAttempts int
	window      time.Duration
	banDuration time.Duration
}

// AttemptInfo tracks authentication attempts
type AttemptInfo struct {
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
	Banned    bool
	BanExpiry time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(maxAttempts int, window, banDuration time.Duration) *RateLimiter {
	return &RateLimiter{
		maxAttempts: maxAttempts,
		window:      window,
		banDuration: banDuration,
	}
}

// Check checks if an IP is allowed to authenticate
func (r *RateLimiter) Check(ip string) bool {
	val, ok := r.attempts.Load(ip)
	if !ok {
		return true
	}

	info := val.(*AttemptInfo)

	// Check if banned
	if info.Banned {
		if time.Now().After(info.BanExpiry) {
			r.attempts.Delete(ip)
			return true
		}
		return false
	}

	// Check if window has expired
	if time.Now().Sub(info.FirstSeen) > r.window {
		r.attempts.Delete(ip)
		return true
	}

	return info.Count < r.maxAttempts
}

// Record records an authentication attempt
func (r *RateLimiter) Record(ip string, success bool) {
	if success {
		r.attempts.Delete(ip)
		return
	}

	val, ok := r.attempts.Load(ip)
	var info *AttemptInfo

	if ok {
		info = val.(*AttemptInfo)
		info.Count++
		info.LastSeen = time.Now()

		// Check if should be banned
		if info.Count >= r.maxAttempts {
			info.Banned = true
			info.BanExpiry = time.Now().Add(r.banDuration)
		}
	} else {
		info = &AttemptInfo{
			Count:     1,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}
	}

	r.attempts.Store(ip, info)
}

// IsBanned checks if an IP is banned
func (r *RateLimiter) IsBanned(ip string) bool {
	val, ok := r.attempts.Load(ip)
	if !ok {
		return false
	}

	info := val.(*AttemptInfo)
	return info.Banned && time.Now().Before(info.BanExpiry)
}

// CompositeAuth combines authentication with rate limiting
type CompositeAuth struct {
	auth    Authenticator
	limiter *RateLimiter
}

// NewCompositeAuth creates a composite authenticator
func NewCompositeAuth(auth Authenticator, limiter *RateLimiter) *CompositeAuth {
	return &CompositeAuth{
		auth:    auth,
		limiter: limiter,
	}
}

// Authenticate authenticates with rate limiting
func (c *CompositeAuth) Authenticate(ip string, credentials []byte) (*AuthInfo, error) {
	if c.limiter != nil {
		if !c.limiter.Check(ip) {
			return nil, errors.New("rate limited")
		}
	}

	info, err := c.auth.Authenticate(credentials)
	if err != nil && c.limiter != nil {
		c.limiter.Record(ip, false)
		return nil, err
	}

	if c.limiter != nil {
		c.limiter.Record(ip, true)
	}

	return info, nil
}

// Method returns the auth method
func (c *CompositeAuth) Method() string {
	return c.auth.Method()
}
