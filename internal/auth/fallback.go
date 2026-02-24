// Package auth provides authentication mechanisms
package auth

import (
	"net/http"
	"time"

	"github.com/redpivot/redpivot/pkg/utils"
)

// FallbackHandler handles unauthorized access attempts by redirecting to a target URL
type FallbackHandler struct {
	TargetURL string
	logger    *utils.Logger
	enabled   bool
}

// NewFallbackHandler creates a new fallback handler
func NewFallbackHandler(targetURL string, logger *utils.Logger) *FallbackHandler {
	return &FallbackHandler{
		TargetURL: targetURL,
		logger:    logger,
		enabled:   targetURL != "",
	}
}

// ServeHTTP redirects unauthorized requests to the target URL
func (f *FallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Extract client IP
	ip := getClientIP(r)

	// Log the unauthorized access attempt
	f.logger.Warn("Unauthorized access attempt, redirecting to fallback URL",
		utils.String("ip", ip),
		utils.String("path", r.URL.Path),
		utils.String("method", r.Method),
		utils.String("user_agent", r.UserAgent()),
		utils.String("target_url", f.TargetURL),
	)

	// Redirect with 302 Found
	http.Redirect(w, r, f.TargetURL, http.StatusFound)
}

// IsEnabled returns whether the fallback handler is enabled
func (f *FallbackHandler) IsEnabled() bool {
	return f.enabled
}

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxied requests)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// FallbackConfig represents the fallback handler configuration
type FallbackConfig struct {
	Enabled  bool          `yaml:"enabled"`
	TargetURL string        `yaml:"target_url"`
	LogOnly  bool          `yaml:"log_only"` // If true, only log without redirecting
}

// FallbackMiddleware creates middleware that uses the fallback handler
type FallbackMiddleware struct {
	handler *FallbackHandler
	next    http.Handler
}

// NewFallbackMiddleware creates a new fallback middleware
func NewFallbackMiddleware(handler *FallbackHandler, next http.Handler) *FallbackMiddleware {
	return &FallbackMiddleware{
		handler: handler,
		next:    next,
	}
}

// ServeHTTP implements the http.Handler interface
func (m *FallbackMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Pass through to next handler
	m.next.ServeHTTP(w, r)
}

// HandleUnauthorized is called when authentication fails
func (f *FallbackHandler) HandleUnauthorized(w http.ResponseWriter, r *http.Request) {
	if !f.enabled {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Log the unauthorized attempt
	ip := getClientIP(r)
	f.logger.Warn("Authentication failed",
		utils.String("ip", ip),
		utils.String("path", r.URL.Path),
		utils.String("method", r.Method),
		utils.String("time", time.Now().Format(time.RFC3339)),
	)

	// Redirect to fallback URL
	http.Redirect(w, r, f.TargetURL, http.StatusFound)
}
