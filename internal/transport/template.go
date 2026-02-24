// Package transport provides HTTP appearance template for traffic伪装
package transport

import (
	"net/http"
	"net/url"

	"github.com/redpivot/redpivot/pkg/utils"
)

// HttpAppearance defines HTTP traffic伪装 configuration
type HttpAppearance struct {
	Enabled      bool              `yaml:"enabled"`
	UserAgent    string            `yaml:"user_agent"`
	ExtraHeaders map[string]string `yaml:"extra_headers"`
	UriTemplate  string            `yaml:"uri_template"`

	logger *utils.Logger
}

// NewHttpAppearance creates a new HttpAppearance instance
func NewHttpAppearance(logger *utils.Logger) *HttpAppearance {
	return &HttpAppearance{
		ExtraHeaders: make(map[string]string),
		logger:       logger,
	}
}

// BuildHeaders constructs HTTP headers for WebSocket connection
// It applies custom User-Agent and additional headers if enabled
func (h *HttpAppearance) BuildHeaders(targetURL string) http.Header {
	headers := make(http.Header)

	if !h.Enabled {
		// Set basic headers for normal WebSocket connection
		headers.Set("Upgrade", "websocket")
		headers.Set("Connection", "Upgrade")
		headers.Set("Sec-WebSocket-Version", "13")
		headers.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		return headers
	}

	// Apply User-Agent if specified
	if h.UserAgent != "" {
		headers.Set("User-Agent", h.UserAgent)
		h.logger.Debug("Applied custom User-Agent", utils.String("ua", h.UserAgent))
	} else {
		// Apply from UA pool if no custom UA specified
		if ua := GetRandomUA(); ua != "" {
			headers.Set("User-Agent", ua)
			h.logger.Debug("Applied random UA from pool", utils.String("ua", ua))
		}
	}

	// Apply WebSocket-specific headers
	headers.Set("Upgrade", "websocket")
	headers.Set("Connection", "Upgrade")
	headers.Set("Sec-WebSocket-Version", "13")
	headers.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	// Apply extra custom headers
	for key, value := range h.ExtraHeaders {
		if key != "" && value != "" {
			headers.Set(key, value)
			h.logger.Debug("Applied custom header",
				utils.String("key", key),
				utils.String("value", value))
		}
	}

	// Apply common browser headers to mimic legitimate traffic
	h.applyCommonHeaders(headers, targetURL)

	return headers
}

// applyCommonHeaders adds headers that mimic real browser traffic
func (h *HttpAppearance) applyCommonHeaders(headers http.Header, targetURL string) {
	// Parse target URL for host information
	parsedURL, err := url.Parse(targetURL)
	if err == nil {
		// Set Host header explicitly
		headers.Set("Host", parsedURL.Host)

		// Set Origin header for WebSocket
		scheme := "https"
		if parsedURL.Scheme == "ws" {
			scheme = "http"
		}
		headers.Set("Origin", scheme+"://"+parsedURL.Host)
	}

	// Common headers that browsers send
	headers.Set("Accept", "*/*")
	headers.Set("Accept-Language", "en-US,en;q=0.9")
	headers.Set("Accept-Encoding", "gzip, deflate, br")
	headers.Set("Cache-Control", "no-cache")
	headers.Set("Pragma", "no-cache")

	// Sec-Fetch headers (modern browsers)
	headers.Set("Sec-Fetch-Site", "none")
	headers.Set("Sec-Fetch-Mode", "websocket")
	headers.Set("Sec-Fetch-User", "?1")
	headers.Set("Sec-Fetch-Dest", "websocket")
}

// SetLogger sets the logger for the HttpAppearance
func (h *HttpAppearance) SetLogger(logger *utils.Logger) {
	h.logger = logger
}

// IsEnabled returns whether HTTP appearance is enabled
func (h *HttpAppearance) IsEnabled() bool {
	return h.Enabled
}
