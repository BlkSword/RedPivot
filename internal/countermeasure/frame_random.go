// Package countermeasure provides anti-traffic-analysis features
package countermeasure

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"sync"
	"time"
)

// FrameRandomizer applies randomization to protocol frames
type FrameRandomizer struct {
	enabled           bool
	minPadding        int
	maxPadding        int
	timingJitterMin   time.Duration
	timingJitterMax   time.Duration
	sizeRandomization bool
	mu                sync.RWMutex
}

// NewFrameRandomizer creates a new frame randomizer
func NewFrameRandomizer(enabled bool, minPadding, maxPadding int, timingJitterMin, timingJitterMax time.Duration, sizeRandomization bool) *FrameRandomizer {
	return &FrameRandomizer{
		enabled:           enabled,
		minPadding:        minPadding,
		maxPadding:        maxPadding,
		timingJitterMin:   timingJitterMin,
		timingJitterMax:   timingJitterMax,
		sizeRandomization: sizeRandomization,
	}
}

// DefaultFrameRandomizer creates a frame randomizer with default settings
func DefaultFrameRandomizer() *FrameRandomizer {
	return NewFrameRandomizer(
		true,
		4,      // minPadding
		128,    // maxPadding
		0,      // timingJitterMin
		50*time.Millisecond, // timingJitterMax
		true,   // sizeRandomization
	)
}

// Randomize adds random padding to data
// Format: [2 bytes: padding length][original data][random padding]
func (f *FrameRandomizer) Randomize(data []byte) []byte {
	if !f.enabled {
		return data
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	// Generate random padding length
	paddingLen := f.randomInt(f.minPadding, f.maxPadding)

	// Create result with padding length prefix
	result := make([]byte, 2+len(data)+paddingLen)
	binary.BigEndian.PutUint16(result[0:2], uint16(paddingLen))
	copy(result[2:], data)

	// Add random padding
	if paddingLen > 0 {
		padding := result[2+len(data):]
		rand.Read(padding)
	}

	return result
}

// Derandomize removes random padding from data
func (f *FrameRandomizer) Derandomize(data []byte) ([]byte, error) {
	if !f.enabled {
		return data, nil
	}

	if len(data) < 2 {
		return data, nil // Not randomized, return as-is
	}

	paddingLen := int(binary.BigEndian.Uint16(data[0:2]))
	dataEnd := len(data) - paddingLen

	// Validate padding length
	if dataEnd < 2 || dataEnd > len(data) {
		return data, nil // Invalid padding, return as-is
	}

	return data[2:dataEnd], nil
}

// RandomDelay returns a random delay within configured bounds
func (f *FrameRandomizer) RandomDelay() time.Duration {
	if !f.enabled {
		return 0
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	if f.timingJitterMin == 0 && f.timingJitterMax == 0 {
		return 0
	}

	delayMs := f.randomInt(int(f.timingJitterMin.Milliseconds()), int(f.timingJitterMax.Milliseconds()))
	return time.Duration(delayMs) * time.Millisecond
}

// RandomizeSize adjusts data size to random target sizes
// This is useful for creating consistent-looking frame sizes
func (f *FrameRandomizer) RandomizeSize(data []byte, targetSizes []int) []byte {
	if !f.enabled || !f.sizeRandomization || len(targetSizes) == 0 {
		return data
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	// Select random target size
	targetIndex := f.randomInt(0, len(targetSizes)-1)
	targetSize := targetSizes[targetIndex]

	currentSize := len(data)

	if currentSize >= targetSize {
		return data
	}

	// Add padding to reach target size
	result := make([]byte, targetSize)
	copy(result, data)

	// Add random padding
	padding := result[currentSize:]
	rand.Read(padding)

	return result
}

// randomInt generates a random integer in [min, max]
func (f *FrameRandomizer) randomInt(min, max int) int {
	if min >= max {
		return min
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return min
	}

	return int(n.Int64()) + min
}

// SetEnabled enables or disables frame randomization
func (f *FrameRandomizer) SetEnabled(enabled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabled = enabled
}

// SetPaddingBounds updates the padding bounds
func (f *FrameRandomizer) SetPaddingBounds(min, max int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.minPadding = min
	f.maxPadding = max
}

// SetTimingJitter updates the timing jitter bounds
func (f *FrameRandomizer) SetTimingJitter(min, max time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.timingJitterMin = min
	f.timingJitterMax = max
}

// FrameRandomizerConfig holds frame randomizer configuration
type FrameRandomizerConfig struct {
	Enabled           bool          `yaml:"enabled"`
	MinPadding        int           `yaml:"min_padding"`
	MaxPadding        int           `yaml:"max_padding"`
	TimingJitterMinMs int           `yaml:"timing_jitter_min_ms"`
	TimingJitterMaxMs int           `yaml:"timing_jitter_max_ms"`
	SizeRandomization bool          `yaml:"size_randomization"`
}

// DefaultFrameRandomizerConfig returns default frame randomizer configuration
func DefaultFrameRandomizerConfig() FrameRandomizerConfig {
	return FrameRandomizerConfig{
		Enabled:           true,
		MinPadding:        4,
		MaxPadding:        128,
		TimingJitterMinMs: 0,
		TimingJitterMaxMs: 50,
		SizeRandomization: true,
	}
}

// ToFrameRandomizer converts config to FrameRandomizer instance
func (c *FrameRandomizerConfig) ToFrameRandomizer() *FrameRandomizer {
	return NewFrameRandomizer(
		c.Enabled,
		c.MinPadding,
		c.MaxPadding,
		time.Duration(c.TimingJitterMinMs)*time.Millisecond,
		time.Duration(c.TimingJitterMaxMs)*time.Millisecond,
		c.SizeRandomization,
	)
}

// ChunksData splits data into randomized chunks
func (f *FrameRandomizer) ChunkData(data []byte, minChunk, maxChunk int) [][]byte {
	if !f.enabled || minChunk >= maxChunk {
		return [][]byte{data}
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	var chunks [][]byte
	offset := 0

	for offset < len(data) {
		// Random chunk size
		chunkSize := f.randomInt(minChunk, maxChunk)

		// Don't exceed remaining data
		if offset+chunkSize > len(data) {
			chunkSize = len(data) - offset
		}

		chunk := make([]byte, chunkSize)
		copy(chunk, data[offset:offset+chunkSize])
		chunks = append(chunks, chunk)

		offset += chunkSize
	}

	return chunks
}

// RandomFrameSize returns a random frame size within bounds
func (f *FrameRandomizer) RandomFrameSize(minSize, maxSize int) int {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if !f.enabled || minSize >= maxSize {
		return minSize
	}

	return f.randomInt(minSize, maxSize)
}

// CommonFrameSizes returns a slice of common frame sizes for size randomization
// These sizes mimic typical HTTPS frame patterns
func CommonFrameSizes() []int {
	return []int{
		64, 128, 256, 512, 1024, 1369, // Common MTU sizes
		1440, 1460,                     // Ethernet MTU related
		8192, 16384,                    // Larger frames
	}
}

// HTTPLikeFrameSizes returns frame sizes that mimic HTTP traffic patterns
func HTTPLikeFrameSizes() []int {
	return []int{
		512, 1024, 1440, 2880, 4096, 8192,
	}
}

// SmallFrameSizes returns smaller frame sizes for low-bandwidth scenarios
func SmallFrameSizes() []int {
	return []int{
		64, 128, 256, 512, 768, 1024,
	}
}
