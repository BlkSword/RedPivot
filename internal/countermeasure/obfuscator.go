// Package countermeasure provides anti-traffic-analysis features
package countermeasure

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"time"
)

// Obfuscator provides traffic obfuscation capabilities
type Obfuscator struct {
	minChunkSize      int
	maxChunkSize      int
	paddingProb       float64
	timingJitterMs    int
	enabled           bool
}

// NewObfuscator creates a new obfuscator with the given configuration
func NewObfuscator(enabled bool, paddingProb float64, timingJitterMs, minChunk, maxChunk int) *Obfuscator {
	return &Obfuscator{
		minChunkSize:      minChunk,
		maxChunkSize:      maxChunk,
		paddingProb:       paddingProb,
		timingJitterMs:    timingJitterMs,
		enabled:           enabled,
	}
}

// DefaultObfuscator creates an obfuscator with default settings
func DefaultObfuscator() *Obfuscator {
	return NewObfuscator(true, 0.3, 50, 64, 1500)
}

// Obfuscate applies obfuscation to data
func (o *Obfuscator) Obfuscate(data []byte) []byte {
	if !o.enabled {
		return data
	}

	// Apply padding with configured probability
	if o.shouldPad() {
		data = o.addPadding(data)
	}

	return data
}

// Deobfuscate removes obfuscation from data
func (o *Obfuscator) Deobfuscate(data []byte) ([]byte, error) {
	if !o.enabled {
		return data, nil
	}

	return o.removePadding(data)
}

// RandomDelay returns a random delay for timing obfuscation
func (o *Obfuscator) RandomDelay() time.Duration {
	if !o.enabled || o.timingJitterMs == 0 {
		return 0
	}

	delayMs := o.randomInt(0, o.timingJitterMs)
	return time.Duration(delayMs) * time.Millisecond
}

// RandomChunk returns a random chunk size for the next transmission
func (o *Obfuscator) RandomChunk() int {
	return o.randomInt(o.minChunkSize, o.maxChunkSize)
}

// shouldPad determines if padding should be applied
func (o *Obfuscator) shouldPad() bool {
	if o.paddingProb <= 0 {
		return false
	}
	if o.paddingProb >= 1 {
		return true
	}

	n, err := rand.Int(rand.Reader, big.NewInt(10000))
	if err != nil {
		return false
	}

	return float64(n.Int64()) < o.paddingProb*10000
}

// addPadding adds random padding to data
// Format: [4 bytes: original length][original data][padding]
func (o *Obfuscator) addPadding(data []byte) []byte {
	padSize := o.randomInt(o.minChunkSize, o.maxChunkSize)
	padding := make([]byte, padSize)
	rand.Read(padding)

	// Create result with length prefix
	result := make([]byte, 4+len(data)+padSize)
	binary.BigEndian.PutUint32(result[0:4], uint32(len(data)))
	copy(result[4:], data)
	copy(result[4+len(data):], padding)

	return result
}

// removePadding removes padding from data
func (o *Obfuscator) removePadding(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return data, nil // Not padded, return as-is
	}

	origLen := binary.BigEndian.Uint32(data[0:4])
	if int(origLen) > len(data)-4 {
		return data, nil // Invalid length, return as-is
	}

	return data[4 : 4+origLen], nil
}

// randomInt generates a random integer in [min, max]
func (o *Obfuscator) randomInt(min, max int) int {
	if min >= max {
		return min
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return min
	}

	return int(n.Int64()) + min
}

// RandomBytes generates random bytes of the given length
func RandomBytes(length int) []byte {
	buf := make([]byte, length)
	rand.Read(buf)
	return buf
}

// TrafficShaper shapes traffic timing to resist fingerprinting
type TrafficShaper struct {
	obfuscator *Obfuscator
	sendQueue  chan []byte
	done       chan struct{}
}

// NewTrafficShaper creates a new traffic shaper
func NewTrafficShaper(obfuscator *Obfuscator) *TrafficShaper {
	return &TrafficShaper{
		obfuscator: obfuscator,
		sendQueue:  make(chan []byte, 256),
		done:       make(chan struct{}),
	}
}

// Queue queues data for sending with timing obfuscation
func (s *TrafficShaper) Queue(data []byte) {
	select {
	case s.sendQueue <- data:
	default:
		// Queue full, drop (or could block)
	}
}

// Start starts the traffic shaper
func (s *TrafficShaper) Start(sendFunc func([]byte) error) {
	go func() {
		for {
			select {
			case <-s.done:
				return
			case data := <-s.sendQueue:
				// Apply random delay
				time.Sleep(s.obfuscator.RandomDelay())
				sendFunc(data)
			}
		}
	}()
}

// Stop stops the traffic shaper
func (s *TrafficShaper) Stop() {
	close(s.done)
}

// GenerateHeartbeat generates a random heartbeat payload
func GenerateHeartbeat() []byte {
	// Random size between 16-64 bytes
	n, _ := rand.Int(rand.Reader, big.NewInt(49)) // 0-48
	size := 16 + int(n.Int64())
	return RandomBytes(size)
}
