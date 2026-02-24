// Package countermeasure provides anti-traffic-analysis features
package countermeasure

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sync"
	"time"
)

// DGAHeartbeat uses Domain Generation Algorithm principles for dynamic heartbeat intervals
// The intervals are deterministic (both ends compute the same) but appear random to observers
type DGAHeartbeat struct {
	seed      []byte
	interval  time.Duration
	jitterMax time.Duration
	mu        sync.RWMutex
	counter   uint64
}

// NewDGAHeartbeat creates a new DGA-based heartbeat generator
func NewDGAHeartbeat(seed []byte, interval, jitterMax time.Duration) (*DGAHeartbeat, error) {
	if len(seed) == 0 {
		// Generate random seed if none provided
		seed = make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
	}

	return &DGAHeartbeat{
		seed:      seed,
		interval:  interval,
		jitterMax: jitterMax,
		counter:   0,
	}, nil
}

// DefaultDGAHeartbeat creates a DGA heartbeat with default settings
func DefaultDGAHeartbeat() (*DGAHeartbeat, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}

	return NewDGAHeartbeat(seed, 30*time.Second, 10*time.Second)
}

// NextInterval calculates the next heartbeat interval using DGA
// The interval is deterministic based on seed, timestamp, and counter
func (d *DGAHeartbeat) NextInterval() time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Create HMAC-SHA256 with seed as key
	mac := hmac.New(sha256.New, d.seed)

	// Include timestamp and counter for uniqueness
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(time.Now().Unix()))
	mac.Write(timestamp)

	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, d.counter)
	mac.Write(counterBytes)

	// Compute HMAC
	hash := mac.Sum(nil)

	// Use first 8 bytes of hash as random value
	randomValue := binary.BigEndian.Uint64(hash[:8])

	// Normalize to [0, 1) range
	normalized := float64(randomValue) / float64(math.MaxUint64)

	// Apply jitter: interval +/- jitterMax
	jitterRange := float64(d.jitterMax) * 2
	jitterOffset := (normalized * jitterRange) - float64(d.jitterMax)

	result := d.interval + time.Duration(jitterOffset)

	// Ensure minimum interval
	minInterval := d.interval - d.jitterMax
	if result < minInterval {
		result = minInterval
	}

	d.counter++

	return result
}

// NextIntervalAt calculates the interval for a specific timestamp
// Useful for synchronizing both ends
func (d *DGAHeartbeat) NextIntervalAt(t time.Time) time.Duration {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Create HMAC-SHA256 with seed as key
	mac := hmac.New(sha256.New, d.seed)

	// Include provided timestamp
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(t.Unix()))
	mac.Write(timestamp)

	// Compute HMAC
	hash := mac.Sum(nil)

	// Use first 8 bytes of hash as random value
	randomValue := binary.BigEndian.Uint64(hash[:8])

	// Normalize to [0, 1) range
	normalized := float64(randomValue) / float64(math.MaxUint64)

	// Apply jitter
	jitterRange := float64(d.jitterMax) * 2
	jitterOffset := (normalized * jitterRange) - float64(d.jitterMax)

	result := d.interval + time.Duration(jitterOffset)

	minInterval := d.interval - d.jitterMax
	if result < minInterval {
		result = minInterval
	}

	return result
}

// ResetCounter resets the counter (useful for reconnection scenarios)
func (d *DGAHeartbeat) ResetCounter() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.counter = 0
}

// SetSeed updates the seed (useful for re-keying scenarios)
func (d *DGAHeartbeat) SetSeed(seed []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seed = seed
	d.counter = 0
}

// GetSeed returns the current seed
func (d *DGAHeartbeat) GetSeed() []byte {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Return a copy to prevent external modification
	seedCopy := make([]byte, len(d.seed))
	copy(seedCopy, d.seed)
	return seedCopy
}

// Validate verifies that both ends will generate the same interval
// given the same seed and timestamp
func (d *DGAHeartbeat) Validate(t time.Time, expected time.Duration) bool {
	return d.NextIntervalAt(t) == expected
}

// DGAHeartbeatConfig holds DGA heartbeat configuration
type DGAHeartbeatConfig struct {
	Seed      []byte        `yaml:"seed"`
	Interval  time.Duration `yaml:"interval"`
	JitterMax time.Duration `yaml:"jitter_max"`
}

// DefaultDGAHeartbeatConfig returns default DGA heartbeat configuration
func DefaultDGAHeartbeatConfig() DGAHeartbeatConfig {
	seed := make([]byte, 32)
	// Note: In actual usage, seed should be properly initialized
	return DGAHeartbeatConfig{
		Seed:      seed,
		Interval:  30 * time.Second,
		JitterMax: 10 * time.Second,
	}
}

// AdaptiveHeartbeat adjusts intervals based on network conditions
type AdaptiveHeartbeat struct {
	dga         *DGAHeartbeat
	minInterval time.Duration
	maxInterval time.Duration
	lastAck     time.Time
	rttSamples  []time.Duration
	mu          sync.RWMutex
}

// NewAdaptiveHeartbeat creates an adaptive heartbeat that adjusts to network conditions
func NewAdaptiveHeartbeat(dga *DGAHeartbeat, minInterval, maxInterval time.Duration) *AdaptiveHeartbeat {
	return &AdaptiveHeartbeat{
		dga:         dga,
		minInterval: minInterval,
		maxInterval: maxInterval,
		rttSamples:  make([]time.Duration, 0, 10),
	}
}

// NextInterval calculates the next interval with adaptive adjustment
func (a *AdaptiveHeartbeat) NextInterval() time.Duration {
	baseInterval := a.dga.NextInterval()

	a.mu.RLock()
	defer a.mu.RUnlock()

	// If we have RTT samples, adjust interval
	if len(a.rttSamples) > 0 {
		avgRTT := a.calculateAverageRTT()
		// Adjust interval based on RTT (higher RTT = longer interval)
		adjustmentFactor := float64(avgRTT) / float64(time.Second)
		adjustedInterval := time.Duration(float64(baseInterval) * (1 + adjustmentFactor*0.5))

		// Clamp to min/max
		if adjustedInterval < a.minInterval {
			adjustedInterval = a.minInterval
		}
		if adjustedInterval > a.maxInterval {
			adjustedInterval = a.maxInterval
		}

		return adjustedInterval
	}

	return baseInterval
}

// RecordRTT records a round-trip time sample
func (a *AdaptiveHeartbeat) RecordRTT(rtt time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.rttSamples = append(a.rttSamples, rtt)

	// Keep only last 10 samples
	if len(a.rttSamples) > 10 {
		a.rttSamples = a.rttSamples[1:]
	}
}

// RecordAck records a heartbeat acknowledgment
func (a *AdaptiveHeartbeat) RecordAck() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastAck = time.Now()
}

// calculateAverageRTT calculates the average RTT from samples
func (a *AdaptiveHeartbeat) calculateAverageRTT() time.Duration {
	if len(a.rttSamples) == 0 {
		return 0
	}

	var sum time.Duration
	for _, rtt := range a.rttSamples {
		sum += rtt
	}
	return sum / time.Duration(len(a.rttSamples))
}
