package opsec

import (
	"crypto/rand"
	"encoding/binary"
	mrand "math/rand"
	"time"
)

// TrafficEvader provides traffic pattern evasion
type TrafficEvader struct {
	baseDelay    time.Duration
	jitterRange  time.Duration
	burstMode    bool
	burstSize    int
}

// NewTrafficEvader creates a new traffic evader
func NewTrafficEvader(baseDelay, jitter time.Duration) *TrafficEvader {
	// Seed math/rand with crypto random
	var seed int64
	binary.Read(rand.Reader, binary.LittleEndian, &seed)
	mrand.Seed(seed)

	return &TrafficEvader{
		baseDelay:   baseDelay,
		jitterRange: jitter,
		burstMode:   false,
		burstSize:   0,
	}
}

// EnableBurstMode enables burst mode for traffic normalization
func (e *TrafficEvader) EnableBurstMode(size int) {
	e.burstMode = true
	e.burstSize = size
}

// Delay returns a delay with random jitter
func (e *TrafficEvader) Delay() time.Duration {
	if e.baseDelay == 0 {
		return 0
	}

	jitter := time.Duration(mrand.Int63n(int64(e.jitterRange)))
	return e.baseDelay + jitter - e.jitterRange/2
}

// Sleep sleeps with jitter
func (e *TrafficEvader) Sleep() {
	delay := e.Delay()
	if delay > 0 {
		time.Sleep(delay)
	}
}

// ShouldPad determines if padding should be applied
func (e *TrafficEvader) ShouldPad(probability float64) bool {
	return mrand.Float64() < probability
}

// RandomPaddingSize returns a random padding size
func (e *TrafficEvader) RandomPaddingSize(min, max int) int {
	if min >= max {
		return min
	}
	return min + mrand.Intn(max-min)
}

// ChunkData splits data into random-sized chunks
func (e *TrafficEvader) ChunkData(data []byte, minChunk, maxChunk int) [][]byte {
	if len(data) == 0 {
		return nil
	}

	var chunks [][]byte
	remaining := data

	for len(remaining) > 0 {
		chunkSize := minChunk
		if maxChunk > minChunk {
			chunkSize = minChunk + mrand.Intn(maxChunk-minChunk)
		}

		if chunkSize > len(remaining) {
			chunkSize = len(remaining)
		}

		chunks = append(chunks, remaining[:chunkSize])
		remaining = remaining[chunkSize:]
	}

	return chunks
}

// ProcessEvader provides process-level evasion
type ProcessEvader struct {
	name     string
	metadata map[string]string
}

// NewProcessEvader creates a new process evader
func NewProcessEvader() *ProcessEvader {
	return &ProcessEvader{
		metadata: make(map[string]string),
	}
}

// SetName sets a process name for disguise
func (p *ProcessEvader) SetName(name string) {
	p.name = name
	// On Linux, this would prctl(PR_SET_NAME)
	// On Windows, this is more complex
}

// AddMetadata adds metadata for the process
func (p *ProcessEvader) AddMetadata(key, value string) {
	p.metadata[key] = value
}

// TimingNormalizer normalizes timing patterns
type TimingNormalizer struct {
	targetRate   int // bytes per second
	lastSend     time.Time
	bytesSent    int
	windowStart  time.Time
	windowSize   time.Duration
}

// NewTimingNormalizer creates a timing normalizer
func NewTimingNormalizer(targetRate int) *TimingNormalizer {
	return &TimingNormalizer{
		targetRate:  targetRate,
		windowSize:  time.Second,
		windowStart: time.Now(),
	}
}

// Record records bytes sent
func (t *TimingNormalizer) Record(bytes int) {
	now := time.Now()

	// Reset window if needed
	if now.Sub(t.windowStart) > t.windowSize {
		t.windowStart = now
		t.bytesSent = 0
	}

	t.bytesSent += bytes
	t.lastSend = now
}

// Wait waits if rate limiting is needed
func (t *TimingNormalizer) Wait() {
	if t.targetRate <= 0 {
		return
	}

	now := time.Now()
	elapsed := now.Sub(t.windowStart)

	// Calculate expected bytes in this window
	expectedBytes := float64(t.targetRate) * elapsed.Seconds()

	// If we've sent too many bytes, wait
	if float64(t.bytesSent) > expectedBytes {
		waitTime := time.Duration(float64(t.bytesSent)/float64(t.targetRate)*float64(time.Second)) - elapsed
		if waitTime > 0 && waitTime < time.Minute {
			time.Sleep(waitTime)
		}
	}
}

// SetTargetRate sets the target transmission rate
func (t *TimingNormalizer) SetTargetRate(rate int) {
	t.targetRate = rate
}
