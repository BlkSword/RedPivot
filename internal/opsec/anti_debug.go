package opsec

import (
	"os"
	"runtime"
	"time"
)

// DebuggerDetectionLevel controls how aggressively to detect debuggers
type DebuggerDetectionLevel int

const (
	DetectionOff     DebuggerDetectionLevel = iota
	DetectionBasic
	DetectionAggressive
)

// AntiDebug provides anti-debugging capabilities
type AntiDebug struct {
	level     DebuggerDetectionLevel
	detected  bool
	stopChan  chan struct{}
}

// NewAntiDebug creates a new anti-debug instance
func NewAntiDebug(level DebuggerDetectionLevel) *AntiDebug {
	return &AntiDebug{
		level:    level,
		stopChan: make(chan struct{}),
	}
}

// Start begins periodic debugger detection
func (a *AntiDebug) Start(onDetect func()) {
	if a.level == DetectionOff {
		return
	}

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-a.stopChan:
				return
			case <-ticker.C:
				if a.IsDebuggerPresent() {
					a.detected = true
					if onDetect != nil {
						onDetect()
					}
					return
				}
			}
		}
	}()
}

// Stop stops the detection loop
func (a *AntiDebug) Stop() {
	close(a.stopChan)
}

// IsDetected returns if a debugger was detected
func (a *AntiDebug) IsDetected() bool {
	return a.detected
}

// IsDebuggerPresent checks if a debugger is attached
func (a *AntiDebug) IsDebuggerPresent() bool {
	return a.checkPtrace() ||
		a.checkTiming() ||
		a.checkEnvironment()
}

// checkPtrace checks for debugger via ptrace (Linux)
func (a *AntiDebug) checkPtrace() bool {
	// On Linux, check /proc/self/status for TracerPid
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/self/status")
		if err == nil {
			// Look for TracerPid: 0 (no debugger)
			// If non-zero, debugger is attached
			status := string(data)
			for i := 0; i < len(status)-10; i++ {
				if status[i:i+10] == "TracerPid:" {
					pid := status[i+10]
					if pid != '0' && pid != ' ' && pid != '\t' {
						return true
					}
				}
			}
		}
	}
	return false
}

// checkTiming detects debuggers via timing analysis
func (a *AntiDebug) checkTiming() bool {
	if a.level < DetectionAggressive {
		return false
	}

	start := time.Now()
	// Some work that should be fast
	sum := 0
	for i := 0; i < 1000; i++ {
		sum += i
	}
	elapsed := time.Since(start)

	// If this took too long, likely being single-stepped
	if elapsed > 10*time.Millisecond {
		return true
	}

	_ = sum // Avoid unused variable warning
	return false
}

// checkEnvironment checks for debugger environment indicators
func (a *AntiDebug) checkEnvironment() bool {
	// Check for common debugger environment variables
	debugVars := []string{
		"GLIBC_TUNABLES",
		"LD_PRELOAD",
		"LD_AUDIT",
	}

	for _, v := range debugVars {
		if os.Getenv(v) != "" {
			return true
		}
	}

	return false
}
