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
	level       DebuggerDetectionLevel
	detected    bool
	checkChan   chan struct{}
	stopChan    chan struct{}
}

// NewAntiDebug creates a new anti-debug instance
func NewAntiDebug(level DebuggerDetectionLevel) *AntiDebug {
	return &AntiDebug{
		level:     level,
		checkChan: make(chan struct{}, 1),
		stopChan:  make(chan struct{}),
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
	// Check common debugger indicators
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

// SandboxCheck provides sandbox detection
type SandboxCheck struct {
	indicators []string
}

// NewSandboxCheck creates a new sandbox checker
func NewSandboxCheck() *SandboxCheck {
	return &SandboxCheck{
		indicators: make([]string, 0),
	}
}

// IsSandbox detects if running in a sandbox/VM
func (s *SandboxCheck) IsSandbox() bool {
	s.indicators = s.indicators[:0]

	// Check CPU count (sandboxes often have 1-2 cores)
	if runtime.NumCPU() < 2 {
		s.indicators = append(s.indicators, "low_cpu_count")
	}

	// Check memory (sandboxes often have limited RAM)
	// Note: This is a heuristic, not definitive
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	if m.Sys < 100*1024*1024 { // Less than 100MB
		s.indicators = append(s.indicators, "low_memory")
	}

	// Check for VM indicators in environment
	vmIndicators := []string{
		"VBOX",
		"VMWARE",
		"QEMU",
		"XEN",
		"VIRTUALBOX",
	}

	for _, env := range os.Environ() {
		for _, indicator := range vmIndicators {
			if containsIgnoreCase(env, indicator) {
				s.indicators = append(s.indicators, "vm_environment")
				return true
			}
		}
	}

	// Check common VM files (Linux)
	vmFiles := []string{
		"/sys/class/dmi/id/product_name",
		"/sys/class/dmi/id/board_vendor",
	}

	for _, f := range vmFiles {
		data, err := os.ReadFile(f)
		if err == nil {
			content := string(data)
			for _, indicator := range vmIndicators {
				if containsIgnoreCase(content, indicator) {
					s.indicators = append(s.indicators, "vm_file:"+f)
					return true
				}
			}
		}
	}

	return len(s.indicators) > 0
}

// GetIndicators returns detected sandbox indicators
func (s *SandboxCheck) GetIndicators() []string {
	return s.indicators
}

// Evade attempts to evade sandbox detection
func (s *SandboxCheck) Evade() bool {
	// Wait to bypass automated analysis
	time.Sleep(30 * time.Second)

	// Check if still running (some sandboxes timeout)
	return true
}

// containsIgnoreCase checks if s contains substr (case insensitive)
func containsIgnoreCase(s, substr string) bool {
	sLower := make([]byte, len(s))
	substrLower := make([]byte, len(substr))

	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		sLower[i] = c
	}

	for i := range substr {
		c := substr[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		substrLower[i] = c
	}

	return contains(string(sLower), string(substrLower))
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
