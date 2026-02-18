// Package opsec provides sandbox detection capabilities
package opsec

import (
	"os"
	"runtime"
	"strings"
)

// SandboxCheck provides sandbox/virtualization detection
type SandboxCheck struct {
	detected bool
	indicators []string
}

// NewSandboxCheck creates a new sandbox checker
func NewSandboxCheck() *SandboxCheck {
	return &SandboxCheck{
		indicators: make([]string, 0),
	}
}

// IsSandbox performs sandbox detection checks
func (s *SandboxCheck) IsSandbox() bool {
	s.detected = false
	s.indicators = s.indicators[:0]

	// Check common sandbox indicators
	s.checkEnvironment()
	s.checkHardware()
	s.checkArtifacts()

	return s.detected
}

// Indicators returns detected sandbox indicators
func (s *SandboxCheck) Indicators() []string {
	return s.indicators
}

// checkEnvironment checks for sandbox environment variables
func (s *SandboxCheck) checkEnvironment() {
	sandboxEnvs := []string{
		"SANDBOX",
		"VBOX",
		"VMWARE",
		"QEMU",
		"XEN",
		"VIRTUALBOX",
		"CUCKOO",
	}

	for _, env := range sandboxEnvs {
		for _, e := range os.Environ() {
			if strings.Contains(strings.ToUpper(e), env) {
				s.addIndicator("environment: " + e)
			}
		}
	}
}

// checkHardware checks for virtualization hardware indicators
func (s *SandboxCheck) checkHardware() {
	if runtime.GOOS == "linux" {
		// Check /sys/class/dmi/id/product_name
		if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
			product := strings.ToLower(string(data))
			virtualIndicators := []string{"virtualbox", "vmware", "qemu", "kvm", "xen"}
			for _, vi := range virtualIndicators {
				if strings.Contains(product, vi) {
					s.addIndicator("hardware: " + string(data))
					break
				}
			}
		}
	}
}

// checkArtifacts checks for common sandbox artifacts
func (s *SandboxCheck) checkArtifacts() {
	sandboxPaths := []string{
		"/.dockerenv",
		"/.dockerinit",
		"C:\\windows\\system32\\drivers\\vmmouse.sys",
		"C:\\windows\\system32\\drivers\\vmhgfs.sys",
	}

	for _, path := range sandboxPaths {
		if _, err := os.Stat(path); err == nil {
			s.addIndicator("artifact: " + path)
		}
	}
}

// addIndicator adds a sandbox indicator
func (s *SandboxCheck) addIndicator(indicator string) {
	s.indicators = append(s.indicators, indicator)
	s.detected = true
}
