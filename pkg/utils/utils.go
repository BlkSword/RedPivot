// Package utils provides utility functions
package utils

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func init() {
	// Seed the random number generator
	rand.Seed(time.Now().UnixNano())
}

// RandomString generates a random string of the given length
func RandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := io.ReadFull(cryptorand.Reader, bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes)[:length], nil
}

// RandomBytes generates random bytes
func RandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	if _, err := io.ReadFull(cryptorand.Reader, bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}

// MustRandomString generates a random string, panics on error
func MustRandomString(length int) string {
	s, err := RandomString(length)
	if err != nil {
		panic(err)
	}
	return s
}

// ParseAddr parses an address string into host and port
func ParseAddr(addr string) (host string, port int, err error) {
	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		return "", 0, errors.New("invalid address format")
	}

	host = parts[0]
	port, err = strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, fmt.Errorf("invalid port: %v", err)
	}

	return host, port, nil
}

// JoinAddr joins host and port into an address string
func JoinAddr(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}

// GetFreePort gets a free port on the given host
func GetFreePort(host string) (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", host+":0")
	if err != nil {
		return 0, err
	}

	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer listener.Close()

	return listener.Addr().(*net.TCPAddr).Port, nil
}

// IsPortAvailable checks if a port is available
func IsPortAvailable(host string, port int) bool {
	addr := JoinAddr(host, port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	listener.Close()
	return true
}

// WaitForPort waits for a port to become available
func WaitForPort(host string, port int, timeout time.Duration) error {
	addr := JoinAddr(host, port)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return errors.New("timeout waiting for port")
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// DirExists checks if a directory exists
func DirExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// EnsureDir ensures a directory exists
func EnsureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

// ExpandPath expands ~ to home directory
func ExpandPath(path string) (string, error) {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

// CopyFile copies a file
func CopyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	return err
}

// Min returns the minimum of two integers
func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Max returns the maximum of two integers
func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Clamp clamps a value between min and max
func Clamp(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

// Contains checks if a slice contains an element
func Contains[T comparable](slice []T, element T) bool {
	for _, e := range slice {
		if e == element {
			return true
		}
	}
	return false
}

// MapKeys returns the keys of a map
func MapKeys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// MapValues returns the values of a map
func MapValues[K comparable, V any](m map[K]V) []V {
	values := make([]V, 0, len(m))
	for _, v := range m {
		values = append(values, v)
	}
	return values
}

// Retry retries a function with exponential backoff
func Retry(fn func() error, maxAttempts int, initialDelay time.Duration) error {
	var err error
	delay := initialDelay

	for i := 0; i < maxAttempts; i++ {
		err = fn()
		if err == nil {
			return nil
		}

		if i < maxAttempts-1 {
			time.Sleep(delay)
			delay = delay * 2
		}
	}

	return err
}

// RetryWithJitter retries with jitter
func RetryWithJitter(fn func() error, maxAttempts int, baseDelay time.Duration, maxJitter time.Duration) error {
	var err error

	for i := 0; i < maxAttempts; i++ {
		err = fn()
		if err == nil {
			return nil
		}

		if i < maxAttempts-1 {
			// Add random jitter
			jitter := time.Duration(rand.Int63n(int64(maxJitter)))
			delay := baseDelay + jitter
			time.Sleep(delay)
			baseDelay = baseDelay * 2
		}
	}

	return err
}
