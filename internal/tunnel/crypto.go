// Package tunnel provides core tunneling functionality
package tunnel

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrInvalidKeySize      = errors.New("key must be 32 bytes")
	ErrCiphertextTooShort  = errors.New("ciphertext too short")
	ErrDecryptionFailed    = errors.New("decryption failed")
	ErrInvalidFrame        = errors.New("invalid encrypted frame")
)

// CryptoLayer provides AEAD encryption using XChaCha20-Poly1305
type CryptoLayer struct {
	aead      cipher.AEAD
	nonceSize int
	key       []byte
}

// NewCryptoLayer creates a new encryption layer with the given key
func NewCryptoLayer(key []byte) (*CryptoLayer, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeySize
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	return &CryptoLayer{
		aead:      aead,
		nonceSize: aead.NonceSize(),
		key:       key,
	}, nil
}

// Encrypt encrypts plaintext and returns nonce + ciphertext
func (c *CryptoLayer) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Seal appends ciphertext to nonce
	ciphertext := c.aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts nonce + ciphertext
func (c *CryptoLayer) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < c.nonceSize {
		return nil, ErrCiphertextTooShort
	}

	nonce := ciphertext[:c.nonceSize]
	ciphertext = ciphertext[c.nonceSize:]

	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// Overhead returns the encryption overhead in bytes
func (c *CryptoLayer) Overhead() int {
	return c.nonceSize + c.aead.Overhead()
}

// EncryptedConn wraps a connection with encryption
type EncryptedConn struct {
	conn    io.ReadWriteCloser
	crypto  *CryptoLayer
	readBuf []byte  // Buffer for leftover decrypted data
	readPos int     // Current position in readBuf
}

// NewEncryptedConn creates an encrypted connection wrapper
func NewEncryptedConn(conn io.ReadWriteCloser, crypto *CryptoLayer) *EncryptedConn {
	return &EncryptedConn{
		conn:   conn,
		crypto: crypto,
	}
}

// Write encrypts and writes data with length prefix
func (c *EncryptedConn) Write(data []byte) (int, error) {
	encrypted, err := c.crypto.Encrypt(data)
	if err != nil {
		return 0, err
	}

	// Write length prefix (4 bytes) + encrypted data
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(encrypted)))

	if _, err := c.conn.Write(lenBuf); err != nil {
		return 0, err
	}
	if _, err := c.conn.Write(encrypted); err != nil {
		return 0, err
	}

	return len(data), nil
}

// Read reads and decrypts data with length prefix
// Supports buffering for partial reads
func (c *EncryptedConn) Read(data []byte) (int, error) {
	// If we have buffered data, return it first
	if c.readBuf != nil && c.readPos < len(c.readBuf) {
		n := copy(data, c.readBuf[c.readPos:])
		c.readPos += n
		if c.readPos >= len(c.readBuf) {
			// Consumed all buffered data
			c.readBuf = nil
			c.readPos = 0
		}
		return n, nil
	}

	// Read length prefix (4 bytes)
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(c.conn, lenBuf); err != nil {
		return 0, err
	}

	length := binary.BigEndian.Uint32(lenBuf)
	// Use a reasonable maximum size for encrypted frames
	const maxFrameSize = 64 * 1024
	if length > maxFrameSize || length == 0 {
		return 0, ErrInvalidFrame
	}

	// Read encrypted data
	encrypted := make([]byte, length)
	if _, err := io.ReadFull(c.conn, encrypted); err != nil {
		return 0, err
	}

	// Decrypt
	decrypted, err := c.crypto.Decrypt(encrypted)
	if err != nil {
		return 0, err
	}

	// Copy to output buffer, potentially buffering the rest
	n := copy(data, decrypted)
	if n < len(decrypted) {
		// Buffer the remaining data
		c.readBuf = decrypted[n:]
		c.readPos = 0
	}

	return n, nil
}

// Close closes the underlying connection
func (c *EncryptedConn) Close() error {
	return c.conn.Close()
}

// GenerateKey generates a random 32-byte key
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// DeriveKey derives a key from a secret using HKDF-like approach
// Note: In production, use proper HKDF from golang.org/x/crypto/hkdf
func DeriveKey(secret []byte, info []byte) ([]byte, error) {
	// Simplified key derivation - use HKDF in production
	key := make([]byte, 32)
	copy(key, secret)

	// Mix in info
	for i, b := range info {
		key[i%32] ^= b
	}

	return key, nil
}
