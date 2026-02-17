// Package tunnel provides core tunneling functionality
package tunnel

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrInvalidKeySize      = errors.New("key must be 32 bytes")
	ErrCiphertextTooShort  = errors.New("ciphertext too short")
	ErrDecryptionFailed    = errors.New("decryption failed")
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
	conn   io.ReadWriteCloser
	crypto *CryptoLayer
}

// NewEncryptedConn creates an encrypted connection wrapper
func NewEncryptedConn(conn io.ReadWriteCloser, crypto *CryptoLayer) *EncryptedConn {
	return &EncryptedConn{
		conn:   conn,
		crypto: crypto,
	}
}

// Write encrypts and writes data
func (c *EncryptedConn) Write(data []byte) (int, error) {
	encrypted, err := c.crypto.Encrypt(data)
	if err != nil {
		return 0, err
	}
	return c.conn.Write(encrypted)
}

// Read reads and decrypts data
func (c *EncryptedConn) Read(data []byte) (int, error) {
	// Read encrypted data (we need to read enough for the encrypted payload)
	// For simplicity, we'll use a length-prefixed approach
	// In practice, you'd want to use a buffered reader

	// This is a simplified version - production code would need proper framing
	n, err := c.conn.Read(data)
	if err != nil {
		return n, err
	}

	decrypted, err := c.crypto.Decrypt(data[:n])
	if err != nil {
		return 0, err
	}

	copy(data, decrypted)
	return len(decrypted), nil
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
