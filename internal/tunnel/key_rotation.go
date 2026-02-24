// Package tunnel provides core tunneling functionality
package tunnel

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/redpivot/redpivot/pkg/utils"
)

var (
	ErrKeyRotationDisabled = errors.New("key rotation is disabled")
	ErrKeyNotFound         = errors.New("key not found")
)

// KeyID is a unique identifier for a key
type KeyID uint64

// KeyRotationConfig holds key rotation configuration
type KeyRotationConfig struct {
	Enabled          bool          `yaml:"enabled"`
	Interval         time.Duration `yaml:"interval"`
	GracePeriod      time.Duration `yaml:"grace_period"`
	KeyHistorySize   int           `yaml:"key_history_size"`
	RotationNotify   bool          `yaml:"rotation_notify"`
}

// DefaultKeyRotationConfig returns default key rotation configuration
func DefaultKeyRotationConfig() KeyRotationConfig {
	return KeyRotationConfig{
		Enabled:        false,
		Interval:       30 * time.Minute,
		GracePeriod:    5 * time.Minute,
		KeyHistorySize: 3,
		RotationNotify: true,
	}
}

// KeyWithID wraps a CryptoLayer with its KeyID and expiration time
type KeyWithID struct {
	ID         KeyID
	Crypto     *CryptoLayer
	ExpiresAt  time.Time
	IsPrimary  bool
}

// KeyRotator manages session key rotation
type KeyRotator struct {
	currentKey  *KeyWithID
	oldKeys     map[KeyID]*KeyWithID // Keys being phased out
	mu          sync.RWMutex
	config      KeyRotationConfig
	stopChan    chan struct{}
	notifyChan  chan []byte // Channel to send key rotation notifications
	logger      *utils.Logger
	keyCounter  KeyID
	rotationFn  func(newKey []byte, keyID KeyID) error // Callback to notify peer
}

// NewKeyRotator creates a new key rotator
func NewKeyRotator(initialKey []byte, config KeyRotationConfig, logger *utils.Logger) (*KeyRotator, error) {
	crypto, err := NewCryptoLayer(initialKey)
	if err != nil {
		return nil, err
	}

	return &KeyRotator{
		currentKey: &KeyWithID{
			ID:        0,
			Crypto:    crypto,
			ExpiresAt: time.Now().Add(config.Interval),
			IsPrimary: true,
		},
		oldKeys:    make(map[KeyID]*KeyWithID),
		config:     config,
		stopChan:   make(chan struct{}),
		notifyChan: make(chan []byte, 1),
		logger:     logger,
		keyCounter: 0,
	}, nil
}

// SetRotationCallback sets the callback function for key rotation notifications
func (k *KeyRotator) SetRotationCallback(fn func(newKey []byte, keyID KeyID) error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.rotationFn = fn
}

// Start begins the key rotation routine
func (k *KeyRotator) Start() {
	if !k.config.Enabled {
		k.logger.Debug("Key rotation is disabled")
		return
	}

	k.logger.Info("Key rotation started",
		utils.String("interval", k.config.Interval.String()),
		utils.Int("grace_period_sec", int(k.config.GracePeriod.Seconds())))

	go k.rotationLoop()
}

// Stop stops the key rotation routine
func (k *KeyRotator) Stop() {
	close(k.stopChan)
	k.logger.Info("Key rotation stopped")
}

// rotationLoop handles periodic key rotation
func (k *KeyRotator) rotationLoop() {
	ticker := time.NewTicker(k.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-k.stopChan:
			return
		case <-ticker.C:
			if err := k.rotateKey(); err != nil {
				k.logger.Error("Key rotation failed", utils.Err(err))
			}
		}
	}
}

// rotateKey generates a new key and notifies both ends
func (k *KeyRotator) rotateKey() error {
	k.mu.Lock()
	defer k.mu.Unlock()

	// Generate new key
	newKey, err := GenerateKey()
	if err != nil {
		return err
	}

	// Create new crypto layer
	newCrypto, err := NewCryptoLayer(newKey)
	if err != nil {
		return err
	}

	k.keyCounter++

	// Move current key to old keys
	if k.config.GracePeriod > 0 {
		k.oldKeys[k.currentKey.ID] = &KeyWithID{
			ID:        k.currentKey.ID,
			Crypto:    k.currentKey.Crypto,
			ExpiresAt: time.Now().Add(k.config.GracePeriod),
			IsPrimary: false,
		}

		// Clean up expired old keys
		k.cleanupExpiredKeys()
	}

	// Set new key as current
	k.currentKey = &KeyWithID{
		ID:        k.keyCounter,
		Crypto:    newCrypto,
		ExpiresAt: time.Now().Add(k.config.Interval),
		IsPrimary: true,
	}

	k.logger.Info("Key rotated successfully",
		utils.String("key_id", k.currentKey.ID.String()),
		utils.Int("history_size", len(k.oldKeys)))

	// Notify peer if callback is set
	if k.rotationFn != nil && k.config.RotationNotify {
		// Send new key encrypted with old key
		notification, err := k.buildKeyNotification(newKey, k.currentKey.ID)
		if err != nil {
			return err
		}

		// Send notification in background
		go func() {
			if err := k.rotationFn(notification, k.currentKey.ID); err != nil {
				k.logger.Error("Failed to send key rotation notification", utils.Err(err))
			}
		}()
	}

	return nil
}

// buildKeyNotification creates a key rotation notification message
// Format: [1 byte: type][8 bytes: key_id][32 bytes: new_key][N bytes: signature]
func (k *KeyRotator) buildKeyNotification(newKey []byte, keyID KeyID) ([]byte, error) {
	notification := make([]byte, 1+8+32)
	notification[0] = 0x01 // Key rotation type
	binary.BigEndian.PutUint64(notification[1:9], uint64(keyID))
	copy(notification[9:41], newKey)

	return notification, nil
}

// cleanupExpiredKeys removes expired keys from history
func (k *KeyRotator) cleanupExpiredKeys() {
	now := time.Now()
	for id, key := range k.oldKeys {
		if now.After(key.ExpiresAt) {
			delete(k.oldKeys, id)
			k.logger.Debug("Expired key removed from history",
				utils.String("key_id", id.String()))
		}
	}

	// Limit history size
	if len(k.oldKeys) > k.config.KeyHistorySize {
		// Remove oldest keys
		for id := range k.oldKeys {
			delete(k.oldKeys, id)
			if len(k.oldKeys) <= k.config.KeyHistorySize {
				break
			}
		}
	}
}

// GetCurrentKey returns the current primary key
func (k *KeyRotator) GetCurrentKey() *CryptoLayer {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.currentKey.Crypto
}

// GetCurrentKeyID returns the current key ID
func (k *KeyRotator) GetCurrentKeyID() KeyID {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.currentKey.ID
}

// GetKey returns the crypto layer for a specific key ID
func (k *KeyRotator) GetKey(keyID KeyID) (*CryptoLayer, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.currentKey.ID == keyID {
		return k.currentKey.Crypto, nil
	}

	if key, ok := k.oldKeys[keyID]; ok {
		if time.Now().Before(key.ExpiresAt) {
			return key.Crypto, nil
		}
	}

	return nil, ErrKeyNotFound
}

// AddKey adds a new key (received from peer during rotation)
func (k *KeyRotator) AddKey(keyID KeyID, keyData []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	// Don't add if it's the same as current
	if k.currentKey.ID == keyID {
		return nil
	}

	// Create crypto layer for new key
	crypto, err := NewCryptoLayer(keyData)
	if err != nil {
		return err
	}

	// Store as old key (peer's current key becomes our old key for decryption)
	k.oldKeys[keyID] = &KeyWithID{
		ID:        keyID,
		Crypto:    crypto,
		ExpiresAt: time.Now().Add(k.config.GracePeriod),
		IsPrimary: false,
	}

	k.logger.Info("New key added from peer",
		utils.String("key_id", keyID.String()))

	return nil
}

// RotateToKey rotates to a specific key ID (initiated by peer)
func (k *KeyRotator) RotateToKey(keyID KeyID, keyData []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	// Create crypto layer for new key
	crypto, err := NewCryptoLayer(keyData)
	if err != nil {
		return err
	}

	// Move current key to old keys if grace period is enabled
	if k.config.GracePeriod > 0 && k.currentKey.ID != keyID {
		k.oldKeys[k.currentKey.ID] = &KeyWithID{
			ID:        k.currentKey.ID,
			Crypto:    k.currentKey.Crypto,
			ExpiresAt: time.Now().Add(k.config.GracePeriod),
			IsPrimary: false,
		}
	}

	// Set new key as current
	k.currentKey = &KeyWithID{
		ID:        keyID,
		Crypto:    crypto,
		ExpiresAt: time.Now().Add(k.config.Interval),
		IsPrimary: true,
	}

	k.logger.Info("Rotated to peer-initiated key",
		utils.String("key_id", keyID.String()))

	return nil
}

// KeyIDString returns the string representation of a KeyID
func (k KeyID) String() string {
	return string(rune(uint64(k) % 26 + 'A'))
}

// EncryptedConnWithRotation wraps a connection with encryption and key rotation support
type EncryptedConnWithRotation struct {
	conn      io.ReadWriteCloser
	rotator   *KeyRotator
	writeBuf  []byte
	readBuf   []byte
	readPos   int
	logger    *utils.Logger
}

// NewEncryptedConnWithRotation creates an encrypted connection with key rotation
func NewEncryptedConnWithRotation(conn io.ReadWriteCloser, rotator *KeyRotator, logger *utils.Logger) *EncryptedConnWithRotation {
	return &EncryptedConnWithRotation{
		conn:    conn,
		rotator: rotator,
		logger:  logger,
	}
}

// Write encrypts and writes data with length prefix and key ID
// Format: [8 bytes: key_id][4 bytes: length][encrypted data]
func (c *EncryptedConnWithRotation) Write(data []byte) (int, error) {
	crypto := c.rotator.GetCurrentKey()
	keyID := c.rotator.GetCurrentKeyID()

	encrypted, err := crypto.Encrypt(data)
	if err != nil {
		return 0, err
	}

	// Build frame: [key_id (8 bytes)][length (4 bytes)][encrypted data]
	frame := make([]byte, 8+4+len(encrypted))
	binary.BigEndian.PutUint64(frame[0:8], uint64(keyID))
	binary.BigEndian.PutUint32(frame[8:12], uint32(len(encrypted)))
	copy(frame[12:], encrypted)

	if _, err := c.conn.Write(frame); err != nil {
		return 0, err
	}

	return len(data), nil
}

// Read reads and decrypts data with key rotation support
// Tries current key first, then falls back to old keys
func (c *EncryptedConnWithRotation) Read(data []byte) (int, error) {
	// Return buffered data first
	if c.readBuf != nil && c.readPos < len(c.readBuf) {
		n := copy(data, c.readBuf[c.readPos:])
		c.readPos += n
		if c.readPos >= len(c.readBuf) {
			c.readBuf = nil
			c.readPos = 0
		}
		return n, nil
	}

	// Read header: [key_id (8 bytes)][length (4 bytes)]
	header := make([]byte, 12)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return 0, err
	}

	keyID := KeyID(binary.BigEndian.Uint64(header[0:8]))
	length := binary.BigEndian.Uint32(header[8:12])

	const maxFrameSize = 64 * 1024
	if length > maxFrameSize || length == 0 {
		return 0, ErrInvalidFrame
	}

	// Read encrypted data
	encrypted := make([]byte, length)
	if _, err := io.ReadFull(c.conn, encrypted); err != nil {
		return 0, err
	}

	// Try to decrypt with the specified key
	crypto, err := c.rotator.GetKey(keyID)
	if err != nil {
		// Key not found, try current key as fallback
		crypto = c.rotator.GetCurrentKey()
		c.logger.Debug("Key not found, using current key",
			utils.String("requested_key_id", keyID.String()))
	}

	decrypted, err := crypto.Decrypt(encrypted)
	if err != nil {
		// Try current key if specified key failed
		if keyID != c.rotator.GetCurrentKeyID() {
			crypto = c.rotator.GetCurrentKey()
			decrypted, err = crypto.Decrypt(encrypted)
		}
		if err != nil {
			return 0, err
		}
	}

	// Copy to output, buffer rest
	n := copy(data, decrypted)
	if n < len(decrypted) {
		c.readBuf = decrypted[n:]
		c.readPos = 0
	}

	return n, nil
}

// Close closes the underlying connection
func (c *EncryptedConnWithRotation) Close() error {
	return c.conn.Close()
}
