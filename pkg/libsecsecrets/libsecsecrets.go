// Package libsecsecrets provides a professional-grade implementation for password obfuscation in Go.
// It implements AES-256-GCM authenticated encryption and a multi-source master key resolution strategy.
//
// Objective:
// To ensure that sensitive credentials (such as SFTP passwords, API keys, or DB credentials)
// are never stored in plaintext on disk or in version control by using standardized
// cryptographic methods and secure key handling.
//
// Core Components:
// 1. Key Resolution: Hierarchical search (Flag > Env > File) with platform security enforcement.
// 2. Cryptography: AES-256-GCM providing confidentiality and integrity.
// 3. Memory Safety: Utilities for zeroing sensitive buffers to minimize exposure.
// 4. Resource Optimization: sync.Pool for efficient buffer management.
package libsecsecrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
)

var (
	// bytePool is a sync.Pool for reducing GC pressure on small byte slices.
	bytePool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 32)
			return &b
		},
	}
)

var (
	// ErrInvalidKey is returned when the provided key is not a valid 32-byte hex string.
	ErrInvalidKey = errors.New("invalid key: expected 64-char hex or 32-byte raw string")
	// ErrNoKeySource is returned when no master key could be resolved from any source.
	ErrNoKeySource = errors.New("no master key found in provided sources")
	// ErrInsecureLocation is returned when a key file is stored in an insecure location.
	ErrInsecureLocation = errors.New("insecure key location detected")
	// ErrInsecurePermissions is returned when a key file has unsafe permissions.
	ErrInsecurePermissions = errors.New("insecure file permissions")
	// ErrCiphertextTooShort is returned when the data to decrypt is shorter than the nonce.
	ErrCiphertextTooShort = errors.New("ciphertext too short")
)

// ZeroBuffer fills the provided byte slice with zeros to clear sensitive data from memory.
func ZeroBuffer(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// RandReader is an internal variable that can be mocked for testing.
var RandReader = rand.Reader

// OsReadFile is an internal variable that can be mocked for testing.
var OsReadFile = os.ReadFile

// OsStat is an internal variable that can be mocked for testing.
var OsStat = os.Stat

// RuntimeGOOS is an internal variable that can be mocked for testing.
var RuntimeGOOS = runtime.GOOS

// DefaultKeyEnv is the default environment variable name used to store the master key.
const DefaultKeyEnv = "SECRETPROTECTOR_MASTER_KEY"

// GenerateKey returns a 64-character hex string representing 32 bytes of entropy.
// It uses crypto/rand for cryptographically secure random number generation.
//
// Data Flow:
// 1. Create a 32-byte slice.
// 2. Populate with random bytes from CSPRNG.
// 3. Return as a hex-encoded string.
func GenerateKey() (string, error) {
	keyPtr := bytePool.Get().(*[]byte)
	key := *keyPtr
	defer func() {
		ZeroBuffer(key)
		bytePool.Put(keyPtr)
	}()

	if _, err := io.ReadFull(RandReader, key); err != nil {
		return "", fmt.Errorf("failed to generate random key: %w", err)
	}
	return hex.EncodeToString(key), nil
}

// ResolveKey finds and validates the master key from three possible sources in order of precedence:
// 1. raw: A direct hex string passed as an argument (Highest precedence).
// 2. env: An environment variable name containing the hex key.
// 3. file: A fully qualified file path containing the hex key (Lowest precedence).
//
// Data Flow:
// 1. Check if 'raw' (CLI flag) is provided.
// 2. If not, lookup the environment variable specified by 'env'.
// 3. If still not found, check the file path 'file' after validating permissions.
// 4. Validate the resulting string (must be 64-char hex or 32-byte raw).
// 5. Return the decoded 32-byte master key.
//
// Security Checks:
// - On Linux/Unix, it enforces owner-only permissions (0400/0600) on the key file.
// - On Windows, it prevents reading from insecure locations like "Public" or "Temp" directories.
func ResolveKey(ctx context.Context, raw, env, file string) ([]byte, error) {
	var keyStr string

	// Step 1: Check for raw key override.
	if raw != "" {
		keyStr = raw
	} else if env != "" {
		// Step 2: Resolve from environment variable.
		keyStr = os.Getenv(env)
	}

	// Step 3: Fallback to file resolution if still not found.
	if keyStr == "" && file != "" {
		if err := validateFilePermissions(file); err != nil {
			return nil, err
		}
		data, err := OsReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file: %w", err)
		}
		keyStr = strings.TrimSpace(string(data))
	}

	if keyStr == "" {
		return nil, ErrNoKeySource
	}

	var key []byte
	var err error

	// Step 4: Validate format and length.
	if len(keyStr) == 64 {
		key, err = hex.DecodeString(keyStr)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
	} else if len(keyStr) == 32 {
		key = []byte(keyStr)
	} else {
		return nil, fmt.Errorf("%w: got %d chars", ErrInvalidKey, len(keyStr))
	}

	return key, nil
}

// Encrypt takes a plaintext string and a 32-byte key, returning a Base64 string.
// The output format is: Base64(nonce + ciphertext).
//
// Data Flow:
// 1. Initialize AES block cipher with the provided key.
// 2. Wrap in GCM (Galois/Counter Mode).
// 3. Generate a unique random nonce.
// 4. Encrypt and seal, prepending the nonce to the result.
func Encrypt(ctx context.Context, plain string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", ErrInvalidKey
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(RandReader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt takes a Base64-encoded string (nonce + ciphertext) and a 32-byte key.
// It returns the original plaintext if the key is valid and the data has not been tampered with.
//
// Data Flow:
// 1. Decode Base64 string into raw bytes.
// 2. Initialize AES-GCM with the key.
// 3. Extract the nonce from the beginning of the data.
// 4. Decrypt and verify the integrity of the ciphertext.
func Decrypt(ctx context.Context, encoded string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", ErrInvalidKey
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", ErrCiphertextTooShort
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	return string(plaintext), nil
}

// validateFilePermissions implements platform-specific security boundaries for key files.
//
// Objective:
// Prevent the use of master keys stored in locations that are accessible to other users
// or are inherently volatile/insecure.
//
// Enforcement:
// - Linux/Unix: Stat the file and check mode. Must be 0400 or 0600.
// - Windows: Path-based detection for "Public", "\temp\", or "/temp/".
func validateFilePermissions(path string) error {
	info, err := OsStat(path)
	if err != nil {
		return err
	}

	if RuntimeGOOS != "windows" {
		// Linux/Unix security: Ensure owner-only read (0400) or read/write (0600).
		mode := info.Mode().Perm()
		if mode != 0400 && mode != 0600 {
			return fmt.Errorf("%w: %o (expected 0400 or 0600)", ErrInsecurePermissions, mode)
		}
	} else {
		// Windows security: Check path for insecure shared or volatile locations.
		lowerPath := strings.ToLower(path)
		if strings.Contains(lowerPath, "public") || strings.Contains(lowerPath, "\\temp\\") || strings.Contains(lowerPath, "/temp/") {
			return fmt.Errorf("%w: %s", ErrInsecureLocation, path)
		}
	}
	return nil
}
