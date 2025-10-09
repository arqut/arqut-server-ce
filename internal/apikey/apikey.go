package apikey

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	// KeyPrefix is the prefix for all API keys
	KeyPrefix = "arq_"

	// KeyLength is the number of random bytes in the key (32 bytes = 256 bits)
	KeyLength = 32

	// Argon2 parameters (recommended values for interactive usage)
	// These provide strong security while keeping verification time reasonable (~100ms)
	Argon2Time    = 3        // Number of iterations
	Argon2Memory  = 64 * 1024 // Memory in KiB (64 MB)
	Argon2Threads = 4        // Number of threads
	Argon2KeyLen  = 32       // Length of the derived key in bytes
	SaltLength    = 16       // Length of random salt in bytes
)

// Generate creates a new API key with the format: arq_<base64url(32 random bytes)>
func Generate() (string, error) {
	// Generate 32 random bytes
	randomBytes := make([]byte, KeyLength)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode to base64url (URL-safe, no padding)
	encoded := base64.RawURLEncoding.EncodeToString(randomBytes)

	return KeyPrefix + encoded, nil
}

// Hash creates an Argon2id hash of the API key
// Returns a hash in the format: base64(salt):base64(hash)
func Hash(apiKey string) (string, error) {
	// Generate random salt
	salt := make([]byte, SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Generate Argon2id hash
	hash := argon2.IDKey([]byte(apiKey), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)

	// Encode salt and hash as base64 and combine them
	saltEncoded := base64.RawStdEncoding.EncodeToString(salt)
	hashEncoded := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("%s:%s", saltEncoded, hashEncoded), nil
}

// Validate checks if the provided API key matches the stored hash using constant-time comparison
func Validate(apiKey, encodedHash string) bool {
	// Parse the encoded hash to extract salt and hash
	salt, hash, err := parseHash(encodedHash)
	if err != nil {
		return false
	}

	// Compute hash of the provided API key using the same salt
	computedHash := argon2.IDKey([]byte(apiKey), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)

	// Compare using constant-time comparison
	return subtle.ConstantTimeCompare(hash, computedHash) == 1
}

// parseHash extracts the salt and hash from the encoded hash string
func parseHash(encodedHash string) (salt, hash []byte, err error) {
	// Find the separator
	var sepIdx = -1
	for i := 0; i < len(encodedHash); i++ {
		if encodedHash[i] == ':' {
			sepIdx = i
			break
		}
	}

	if sepIdx == -1 {
		return nil, nil, fmt.Errorf("invalid hash format: missing separator")
	}

	// Decode salt
	salt, err = base64.RawStdEncoding.DecodeString(encodedHash[:sepIdx])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	// Decode hash
	hash, err = base64.RawStdEncoding.DecodeString(encodedHash[sepIdx+1:])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode hash: %w", err)
	}

	return salt, hash, nil
}

// ValidateFormat checks if the API key has the correct format
func ValidateFormat(apiKey string) bool {
	// Check prefix
	if len(apiKey) < len(KeyPrefix) {
		return false
	}

	if apiKey[:len(KeyPrefix)] != KeyPrefix {
		return false
	}

	// Check length: prefix (4) + base64url encoded 32 bytes (43 chars without padding)
	// base64url encoding of 32 bytes = ceil(32 * 8 / 6) = 43 characters
	expectedLen := len(KeyPrefix) + 43
	if len(apiKey) != expectedLen {
		return false
	}

	// Try to decode the base64url part to verify it's valid
	encoded := apiKey[len(KeyPrefix):]
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}

	// Verify decoded length
	return len(decoded) == KeyLength
}

// GenerateWithHash creates a new API key and its Argon2id hash
func GenerateWithHash() (apiKey string, hash string, err error) {
	apiKey, err = Generate()
	if err != nil {
		return "", "", err
	}

	hash, err = Hash(apiKey)
	if err != nil {
		return "", "", err
	}

	return apiKey, hash, nil
}

// GetCreatedAt returns the current timestamp in RFC3339 format
func GetCreatedAt() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// ValidateConstantTime performs constant-time string comparison
// This prevents timing attacks when comparing API keys
func ValidateConstantTime(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
