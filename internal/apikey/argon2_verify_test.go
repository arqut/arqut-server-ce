package apikey

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
)

// TestArgon2ActuallyUsed verifies that we're actually using Argon2id
// and not some other hashing mechanism
func TestArgon2ActuallyUsed(t *testing.T) {
	apiKey := "arq_test_key_12345678901234567890123456789012"

	// Generate hash using our function
	hash, err := Hash(apiKey)
	require.NoError(t, err)

	// Parse the hash to extract salt and expected hash
	salt, expectedHash, err := parseHash(hash)
	require.NoError(t, err)

	// Manually compute Argon2id hash with the same parameters and salt
	computedHash := argon2.IDKey(
		[]byte(apiKey),
		salt,
		Argon2Time,
		Argon2Memory,
		Argon2Threads,
		Argon2KeyLen,
	)

	// If we're actually using Argon2id, the hashes should match
	assert.Equal(t, expectedHash, computedHash, "Hash should be computed using Argon2id with our parameters")
}

// TestArgon2Parameters verifies the exact parameters we're using
func TestArgon2ParametersValues(t *testing.T) {
	assert.Equal(t, uint32(3), uint32(Argon2Time), "Time parameter should be 3")
	assert.Equal(t, uint32(64*1024), uint32(Argon2Memory), "Memory should be 64MB (64*1024 KiB)")
	assert.Equal(t, uint8(4), uint8(Argon2Threads), "Should use 4 threads")
	assert.Equal(t, uint32(32), uint32(Argon2KeyLen), "Key length should be 32 bytes")
	assert.Equal(t, 16, SaltLength, "Salt should be 16 bytes")
}

// TestHashFormatStructure verifies the exact structure of the hash
func TestHashFormatStructure(t *testing.T) {
	apiKey := "arq_test_key_12345678901234567890123456789012"
	hash, err := Hash(apiKey)
	require.NoError(t, err)

	// Parse components
	salt, hashBytes, err := parseHash(hash)
	require.NoError(t, err)

	// Verify salt length
	assert.Equal(t, SaltLength, len(salt), "Salt should be 16 bytes")

	// Verify hash length
	assert.Equal(t, Argon2KeyLen, len(hashBytes), "Hash should be 32 bytes")

	// Verify the hash string format
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hashBytes)
	expectedFormat := saltB64 + ":" + hashB64
	assert.Equal(t, expectedFormat, hash, "Hash format should be salt:hash in base64")
}

// TestArgon2NotBcrypt verifies we're NOT using bcrypt anymore
func TestArgon2NotBcrypt(t *testing.T) {
	apiKey := "arq_test_key_12345678901234567890123456789012"
	hash, err := Hash(apiKey)
	require.NoError(t, err)

	// Bcrypt hashes start with $2a$ or $2b$ or $2y$
	assert.False(t, len(hash) > 3 && hash[0] == '$' && hash[1] == '2',
		"Hash should NOT be in bcrypt format")

	// Our format should have exactly one colon separator
	colonCount := 0
	for _, ch := range hash {
		if ch == ':' {
			colonCount++
		}
	}
	assert.Equal(t, 1, colonCount, "Hash should have exactly one colon separator (salt:hash)")
}

// TestConstantTimeValidation verifies validation uses constant-time comparison
func TestConstantTimeValidation(t *testing.T) {
	apiKey := "arq_test_key_12345678901234567890123456789012"
	hash, err := Hash(apiKey)
	require.NoError(t, err)

	// Valid key should validate
	assert.True(t, Validate(apiKey, hash))

	// Invalid key should NOT validate
	wrongKey := "arq_wrong_key_1234567890123456789012345678"
	assert.False(t, Validate(wrongKey, hash))

	// This test doesn't prove constant-time behavior, but verifies the function works
	// Constant-time is ensured by using subtle.ConstantTimeCompare in the implementation
}
