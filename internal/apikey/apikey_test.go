package apikey

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerate(t *testing.T) {
	key, err := Generate()
	require.NoError(t, err)
	assert.NotEmpty(t, key)

	// Check prefix
	assert.True(t, strings.HasPrefix(key, KeyPrefix))

	// Check length: prefix (4) + base64url encoded 32 bytes (43 chars)
	expectedLen := len(KeyPrefix) + 43
	assert.Equal(t, expectedLen, len(key))
}

func TestGenerate_Uniqueness(t *testing.T) {
	// Generate multiple keys and ensure they're all unique
	keys := make(map[string]bool)
	for i := 0; i < 100; i++ {
		key, err := Generate()
		require.NoError(t, err)
		assert.False(t, keys[key], "Generated duplicate key")
		keys[key] = true
	}
}

func TestHash(t *testing.T) {
	key := "arq_test_key_12345678901234567890123456789012"

	hash, err := Hash(key)
	require.NoError(t, err)
	assert.NotEmpty(t, hash)

	// Verify hash format: base64(salt):base64(hash)
	assert.Contains(t, hash, ":")
	parts := strings.Split(hash, ":")
	assert.Len(t, parts, 2, "Hash should have two parts separated by ':'")
	assert.NotEmpty(t, parts[0], "Salt should not be empty")
	assert.NotEmpty(t, parts[1], "Hash should not be empty")
}

func TestHash_DifferentHashes(t *testing.T) {
	key := "arq_test_key_12345678901234567890123456789012"

	// Generate two hashes of the same key
	hash1, err := Hash(key)
	require.NoError(t, err)

	hash2, err := Hash(key)
	require.NoError(t, err)

	// Argon2 generates different salts, so hashes should differ
	assert.NotEqual(t, hash1, hash2)

	// But both should validate against the same key
	assert.True(t, Validate(key, hash1))
	assert.True(t, Validate(key, hash2))
}

func TestValidate(t *testing.T) {
	key := "arq_test_key_12345678901234567890123456789012"
	hash, err := Hash(key)
	require.NoError(t, err)

	tests := []struct {
		name     string
		key      string
		hash     string
		expected bool
	}{
		{
			name:     "valid key and hash",
			key:      key,
			hash:     hash,
			expected: true,
		},
		{
			name:     "invalid key",
			key:      "arq_wrong_key_1234567890123456789012345678",
			hash:     hash,
			expected: false,
		},
		{
			name:     "invalid hash format",
			key:      key,
			hash:     "invalid_hash_format",
			expected: false,
		},
		{
			name:     "empty key",
			key:      "",
			hash:     hash,
			expected: false,
		},
		{
			name:     "empty hash",
			key:      key,
			hash:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Validate(tt.key, tt.hash)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateFormat(t *testing.T) {
	validKey, err := Generate()
	require.NoError(t, err)

	tests := []struct {
		name     string
		key      string
		expected bool
	}{
		{
			name:     "valid generated key",
			key:      validKey,
			expected: true,
		},
		{
			name:     "missing prefix",
			key:      "xxx_1234567890123456789012345678901234567890123",
			expected: false,
		},
		{
			name:     "too short",
			key:      "arq_123",
			expected: false,
		},
		{
			name:     "too long",
			key:      "arq_12345678901234567890123456789012345678901234567890",
			expected: false,
		},
		{
			name:     "empty string",
			key:      "",
			expected: false,
		},
		{
			name:     "only prefix",
			key:      KeyPrefix,
			expected: false,
		},
		{
			name:     "invalid base64url characters",
			key:      "arq_!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateFormat(tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateWithHash(t *testing.T) {
	key, hash, err := GenerateWithHash()
	require.NoError(t, err)
	assert.NotEmpty(t, key)
	assert.NotEmpty(t, hash)

	// Verify format
	assert.True(t, ValidateFormat(key))

	// Verify hash matches key
	assert.True(t, Validate(key, hash))
}

func TestGetCreatedAt(t *testing.T) {
	createdAt := GetCreatedAt()
	assert.NotEmpty(t, createdAt)

	// Should be RFC3339 format (contains T and Z)
	assert.Contains(t, createdAt, "T")
	assert.Contains(t, createdAt, "Z")
}

func TestValidateConstantTime(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		expected bool
	}{
		{
			name:     "equal strings",
			a:        "arq_test123",
			b:        "arq_test123",
			expected: true,
		},
		{
			name:     "different strings",
			a:        "arq_test123",
			b:        "arq_test456",
			expected: false,
		},
		{
			name:     "different lengths",
			a:        "arq_test123",
			b:        "arq_test",
			expected: false,
		},
		{
			name:     "empty strings",
			a:        "",
			b:        "",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateConstantTime(tt.a, tt.b)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestArgon2Parameters(t *testing.T) {
	// Verify hash format and that it validates correctly
	key := "arq_test_key_12345678901234567890123456789012"
	hash, err := Hash(key)
	require.NoError(t, err)

	// Verify hash format: salt:hash
	parts := strings.Split(hash, ":")
	require.Len(t, parts, 2, "Hash should have salt:hash format")

	// Verify the hash validates
	assert.True(t, Validate(key, hash), "Hash should validate against the original key")
}

func TestParseHash(t *testing.T) {
	tests := []struct {
		name      string
		hash      string
		shouldErr bool
	}{
		{
			name:      "valid hash",
			hash:      "c2FsdA:aGFzaA",
			shouldErr: false,
		},
		{
			name:      "missing separator",
			hash:      "invalidseparator",
			shouldErr: true,
		},
		{
			name:      "invalid base64 salt",
			hash:      "!!!:aGFzaA",
			shouldErr: true,
		},
		{
			name:      "invalid base64 hash",
			hash:      "c2FsdA:!!!",
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parseHash(tt.hash)
			if tt.shouldErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func BenchmarkGenerate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := Generate()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHash(b *testing.B) {
	key := "arq_test_key_12345678901234567890123456789012"
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := Hash(key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidate(b *testing.B) {
	key := "arq_test_key_12345678901234567890123456789012"
	hash, _ := Hash(key)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		Validate(key, hash)
	}
}

func BenchmarkValidateFormat(b *testing.B) {
	key, _ := Generate()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ValidateFormat(key)
	}
}
