package signaling

import (
	"crypto/rand"
	"math/big"
)

const (
	// serviceIDLength is the length of generated service IDs
	serviceIDLength = 16
	// alphabets contains alphanumeric characters for ID generation
	alphabets = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// generateServiceID generates a random service ID using cryptographically secure random bytes
func generateServiceID() (string, error) {
	id := make([]byte, serviceIDLength)

	for i := 0; i < serviceIDLength; i++ {
		char, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabets))))
		if err != nil {
			return "", err
		}
		id[i] = alphabets[char.Int64()]
	}

	return string(id), nil
}
