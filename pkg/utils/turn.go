package utils

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"
)

// generateTURNCredentials generates coturn-compatible credentials
func GenerateTURNCredentials(peerType, peerID string, ttl int, secret string) (username, password string, expiry int64) {
	// Calculate expiry timestamp
	expiry = time.Now().Unix() + int64(ttl)

	// Generate username: peerType:peerID:timestamp
	username = fmt.Sprintf("%s:%s:%d", peerType, peerID, expiry)

	// Generate password: base64(HMAC-SHA256(secret, username))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(username))
	password = base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return username, password, expiry
}
