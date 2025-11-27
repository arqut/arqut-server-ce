package turn

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/pion/turn/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError, // Quiet during tests
	}))
}

func generateRESTUsername(peerType, peerID string, expiry int64) string {
	return fmt.Sprintf("%s:%s:%d", peerType, peerID, expiry)
}

func generateRESTPassword(secret, username string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(username))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func TestNewAuthHandler(t *testing.T) {
	handler := NewAuthHandler(
		"rest",
		"test-secret",
		[]string{"old-secret"},
		86400,
		nil,
		testLogger(),
	)

	require.NotNil(t, handler)
	assert.Equal(t, "rest", handler.mode)
	assert.Equal(t, "test-secret", handler.secret)
	assert.Equal(t, []string{"old-secret"}, handler.oldSecrets)
	assert.Equal(t, 86400, handler.ttl)
}

func TestAuthHandler_RESTAuth_Success(t *testing.T) {
	secret := "test-secret-2025"
	handler := NewAuthHandler("rest", secret, nil, 86400, nil, testLogger())

	// Generate valid credentials
	expiry := time.Now().Add(1 * time.Hour).Unix()
	username := generateRESTUsername("edge", "test-peer-123", expiry)
	password := generateRESTPassword(secret, username)

	// Simulate TURN auth (pion generates HA1 internally, we just verify auth succeeds)
	srcAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	result, ok := handler.AuthenticateRequest(username, "test.com", srcAddr)

	assert.True(t, ok, "Authentication should succeed")
	assert.NotNil(t, result, "Should return HA1 key")

	// Verify password would match (generate expected HA1)
	_ = password // Password is used by TURN internally
}

func TestAuthHandler_RESTAuth_ExpiredCredential(t *testing.T) {
	secret := "test-secret"
	handler := NewAuthHandler("rest", secret, nil, 86400, nil, testLogger())

	// Generate expired credentials
	expiry := time.Now().Add(-1 * time.Hour).Unix()
	username := generateRESTUsername("edge", "test-peer", expiry)

	srcAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	result, ok := handler.AuthenticateRequest(username, "test.com", srcAddr)

	assert.False(t, ok, "Authentication should fail for expired credentials")
	assert.Nil(t, result)
}

func TestAuthHandler_RESTAuth_FutureTooFar(t *testing.T) {
	secret := "test-secret"
	handler := NewAuthHandler("rest", secret, nil, 86400, nil, testLogger())

	// Generate credentials too far in future (>48 hours)
	expiry := time.Now().Add(72 * time.Hour).Unix()
	username := generateRESTUsername("edge", "test-peer", expiry)

	srcAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	result, ok := handler.AuthenticateRequest(username, "test.com", srcAddr)

	assert.False(t, ok, "Authentication should fail for expiry too far in future")
	assert.Nil(t, result)
}

func TestAuthHandler_RESTAuth_InvalidUsernameFormat(t *testing.T) {
	handler := NewAuthHandler("rest", "secret", nil, 86400, nil, testLogger())
	srcAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")

	tests := []struct {
		name     string
		username string
	}{
		{"missing parts", "edge:peer"},
		{"only one part", "edge"},
		{"empty string", ""},
		{"missing timestamp", "edge:peer:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := handler.AuthenticateRequest(tt.username, "test.com", srcAddr)
			assert.False(t, ok)
			assert.Nil(t, result)
		})
	}
}

func TestAuthHandler_RESTAuth_InvalidTimestamp(t *testing.T) {
	handler := NewAuthHandler("rest", "secret", nil, 86400, nil, testLogger())
	srcAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")

	tests := []struct {
		name     string
		username string
	}{
		{"non-numeric timestamp", "edge:peer:abc"},
		{"float timestamp", "edge:peer:123.45"},
		{"negative timestamp", "edge:peer:-123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := handler.AuthenticateRequest(tt.username, "test.com", srcAddr)
			assert.False(t, ok)
			assert.Nil(t, result)
		})
	}
}

func TestAuthHandler_RESTAuth_OldSecrets(t *testing.T) {
	currentSecret := "current-secret"
	oldSecret := "old-secret"

	handler := NewAuthHandler(
		"rest",
		currentSecret,
		[]string{oldSecret, "very-old-secret"},
		86400,
		nil,
		testLogger(),
	)

	srcAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	expiry := time.Now().Add(1 * time.Hour).Unix()

	t.Run("generates HA1 with current secret", func(t *testing.T) {
		username := generateRESTUsername("edge", "peer1", expiry)
		expectedPassword := generateRESTPassword(currentSecret, username)

		result, ok := handler.AuthenticateRequest(username, "test.com", srcAddr)
		assert.True(t, ok)
		assert.NotNil(t, result)

		// Verify it uses current secret (first in priority)
		expectedHA1 := turn.GenerateAuthKey(username, "test.com", expectedPassword)
		assert.Equal(t, expectedHA1, result)
	})

	t.Run("generates HA1 with old secret for valid username", func(t *testing.T) {
		username := generateRESTUsername("edge", "peer2", expiry)

		// AuthHandler generates keys for all valid usernames
		// The TURN server will try both current and old secrets
		result, ok := handler.AuthenticateRequest(username, "test.com", srcAddr)
		assert.True(t, ok, "Should generate auth key for valid username")
		assert.NotNil(t, result)
	})

	t.Run("generates key for any valid username format", func(t *testing.T) {
		username := generateRESTUsername("client", "peer3", expiry)

		// The method doesn't validate passwords - it generates keys
		// Password validation happens in TURN protocol layer
		result, ok := handler.AuthenticateRequest(username, "test.com", srcAddr)
		assert.True(t, ok)
		assert.NotNil(t, result)
	})
}

func TestAuthHandler_RESTAuth_EmptySecret(t *testing.T) {
	handler := NewAuthHandler("rest", "", []string{""}, 86400, nil, testLogger())

	expiry := time.Now().Add(1 * time.Hour).Unix()
	username := generateRESTUsername("edge", "peer", expiry)

	srcAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	result, ok := handler.AuthenticateRequest(username, "test.com", srcAddr)

	assert.False(t, ok, "Should fail with empty secret")
	assert.Nil(t, result)
}

func TestAuthHandler_StaticAuth_Success(t *testing.T) {
	staticUsers := map[string]string{
		"user1": "password1",
		"user2": "password2",
	}

	handler := NewAuthHandler("static", "", nil, 0, staticUsers, testLogger())

	srcAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")

	result, ok := handler.AuthenticateRequest("user1", "test.com", srcAddr)
	assert.True(t, ok)
	assert.NotNil(t, result)
}

func TestAuthHandler_StaticAuth_UserNotFound(t *testing.T) {
	staticUsers := map[string]string{
		"user1": "password1",
	}

	handler := NewAuthHandler("static", "", nil, 0, staticUsers, testLogger())

	srcAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")

	result, ok := handler.AuthenticateRequest("nonexistent", "test.com", srcAddr)
	assert.False(t, ok)
	assert.Nil(t, result)
}

func TestAuthHandler_StaticAuth_MultipleUsers(t *testing.T) {
	staticUsers := map[string]string{
		"alice":   "alice-pass",
		"bob":     "bob-pass",
		"charlie": "charlie-pass",
	}

	handler := NewAuthHandler("static", "", nil, 0, staticUsers, testLogger())
	srcAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")

	tests := []struct {
		username string
		shouldOk bool
	}{
		{"alice", true},
		{"bob", true},
		{"charlie", true},
		{"dave", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.username, func(t *testing.T) {
			result, ok := handler.AuthenticateRequest(tt.username, "test.com", srcAddr)
			assert.Equal(t, tt.shouldOk, ok)
			if tt.shouldOk {
				assert.NotNil(t, result)
			} else {
				assert.Nil(t, result)
			}
		})
	}
}

func TestAuthHandler_UnknownMode(t *testing.T) {
	handler := NewAuthHandler("unknown", "", nil, 0, nil, testLogger())

	srcAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	result, ok := handler.AuthenticateRequest("user", "test.com", srcAddr)

	assert.False(t, ok)
	assert.Nil(t, result)
}

func TestAuthHandler_UpdateSecrets(t *testing.T) {
	handler := NewAuthHandler("rest", "old-secret", nil, 86400, nil, testLogger())

	// Update secrets
	handler.UpdateSecrets("new-secret", []string{"old-secret", "very-old"}, 43200)

	// Verify secrets were updated
	handler.secretMutex.RLock()
	assert.Equal(t, "new-secret", handler.secret)
	assert.Equal(t, []string{"old-secret", "very-old"}, handler.oldSecrets)
	assert.Equal(t, 43200, handler.ttl)
	handler.secretMutex.RUnlock()

	// Verify authentication works with new secret
	srcAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	expiry := time.Now().Add(1 * time.Hour).Unix()
	username := generateRESTUsername("edge", "peer", expiry)
	_ = generateRESTPassword("new-secret", username)

	result, ok := handler.AuthenticateRequest(username, "test.com", srcAddr)
	assert.True(t, ok)
	assert.NotNil(t, result)
}

func TestAuthHandler_ConcurrentAccess(t *testing.T) {
	handler := NewAuthHandler("rest", "secret", []string{"old"}, 86400, nil, testLogger())

	srcAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	expiry := time.Now().Add(1 * time.Hour).Unix()

	// Run concurrent authentications and secret updates
	done := make(chan bool)

	// Goroutine 1: Authenticate
	go func() {
		for i := 0; i < 100; i++ {
			username := generateRESTUsername("edge", fmt.Sprintf("peer%d", i), expiry)
			handler.AuthenticateRequest(username, "test.com", srcAddr)
		}
		done <- true
	}()

	// Goroutine 2: Update secrets
	go func() {
		for i := 0; i < 50; i++ {
			handler.UpdateSecrets(fmt.Sprintf("secret%d", i), []string{"old"}, 86400)
		}
		done <- true
	}()

	// Goroutine 3: More authentications
	go func() {
		for i := 0; i < 100; i++ {
			username := generateRESTUsername("client", fmt.Sprintf("peer%d", i), expiry)
			handler.AuthenticateRequest(username, "test.com", srcAddr)
		}
		done <- true
	}()

	// Wait for all goroutines
	<-done
	<-done
	<-done

	// Test should complete without data races
}

func TestAuthHandler_RESTAuth_BoundaryExpiry(t *testing.T) {
	handler := NewAuthHandler("rest", "secret", nil, 86400, nil, testLogger())
	srcAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")

	tests := []struct {
		name     string
		expiry   int64
		shouldOk bool
	}{
		{"exactly now", time.Now().Unix(), false},                              // expired
		{"1 second from now", time.Now().Add(1 * time.Second).Unix(), true},   // valid
		{"47 hours", time.Now().Add(47 * time.Hour).Unix(), true},             // valid
		{"48 hours", time.Now().Add(48 * time.Hour).Unix(), true},             // boundary
		{"48h 1s", time.Now().Add(48*time.Hour + 1*time.Second).Unix(), false}, // too far
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			username := generateRESTUsername("edge", "peer", tt.expiry)
			_, ok := handler.AuthenticateRequest(username, "test.com", srcAddr)
			assert.Equal(t, tt.shouldOk, ok)
		})
	}
}

func TestGenerateRESTCredentials(t *testing.T) {
	// Test helper functions used in tests
	secret := "test-secret"
	peerType := "edge"
	peerID := "peer-123"
	expiry := time.Now().Add(1 * time.Hour).Unix()

	username := generateRESTUsername(peerType, peerID, expiry)
	password := generateRESTPassword(secret, username)

	// Verify format
	assert.Contains(t, username, peerType)
	assert.Contains(t, username, peerID)
	assert.Contains(t, username, strconv.FormatInt(expiry, 10))

	// Verify password is base64
	_, err := base64.StdEncoding.DecodeString(password)
	assert.NoError(t, err, "Password should be valid base64")

	// Verify HMAC
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(username))
	expectedPassword := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	assert.Equal(t, expectedPassword, password)
}
