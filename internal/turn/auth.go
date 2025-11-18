package turn

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pion/turn/v4"
)

// AuthHandler manages TURN authentication
type AuthHandler struct {
	mode   string
	logger *slog.Logger

	// REST auth (mutex-protected for secret rotation)
	secretMutex sync.RWMutex
	secret      string
	oldSecrets  []string
	ttl         int

	// Static auth
	staticUsers map[string]string // username -> password
}

// NewAuthHandler creates a new authentication handler
func NewAuthHandler(mode string, secret string, oldSecrets []string, ttl int, staticUsers map[string]string, logger *slog.Logger) *AuthHandler {
	return &AuthHandler{
		mode:        mode,
		logger:      logger,
		secret:      secret,
		oldSecrets:  oldSecrets,
		ttl:         ttl,
		staticUsers: staticUsers,
	}
}

// Authenticate implements turn.AuthHandler interface
func (h *AuthHandler) AuthenticateRequest(username, realm string, srcAddr net.Addr) ([]byte, bool) {
	switch h.mode {
	case "rest":
		return h.restAuth(username, realm, srcAddr)
	case "static":
		return h.staticAuth(username, realm, srcAddr)
	default:
		h.logger.Error("Unknown auth mode", "mode", h.mode)
		return nil, false
	}
}

// restAuth handles REST-style authentication (coturn-compatible)
// Username format: <peerType>:<peerID>:<unix_expiry>
// Password: base64(HMAC-SHA256(secret, username))
func (h *AuthHandler) restAuth(username, realm string, srcAddr net.Addr) ([]byte, bool) {
	h.logger.Debug("REST auth attempt",
		"username", username,
		"realm", realm,
		"addr", srcAddr.String(),
	)

	// Parse username: <peerType>:<peerID>:<unix_expiry>
	parts := strings.SplitN(username, ":", 3)
	if len(parts) != 3 {
		h.logger.Warn("REST auth failed: invalid username format",
			"username", username,
			"expected", "peerType:peerID:timestamp",
		)
		return nil, false
	}

	peerType := parts[0]
	peerID := parts[1]
	timestampStr := parts[2]

	// Parse expiry timestamp
	expiry, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		h.logger.Warn("REST auth failed: invalid expiry timestamp",
			"username", username,
			"error", err,
		)
		return nil, false
	}

	// Check if credential has expired
	expiryTime := time.Unix(expiry, 0)
	if expiryTime.Before(time.Now()) {
		h.logger.Warn("REST auth failed: credential expired",
			"username", username,
			"expired_at", expiryTime,
		)
		return nil, false
	}

	// Check if expiry is too far in the future (prevent abuse)
	maxFutureTime := time.Now().Add(48 * time.Hour)
	if expiryTime.After(maxFutureTime) {
		h.logger.Warn("REST auth failed: expiry too far in future",
			"username", username,
			"expiry", expiryTime,
		)
		return nil, false
	}

	// Try current and old secrets
	h.secretMutex.RLock()
	currentSecret := h.secret
	oldSecrets := h.oldSecrets
	h.secretMutex.RUnlock()

	secrets := []string{currentSecret}
	secrets = append(secrets, oldSecrets...)

	for _, secret := range secrets {
		if secret == "" {
			continue
		}

		// Generate expected password: base64(HMAC-SHA256(secret, username))
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(username))
		expectedPassword := base64.StdEncoding.EncodeToString(mac.Sum(nil))

		// Generate HA1: MD5(username:realm:password)
		ha1 := turn.GenerateAuthKey(username, realm, expectedPassword)

		h.logger.Info("REST auth successful",
			"username", username,
			"peer_type", peerType,
			"peer_id", peerID,
			"expires", expiryTime,
			"addr", srcAddr.String(),
		)
		return ha1, true
	}

	h.logger.Warn("REST auth failed: no valid secret",
		"username", username,
	)
	return nil, false
}

// staticAuth handles static user authentication
func (h *AuthHandler) staticAuth(username, realm string, srcAddr net.Addr) ([]byte, bool) {
	h.logger.Debug("Static auth attempt",
		"username", username,
		"realm", realm,
		"addr", srcAddr.String(),
	)

	password, exists := h.staticUsers[username]
	if !exists {
		h.logger.Warn("Static auth failed: user not found",
			"username", username,
		)
		return nil, false
	}

	h.logger.Info("Static auth successful",
		"username", username,
		"addr", srcAddr.String(),
	)

	return turn.GenerateAuthKey(username, realm, password), true
}

// UpdateSecrets updates the REST auth secrets (for hot rotation)
func (h *AuthHandler) UpdateSecrets(current string, old []string, ttl int) {
	h.secretMutex.Lock()
	defer h.secretMutex.Unlock()

	h.secret = current
	h.oldSecrets = old
	h.ttl = ttl

	h.logger.Info("Secrets updated", "ttl", ttl)
}
