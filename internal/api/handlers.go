package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/arqut/arqut-server-ce/pkg/models"
	"github.com/gofiber/fiber/v2"
)

// Health check endpoint
func (s *Server) handleHealth(c *fiber.Ctx) error {
	return c.JSON(MakeResponse(fiber.Map{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	}, nil, ""))
}

// Generate TURN credentials
func (s *Server) handleGenerateCredentials(c *fiber.Ctx) error {
	var req struct {
		PeerType string `json:"peer_type"` // "edge" or "client"
		PeerID   string `json:"peer_id"`
		TTL      int    `json:"ttl,omitempty"` // Optional, defaults to config value
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(
			MakeResponse(nil, "Invalid request body", ""))
	}

	// Validate required fields
	if req.PeerType == "" || req.PeerID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(
			MakeResponse(nil, "peer_type and peer_id are required", ""))
	}

	// Validate peer type
	if req.PeerType != "edge" && req.PeerType != "client" {
		return c.Status(fiber.StatusBadRequest).JSON(
			MakeResponse(nil, "peer_type must be 'edge' or 'client'", ""))
	}

	// Use configured TTL if not provided
	ttl := req.TTL
	if ttl == 0 {
		ttl = s.turnCfg.Auth.TTLSeconds
	}

	// Generate credentials
	username, password, expiry := s.generateTURNCredentials(req.PeerType, req.PeerID, ttl)

	return c.JSON(MakeResponse(fiber.Map{
		"username": username,
		"password": password,
		"ttl":      ttl,
		"expires":  time.Unix(expiry, 0).UTC().Format(time.RFC3339),
	}, nil, ""))
}

// Get ICE servers configuration
func (s *Server) handleGetICEServers(c *fiber.Ctx) error {
	// Query parameters for credential generation
	peerType := c.Query("peer_type", "client")
	peerID := c.Query("peer_id", "")

	if peerID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(
			MakeResponse(nil, "peer_id query parameter is required", ""))
	}

	// Generate TURN credentials
	username, password, expiry := s.generateTURNCredentials(peerType, peerID, s.turnCfg.Auth.TTLSeconds)

	// Build ICE servers list
	iceServers := []fiber.Map{
		{
			"urls": []string{
				fmt.Sprintf("stun:%s:3478", s.turnCfg.PublicIP),
			},
		},
		{
			"urls": []string{
				fmt.Sprintf("turn:%s:3478?transport=udp", s.turnCfg.PublicIP),
				fmt.Sprintf("turn:%s:3478?transport=tcp", s.turnCfg.PublicIP),
			},
			"username":   username,
			"credential": password,
		},
	}

	// Add TURNS if TLS is configured
	if s.turnCfg.Ports.TLS > 0 {
		iceServers = append(iceServers, fiber.Map{
			"urls": []string{
				fmt.Sprintf("turns:%s:%d?transport=tcp", s.turnCfg.PublicIP, s.turnCfg.Ports.TLS),
			},
			"username":   username,
			"credential": password,
		})
	}

	return c.JSON(MakeResponse(fiber.Map{
		"ice_servers": iceServers,
		"expires":     time.Unix(expiry, 0).UTC().Format(time.RFC3339),
	}, nil, ""))
}

// List all peers
func (s *Server) handleListPeers(c *fiber.Ctx) error {
	peerType := c.Query("type", "") // Optional filter by type

	var peers []fiber.Map

	if peerType != "" {
		// Filter by type
		filteredPeers := s.registry.GetPeersByType(peerType)
		for _, peer := range filteredPeers {
			peers = append(peers, peerToMap(peer))
		}
	} else {
		// Get all peers
		allPeers := s.registry.GetAllPeers()
		for _, peer := range allPeers {
			peers = append(peers, peerToMap(peer))
		}
	}

	return c.JSON(MakeResponse(fiber.Map{
		"peers": peers,
		"count": len(peers),
	}, nil, ""))
}

// Get a specific peer
func (s *Server) handleGetPeer(c *fiber.Ctx) error {
	peerID := c.Params("id")

	peer, exists := s.registry.GetPeer(peerID)
	if !exists {
		return c.Status(fiber.StatusNotFound).JSON(
			MakeResponse(nil, "Peer not found", ""))
	}

	return c.JSON(MakeResponse(peerToMap(peer), nil, ""))
}

// Rotate TURN secrets (admin endpoint)
func (s *Server) handleRotateSecrets(c *fiber.Ctx) error {
	var req struct {
		Secret     string   `json:"secret"`
		OldSecrets []string `json:"old_secrets"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(
			MakeResponse(nil, "Invalid request body", ""))
	}

	if req.Secret == "" {
		return c.Status(fiber.StatusBadRequest).JSON(
			MakeResponse(nil, "secret is required", ""))
	}

	// TODO: Call TURN server's UpdateSecrets method
	// This requires passing the TURN server instance to the API server

	s.logger.Info("TURN secrets rotation requested")

	return c.JSON(MakeResponse(nil, nil, "Secrets rotation endpoint - to be implemented"))
}

// Helper functions

// generateTURNCredentials generates coturn-compatible credentials
func (s *Server) generateTURNCredentials(peerType, peerID string, ttl int) (username, password string, expiry int64) {
	// Calculate expiry timestamp
	expiry = time.Now().Unix() + int64(ttl)

	// Generate username: peerType:peerID:timestamp
	username = fmt.Sprintf("%s:%s:%d", peerType, peerID, expiry)

	// Generate password: base64(HMAC-SHA256(secret, username))
	mac := hmac.New(sha256.New, []byte(s.turnCfg.Auth.Secret))
	mac.Write([]byte(username))
	password = base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return username, password, expiry
}

// peerToMap converts a Peer to a map for JSON response
func peerToMap(peer *models.Peer) fiber.Map {
	return fiber.Map{
		"id":         peer.ID,
		"type":       peer.Type,
		"account_id": peer.AccountID,
		"public_key": peer.PublicKey,
		"edge_id":    peer.EdgeID,
		"connected":  peer.Connected,
		"last_ping":  peer.LastPing.UTC().Format(time.RFC3339),
		"created_at": peer.CreatedAt.UTC().Format(time.RFC3339),
	}
}
