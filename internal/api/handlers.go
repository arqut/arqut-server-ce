package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/arqut/arqut-server-ce/pkg/api"
	"github.com/arqut/arqut-server-ce/pkg/models"
	"github.com/arqut/arqut-server-ce/pkg/utils"
	"github.com/gofiber/fiber/v2"
	"github.com/skip2/go-qrcode"
)

// Health check endpoint
func (s *Server) handleHealth(c *fiber.Ctx) error {
	return api.SuccessResp(c, fiber.Map{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

// Generate TURN credentials
func (s *Server) handleGenerateCredentials(c *fiber.Ctx) error {
	var req struct {
		PeerType string `json:"peer_type"` // "edge" or "client"
		PeerID   string `json:"peer_id"`
		TTL      int    `json:"ttl,omitempty"` // Optional, defaults to config value
	}

	if err := c.BodyParser(&req); err != nil {
		return api.ErrorBadRequestResp(c, "Invalid request body")
	}

	// Validate required fields
	if req.PeerType == "" || req.PeerID == "" {
		return api.ErrorBadRequestResp(c, "peer_type and peer_id are required")
	}

	// Validate peer type
	if req.PeerType != "edge" && req.PeerType != "client" {
		return api.ErrorBadRequestResp(c, "peer_type must be 'edge' or 'client'")
	}

	// Use configured TTL if not provided
	ttl := req.TTL
	if ttl == 0 {
		ttl = s.turnCfg.Auth.TTLSeconds
	}

	// Generate credentials
	username, password, expiry := utils.GenerateTURNCredentials(req.PeerType, req.PeerID, ttl, s.turnCfg.Auth.Secret)

	return api.SuccessResp(c, fiber.Map{
		"username": username,
		"password": password,
		"ttl":      ttl,
		"expires":  time.Unix(expiry, 0).UTC().Format(time.RFC3339),
	})
}

// Get ICE servers configuration
func (s *Server) handleGetICEServers(c *fiber.Ctx) error {
	// Query parameters for credential generation
	peerType := c.Query("peer_type", "client")
	peerID := c.Query("peer_id", "")

	if peerID == "" {
		return api.ErrorBadRequestResp(c, "peer_id query parameter is required")
	}

	// Generate TURN credentials
	username, password, expiry := utils.GenerateTURNCredentials(peerType, peerID, s.turnCfg.Auth.TTLSeconds, s.turnCfg.Auth.Secret)

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

	return api.SuccessResp(c, fiber.Map{
		"ice_servers": iceServers,
		"expires":     time.Unix(expiry, 0).UTC().Format(time.RFC3339),
	})
}

// List all peers
func (s *Server) handleListPeers(c *fiber.Ctx) error {
	peerType := c.Query("type", "") // Optional filter by type

	var peers []*models.Peer

	if peerType != "" {
		// Filter by type
		peers = s.registry.GetPeersByType(peerType)
	} else {
		// Get all peers
		peers = s.registry.GetAllPeers()
	}

	return api.SuccessResp(c, peers)
}

func (s *Server) handleListServices(c *fiber.Ctx) error {
	services, err := s.storage.ListAllServices()
	if err != nil {
		return api.ErrorInternalServerErrorResp(c, "Failed to list services")
	}

	return api.SuccessResp(c, services)
}

func (s *Server) handleDeleteService(c *fiber.Ctx) error {
	err := s.storage.DeleteEdgeService(c.Params("id"))
	if err != nil {
		return api.ErrorInternalServerErrorResp(c, "Failed to delete service")
	}

	return api.SuccessResp(c, fiber.Map{
		"message": "Service deleted successfully",
	})
}

// Serve the services dashboard HTML page
func (s *Server) handleServicesDashboard(c *fiber.Ctx) error {
	c.Set("Content-Type", "text/html; charset=utf-8")
	return c.Send(servicesHTML)
}

// Get mobile app binding data for QR code
func (s *Server) handleMobileBinding(c *fiber.Ctx) error {
	// Build server URL from request
	scheme := c.Protocol()
	host := c.Hostname()

	// Strip port from hostname if present (some setups include it)
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		// Check if it's not an IPv6 address
		if !strings.Contains(host, "[") {
			host = host[:idx]
		}
	}

	// If running locally, use the machine's local network IP instead of localhost
	isLocal := host == "localhost" || strings.HasPrefix(host, "127.")
	if isLocal {
		if localIP := getLocalIP(); localIP != "" {
			host = localIP
		}
	}

	// Use the configured API port (not c.Port() which returns client's port)
	port := s.cfg.Port
	if port != 80 && port != 443 {
		host = fmt.Sprintf("%s:%d", host, port)
	}

	// API key from auth header (already validated by middleware)
	apiKey := strings.TrimPrefix(c.Get("Authorization"), "Bearer ")

	bindingData := map[string]any{
		"server":  fmt.Sprintf("%s://%s", scheme, host),
		"api_key": apiKey,
		"version": 1,
	}

	// Generate JSON for QR code
	bindingJSON, err := json.Marshal(bindingData)
	if err != nil {
		return api.ErrorInternalServerErrorResp(c, "Failed to generate binding data")
	}

	// Generate QR code PNG
	qrPNG, err := qrcode.Encode(string(bindingJSON), qrcode.Medium, 256)
	if err != nil {
		return api.ErrorInternalServerErrorResp(c, "Failed to generate QR code")
	}

	// Return binding data with QR code as base64 data URL
	return api.SuccessResp(c, fiber.Map{
		"server":   bindingData["server"],
		"api_key":  bindingData["api_key"],
		"version":  bindingData["version"],
		"qr_image": "data:image/png;base64," + base64.StdEncoding.EncodeToString(qrPNG),
	})
}

// Get a specific peer
func (s *Server) handleGetPeer(c *fiber.Ctx) error {
	peerID := c.Params("id")

	peer, exists := s.registry.GetPeer(peerID)
	if !exists {
		return api.ErrorNotFoundResp(c, "Peer not found")
	}

	return api.SuccessResp(c, peerToMap(peer))
}

// Rotate TURN secrets (admin endpoint)
func (s *Server) handleRotateSecrets(c *fiber.Ctx) error {
	var req struct {
		Secret     string   `json:"secret"`
		OldSecrets []string `json:"old_secrets"`
	}

	if err := c.BodyParser(&req); err != nil {
		return api.ErrorBadRequestResp(c, "Invalid request body")
	}

	if req.Secret == "" {
		return api.ErrorBadRequestResp(c, "secret is required")
	}

	// TODO: Call TURN server's UpdateSecrets method
	// This requires passing the TURN server instance to the API server

	s.logger.Info("TURN secrets rotation requested")

	return api.SuccessResp(c, fiber.Map{
		"message": "Secrets rotation endpoint - to be implemented",
	})
}

// Helper functions

// // generateTURNCredentials generates coturn-compatible credentials
// func (s *Server) generateTURNCredentials(peerType, peerID string, ttl int) (username, password string, expiry int64) {
// 	// Calculate expiry timestamp
// 	expiry = time.Now().Unix() + int64(ttl)

// 	// Generate username: peerType:peerID:timestamp
// 	username = fmt.Sprintf("%s:%s:%d", peerType, peerID, expiry)

// 	// Generate password: base64(HMAC-SHA256(secret, username))
// 	mac := hmac.New(sha256.New, []byte(s.turnCfg.Auth.Secret))
// 	mac.Write([]byte(username))
// 	password = base64.StdEncoding.EncodeToString(mac.Sum(nil))

// 	return username, password, expiry
// }

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

// getLocalIP returns the machine's local network IP address (non-loopback)
// Prioritizes common LAN ranges: 192.168.x.x > 10.x.x.x > 172.16-31.x.x
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}

	var candidates []net.IP
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				candidates = append(candidates, ip4)
			}
		}
	}

	// Prioritize 192.168.x.x (typical home/office LAN)
	for _, ip := range candidates {
		if ip[0] == 192 && ip[1] == 168 {
			return ip.String()
		}
	}

	// Then prefer 10.x.x.x but avoid WSL/VPN ranges (10.255.x.x, 10.242.x.x)
	for _, ip := range candidates {
		if ip[0] == 10 && ip[1] != 255 && ip[1] != 242 {
			return ip.String()
		}
	}

	// Then 172.16-31.x.x (private range, but avoid Docker 172.17-19.x.x)
	for _, ip := range candidates {
		if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 && ip[1] != 17 && ip[1] != 18 && ip[1] != 19 {
			return ip.String()
		}
	}

	// Fall back to any IPv4
	if len(candidates) > 0 {
		return candidates[0].String()
	}
	return ""
}
