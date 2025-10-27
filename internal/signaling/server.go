package signaling

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/arqut/arqut-server-ce/internal/config"
	"github.com/arqut/arqut-server-ce/internal/registry"
	"github.com/arqut/arqut-server-ce/internal/storage"
	"github.com/arqut/arqut-server-ce/internal/pkg/models"
	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
)

const (
	writeWait          = 10 * time.Second
	readWait           = 60 * time.Second
	pingInterval       = 30 * time.Second
	maxMessageSize     = 512 * 1024 // 512 KB
	maxBatchSize       = 1000        // Maximum services in batch sync
	channelSendTimeout = 1 * time.Second
)

// WebSocketConn interface for testability
type WebSocketConn interface {
	WriteJSON(v interface{}) error
	WriteMessage(messageType int, data []byte) error
	Close() error
	SetWriteDeadline(t time.Time) error
}

// PeerConnection represents a WebSocket connection for a peer
type PeerConnection struct {
	Peer            *models.Peer
	Conn            WebSocketConn
	Ctx             context.Context
	Cancel          context.CancelFunc
	ClientDataChans map[string]chan *models.SignalingMessage // For synchronous API responses
}

// Server handles WebRTC signaling
type Server struct {
	config      *config.SignalingConfig
	turnConfig  *config.TurnConfig
	logger      *slog.Logger
	registry    *registry.Registry
	storage     storage.Storage
	connections map[string]*PeerConnection
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

// New creates a new signaling server
func New(cfg *config.SignalingConfig, turnCfg *config.TurnConfig, reg *registry.Registry, store storage.Storage, logger *slog.Logger) *Server {
	ctx, cancel := context.WithCancel(context.Background())

	return &Server{
		config:      cfg,
		turnConfig:  turnCfg,
		logger:      logger.With("component", "signaling"),
		registry:    reg,
		storage:     store,
		connections: make(map[string]*PeerConnection),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Start starts the signaling server cleanup routines
func (s *Server) Start() {
	s.logger.Info("Signaling server started")

	// Start stale connection cleanup
	go s.cleanupLoop()
}

// Stop stops the signaling server
func (s *Server) Stop() error {
	s.logger.Info("Stopping signaling server")
	s.cancel()

	// Close all connections
	s.mu.Lock()
	for _, conn := range s.connections {
		if conn.Cancel != nil {
			conn.Cancel()
		}
		if conn.Conn != nil {
			conn.Conn.Close()
		}
	}
	s.mu.Unlock()

	s.logger.Info("Signaling server stopped")
	return nil
}

// RegisterRoutes registers the signaling routes with Fiber
func (s *Server) RegisterRoutes(router fiber.Router) {
	ws := router.Group("/signaling")

	// WebSocket endpoint: /signaling/ws/:type?id=xxx&edgeid=xxx
	ws.Get("/ws/:type", s.wsMiddleware(), s.handleWebSocket())

	// REST endpoint for client connection requests
	ws.Post("/client/connect", s.handleClientConnect())
}

// wsMiddleware validates WebSocket upgrade requests
func (s *Server) wsMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !websocket.IsWebSocketUpgrade(c) {
			return fiber.ErrUpgradeRequired
		}

		// Validate type parameter
		peerType := c.Params("type")
		if peerType != "edge" && peerType != "client" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "type must be 'edge' or 'client'",
			})
		}

		// Validate required query parameters
		if c.Query("id") == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "missing id parameter",
			})
		}

		// For clients, edgeid is required
		if peerType == "client" && c.Query("edgeid") == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "missing edgeid parameter for client",
			})
		}

		return c.Next()
	}
}

// handleWebSocket handles WebSocket connections
func (s *Server) handleWebSocket() fiber.Handler {
	return websocket.New(func(conn *websocket.Conn) {
		peerType := conn.Params("type")
		id := conn.Query("id")
		edgeID := conn.Query("edgeid")
		publicKey := conn.Query("publickey")

		// Create peer
		peer := &models.Peer{
			ID:        id,
			Type:      peerType,
			EdgeID:    edgeID,
			PublicKey: publicKey,
		}

		// Create peer connection
		ctx, cancel := context.WithCancel(s.ctx)
		peerConn := &PeerConnection{
			Peer:   peer,
			Conn:   conn,
			Ctx:    ctx,
			Cancel: cancel,
		}

		// Initialize client data channels for edge peers (for api-connect-request responses)
		if peerType == "edge" {
			peerConn.ClientDataChans = make(map[string]chan *models.SignalingMessage)
		}

		// Add to registry and connections
		s.registry.AddPeer(peer)
		s.mu.Lock()
		// Check for existing connection and close it first
		if oldConn, exists := s.connections[id]; exists {
			s.logger.Warn("Duplicate connection detected, closing old connection",
				"id", id,
				"type", peerType,
			)
			if oldConn.Cancel != nil {
				oldConn.Cancel()
			}
			if oldConn.Conn != nil {
				oldConn.Conn.Close()
			}
		}
		s.connections[id] = peerConn
		s.mu.Unlock()

		s.logger.Info("Peer connected",
			"id", id,
			"type", peerType,
		)

		// Start connection monitoring
		go s.monitorConnection(peerConn)

		// Handle cleanup
		defer func() {
			cancel()
			conn.Close()
			s.registry.RemovePeer(id)
			s.mu.Lock()
			delete(s.connections, id)
			s.mu.Unlock()
			s.logger.Info("Peer disconnected", "id", id, "type", peerType)
		}()

		// Configure connection
		conn.SetReadLimit(maxMessageSize)
		conn.SetReadDeadline(time.Now().Add(readWait))
		conn.SetPongHandler(func(string) error {
			s.registry.UpdateLastPing(id)
			conn.SetReadDeadline(time.Now().Add(readWait))
			return nil
		})

		// Read loop
		for {
			conn.SetReadDeadline(time.Now().Add(readWait))

			var msg models.SignalingMessage
			if err := conn.ReadJSON(&msg); err != nil {
				s.logger.Debug("WebSocket read error", "peer", id, "error", err)
				break
			}

			s.logger.Debug("Received message",
				"from", id,
				"type", msg.Type,
				"to", msg.To,
			)

			// Handle message
			s.handleMessage(peerConn, &msg)
		}
	})
}

// handleMessage processes incoming signaling messages
func (s *Server) handleMessage(from *PeerConnection, msg *models.SignalingMessage) {
	switch msg.Type {
	case "edge:register":
		s.handleEdgeRegistration(from, msg)

	case "connect-request":
		s.handleConnectRequest(from, msg)

	case "api-connect-request":
		s.handleAPIConnectRequest(from, msg)

	case "api-connect-response":
		s.handleAPIConnectResponse(from, msg)

	case "turn-request":
		s.handleTurnRequest(from)

	case MessageTypeServiceSync:
		s.handleServiceSync(from, msg)

	case MessageTypeServiceSyncBatch:
		s.handleServiceSyncBatch(from, msg)

	case MessageTypeServiceListRequest:
		s.handleServiceListRequest(from, msg)

	case "connect-response", "offer", "answer", "ice-candidate":
		s.forwardMessage(msg)

	case "get-peers":
		s.handleGetPeers(from)

	default:
		s.logger.Warn("Unknown message type", "type", msg.Type)
	}
}

// handleEdgeRegistration handles edge device registration
func (s *Server) handleEdgeRegistration(from *PeerConnection, msg *models.SignalingMessage) {
	// Parse registration data
	dataMap, ok := msg.Data.(map[string]interface{})
	if !ok {
		s.sendError(from.Conn, "Invalid registration data")
		return
	}

	edgeID, _ := dataMap["edgeId"].(string)
	if edgeID == "" {
		s.sendError(from.Conn, "edgeId is required")
		return
	}

	// Validate that the edge ID matches the connection ID
	// We no longer support dynamic ID updates to avoid registry inconsistencies
	if from.Peer.ID != edgeID {
		s.logger.Warn("Edge ID mismatch during registration",
			"connection_id", from.Peer.ID,
			"requested_id", edgeID,
		)
		s.sendError(from.Conn, "Edge ID must match connection ID")
		return
	}

	s.logger.Info("Edge registered", "edge_id", edgeID)

	// Send confirmation
	s.sendMessage(from.Conn, &models.SignalingMessage{
		Type: "edge:register-success",
		Data: fiber.Map{
			"edgeId": edgeID,
		},
	})
}

// forwardMessage forwards a message to the target peer
func (s *Server) forwardMessage(msg *models.SignalingMessage) {
	if msg.To == "" {
		s.logger.Warn("Message has no recipient", "type", msg.Type)
		return
	}

	s.mu.RLock()
	targetConn, exists := s.connections[msg.To]
	s.mu.RUnlock()

	if !exists {
		s.logger.Warn("Target peer not found", "to", msg.To)
		return
	}

	if err := s.sendMessage(targetConn.Conn, msg); err != nil {
		s.logger.Error("Failed to forward message",
			"to", msg.To,
			"type", msg.Type,
			"error", err,
		)
	}
}

// handleGetPeers sends the list of connected peers
func (s *Server) handleGetPeers(from *PeerConnection) {
	peers := s.registry.GetAllPeers()

	s.sendMessage(from.Conn, &models.SignalingMessage{
		Type: "peer-list",
		Data: peers,
	})
}

// handleConnectRequest handles peer-to-peer connection requests via WebSocket
func (s *Server) handleConnectRequest(from *PeerConnection, msg *models.SignalingMessage) {
	s.logger.Debug("Handling connect-request",
		"from", from.Peer.ID,
		"to", msg.To,
	)

	// Forward to target peer
	s.forwardMessage(msg)
}

// handleAPIConnectRequest handles API-initiated connection requests from edge
func (s *Server) handleAPIConnectRequest(from *PeerConnection, msg *models.SignalingMessage) {
	// This should not be received from WebSocket clients - only sent TO edge via REST API
	s.logger.Warn("Received api-connect-request from WebSocket (should come from REST API)",
		"from", from.Peer.ID,
	)
}

// handleAPIConnectResponse handles edge response to API connection request
func (s *Server) handleAPIConnectResponse(from *PeerConnection, msg *models.SignalingMessage) {
	s.logger.Debug("Handling api-connect-response",
		"from", from.Peer.ID,
		"to", msg.To,
	)

	// Check if there's a waiting channel for this client
	if ch, exists := from.ClientDataChans[msg.To]; exists {
		select {
		case ch <- msg:
			s.logger.Debug("Sent response to waiting REST API request", "client_id", msg.To)
		case <-time.After(channelSendTimeout):
			s.logger.Error("Timeout sending response to REST API channel - this indicates a bug",
				"client_id", msg.To,
				"timeout", channelSendTimeout)
		}
	} else {
		s.logger.Warn("No waiting channel for api-connect-response", "client_id", msg.To)
	}
}

// handleTurnRequest sends TURN credentials via WebSocket
func (s *Server) handleTurnRequest(from *PeerConnection) {
	s.logger.Debug("Handling turn-request", "peer", from.Peer.ID)

	if s.turnConfig == nil {
		s.sendError(from.Conn, "TURN configuration not available")
		return
	}

	// Generate TURN credentials
	username, password, expiry := s.generateTURNCredentials(
		from.Peer.Type,
		from.Peer.ID,
		s.turnConfig.Auth.TTLSeconds,
	)

	// Build TURN server URLs
	urls := []string{
		fmt.Sprintf("stun:%s:3478", s.turnConfig.PublicIP),
		fmt.Sprintf("turn:%s:3478?transport=udp", s.turnConfig.PublicIP),
		fmt.Sprintf("turn:%s:3478?transport=tcp", s.turnConfig.PublicIP),
	}

	// Add TURNS if TLS is configured
	if s.turnConfig.Ports.TLS > 0 {
		urls = append(urls, fmt.Sprintf("turns:%s:%d?transport=tcp", s.turnConfig.PublicIP, s.turnConfig.Ports.TLS))
	}

	creds := models.TurnCredentials{
		Username: username,
		Password: password,
		TTL:      s.turnConfig.Auth.TTLSeconds,
		Expires:  time.Unix(expiry, 0).UTC().Format(time.RFC3339),
		URLs:     urls,
	}

	s.sendMessage(from.Conn, &models.SignalingMessage{
		Type: "turn-response",
		Data: creds,
	})
}

// generateTURNCredentials generates coturn-compatible credentials
func (s *Server) generateTURNCredentials(peerType, peerID string, ttl int) (username, password string, expiry int64) {
	expiry = time.Now().Unix() + int64(ttl)
	username = fmt.Sprintf("%s:%s:%d", peerType, peerID, expiry)

	mac := hmac.New(sha256.New, []byte(s.turnConfig.Auth.Secret))
	mac.Write([]byte(username))
	password = base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return username, password, expiry
}

// handleClientConnect handles REST API client connection requests
func (s *Server) handleClientConnect() fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req models.ClientConnectRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
			})
		}

		if req.ID == "" || req.EdgeID == "" || req.PublicKey == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "id, edge_id, and public_key are required",
			})
		}

		// Check if edge is online and setup response channel atomically
		s.mu.Lock()
		edgeConn, exists := s.connections[req.EdgeID]
		if !exists {
			s.mu.Unlock()
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": fmt.Sprintf("Edge %s is not online", req.EdgeID),
			})
		}

		// Verify ClientDataChans is initialized (should be for edge peers)
		if edgeConn.ClientDataChans == nil {
			s.mu.Unlock()
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Edge connection not properly initialized",
			})
		}

		// Create response channel for this client
		responseChan := make(chan *models.SignalingMessage, 1)
		edgeConn.ClientDataChans[req.ID] = responseChan
		s.mu.Unlock()

		// Ensure cleanup of channel
		defer func() {
			s.mu.Lock()
			if edgeConn.ClientDataChans != nil {
				close(edgeConn.ClientDataChans[req.ID])
				delete(edgeConn.ClientDataChans, req.ID)
			}
			s.mu.Unlock()
		}()

		// Send connection request to edge
		if err := s.sendMessage(edgeConn.Conn, &models.SignalingMessage{
			Type: "api-connect-request",
			Data: req,
		}); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to send request to edge",
			})
		}

		// Wait for edge response with timeout
		select {
		case msg := <-responseChan:
			// Return the edge response data
			return c.JSON(fiber.Map{
				"success": true,
				"data":    msg.Data,
			})
		case <-time.After(10 * time.Second):
			return c.Status(fiber.StatusRequestTimeout).JSON(fiber.Map{
				"success": false,
				"error":   "Timeout waiting for edge response",
			})
		}
	}
}

// sendMessage sends a message to a WebSocket connection
func (s *Server) sendMessage(conn WebSocketConn, msg *models.SignalingMessage) error {
	conn.SetWriteDeadline(time.Now().Add(writeWait))
	return conn.WriteJSON(msg)
}

// sendError sends an error message to a WebSocket connection
func (s *Server) sendError(conn WebSocketConn, errMsg string) {
	s.sendMessage(conn, &models.SignalingMessage{
		Type: "error",
		Data: fiber.Map{"error": errMsg},
	})
}

// monitorConnection monitors a peer connection and sends pings
func (s *Server) monitorConnection(peerConn *PeerConnection) {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-peerConn.Ctx.Done():
			return
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			peerConn.Conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := peerConn.Conn.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
				s.logger.Warn("Failed to send ping", "peer", peerConn.Peer.ID, "error", err)
				if peerConn.Cancel != nil {
					peerConn.Cancel()
				}
				return
			}
		}
	}
}

// cleanupLoop periodically removes stale connections
func (s *Server) cleanupLoop() {
	ticker := time.NewTicker(s.config.SessionTimeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			removed := s.registry.CleanupStale(s.config.SessionTimeout)
			if len(removed) > 0 {
				s.logger.Info("Cleaned up stale peers", "count", len(removed))

				// Remove from connections
				s.mu.Lock()
				for _, id := range removed {
					if conn, exists := s.connections[id]; exists {
						if conn.Cancel != nil {
							conn.Cancel()
						}
						delete(s.connections, id)
					}
				}
				s.mu.Unlock()
			}
		}
	}
}
