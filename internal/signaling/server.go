package signaling

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/arqut/arqut-server-ce/internal/config"
	"github.com/arqut/arqut-server-ce/internal/registry"
	"github.com/arqut/arqut-server-ce/pkg/models"
	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
)

const (
	writeWait      = 10 * time.Second
	readWait       = 60 * time.Second
	pingInterval   = 30 * time.Second
	maxMessageSize = 512 * 1024 // 512 KB
)

// PeerConnection represents a WebSocket connection for a peer
type PeerConnection struct {
	Peer   *models.Peer
	Conn   *websocket.Conn
	Ctx    context.Context
	Cancel context.CancelFunc
}

// Server handles WebRTC signaling
type Server struct {
	config      *config.SignalingConfig
	logger      *slog.Logger
	registry    *registry.Registry
	connections map[string]*PeerConnection
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

// New creates a new signaling server
func New(cfg *config.SignalingConfig, reg *registry.Registry, logger *slog.Logger) *Server {
	ctx, cancel := context.WithCancel(context.Background())

	return &Server{
		config:      cfg,
		logger:      logger.With("component", "signaling"),
		registry:    reg,
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

		// Add to registry and connections
		s.registry.AddPeer(peer)
		s.mu.Lock()
		s.connections[id] = peerConn
		s.mu.Unlock()

		s.logger.Info("Peer connected",
			"id", id,
			"type", peerType,
			"edge_id", edgeID,
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

	case "offer", "answer", "ice-candidate":
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

	// Update peer info
	from.Peer.ID = edgeID

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

		// Check if edge is online
		s.mu.RLock()
		edgeConn, exists := s.connections[req.EdgeID]
		s.mu.RUnlock()

		if !exists {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": fmt.Sprintf("Edge %s is not online", req.EdgeID),
			})
		}

		// Send connection request to edge
		if err := s.sendMessage(edgeConn.Conn, &models.SignalingMessage{
			Type: "api-connect-request",
			Data: req,
		}); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to send request to edge",
			})
		}

		return c.JSON(fiber.Map{
			"status": "request sent to edge",
		})
	}
}

// sendMessage sends a message to a WebSocket connection
func (s *Server) sendMessage(conn *websocket.Conn, msg *models.SignalingMessage) error {
	conn.SetWriteDeadline(time.Now().Add(writeWait))
	return conn.WriteJSON(msg)
}

// sendError sends an error message to a WebSocket connection
func (s *Server) sendError(conn *websocket.Conn, errMsg string) {
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
