package signaling

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/arqut/arqut-server-ce/pkg/config"
	"github.com/arqut/arqut-server-ce/pkg/logger"
	"github.com/arqut/arqut-server-ce/pkg/models"
	"github.com/arqut/arqut-server-ce/pkg/registry"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func setupTestServer(t *testing.T) (*Server, *registry.Registry) {
	cfg := &config.SignalingConfig{
		MaxPeersPerRoom: 10,
		SessionTimeout:  300 * time.Second,
	}

	turnCfg := &config.TurnConfig{
		PublicIP: "203.0.113.1",
		Ports: config.TurnPorts{
			UDP: 3478,
			TCP: 3478,
			TLS: 5349,
		},
		Auth: config.AuthConfig{
			Mode:       "rest",
			Secret:     "test-secret-123",
			TTLSeconds: 86400,
		},
	}

	log := logger.New(logger.Config{
		Level:  "error", // Suppress logs in tests
		Format: "text",
	})

	reg := registry.New()
	server := New(cfg, turnCfg, reg, nil, log.Logger)

	return server, reg
}

func TestNew(t *testing.T) {
	server, _ := setupTestServer(t)
	assert.NotNil(t, server)
	assert.NotNil(t, server.config)
	assert.NotNil(t, server.turnConfig)
	assert.NotNil(t, server.registry)
	assert.NotNil(t, server.connections)
}

func TestGenerateTURNCredentials(t *testing.T) {
	server, _ := setupTestServer(t)

	tests := []struct {
		name     string
		peerType string
		peerID   string
		ttl      int
	}{
		{
			name:     "edge peer credentials",
			peerType: "edge",
			peerID:   "edge-1",
			ttl:      3600,
		},
		{
			name:     "client peer credentials",
			peerType: "client",
			peerID:   "client-123",
			ttl:      7200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			username, password, expiry := server.generateTURNCredentials(tt.peerType, tt.peerID, tt.ttl)

			// Verify username format: peerType:peerID:timestamp
			parts := strings.Split(username, ":")
			assert.Len(t, parts, 3, "Username should have 3 parts")
			assert.Equal(t, tt.peerType, parts[0])
			assert.Equal(t, tt.peerID, parts[1])

			// Verify expiry is in the future
			now := time.Now().Unix()
			assert.Greater(t, expiry, now)
			assert.LessOrEqual(t, expiry, now+int64(tt.ttl)+1) // Allow 1 second variance

			// Verify password is base64 encoded and non-empty
			assert.NotEmpty(t, password)
			assert.Greater(t, len(password), 20) // HMAC-SHA256 base64 should be longer

			// Verify credentials are consistent for same timestamp
			username2, password2, expiry2 := server.generateTURNCredentials(tt.peerType, tt.peerID, tt.ttl)
			assert.Equal(t, username, username2)
			assert.Equal(t, password, password2)
			assert.Equal(t, expiry, expiry2)
		})
	}
}

func TestGenerateTURNCredentials_DifferentSecrets(t *testing.T) {
	// Create two servers with different secrets
	cfg := &config.SignalingConfig{
		MaxPeersPerRoom: 10,
		SessionTimeout:  300 * time.Second,
	}

	turnCfg1 := &config.TurnConfig{
		PublicIP: "203.0.113.1",
		Auth: config.AuthConfig{
			Secret:     "secret-1",
			TTLSeconds: 86400,
		},
	}

	turnCfg2 := &config.TurnConfig{
		PublicIP: "203.0.113.1",
		Auth: config.AuthConfig{
			Secret:     "secret-2",
			TTLSeconds: 86400,
		},
	}

	log := logger.New(logger.Config{Level: "error", Format: "text"})
	reg := registry.New()

	server1 := New(cfg, turnCfg1, reg, nil, log.Logger)
	server2 := New(cfg, turnCfg2, reg, nil, log.Logger)

	// Generate credentials with same parameters but different secrets
	_, password1, _ := server1.generateTURNCredentials("client", "test", 3600)
	_, password2, _ := server2.generateTURNCredentials("client", "test", 3600)

	// Passwords should be different
	assert.NotEqual(t, password1, password2, "Different secrets should produce different passwords")
}

func TestHandleAPIConnectResponse(t *testing.T) {
	server, reg := setupTestServer(t)

	// Create edge peer with response channels
	edgePeer := &models.Peer{ID: "edge-1", Type: "edge"}
	reg.AddPeer(edgePeer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	edgeConn := &PeerConnection{
		Peer:            edgePeer,
		Conn:            nil,
		Ctx:             ctx,
		Cancel:          cancel,
		ClientDataChans: make(map[string]chan *models.SignalingMessage),
	}

	// Create response channel for client
	clientID := "client-123"
	responseChan := make(chan *models.SignalingMessage, 1)
	edgeConn.ClientDataChans[clientID] = responseChan

	server.mu.Lock()
	server.connections["edge-1"] = edgeConn
	server.mu.Unlock()

	// Test successful response delivery
	t.Run("successful response delivery", func(t *testing.T) {
		responseMsg := &models.SignalingMessage{
			Type: "api-connect-response",
			From: "edge-1",
			To:   clientID,
			Data: map[string]interface{}{
				"status": "connected",
				"ip":     "10.0.0.1",
			},
		}

		// Handle the response
		server.handleAPIConnectResponse(edgeConn, responseMsg)

		// Verify response was delivered to channel
		select {
		case receivedMsg := <-responseChan:
			assert.Equal(t, responseMsg, receivedMsg)
		case <-time.After(100 * time.Millisecond):
			t.Fatal("Response not delivered to channel")
		}
	})

	// Test response to non-existent channel
	t.Run("response to non-existent channel", func(t *testing.T) {
		responseMsg := &models.SignalingMessage{
			Type: "api-connect-response",
			From: "edge-1",
			To:   "non-existent-client",
			Data: map[string]interface{}{},
		}

		// Should not panic, just log warning
		server.handleAPIConnectResponse(edgeConn, responseMsg)
	})
}

func TestResponseChannelCleanup(t *testing.T) {
	server, reg := setupTestServer(t)

	// Create edge peer
	edgePeer := &models.Peer{ID: "edge-1", Type: "edge"}
	reg.AddPeer(edgePeer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	edgeConn := &PeerConnection{
		Peer:            edgePeer,
		Conn:            nil,
		Ctx:             ctx,
		Cancel:          cancel,
		ClientDataChans: make(map[string]chan *models.SignalingMessage),
	}

	server.mu.Lock()
	server.connections["edge-1"] = edgeConn
	server.mu.Unlock()

	clientID := "client-test"

	// Create and cleanup channel
	responseChan := make(chan *models.SignalingMessage, 1)
	edgeConn.ClientDataChans[clientID] = responseChan

	// Verify channel exists
	_, exists := edgeConn.ClientDataChans[clientID]
	assert.True(t, exists)

	// Simulate cleanup (what defer does in handleClientConnect)
	close(edgeConn.ClientDataChans[clientID])
	delete(edgeConn.ClientDataChans, clientID)

	// Verify channel was cleaned up
	_, exists = edgeConn.ClientDataChans[clientID]
	assert.False(t, exists)
}

func TestClientDataChansInitialization(t *testing.T) {
	_, reg := setupTestServer(t)

	// Test that edge peers get ClientDataChans initialized
	edgePeer := &models.Peer{ID: "edge-1", Type: "edge"}
	reg.AddPeer(edgePeer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Simulate what handleWebSocket does for edge peers
	edgeConn := &PeerConnection{
		Peer:   edgePeer,
		Conn:   nil,
		Ctx:    ctx,
		Cancel: cancel,
	}

	// Edge peers should have ClientDataChans initialized
	peerType := "edge"
	if peerType == "edge" {
		edgeConn.ClientDataChans = make(map[string]chan *models.SignalingMessage)
	}

	assert.NotNil(t, edgeConn.ClientDataChans)

	// Test that client peers don't get ClientDataChans
	clientPeer := &models.Peer{ID: "client-1", Type: "client"}
	clientConn := &PeerConnection{
		Peer:   clientPeer,
		Conn:   nil,
		Ctx:    ctx,
		Cancel: cancel,
	}

	// Client peers should not have ClientDataChans initialized
	peerType = "client"
	if peerType == "edge" {
		clientConn.ClientDataChans = make(map[string]chan *models.SignalingMessage)
	}

	assert.Nil(t, clientConn.ClientDataChans)
}

func TestServerStartStop(t *testing.T) {
	server, _ := setupTestServer(t)

	// Test Start
	server.Start()

	// Verify context is not cancelled
	select {
	case <-server.ctx.Done():
		t.Fatal("Server context should not be cancelled after Start")
	default:
		// Expected
	}

	// Test Stop
	err := server.Stop()
	require.NoError(t, err)

	// Verify context is cancelled
	select {
	case <-server.ctx.Done():
		// Expected
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Server context should be cancelled after Stop")
	}
}

func TestGetPeerConnection(t *testing.T) {
	server, reg := setupTestServer(t)

	// Test getting non-existent connection
	conn, exists := server.GetPeerConnection("non-existent")
	assert.False(t, exists)
	assert.Nil(t, conn)

	// Add a peer connection
	peer := &models.Peer{ID: "test-peer", Type: "edge"}
	reg.AddPeer(peer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	peerConn := &PeerConnection{
		Peer:   peer,
		Ctx:    ctx,
		Cancel: cancel,
	}

	server.mu.Lock()
	server.connections["test-peer"] = peerConn
	server.mu.Unlock()

	// Test getting existing connection
	conn, exists = server.GetPeerConnection("test-peer")
	assert.True(t, exists)
	assert.NotNil(t, conn)
	assert.Equal(t, "test-peer", conn.Peer.ID)
}

func TestAddCustomMessageHandler(t *testing.T) {
	server, _ := setupTestServer(t)

	// Verify no handlers initially
	assert.Empty(t, server.customMessageHandlers)

	// Add first handler
	handler1 := func(from *PeerConnection, msg *models.SignalingMessage) bool {
		return true
	}
	server.AddCustomMessageHandler(handler1)
	assert.Len(t, server.customMessageHandlers, 1)

	// Add second handler
	handler2 := func(from *PeerConnection, msg *models.SignalingMessage) bool {
		return false
	}
	server.AddCustomMessageHandler(handler2)
	assert.Len(t, server.customMessageHandlers, 2)
}

func TestSendMessage(t *testing.T) {
	server, _ := setupTestServer(t)

	mockConn := &mockWebSocketConn{}

	// Test successful send
	msg := &models.SignalingMessage{
		Type: "test",
		Data: "hello",
	}
	server.SendMessage(mockConn, msg)

	assert.Len(t, mockConn.sentMessages, 1)
	assert.Equal(t, "test", mockConn.sentMessages[0].Type)
}

func TestSendError(t *testing.T) {
	server, _ := setupTestServer(t)

	mockConn := &mockWebSocketConn{}

	// Test sending error
	server.SendError(mockConn, "test error message")

	assert.Len(t, mockConn.sentMessages, 1)
	assert.Equal(t, "error", mockConn.sentMessages[0].Type)

	// Verify error message content - SendError uses fiber.Map{"error": errMsg}
	data, ok := mockConn.sentMessages[0].Data.(fiber.Map)
	assert.True(t, ok, "Data should be fiber.Map")
	assert.Equal(t, "test error message", data["error"])
}

func TestStopWithConnections(t *testing.T) {
	server, reg := setupTestServer(t)

	// Add multiple peer connections
	for i := 0; i < 3; i++ {
		peerID := fmt.Sprintf("peer-%d", i)
		peer := &models.Peer{ID: peerID, Type: "edge"}
		reg.AddPeer(peer)

		ctx, cancel := context.WithCancel(context.Background())
		mockConn := &mockWebSocketConn{}

		peerConn := &PeerConnection{
			Peer:   peer,
			Conn:   mockConn,
			Ctx:    ctx,
			Cancel: cancel,
		}

		server.mu.Lock()
		server.connections[peerID] = peerConn
		server.mu.Unlock()
	}

	// Verify connections exist
	server.mu.RLock()
	assert.Len(t, server.connections, 3)
	server.mu.RUnlock()

	// Stop server
	err := server.Stop()
	require.NoError(t, err)

	// Verify context is cancelled
	select {
	case <-server.ctx.Done():
		// Expected
	default:
		t.Fatal("Server context should be cancelled")
	}
}

func TestHandleMessage(t *testing.T) {
	server, reg := setupTestServer(t)

	peer := &models.Peer{ID: "test-peer", Type: "edge"}
	reg.AddPeer(peer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mockConn := &mockWebSocketConn{}
	peerConn := &PeerConnection{
		Peer:   peer,
		Conn:   mockConn,
		Ctx:    ctx,
		Cancel: cancel,
	}

	t.Run("unknown message type", func(t *testing.T) {
		mockConn.sentMessages = nil

		msg := &models.SignalingMessage{
			Type: "unknown-type",
			From: "test-peer",
		}

		// Should not panic, just log warning
		server.handleMessage(peerConn, msg)

		// No error message sent for unknown types
		assert.Equal(t, 0, len(mockConn.sentMessages))
	})

	t.Run("get-peers message type", func(t *testing.T) {
		mockConn.sentMessages = nil

		msg := &models.SignalingMessage{
			Type: "get-peers",
			From: "test-peer",
		}

		server.handleMessage(peerConn, msg)

		assert.Equal(t, 1, len(mockConn.sentMessages))
		assert.Equal(t, "peer-list", mockConn.sentMessages[0].Type)
	})

	t.Run("edge:register message type", func(t *testing.T) {
		mockConn.sentMessages = nil

		msg := &models.SignalingMessage{
			Type: "edge:register",
			From: "test-peer",
			Data: map[string]interface{}{
				"edgeId": "test-peer",
			},
		}

		server.handleMessage(peerConn, msg)

		assert.Equal(t, 1, len(mockConn.sentMessages))
		assert.Equal(t, "edge:register-success", mockConn.sentMessages[0].Type)
	})

	t.Run("turn-request message type", func(t *testing.T) {
		mockConn.sentMessages = nil

		msg := &models.SignalingMessage{
			Type: "turn-request",
			From: "test-peer",
		}

		server.handleMessage(peerConn, msg)

		assert.Equal(t, 1, len(mockConn.sentMessages))
		assert.Equal(t, "turn-response", mockConn.sentMessages[0].Type)
	})

	t.Run("api-connect-request message type", func(t *testing.T) {
		mockConn.sentMessages = nil

		msg := &models.SignalingMessage{
			Type: "api-connect-request",
			From: "test-peer",
		}

		// Should just log warning, no message sent
		server.handleMessage(peerConn, msg)

		assert.Equal(t, 0, len(mockConn.sentMessages))
	})

	t.Run("connect-request message type", func(t *testing.T) {
		mockConn.sentMessages = nil

		// Add target peer
		target := &models.Peer{ID: "target-peer", Type: "client"}
		reg.AddPeer(target)

		targetCtx, targetCancel := context.WithCancel(context.Background())
		defer targetCancel()

		targetMockConn := &mockWebSocketConn{}
		targetConn := &PeerConnection{
			Peer:   target,
			Conn:   targetMockConn,
			Ctx:    targetCtx,
			Cancel: targetCancel,
		}

		server.mu.Lock()
		server.connections["target-peer"] = targetConn
		server.mu.Unlock()

		msg := &models.SignalingMessage{
			Type: "connect-request",
			From: "test-peer",
			To:   "target-peer",
		}

		server.handleMessage(peerConn, msg)

		// Message should be forwarded to target
		assert.Equal(t, 1, len(targetMockConn.sentMessages))
	})

	t.Run("offer message type forwards", func(t *testing.T) {
		// Add target peer for forward
		target2 := &models.Peer{ID: "target-2", Type: "client"}
		reg.AddPeer(target2)

		target2Ctx, target2Cancel := context.WithCancel(context.Background())
		defer target2Cancel()

		target2MockConn := &mockWebSocketConn{}
		target2Conn := &PeerConnection{
			Peer:   target2,
			Conn:   target2MockConn,
			Ctx:    target2Ctx,
			Cancel: target2Cancel,
		}

		server.mu.Lock()
		server.connections["target-2"] = target2Conn
		server.mu.Unlock()

		msg := &models.SignalingMessage{
			Type: "offer",
			From: "test-peer",
			To:   "target-2",
			Data: "sdp-offer",
		}

		server.handleMessage(peerConn, msg)

		assert.Equal(t, 1, len(target2MockConn.sentMessages))
		assert.Equal(t, "offer", target2MockConn.sentMessages[0].Type)
	})
}

func TestHandleAPIConnectResponseTimeout(t *testing.T) {
	server, reg := setupTestServer(t)

	edgeID := "edge-1"
	peer := &models.Peer{ID: edgeID, Type: "edge"}
	reg.AddPeer(peer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mockConn := &mockWebSocketConn{}
	peerConn := &PeerConnection{
		Peer:            peer,
		Conn:            mockConn,
		Ctx:             ctx,
		Cancel:          cancel,
		ClientDataChans: make(map[string]chan *models.SignalingMessage),
	}

	// Create a channel with no buffer and no receiver (will timeout)
	clientID := "client-timeout"
	blockedChan := make(chan *models.SignalingMessage) // No buffer
	peerConn.ClientDataChans[clientID] = blockedChan

	msg := &models.SignalingMessage{
		Type: "api-connect-response",
		From: edgeID,
		To:   clientID,
		Data: map[string]interface{}{"status": "ok"},
	}

	// This should timeout since nobody is receiving
	// Note: This test will take channelSendTimeout to complete
	server.handleAPIConnectResponse(peerConn, msg)

	// The function should complete without panic
}

func TestForwardMessageWithError(t *testing.T) {
	server, reg := setupTestServer(t)

	peer := &models.Peer{ID: "target-err", Type: "client"}
	reg.AddPeer(peer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use error mock connection
	errConn := &errorMockWebSocketConn{}
	peerConn := &PeerConnection{
		Peer:   peer,
		Conn:   errConn,
		Ctx:    ctx,
		Cancel: cancel,
	}

	server.mu.Lock()
	server.connections["target-err"] = peerConn
	server.mu.Unlock()

	msg := &models.SignalingMessage{
		Type: "offer",
		From: "sender-1",
		To:   "target-err",
		Data: "sdp data",
	}

	// Should not panic, just log error
	server.forwardMessage(msg)
}

// errorMockWebSocketConn returns errors on write
type errorMockWebSocketConn struct{}

func (m *errorMockWebSocketConn) WriteJSON(v interface{}) error {
	return errors.New("mock write error")
}

func (m *errorMockWebSocketConn) WriteMessage(messageType int, data []byte) error {
	return errors.New("mock write error")
}

func (m *errorMockWebSocketConn) Close() error {
	return nil
}

func (m *errorMockWebSocketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestHandleMessageServiceTypes(t *testing.T) {
	server, reg := setupTestServer(t)
	mockStorage := new(MockStorage)
	server.storage = mockStorage

	peer := &models.Peer{ID: "edge-1", Type: "edge"}
	reg.AddPeer(peer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mockConn := &mockWebSocketConn{}
	peerConn := &PeerConnection{
		Peer:   peer,
		Conn:   mockConn,
		Ctx:    ctx,
		Cancel: cancel,
	}

	t.Run("service-sync message type", func(t *testing.T) {
		mockStorage.ExpectedCalls = nil
		mockConn.sentMessages = nil

		mockStorage.On("CreateEdgeService", mock.AnythingOfType("*models.EdgeService")).Return(nil)

		msg := &models.SignalingMessage{
			Type: MessageTypeServiceSync,
			From: "edge-1",
			Data: map[string]interface{}{
				"operation": "created",
				"service": map[string]interface{}{
					"id":          "svc-1",
					"name":        "Test Service",
					"tunnel_port": 8080,
					"local_host":  "localhost",
					"local_port":  3000,
					"protocol":    "http",
				},
			},
		}

		server.handleMessage(peerConn, msg)

		assert.Equal(t, 1, len(mockConn.sentMessages))
		assert.Equal(t, MessageTypeServiceSyncAck, mockConn.sentMessages[0].Type)
	})

	t.Run("service-sync-batch message type", func(t *testing.T) {
		mockStorage.ExpectedCalls = nil
		mockConn.sentMessages = nil

		mockStorage.On("GetEdgeService", "svc-2").Return(nil, errors.New("not found"))
		mockStorage.On("CreateEdgeService", mock.AnythingOfType("*models.EdgeService")).Return(nil)

		msg := &models.SignalingMessage{
			Type: MessageTypeServiceSyncBatch,
			From: "edge-1",
			Data: map[string]interface{}{
				"services": []interface{}{
					map[string]interface{}{
						"id":          "svc-2",
						"name":        "Test Service 2",
						"tunnel_port": 8081,
						"local_host":  "localhost",
						"local_port":  3001,
						"protocol":    "http",
					},
				},
			},
		}

		server.handleMessage(peerConn, msg)

		assert.Equal(t, 1, len(mockConn.sentMessages))
		assert.Equal(t, MessageTypeServiceSyncAck, mockConn.sentMessages[0].Type)
	})

	t.Run("service-list-request message type", func(t *testing.T) {
		mockStorage.ExpectedCalls = nil
		mockConn.sentMessages = nil

		mockStorage.On("ListEdgeServices", "edge-1").Return([]*models.EdgeService{}, nil)

		msg := &models.SignalingMessage{
			Type: MessageTypeServiceListRequest,
			From: "edge-1",
		}

		server.handleMessage(peerConn, msg)

		assert.Equal(t, 1, len(mockConn.sentMessages))
		assert.Equal(t, MessageTypeServiceListResponse, mockConn.sentMessages[0].Type)
	})

	t.Run("api-connect-response message type", func(t *testing.T) {
		mockConn.sentMessages = nil

		// Setup client data channel
		peerConn.ClientDataChans = make(map[string]chan *models.SignalingMessage)
		clientChan := make(chan *models.SignalingMessage, 1)
		peerConn.ClientDataChans["client-1"] = clientChan

		msg := &models.SignalingMessage{
			Type: "api-connect-response",
			From: "edge-1",
			To:   "client-1",
			Data: map[string]interface{}{"status": "ok"},
		}

		server.handleMessage(peerConn, msg)

		// Should have sent response to channel
		select {
		case received := <-clientChan:
			assert.Equal(t, msg, received)
		default:
			t.Fatal("Expected message on channel")
		}
	})
}

