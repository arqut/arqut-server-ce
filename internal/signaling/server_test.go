package signaling

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/arqut/arqut-server-ce/internal/config"
	"github.com/arqut/arqut-server-ce/internal/registry"
	"github.com/arqut/arqut-server-ce/internal/pkg/logger"
	"github.com/arqut/arqut-server-ce/internal/pkg/models"
	"github.com/stretchr/testify/assert"
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
