package signaling

import (
	"context"
	"testing"
	"time"

	"github.com/arqut/arqut-server-ce/internal/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleEdgeRegistration(t *testing.T) {
	server, reg := setupTestServer(t)

	t.Run("registration with matching ID succeeds", func(t *testing.T) {
		edgeID := "edge-123"
		peer := &models.Peer{ID: edgeID, Type: "edge"}
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

		msg := &models.SignalingMessage{
			Type: "edge:register",
			Data: map[string]interface{}{
				"edgeId": edgeID,
			},
		}

		// Should succeed because IDs match
		server.handleEdgeRegistration(peerConn, msg)

		// Verify success message was sent
		assert.Equal(t, 1, len(mockConn.sentMessages))
		sentMsg := mockConn.sentMessages[0]
		assert.Equal(t, "edge:register-success", sentMsg.Type)
	})

	t.Run("registration with mismatched ID fails", func(t *testing.T) {
		connID := "edge-original"
		requestedID := "edge-different"

		peer := &models.Peer{ID: connID, Type: "edge"}
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

		msg := &models.SignalingMessage{
			Type: "edge:register",
			Data: map[string]interface{}{
				"edgeId": requestedID,
			},
		}

		// Should fail because IDs don't match
		server.handleEdgeRegistration(peerConn, msg)

		// Verify error message was sent
		assert.Equal(t, 1, len(mockConn.sentMessages))
		sentMsg := mockConn.sentMessages[0]
		assert.Equal(t, "error", sentMsg.Type)
	})

	t.Run("registration with invalid data fails", func(t *testing.T) {
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

		msg := &models.SignalingMessage{
			Type: "edge:register",
			Data: "invalid data",
		}

		server.handleEdgeRegistration(peerConn, msg)

		// Verify error message was sent
		assert.Equal(t, 1, len(mockConn.sentMessages))
		assert.Equal(t, "error", mockConn.sentMessages[0].Type)
	})

	t.Run("registration with empty edge ID fails", func(t *testing.T) {
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

		msg := &models.SignalingMessage{
			Type: "edge:register",
			Data: map[string]interface{}{
				"edgeId": "",
			},
		}

		server.handleEdgeRegistration(peerConn, msg)

		// Verify error message was sent
		assert.Equal(t, 1, len(mockConn.sentMessages))
		assert.Equal(t, "error", mockConn.sentMessages[0].Type)
	})
}

func TestDuplicateConnectionHandling(t *testing.T) {
	server, reg := setupTestServer(t)

	peerID := "edge-duplicate"

	// Create first connection
	peer1 := &models.Peer{ID: peerID, Type: "edge"}
	reg.AddPeer(peer1)

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()

	mockConn1 := &mockWebSocketConn{}
	peerConn1 := &PeerConnection{
		Peer:            peer1,
		Conn:            mockConn1,
		Ctx:             ctx1,
		Cancel:          cancel1,
		ClientDataChans: make(map[string]chan *models.SignalingMessage),
	}

	server.mu.Lock()
	server.connections[peerID] = peerConn1
	server.mu.Unlock()

	// Verify first connection exists
	server.mu.RLock()
	conn, exists := server.connections[peerID]
	server.mu.RUnlock()
	assert.True(t, exists)
	assert.Equal(t, peerConn1, conn)

	// Create second connection with same ID (duplicate)
	peer2 := &models.Peer{ID: peerID, Type: "edge"}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()

	mockConn2 := &mockWebSocketConn{}
	peerConn2 := &PeerConnection{
		Peer:            peer2,
		Conn:            mockConn2,
		Ctx:             ctx2,
		Cancel:          cancel2,
		ClientDataChans: make(map[string]chan *models.SignalingMessage),
	}

	// Simulate what handleWebSocket does - check for duplicate and close old connection
	server.mu.Lock()
	if oldConn, exists := server.connections[peerID]; exists {
		if oldConn.Cancel != nil {
			oldConn.Cancel()
		}
		if oldConn.Conn != nil {
			oldConn.Conn.Close()
		}
	}
	server.connections[peerID] = peerConn2
	server.mu.Unlock()

	// Verify old connection was cancelled
	select {
	case <-ctx1.Done():
		// Expected - old connection should be cancelled
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Old connection context should be cancelled")
	}

	// Verify new connection is active
	server.mu.RLock()
	conn, exists = server.connections[peerID]
	server.mu.RUnlock()
	assert.True(t, exists)
	assert.Equal(t, peerConn2, conn)
	assert.True(t, mockConn1.closed)
}

func TestForwardMessage(t *testing.T) {
	server, reg := setupTestServer(t)

	// Create target peer
	targetID := "peer-target"
	targetPeer := &models.Peer{ID: targetID, Type: "client"}
	reg.AddPeer(targetPeer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mockConn := &mockWebSocketConn{}
	targetConn := &PeerConnection{
		Peer:   targetPeer,
		Conn:   mockConn,
		Ctx:    ctx,
		Cancel: cancel,
	}

	server.mu.Lock()
	server.connections[targetID] = targetConn
	server.mu.Unlock()

	t.Run("forwards message to existing peer", func(t *testing.T) {
		msg := &models.SignalingMessage{
			Type: "offer",
			From: "peer-sender",
			To:   targetID,
			Data: map[string]interface{}{
				"sdp": "v=0...",
			},
		}

		server.forwardMessage(msg)

		// Verify message was sent
		assert.Equal(t, 1, len(mockConn.sentMessages))
		assert.Equal(t, msg, mockConn.sentMessages[0])
	})

	t.Run("handles missing recipient gracefully", func(t *testing.T) {
		msg := &models.SignalingMessage{
			Type: "offer",
			From: "peer-sender",
			To:   "",
			Data: map[string]interface{}{},
		}

		// Should not panic
		server.forwardMessage(msg)
	})

	t.Run("handles non-existent target peer gracefully", func(t *testing.T) {
		msg := &models.SignalingMessage{
			Type: "offer",
			From: "peer-sender",
			To:   "non-existent-peer",
			Data: map[string]interface{}{},
		}

		// Should not panic
		server.forwardMessage(msg)
	})
}

func TestHandleGetPeers(t *testing.T) {
	server, reg := setupTestServer(t)

	// Add some peers
	peer1 := &models.Peer{ID: "edge-1", Type: "edge"}
	peer2 := &models.Peer{ID: "client-1", Type: "client"}
	reg.AddPeer(peer1)
	reg.AddPeer(peer2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mockConn := &mockWebSocketConn{}
	requestingPeer := &PeerConnection{
		Peer:   &models.Peer{ID: "requester", Type: "edge"},
		Conn:   mockConn,
		Ctx:    ctx,
		Cancel: cancel,
	}

	server.handleGetPeers(requestingPeer)

	// Verify peer-list message was sent
	require.Equal(t, 1, len(mockConn.sentMessages))
	msg := mockConn.sentMessages[0]
	assert.Equal(t, "peer-list", msg.Type)

	// Verify it contains peer data
	assert.NotNil(t, msg.Data)
}

func TestHandleTurnRequest(t *testing.T) {
	server, _ := setupTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mockConn := &mockWebSocketConn{}
	peer := &models.Peer{ID: "client-1", Type: "client"}
	peerConn := &PeerConnection{
		Peer:   peer,
		Conn:   mockConn,
		Ctx:    ctx,
		Cancel: cancel,
	}

	t.Run("generates TURN credentials successfully", func(t *testing.T) {
		server.handleTurnRequest(peerConn)

		// Verify turn-response was sent
		require.Equal(t, 1, len(mockConn.sentMessages))
		msg := mockConn.sentMessages[0]
		assert.Equal(t, "turn-response", msg.Type)

		// Verify credentials are included
		creds, ok := msg.Data.(models.TurnCredentials)
		require.True(t, ok)
		assert.NotEmpty(t, creds.Username)
		assert.NotEmpty(t, creds.Password)
		assert.NotEmpty(t, creds.URLs)
		assert.Greater(t, len(creds.URLs), 0)
	})

	t.Run("handles missing TURN config gracefully", func(t *testing.T) {
		serverNoTurn := New(server.config, nil, server.registry, nil, server.logger)
		mockConn2 := &mockWebSocketConn{}
		peerConn2 := &PeerConnection{
			Peer:   peer,
			Conn:   mockConn2,
			Ctx:    ctx,
			Cancel: cancel,
		}

		serverNoTurn.handleTurnRequest(peerConn2)

		// Should send error
		require.Equal(t, 1, len(mockConn2.sentMessages))
		assert.Equal(t, "error", mockConn2.sentMessages[0].Type)
	})
}

func TestHandleConnectRequest(t *testing.T) {
	server, reg := setupTestServer(t)

	// Create sender and target peers
	senderPeer := &models.Peer{ID: "peer-sender", Type: "client"}
	targetPeer := &models.Peer{ID: "peer-target", Type: "client"}
	reg.AddPeer(senderPeer)
	reg.AddPeer(targetPeer)

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()

	mockConnSender := &mockWebSocketConn{}
	mockConnTarget := &mockWebSocketConn{}

	senderConn := &PeerConnection{
		Peer:   senderPeer,
		Conn:   mockConnSender,
		Ctx:    ctx1,
		Cancel: cancel1,
	}

	targetConn := &PeerConnection{
		Peer:   targetPeer,
		Conn:   mockConnTarget,
		Ctx:    ctx2,
		Cancel: cancel2,
	}

	server.mu.Lock()
	server.connections["peer-sender"] = senderConn
	server.connections["peer-target"] = targetConn
	server.mu.Unlock()

	msg := &models.SignalingMessage{
		Type: "connect-request",
		From: "peer-sender",
		To:   "peer-target",
		Data: map[string]interface{}{
			"publicKey": "test-key",
		},
	}

	server.handleConnectRequest(senderConn, msg)

	// Verify message was forwarded to target
	assert.Equal(t, 1, len(mockConnTarget.sentMessages))
	assert.Equal(t, msg, mockConnTarget.sentMessages[0])
}

func TestHandleAPIConnectRequest(t *testing.T) {
	server, _ := setupTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mockConn := &mockWebSocketConn{}
	peer := &models.Peer{ID: "edge-1", Type: "edge"}
	peerConn := &PeerConnection{
		Peer:   peer,
		Conn:   mockConn,
		Ctx:    ctx,
		Cancel: cancel,
	}

	msg := &models.SignalingMessage{
		Type: "api-connect-request",
		From: "api",
		To:   "edge-1",
		Data: map[string]interface{}{},
	}

	// This should just log a warning - api-connect-request should come from REST API, not WebSocket
	server.handleAPIConnectRequest(peerConn, msg)

	// No messages should be sent
	assert.Equal(t, 0, len(mockConn.sentMessages))
}

// Mock WebSocket connection for testing
type mockWebSocketConn struct {
	sentMessages []*models.SignalingMessage
	closed       bool
}

func (m *mockWebSocketConn) WriteJSON(v interface{}) error {
	if msg, ok := v.(*models.SignalingMessage); ok {
		m.sentMessages = append(m.sentMessages, msg)
	}
	return nil
}

func (m *mockWebSocketConn) WriteMessage(messageType int, data []byte) error {
	return nil
}

func (m *mockWebSocketConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockWebSocketConn) SetWriteDeadline(t time.Time) error {
	return nil
}
