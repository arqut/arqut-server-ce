package signaling

import (
	"context"
	"errors"
	"testing"

	"github.com/arqut/arqut-server-ce/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockStorage is a mock implementation of storage.Storage
type MockStorage struct {
	mock.Mock
}

func (m *MockStorage) Init() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockStorage) CreateEdgeService(service *models.EdgeService) error {
	args := m.Called(service)
	return args.Error(0)
}

func (m *MockStorage) UpdateEdgeService(service *models.EdgeService) error {
	args := m.Called(service)
	return args.Error(0)
}

func (m *MockStorage) DeleteEdgeService(edgeID, localID string) error {
	args := m.Called(edgeID, localID)
	return args.Error(0)
}

func (m *MockStorage) GetEdgeServiceByLocalID(edgeID, localID string) (*models.EdgeService, error) {
	args := m.Called(edgeID, localID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.EdgeService), args.Error(1)
}

func (m *MockStorage) ListEdgeServices(edgeID string) ([]*models.EdgeService, error) {
	args := m.Called(edgeID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.EdgeService), args.Error(1)
}

func (m *MockStorage) ListAllActiveServices() ([]*models.EdgeService, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.EdgeService), args.Error(1)
}

func (m *MockStorage) ListAllServices() ([]*models.EdgeService, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.EdgeService), args.Error(1)
}

func (m *MockStorage) Close() error {
	args := m.Called()
	return args.Error(0)
}

func TestHandleServiceSync(t *testing.T) {
	server, reg := setupTestServer(t)
	mockStorage := new(MockStorage)
	server.storage = mockStorage

	edgeID := "edge-1"
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

	t.Run("create service successfully", func(t *testing.T) {
		mockStorage.ExpectedCalls = nil
		mockConn.sentMessages = nil

		msg := &models.SignalingMessage{
			Type: "service-sync",
			From: edgeID,
			Data: map[string]interface{}{
				"operation": "created",
				"service": map[string]interface{}{
					"localId":    "svc-1",
					"name":       "Web Server",
					"tunnelPort": 8080,
					"localHost":  "localhost",
					"localPort":  3000,
					"protocol":   "http",
					"status":     "active",
				},
			},
		}

		mockStorage.On("CreateEdgeService", mock.AnythingOfType("*models.EdgeService")).Return(nil)

		server.handleServiceSync(peerConn, msg)

		// Verify storage was called
		mockStorage.AssertExpectations(t)

		// Verify ack was sent
		assert.Equal(t, 1, len(mockConn.sentMessages))
		ackMsg := mockConn.sentMessages[0]
		assert.Equal(t, MessageTypeServiceSyncAck, ackMsg.Type)

		// Check ack contains success status
		ackData := ackMsg.Data.(map[string]interface{})
		assert.Equal(t, "success", ackData["status"])
	})

	t.Run("update service successfully", func(t *testing.T) {
		mockStorage.ExpectedCalls = nil
		mockConn.sentMessages = nil

		existingService := &models.EdgeService{
			ID:         "server-id-123",
			EdgeID:     edgeID,
			LocalID:    "svc-1",
			Name:       "Old Name",
			TunnelPort: 8080,
			LocalHost:  "localhost",
			LocalPort:  3000,
			Protocol:   "http",
			Status:     "active",
		}

		msg := &models.SignalingMessage{
			Type: "service-sync",
			From: edgeID,
			Data: map[string]interface{}{
				"operation": "updated",
				"service": map[string]interface{}{
					"localId":    "svc-1",
					"name":       "Updated Name",
					"tunnelPort": 8081,
					"localHost":  "localhost",
					"localPort":  3001,
					"protocol":   "http",
					"status":     "active",
				},
			},
		}

		mockStorage.On("GetEdgeServiceByLocalID", edgeID, "svc-1").Return(existingService, nil)
		mockStorage.On("UpdateEdgeService", mock.AnythingOfType("*models.EdgeService")).Return(nil)

		server.handleServiceSync(peerConn, msg)

		// Verify storage was called
		mockStorage.AssertExpectations(t)

		// Verify ack was sent with success
		assert.Equal(t, 1, len(mockConn.sentMessages))
		ackData := mockConn.sentMessages[0].Data.(map[string]interface{})
		assert.Equal(t, "success", ackData["status"])
	})

	t.Run("delete service successfully", func(t *testing.T) {
		mockStorage.ExpectedCalls = nil
		mockConn.sentMessages = nil

		msg := &models.SignalingMessage{
			Type: "service-sync",
			From: edgeID,
			Data: map[string]interface{}{
				"operation": "deleted",
				"service": map[string]interface{}{
					"localId":    "svc-1",
					"name":       "Web Server",
					"tunnelPort": 8080,
					"localHost":  "localhost",
					"localPort":  3000,
					"protocol":   "http",
				},
			},
		}

		mockStorage.On("DeleteEdgeService", edgeID, "svc-1").Return(nil)

		server.handleServiceSync(peerConn, msg)

		// Verify storage was called
		mockStorage.AssertExpectations(t)

		// Verify ack was sent
		assert.Equal(t, 1, len(mockConn.sentMessages))
		ackData := mockConn.sentMessages[0].Data.(map[string]interface{})
		assert.Equal(t, "success", ackData["status"])
	})

	t.Run("invalid service data format", func(t *testing.T) {
		mockConn.sentMessages = nil

		msg := &models.SignalingMessage{
			Type: "service-sync",
			From: edgeID,
			Data: "invalid data",
		}

		server.handleServiceSync(peerConn, msg)

		// Verify error ack was sent
		assert.Equal(t, 1, len(mockConn.sentMessages))
		ackData := mockConn.sentMessages[0].Data.(map[string]interface{})
		assert.Equal(t, "error", ackData["status"])
	})

	t.Run("invalid service format in data", func(t *testing.T) {
		mockConn.sentMessages = nil

		msg := &models.SignalingMessage{
			Type: "service-sync",
			From: edgeID,
			Data: map[string]interface{}{
				"operation": "created",
				"service":   "invalid service data",
			},
		}

		server.handleServiceSync(peerConn, msg)

		// Verify error ack was sent
		assert.Equal(t, 1, len(mockConn.sentMessages))
		ackData := mockConn.sentMessages[0].Data.(map[string]interface{})
		assert.Equal(t, "error", ackData["status"])
	})

	t.Run("validation failure", func(t *testing.T) {
		mockConn.sentMessages = nil

		msg := &models.SignalingMessage{
			Type: "service-sync",
			From: edgeID,
			Data: map[string]interface{}{
				"operation": "created",
				"service": map[string]interface{}{
					"localId":    "svc-1",
					"name":       "", // Invalid: empty name
					"tunnelPort": 8080,
					"localHost":  "localhost",
					"localPort":  3000,
					"protocol":   "http",
				},
			},
		}

		server.handleServiceSync(peerConn, msg)

		// Verify error ack was sent
		assert.Equal(t, 1, len(mockConn.sentMessages))
		ackData := mockConn.sentMessages[0].Data.(map[string]interface{})
		assert.Equal(t, "error", ackData["status"])
	})

	t.Run("storage error on create", func(t *testing.T) {
		mockStorage.ExpectedCalls = nil
		mockConn.sentMessages = nil

		msg := &models.SignalingMessage{
			Type: "service-sync",
			From: edgeID,
			Data: map[string]interface{}{
				"operation": "created",
				"service": map[string]interface{}{
					"localId":    "svc-1",
					"name":       "Web Server",
					"tunnelPort": 8080,
					"localHost":  "localhost",
					"localPort":  3000,
					"protocol":   "http",
				},
			},
		}

		mockStorage.On("CreateEdgeService", mock.AnythingOfType("*models.EdgeService")).
			Return(errors.New("database error"))

		server.handleServiceSync(peerConn, msg)

		// Verify error ack was sent
		assert.Equal(t, 1, len(mockConn.sentMessages))
		ackData := mockConn.sentMessages[0].Data.(map[string]interface{})
		assert.Equal(t, "error", ackData["status"])
	})

	t.Run("invalid operation", func(t *testing.T) {
		mockConn.sentMessages = nil

		msg := &models.SignalingMessage{
			Type: "service-sync",
			From: edgeID,
			Data: map[string]interface{}{
				"operation": "invalid-op",
				"service": map[string]interface{}{
					"localId":    "svc-1",
					"name":       "Web Server",
					"tunnelPort": 8080,
					"localHost":  "localhost",
					"localPort":  3000,
					"protocol":   "http",
				},
			},
		}

		server.handleServiceSync(peerConn, msg)

		// Verify error ack was sent
		assert.Equal(t, 1, len(mockConn.sentMessages))
		ackData := mockConn.sentMessages[0].Data.(map[string]interface{})
		assert.Equal(t, "error", ackData["status"])
	})
}

func TestHandleServiceSyncBatch(t *testing.T) {
	server, reg := setupTestServer(t)
	mockStorage := new(MockStorage)
	server.storage = mockStorage

	edgeID := "edge-1"
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

	t.Run("batch sync with valid services", func(t *testing.T) {
		mockStorage.ExpectedCalls = nil
		mockConn.sentMessages = nil

		services := []interface{}{
			map[string]interface{}{
				"localId":    "svc-1",
				"name":       "Service 1",
				"tunnelPort": 8080,
				"localHost":  "localhost",
				"localPort":  3000,
				"protocol":   "http",
				"status":     "active",
			},
			map[string]interface{}{
				"localId":    "svc-2",
				"name":       "Service 2",
				"tunnelPort": 8081,
				"localHost":  "localhost",
				"localPort":  3001,
				"protocol":   "websocket",
				"status":     "active",
			},
		}

		msg := &models.SignalingMessage{
			Type: MessageTypeServiceSyncBatch,
			From: edgeID,
			Data: map[string]interface{}{
				"services": services,
			},
		}

		// Mock storage - first update fails (not found), then create succeeds
		mockStorage.On("GetEdgeServiceByLocalID", edgeID, "svc-1").
			Return(nil, errors.New("not found"))
		mockStorage.On("CreateEdgeService", mock.MatchedBy(func(svc *models.EdgeService) bool {
			return svc.LocalID == "svc-1"
		})).Return(nil)

		mockStorage.On("GetEdgeServiceByLocalID", edgeID, "svc-2").
			Return(nil, errors.New("not found"))
		mockStorage.On("CreateEdgeService", mock.MatchedBy(func(svc *models.EdgeService) bool {
			return svc.LocalID == "svc-2"
		})).Return(nil)

		server.handleServiceSyncBatch(peerConn, msg)

		// Verify storage was called for both services
		mockStorage.AssertExpectations(t)

		// Verify success ack was sent
		assert.Equal(t, 1, len(mockConn.sentMessages))
		ackMsg := mockConn.sentMessages[0]
		assert.Equal(t, MessageTypeServiceSyncAck, ackMsg.Type)
		ackData := ackMsg.Data.(map[string]interface{})
		assert.Equal(t, "success", ackData["status"])
	})

	t.Run("batch exceeds maximum size", func(t *testing.T) {
		mockConn.sentMessages = nil

		// Create services array exceeding maxBatchSize
		services := make([]interface{}, maxBatchSize+1)
		for i := 0; i < maxBatchSize+1; i++ {
			services[i] = map[string]interface{}{
				"localId":    "svc-" + string(rune(i)),
				"name":       "Service",
				"tunnelPort": 8080,
				"localHost":  "localhost",
				"localPort":  3000,
				"protocol":   "http",
			}
		}

		msg := &models.SignalingMessage{
			Type: MessageTypeServiceSyncBatch,
			From: edgeID,
			Data: map[string]interface{}{
				"services": services,
			},
		}

		server.handleServiceSyncBatch(peerConn, msg)

		// Verify error was sent
		assert.Equal(t, 1, len(mockConn.sentMessages))
		assert.Equal(t, "error", mockConn.sentMessages[0].Type)
	})

	t.Run("invalid batch data format", func(t *testing.T) {
		mockConn.sentMessages = nil

		msg := &models.SignalingMessage{
			Type: MessageTypeServiceSyncBatch,
			From: edgeID,
			Data: "invalid data",
		}

		server.handleServiceSyncBatch(peerConn, msg)

		// Verify error was sent
		assert.Equal(t, 1, len(mockConn.sentMessages))
		assert.Equal(t, "error", mockConn.sentMessages[0].Type)
	})

	t.Run("invalid services array format", func(t *testing.T) {
		mockConn.sentMessages = nil

		msg := &models.SignalingMessage{
			Type: MessageTypeServiceSyncBatch,
			From: edgeID,
			Data: map[string]interface{}{
				"services": "not an array",
			},
		}

		server.handleServiceSyncBatch(peerConn, msg)

		// Verify error was sent
		assert.Equal(t, 1, len(mockConn.sentMessages))
		assert.Equal(t, "error", mockConn.sentMessages[0].Type)
	})

	t.Run("batch with invalid service entries", func(t *testing.T) {
		mockStorage.ExpectedCalls = nil
		mockConn.sentMessages = nil

		services := []interface{}{
			map[string]interface{}{
				"localId":    "svc-valid",
				"name":       "Valid Service",
				"tunnelPort": 8080,
				"localHost":  "localhost",
				"localPort":  3000,
				"protocol":   "http",
			},
			"invalid service", // This should be skipped
			map[string]interface{}{
				"localId":    "svc-invalid",
				"name":       "", // Invalid: empty name
				"tunnelPort": 8081,
				"localHost":  "localhost",
				"localPort":  3001,
				"protocol":   "http",
			},
		}

		msg := &models.SignalingMessage{
			Type: MessageTypeServiceSyncBatch,
			From: edgeID,
			Data: map[string]interface{}{
				"services": services,
			},
		}

		// Only the valid service should be created
		mockStorage.On("GetEdgeServiceByLocalID", edgeID, "svc-valid").
			Return(nil, errors.New("not found"))
		mockStorage.On("CreateEdgeService", mock.MatchedBy(func(svc *models.EdgeService) bool {
			return svc.LocalID == "svc-valid"
		})).Return(nil)

		server.handleServiceSyncBatch(peerConn, msg)

		// Verify only valid service was processed
		mockStorage.AssertExpectations(t)

		// Verify ack was sent
		assert.Equal(t, 1, len(mockConn.sentMessages))
	})
}

func TestHandleServiceListRequest(t *testing.T) {
	server, reg := setupTestServer(t)
	mockStorage := new(MockStorage)
	server.storage = mockStorage

	edgeID := "edge-1"
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

	t.Run("returns service list successfully", func(t *testing.T) {
		mockStorage.ExpectedCalls = nil
		mockConn.sentMessages = nil

		services := []*models.EdgeService{
			{
				ID:         "srv-1",
				EdgeID:     edgeID,
				LocalID:    "svc-1",
				Name:       "Service 1",
				TunnelPort: 8080,
				LocalHost:  "localhost",
				LocalPort:  3000,
				Protocol:   "http",
				Status:     "active",
			},
			{
				ID:         "srv-2",
				EdgeID:     edgeID,
				LocalID:    "svc-2",
				Name:       "Service 2",
				TunnelPort: 8081,
				LocalHost:  "localhost",
				LocalPort:  3001,
				Protocol:   "websocket",
				Status:     "active",
			},
		}

		mockStorage.On("ListEdgeServices", edgeID).Return(services, nil)

		msg := &models.SignalingMessage{
			Type: MessageTypeServiceListRequest,
			From: edgeID,
		}

		server.handleServiceListRequest(peerConn, msg)

		// Verify storage was called
		mockStorage.AssertExpectations(t)

		// Verify response was sent
		assert.Equal(t, 1, len(mockConn.sentMessages))
		responseMsg := mockConn.sentMessages[0]
		assert.Equal(t, MessageTypeServiceListResponse, responseMsg.Type)

		// Verify services are in response
		responseData := responseMsg.Data.(map[string]interface{})
		serviceList := responseData["services"].([]models.ServiceData)
		assert.Equal(t, 2, len(serviceList))
	})

	t.Run("handles storage error", func(t *testing.T) {
		mockStorage.ExpectedCalls = nil
		mockConn.sentMessages = nil

		mockStorage.On("ListEdgeServices", edgeID).
			Return(nil, errors.New("database error"))

		msg := &models.SignalingMessage{
			Type: MessageTypeServiceListRequest,
			From: edgeID,
		}

		server.handleServiceListRequest(peerConn, msg)

		// Verify error was sent
		assert.Equal(t, 1, len(mockConn.sentMessages))
		assert.Equal(t, "error", mockConn.sentMessages[0].Type)
	})
}
