package storage

import (
	"os"
	"testing"
	"time"

	"github.com/arqut/arqut-server-ce/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestStorage(t *testing.T) (*SQLiteStorage, func()) {
	// Create temp database
	dbPath := "test_services.db"
	storage, err := NewSQLiteStorage(dbPath)
	require.NoError(t, err)

	err = storage.Init()
	require.NoError(t, err)

	cleanup := func() {
		storage.Close()
		os.Remove(dbPath)
	}

	return storage, cleanup
}

func TestCreateEdgeService(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	service := &models.EdgeService{
		ID:         "server-123",
		EdgeID:     "edge-1",
		LocalID:    "local-123",
		Name:       "test-service",
		TunnelPort: 8080,
		LocalHost:  "localhost",
		LocalPort:  3000,
		Protocol:   "http",
		Status:     "active",
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	err := storage.CreateEdgeService(service)
	assert.NoError(t, err)

	// Verify it was created
	retrieved, err := storage.GetEdgeServiceByLocalID("edge-1", "local-123")
	assert.NoError(t, err)
	assert.Equal(t, service.ID, retrieved.ID)
	assert.Equal(t, service.Name, retrieved.Name)
}

func TestCreateEdgeService_DuplicateLocalID(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	service1 := &models.EdgeService{
		ID:         "server-123",
		EdgeID:     "edge-1",
		LocalID:    "local-123",
		Name:       "test-service-1",
		TunnelPort: 8080,
		LocalHost:  "localhost",
		LocalPort:  3000,
		Protocol:   "http",
		Status:     "active",
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	err := storage.CreateEdgeService(service1)
	require.NoError(t, err)

	// Try to create another service with same edge_id + local_id
	service2 := &models.EdgeService{
		ID:         "server-456",
		EdgeID:     "edge-1",
		LocalID:    "local-123", // Same local_id for same edge
		Name:       "test-service-2",
		TunnelPort: 8081,
		LocalHost:  "localhost",
		LocalPort:  3001,
		Protocol:   "http",
		Status:     "active",
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	err = storage.CreateEdgeService(service2)
	assert.Error(t, err) // Should fail due to unique constraint
}

func TestCreateEdgeService_DifferentEdgesSameLocalID(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	service1 := &models.EdgeService{
		ID:         "server-123",
		EdgeID:     "edge-1",
		LocalID:    "local-123",
		Name:       "test-service-1",
		TunnelPort: 8080,
		LocalHost:  "localhost",
		LocalPort:  3000,
		Protocol:   "http",
		Status:     "active",
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	err := storage.CreateEdgeService(service1)
	require.NoError(t, err)

	// Different edge can have same local_id
	service2 := &models.EdgeService{
		ID:         "server-456",
		EdgeID:     "edge-2", // Different edge
		LocalID:    "local-123", // Same local_id
		Name:       "test-service-2",
		TunnelPort: 8081,
		LocalHost:  "localhost",
		LocalPort:  3001,
		Protocol:   "http",
		Status:     "active",
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	err = storage.CreateEdgeService(service2)
	assert.NoError(t, err) // Should succeed
}

func TestUpdateEdgeService(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	service := &models.EdgeService{
		ID:         "server-123",
		EdgeID:     "edge-1",
		LocalID:    "local-123",
		Name:       "test-service",
		TunnelPort: 8080,
		LocalHost:  "localhost",
		LocalPort:  3000,
		Protocol:   "http",
		Status:     "active",
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	err := storage.CreateEdgeService(service)
	require.NoError(t, err)

	// Update the service
	service.Name = "updated-service"
	service.TunnelPort = 9090
	service.Status = "inactive"
	service.UpdatedAt = time.Now()

	err = storage.UpdateEdgeService(service)
	assert.NoError(t, err)

	// Verify update
	retrieved, err := storage.GetEdgeServiceByLocalID("edge-1", "local-123")
	assert.NoError(t, err)
	assert.Equal(t, "updated-service", retrieved.Name)
	assert.Equal(t, 9090, retrieved.TunnelPort)
	assert.Equal(t, "inactive", retrieved.Status)
}

func TestDeleteEdgeService(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	service := &models.EdgeService{
		ID:         "server-123",
		EdgeID:     "edge-1",
		LocalID:    "local-123",
		Name:       "test-service",
		TunnelPort: 8080,
		LocalHost:  "localhost",
		LocalPort:  3000,
		Protocol:   "http",
		Status:     "active",
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	err := storage.CreateEdgeService(service)
	require.NoError(t, err)

	// Delete the service (soft delete - sets status to deleted)
	err = storage.DeleteEdgeService("edge-1", "local-123")
	assert.NoError(t, err)

	// Verify it's marked as deleted
	retrieved, err := storage.GetEdgeServiceByLocalID("edge-1", "local-123")
	assert.NoError(t, err)
	assert.Equal(t, "deleted", retrieved.Status)
}

func TestDeleteEdgeService_NotFound(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	err := storage.DeleteEdgeService("edge-999", "local-999")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service not found")
}

func TestListEdgeServices(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	// Create multiple services
	services := []*models.EdgeService{
		{
			ID:         "server-1",
			EdgeID:     "edge-1",
			LocalID:    "local-1",
			Name:       "service-1",
			TunnelPort: 8080,
			LocalHost:  "localhost",
			LocalPort:  3000,
			Protocol:   "http",
			Status:     "active",
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
		{
			ID:         "server-2",
			EdgeID:     "edge-1",
			LocalID:    "local-2",
			Name:       "service-2",
			TunnelPort: 8081,
			LocalHost:  "localhost",
			LocalPort:  3001,
			Protocol:   "websocket",
			Status:     "active",
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
		{
			ID:         "server-3",
			EdgeID:     "edge-2", // Different edge
			LocalID:    "local-3",
			Name:       "service-3",
			TunnelPort: 8082,
			LocalHost:  "localhost",
			LocalPort:  3002,
			Protocol:   "http",
			Status:     "active",
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
	}

	for _, svc := range services {
		err := storage.CreateEdgeService(svc)
		require.NoError(t, err)
	}

	// List services for edge-1
	edge1Services, err := storage.ListEdgeServices("edge-1")
	assert.NoError(t, err)
	assert.Len(t, edge1Services, 2)

	// List services for edge-2
	edge2Services, err := storage.ListEdgeServices("edge-2")
	assert.NoError(t, err)
	assert.Len(t, edge2Services, 1)
}

func TestListEdgeServices_ExcludesDeleted(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	services := []*models.EdgeService{
		{
			ID:         "server-1",
			EdgeID:     "edge-1",
			LocalID:    "local-1",
			Name:       "service-1",
			TunnelPort: 8080,
			LocalHost:  "localhost",
			LocalPort:  3000,
			Protocol:   "http",
			Status:     "active",
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
		{
			ID:         "server-2",
			EdgeID:     "edge-1",
			LocalID:    "local-2",
			Name:       "service-2",
			TunnelPort: 8081,
			LocalHost:  "localhost",
			LocalPort:  3001,
			Protocol:   "http",
			Status:     "deleted",
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
	}

	for _, svc := range services {
		err := storage.CreateEdgeService(svc)
		require.NoError(t, err)
	}

	// List should exclude deleted services
	edgeServices, err := storage.ListEdgeServices("edge-1")
	assert.NoError(t, err)
	assert.Len(t, edgeServices, 1)
	assert.Equal(t, "service-1", edgeServices[0].Name)
}

func TestListAllActiveServices(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	services := []*models.EdgeService{
		{
			ID:         "server-1",
			EdgeID:     "edge-1",
			LocalID:    "local-1",
			Name:       "service-1",
			TunnelPort: 8080,
			LocalHost:  "localhost",
			LocalPort:  3000,
			Protocol:   "http",
			Status:     "active",
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
		{
			ID:         "server-2",
			EdgeID:     "edge-2",
			LocalID:    "local-2",
			Name:       "service-2",
			TunnelPort: 8081,
			LocalHost:  "localhost",
			LocalPort:  3001,
			Protocol:   "http",
			Status:     "active",
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
		{
			ID:         "server-3",
			EdgeID:     "edge-3",
			LocalID:    "local-3",
			Name:       "service-3",
			TunnelPort: 8082,
			LocalHost:  "localhost",
			LocalPort:  3002,
			Protocol:   "http",
			Status:     "inactive",
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
	}

	for _, svc := range services {
		err := storage.CreateEdgeService(svc)
		require.NoError(t, err)
	}

	// List all active services
	activeServices, err := storage.ListAllActiveServices()
	assert.NoError(t, err)
	assert.Len(t, activeServices, 2) // Only active services
}
