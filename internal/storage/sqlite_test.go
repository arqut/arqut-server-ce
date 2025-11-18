package storage

import (
	"os"
	"testing"
	"time"

	"github.com/arqut/arqut-server-ce/internal/pkg/models"
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
		ID:         "svc-123",
		EdgeID:     "edge-1",
		Name:       "test-service",
		TunnelPort: 8080,
		LocalHost:  "localhost",
		LocalPort:  3000,
		Protocol:   "http",
		Enabled:    true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	err := storage.CreateEdgeService(service)
	assert.NoError(t, err)

	// Verify it was created
	retrieved, err := storage.GetEdgeService("svc-123")
	assert.NoError(t, err)
	assert.Equal(t, service.ID, retrieved.ID)
	assert.Equal(t, service.Name, retrieved.Name)
}

func TestCreateEdgeService_DuplicateID(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	service1 := &models.EdgeService{
		ID:         "svc-123",
		EdgeID:     "edge-1",
		Name:       "test-service-1",
		TunnelPort: 8080,
		LocalHost:  "localhost",
		LocalPort:  3000,
		Protocol:   "http",
		Enabled:    true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	err := storage.CreateEdgeService(service1)
	require.NoError(t, err)

	// Try to create another service with same ID
	service2 := &models.EdgeService{
		ID:         "svc-123", // Same ID
		EdgeID:     "edge-2",
		Name:       "test-service-2",
		TunnelPort: 8081,
		LocalHost:  "localhost",
		LocalPort:  3001,
		Protocol:   "http",
		Enabled:    true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	err = storage.CreateEdgeService(service2)
	assert.Error(t, err) // Should fail due to primary key constraint
}

func TestCreateEdgeService_DifferentEdgesSameLocalID(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	service1 := &models.EdgeService{
		ID:         "svc-123",
		EdgeID:     "edge-1",
		Name:       "test-service-1",
		TunnelPort: 8080,
		LocalHost:  "localhost",
		LocalPort:  3000,
		Protocol:   "http",
		Enabled:    true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	err := storage.CreateEdgeService(service1)
	require.NoError(t, err)

	// Different edge can have same local_id
	service2 := &models.EdgeService{
		ID:         "svc-456",
		EdgeID:     "edge-2", // Different edge
		Name:       "test-service-2",
		TunnelPort: 8081,
		LocalHost:  "localhost",
		LocalPort:  3001,
		Protocol:   "http",
		Enabled:    true,
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
		ID:         "svc-123",
		EdgeID:     "edge-1",
		Name:       "test-service",
		TunnelPort: 8080,
		LocalHost:  "localhost",
		LocalPort:  3000,
		Protocol:   "http",
		Enabled:    true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	err := storage.CreateEdgeService(service)
	require.NoError(t, err)

	// Update the service
	service.Name = "updated-service"
	service.TunnelPort = 9090
	service.Enabled = false
	service.UpdatedAt = time.Now()

	err = storage.UpdateEdgeService(service)
	assert.NoError(t, err)

	// Verify update
	retrieved, err := storage.GetEdgeService("svc-123")
	assert.NoError(t, err)
	assert.Equal(t, "updated-service", retrieved.Name)
	assert.Equal(t, 9090, retrieved.TunnelPort)
	assert.Equal(t, false, retrieved.Enabled)
}

func TestDeleteEdgeService(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	service := &models.EdgeService{
		ID:         "svc-123",
		EdgeID:     "edge-1",
		Name:       "test-service",
		TunnelPort: 8080,
		LocalHost:  "localhost",
		LocalPort:  3000,
		Protocol:   "http",
		Enabled:    true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	err := storage.CreateEdgeService(service)
	require.NoError(t, err)

	// Delete the service (hard delete)
	err = storage.DeleteEdgeService("svc-123")
	assert.NoError(t, err)

	// Verify it's actually deleted
	_, err = storage.GetEdgeService("svc-123")
	assert.Error(t, err) // Should not be found
	assert.Contains(t, err.Error(), "service not found")
}

func TestDeleteEdgeService_NotFound(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	err := storage.DeleteEdgeService("svc-999")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service not found")
}

func TestListEdgeServices(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	// Create multiple services
	services := []*models.EdgeService{
		{
			ID:         "svc-1",
			EdgeID:     "edge-1",
			Name:       "service-1",
			TunnelPort: 8080,
			LocalHost:  "localhost",
			LocalPort:  3000,
			Protocol:   "http",
			Enabled:    true,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
		{
			ID:         "svc-2",
			EdgeID:     "edge-1",
			Name:       "service-2",
			TunnelPort: 8081,
			LocalHost:  "localhost",
			LocalPort:  3001,
			Protocol:   "websocket",
			Enabled:    true,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
		{
			ID:         "svc-3",
			EdgeID:     "edge-2", // Different edge
			Name:       "service-3",
			TunnelPort: 8082,
			LocalHost:  "localhost",
			LocalPort:  3002,
			Protocol:   "http",
			Enabled:    true,
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

func TestListEdgeServices_IncludesAllServices(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	services := []*models.EdgeService{
		{
			ID:         "svc-1",
			EdgeID:     "edge-1",
			Name:       "service-1",
			TunnelPort: 8080,
			LocalHost:  "localhost",
			LocalPort:  3000,
			Protocol:   "http",
			Enabled:    true,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
		{
			ID:         "svc-2",
			EdgeID:     "edge-1",
			Name:       "service-2",
			TunnelPort: 8081,
			LocalHost:  "localhost",
			LocalPort:  3001,
			Protocol:   "http",
			Enabled:    false,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
	}

	for _, svc := range services {
		err := storage.CreateEdgeService(svc)
		require.NoError(t, err)
	}

	// List should include all services (both enabled and disabled)
	edgeServices, err := storage.ListEdgeServices("edge-1")
	assert.NoError(t, err)
	assert.Len(t, edgeServices, 2)
}

func TestListAllEnabledServices(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	services := []*models.EdgeService{
		{
			ID:         "svc-1",
			EdgeID:     "edge-1",
			Name:       "service-1",
			TunnelPort: 8080,
			LocalHost:  "localhost",
			LocalPort:  3000,
			Protocol:   "http",
			Enabled:    true,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
		{
			ID:         "svc-2",
			EdgeID:     "edge-2",
			Name:       "service-2",
			TunnelPort: 8081,
			LocalHost:  "localhost",
			LocalPort:  3001,
			Protocol:   "http",
			Enabled:    true,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
		{
			ID:         "svc-3",
			EdgeID:     "edge-3",
			Name:       "service-3",
			TunnelPort: 8082,
			LocalHost:  "localhost",
			LocalPort:  3002,
			Protocol:   "http",
			Enabled:    false,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
	}

	for _, svc := range services {
		err := storage.CreateEdgeService(svc)
		require.NoError(t, err)
	}

	// List all enabled services
	enabledServices, err := storage.ListAllEnabledServices()
	assert.NoError(t, err)
	assert.Len(t, enabledServices, 2) // Only enabled services (not disabled)
}
