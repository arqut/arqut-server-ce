package storage

import "github.com/arqut/arqut-server-ce/internal/pkg/models"

// Storage defines the interface for persisting service metadata
type Storage interface {
	// Initialize the storage (create tables, run migrations)
	Init() error

	// Close the storage connection
	Close() error

	// Service metadata management
	CreateEdgeService(service *models.EdgeService) error
	UpdateEdgeService(service *models.EdgeService) error
	DeleteEdgeService(id string) error
	GetEdgeService(id string) (*models.EdgeService, error)
	ListEdgeServices(edgeID string) ([]*models.EdgeService, error)
	ListAllServices() ([]*models.EdgeService, error)
	ListAllEnabledServices() ([]*models.EdgeService, error)
}
