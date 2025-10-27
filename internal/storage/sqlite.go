package storage

import (
	"fmt"

	"github.com/arqut/arqut-server-ce/internal/pkg/models"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// SQLiteStorage implements the Storage interface using SQLite with GORM
type SQLiteStorage struct {
	db *gorm.DB
}

// NewSQLiteStorage creates a new SQLite storage instance
func NewSQLiteStorage(dbPath string) (*SQLiteStorage, error) {
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent), // Suppress SQL logs
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	storage := &SQLiteStorage{db: db}
	return storage, nil
}

// Init initializes the database schema
func (s *SQLiteStorage) Init() error {
	// Auto-migrate the EdgeService model
	if err := s.db.AutoMigrate(&models.EdgeService{}); err != nil {
		return fmt.Errorf("failed to migrate schema: %w", err)
	}

	// Create index on enabled status
	if err := s.db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_edge_services_enabled
		ON edge_services(enabled)
	`).Error; err != nil {
		return fmt.Errorf("failed to create enabled index: %w", err)
	}

	return nil
}

// Close closes the database connection
func (s *SQLiteStorage) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying DB: %w", err)
	}
	return sqlDB.Close()
}

// CreateEdgeService creates a new service entry
func (s *SQLiteStorage) CreateEdgeService(service *models.EdgeService) error {
	if err := s.db.Create(service).Error; err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}
	return nil
}

// UpdateEdgeService updates an existing service
func (s *SQLiteStorage) UpdateEdgeService(service *models.EdgeService) error {
	if err := s.db.Save(service).Error; err != nil {
		return fmt.Errorf("failed to update service: %w", err)
	}
	return nil
}

// DeleteEdgeService deletes a service by ID
func (s *SQLiteStorage) DeleteEdgeService(id string) error {
	result := s.db.Delete(&models.EdgeService{}, "id = ?", id)

	if result.Error != nil {
		return fmt.Errorf("failed to delete service: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("service not found")
	}

	return nil
}

// GetEdgeService retrieves a service by ID
func (s *SQLiteStorage) GetEdgeService(id string) (*models.EdgeService, error) {
	var service models.EdgeService
	result := s.db.Where("id = ?", id).First(&service)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("service not found")
		}
		return nil, fmt.Errorf("failed to get service: %w", result.Error)
	}

	return &service, nil
}

// ListEdgeServices lists all services for a specific edge
func (s *SQLiteStorage) ListEdgeServices(edgeID string) ([]*models.EdgeService, error) {
	var services []*models.EdgeService
	result := s.db.Where("edge_id = ?", edgeID).
		Order("created_at DESC").
		Find(&services)

	if result.Error != nil {
		return nil, fmt.Errorf("failed to list services: %w", result.Error)
	}

	return services, nil
}

// ListAllEnabledServices lists all enabled services across all edges
func (s *SQLiteStorage) ListAllEnabledServices() ([]*models.EdgeService, error) {
	var services []*models.EdgeService
	result := s.db.Where("enabled = ?", true).
		Order("edge_id, created_at DESC").
		Find(&services)

	if result.Error != nil {
		return nil, fmt.Errorf("failed to list enabled services: %w", result.Error)
	}

	return services, nil
}

// ListAllServices lists all services regardless of status
func (s *SQLiteStorage) ListAllServices() ([]*models.EdgeService, error) {
	var services []*models.EdgeService
	result := s.db.Order("edge_id, created_at DESC").Find(&services)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to list services: %w", result.Error)
	}

	return services, nil
}
