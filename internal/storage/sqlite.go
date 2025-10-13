package storage

import (
	"fmt"

	"github.com/arqut/arqut-server-ce/pkg/models"
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

	// Create unique index on edge_id + local_id
	if err := s.db.Exec(`
		CREATE UNIQUE INDEX IF NOT EXISTS idx_edge_services_edge_local
		ON edge_services(edge_id, local_id)
	`).Error; err != nil {
		return fmt.Errorf("failed to create unique index: %w", err)
	}

	// Create index on status
	if err := s.db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_edge_services_status
		ON edge_services(status)
	`).Error; err != nil {
		return fmt.Errorf("failed to create status index: %w", err)
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

// DeleteEdgeService marks a service as deleted
func (s *SQLiteStorage) DeleteEdgeService(edgeID, localID string) error {
	result := s.db.Model(&models.EdgeService{}).
		Where("edge_id = ? AND local_id = ?", edgeID, localID).
		Update("status", "deleted")

	if result.Error != nil {
		return fmt.Errorf("failed to delete service: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("service not found")
	}

	return nil
}

// GetEdgeServiceByLocalID retrieves a service by edge ID and local ID
func (s *SQLiteStorage) GetEdgeServiceByLocalID(edgeID, localID string) (*models.EdgeService, error) {
	var service models.EdgeService
	result := s.db.Where("edge_id = ? AND local_id = ?", edgeID, localID).First(&service)

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
	result := s.db.Where("edge_id = ? AND status != ?", edgeID, "deleted").
		Order("created_at DESC").
		Find(&services)

	if result.Error != nil {
		return nil, fmt.Errorf("failed to list services: %w", result.Error)
	}

	return services, nil
}

// ListAllActiveServices lists all active services across all edges
func (s *SQLiteStorage) ListAllActiveServices() ([]*models.EdgeService, error) {
	var services []*models.EdgeService
	result := s.db.Where("status = ?", "active").
		Order("edge_id, created_at DESC").
		Find(&services)

	if result.Error != nil {
		return nil, fmt.Errorf("failed to list active services: %w", result.Error)
	}

	return services, nil
}
