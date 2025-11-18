package signaling

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/arqut/arqut-server-ce/internal/pkg/models"
)

// Message type constants for service sync
const (
	MessageTypeServiceSync         = "service-sync"
	MessageTypeServiceSyncAck      = "service-sync-ack"
	MessageTypeServiceSyncBatch    = "service-sync-batch"
	MessageTypeServiceListRequest  = "service-list-request"
	MessageTypeServiceListResponse = "service-list-response"
)

// handleServiceSync processes single service sync from edge
func (s *Server) handleServiceSync(from *PeerConnection, msg *models.SignalingMessage) {
	s.logger.Debug("Received service sync message", "edge", from.Peer.ID, "from", from.Peer.Type)

	// Parse service sync message
	data, ok := msg.Data.(map[string]interface{})
	if !ok {
		s.logger.Error("Invalid service sync message data format", "edge", from.Peer.ID)
		s.sendServiceSyncAck(from, "", "", "error", "Invalid message data format")
		return
	}

	operation, _ := data["operation"].(string)
	serviceData, ok := data["service"].(map[string]interface{})
	if !ok {
		s.logger.Error("Invalid service data format in sync message", "edge", from.Peer.ID, "operation", operation)
		s.sendServiceSyncAck(from, "", "", "error", "Invalid service data format")
		return
	}

	// Convert to EdgeService
	service, err := s.parseEdgeService(serviceData)
	if err != nil {
		s.logger.Error("Failed to parse service data", "edge", from.Peer.ID, "operation", operation, "error", err)
		s.sendServiceSyncAck(from, "", "", "error", fmt.Sprintf("Failed to parse service: %v", err))
		return
	}

	// Set EdgeID from peer connection
	service.EdgeID = from.Peer.ID

	s.logger.Info("Processing service sync",
		"edge", from.Peer.ID,
		"operation", operation,
		"service_id", service.ID,
		"name", service.Name,
		"tunnel_port", service.TunnelPort)

	// Validate service data
	if err := validateService(service); err != nil {
		s.logger.Warn("Service validation failed",
			"edge", from.Peer.ID,
			"service_id", service.ID,
			"error", err)
		s.sendServiceSyncAck(from, service.ID, service.ID, "error", err.Error())
		return
	}

	// Process based on operation
	switch operation {
	case "created":
		err = s.createService(service)
	case "updated":
		err = s.updateService(service)
	case "deleted":
		err = s.deleteService(service.ID)
	default:
		s.logger.Warn("Invalid service sync operation", "edge", from.Peer.ID, "operation", operation)
		s.sendServiceSyncAck(from, service.ID, "", "error", "invalid operation")
		return
	}

	if err != nil {
		s.logger.Error("Service sync operation failed",
			"edge", from.Peer.ID,
			"operation", operation,
			"service_id", service.ID,
			"error", err)
		s.sendServiceSyncAck(from, service.ID, "", "error", err.Error())
		return
	}

	s.logger.Info("Service sync completed successfully",
		"edge", from.Peer.ID,
		"operation", operation,
		"service_id", service.ID)

	// Send success acknowledgment
	s.sendServiceSyncAck(from, service.ID, service.ID, "success", "")
}

// handleServiceSyncBatch processes bulk sync on reconnection
func (s *Server) handleServiceSyncBatch(from *PeerConnection, msg *models.SignalingMessage) {
	s.logger.Debug("Received batch sync message", "edge", from.Peer.ID, "from", from.Peer.Type)

	// Parse batch message
	data, ok := msg.Data.(map[string]interface{})
	if !ok {
		s.logger.Error("Failed to cast msg.Data to map[string]interface{}",
			"edge", from.Peer.ID,
			"data_type", fmt.Sprintf("%T", msg.Data),
			"data_value", fmt.Sprintf("%+v", msg.Data))
		s.sendError(from.Conn, "Invalid batch sync message")
		return
	}

	servicesData, ok := data["services"].([]interface{})
	if !ok {
		s.logger.Error("Failed to cast services to []interface{}",
			"edge", from.Peer.ID,
			"services_type", fmt.Sprintf("%T", data["services"]),
			"services_value", fmt.Sprintf("%+v", data["services"]))
		s.sendError(from.Conn, "Invalid services array")
		return
	}

	// Validate batch size to prevent abuse
	if len(servicesData) > maxBatchSize {
		s.logger.Warn("Batch size exceeds limit",
			"edge", from.Peer.ID,
			"count", len(servicesData),
			"max", maxBatchSize)
		s.sendError(from.Conn, fmt.Sprintf("Batch size exceeds maximum of %d services", maxBatchSize))
		return
	}

	s.logger.Info("Processing batch sync", "edge", from.Peer.ID, "count", len(servicesData))

	// Process each service (upsert pattern)
	successCount := 0
	failedCount := 0
	for i, svcData := range servicesData {
		s.logger.Debug("Processing batch service", "edge", from.Peer.ID, "index", i)

		svcMap, ok := svcData.(map[string]interface{})
		if !ok {
			s.logger.Warn("Invalid service data in batch",
				"edge", from.Peer.ID,
				"index", i,
				"type", fmt.Sprintf("%T", svcData))
			failedCount++
			continue
		}

		service, err := s.parseEdgeService(svcMap)
		if err != nil {
			s.logger.Warn("Failed to parse service in batch",
				"edge", from.Peer.ID,
				"index", i,
				"error", err)
			failedCount++
			continue
		}

		// Set EdgeID from peer connection
		service.EdgeID = from.Peer.ID

		s.logger.Debug("Validating batch service",
			"edge", from.Peer.ID,
			"index", i,
			"service_id", service.ID,
			"name", service.Name)

		if err := validateService(service); err != nil {
			s.logger.Warn("Invalid service in batch",
				"edge", from.Peer.ID,
				"index", i,
				"service_id", service.ID,
				"error", err)
			failedCount++
			continue
		}

		// Try to update first, create if not exists
		err = s.updateService(service)
		if err != nil {
			// Service doesn't exist, create it
			s.logger.Debug("Service not found, creating new",
				"edge", from.Peer.ID,
				"service_id", service.ID)
			err = s.createService(service)
			if err != nil {
				s.logger.Warn("Failed to sync service",
					"edge", from.Peer.ID,
					"index", i,
					"service_id", service.ID,
					"error", err)
				failedCount++
				continue
			}
		}
		successCount++
	}

	s.logger.Info("Batch sync completed",
		"edge", from.Peer.ID,
		"success", successCount,
		"failed", failedCount,
		"total", len(servicesData))

	// Send acknowledgment
	s.sendMessage(from.Conn, &models.SignalingMessage{
		Type: MessageTypeServiceSyncAck,
		Data: map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("Synced %d services", successCount),
		},
	})
}

// handleServiceListRequest returns all services for this edge
func (s *Server) handleServiceListRequest(from *PeerConnection, msg *models.SignalingMessage) {
	services, err := s.storage.ListEdgeServices(from.Peer.ID)
	if err != nil {
		s.sendError(from.Conn, "Failed to retrieve services")
		s.logger.Error("Failed to list services", "edge", from.Peer.ID, "error", err)
		return
	}

	// Convert pointers to values for JSON serialization
	serviceList := make([]models.EdgeService, len(services))
	for i, svc := range services {
		serviceList[i] = *svc
	}

	s.sendMessage(from.Conn, &models.SignalingMessage{
		Type: MessageTypeServiceListResponse,
		Data: map[string]interface{}{
			"services": serviceList,
		},
	})

	s.logger.Debug("Service list sent", "edge", from.Peer.ID, "count", len(services))
}

// Helper functions

func (s *Server) createService(service *models.EdgeService) error {
	// Set timestamps
	service.CreatedAt = time.Now()
	service.UpdatedAt = time.Now()

	if err := s.storage.CreateEdgeService(service); err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}

	s.logger.Info("Service created",
		"edge", service.EdgeID,
		"service_id", service.ID,
		"name", service.Name)

	return nil
}

func (s *Server) updateService(service *models.EdgeService) error {
	existing, err := s.storage.GetEdgeService(service.ID)
	if err != nil {
		return fmt.Errorf("service not found: %w", err)
	}

	// Verify edge ownership
	if existing.EdgeID != service.EdgeID {
		return fmt.Errorf("service belongs to different edge")
	}

	// Update fields
	existing.Name = service.Name
	existing.TunnelPort = service.TunnelPort
	existing.LocalHost = service.LocalHost
	existing.LocalPort = service.LocalPort
	existing.Protocol = service.Protocol
	existing.Enabled = service.Enabled
	existing.UpdatedAt = time.Now()

	if err := s.storage.UpdateEdgeService(existing); err != nil {
		return fmt.Errorf("failed to update service: %w", err)
	}

	s.logger.Info("Service updated",
		"edge", service.EdgeID,
		"service_id", service.ID,
		"name", service.Name)

	return nil
}

func (s *Server) deleteService(id string) error {
	if err := s.storage.DeleteEdgeService(id); err != nil {
		return fmt.Errorf("failed to delete service: %w", err)
	}

	s.logger.Info("Service deleted", "service_id", id)
	return nil
}

func (s *Server) sendServiceSyncAck(peer *PeerConnection, localID, serverID, status, errorMsg string) {
	s.sendMessage(peer.Conn, &models.SignalingMessage{
		Type: MessageTypeServiceSyncAck,
		Data: map[string]interface{}{
			"localId":  localID,
			"serverId": serverID,
			"status":   status,
			"error":    errorMsg,
		},
	})
}

func (s *Server) parseEdgeService(data map[string]interface{}) (*models.EdgeService, error) {
	// Marshal and unmarshal to convert map to struct
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal service data: %w", err)
	}

	var service models.EdgeService
	if err := json.Unmarshal(jsonData, &service); err != nil {
		return nil, fmt.Errorf("failed to unmarshal service data: %w", err)
	}

	return &service, nil
}
