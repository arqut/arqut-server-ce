package signaling

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/arqut/arqut-server-ce/pkg/models"
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
	// Parse service sync message
	data, ok := msg.Data.(map[string]interface{})
	if !ok {
		s.sendServiceSyncAck(from, "", "", "error", "Invalid message data format")
		return
	}

	operation, _ := data["operation"].(string)
	serviceData, ok := data["service"].(map[string]interface{})
	if !ok {
		s.sendServiceSyncAck(from, "", "", "error", "Invalid service data format")
		return
	}

	// Convert to ServiceData
	service, err := s.parseServiceData(serviceData)
	if err != nil {
		s.sendServiceSyncAck(from, "", "", "error", fmt.Sprintf("Failed to parse service: %v", err))
		return
	}

	// Validate service data
	if err := validateService(service); err != nil {
		s.sendServiceSyncAck(from, service.LocalID, "", "error", err.Error())
		return
	}

	// Process based on operation
	var serverID string

	switch operation {
	case "created":
		serverID, err = s.createService(from.Peer.ID, service)
	case "updated":
		serverID, err = s.updateService(from.Peer.ID, service)
	case "deleted":
		err = s.deleteService(from.Peer.ID, service.LocalID)
	default:
		s.sendServiceSyncAck(from, service.LocalID, "", "error", "invalid operation")
		return
	}

	if err != nil {
		s.sendServiceSyncAck(from, service.LocalID, "", "error", err.Error())
		return
	}

	// Send success acknowledgment
	s.sendServiceSyncAck(from, service.LocalID, serverID, "success", "")
}

// handleServiceSyncBatch processes bulk sync on reconnection
func (s *Server) handleServiceSyncBatch(from *PeerConnection, msg *models.SignalingMessage) {
	// Parse batch message
	data, ok := msg.Data.(map[string]interface{})
	if !ok {
		s.sendError(from.Conn, "Invalid batch sync message")
		return
	}

	servicesData, ok := data["services"].([]interface{})
	if !ok {
		s.sendError(from.Conn, "Invalid services array")
		return
	}

	s.logger.Info("Processing batch sync", "edge", from.Peer.ID, "count", len(servicesData))

	// Process each service (upsert pattern)
	successCount := 0
	for _, svcData := range servicesData {
		svcMap, ok := svcData.(map[string]interface{})
		if !ok {
			s.logger.Warn("Invalid service data in batch", "edge", from.Peer.ID)
			continue
		}

		service, err := s.parseServiceData(svcMap)
		if err != nil {
			s.logger.Warn("Failed to parse service in batch", "edge", from.Peer.ID, "error", err)
			continue
		}

		if err := validateService(service); err != nil {
			s.logger.Warn("Invalid service in batch", "edge", from.Peer.ID, "error", err)
			continue
		}

		// Try to update first, create if not exists
		_, err = s.updateService(from.Peer.ID, service)
		if err != nil {
			// Service doesn't exist, create it
			_, err = s.createService(from.Peer.ID, service)
			if err != nil {
				s.logger.Warn("Failed to sync service", "edge", from.Peer.ID, "error", err)
				continue
			}
		}
		successCount++
	}

	s.logger.Info("Batch sync completed", "edge", from.Peer.ID, "success", successCount, "total", len(servicesData))

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

	// Convert to ServiceData format
	serviceData := make([]models.ServiceData, len(services))
	for i, svc := range services {
		serviceData[i] = models.ServiceData{
			LocalID:    svc.LocalID,
			Name:       svc.Name,
			TunnelPort: svc.TunnelPort,
			LocalHost:  svc.LocalHost,
			LocalPort:  svc.LocalPort,
			Protocol:   svc.Protocol,
			Status:     svc.Status,
		}
	}

	s.sendMessage(from.Conn, &models.SignalingMessage{
		Type: MessageTypeServiceListResponse,
		Data: map[string]interface{}{
			"services": serviceData,
		},
	})

	s.logger.Debug("Service list sent", "edge", from.Peer.ID, "count", len(services))
}

// Helper functions

func (s *Server) createService(edgeID string, service *models.ServiceData) (string, error) {
	serverID, err := generateServiceID()
	if err != nil {
		return "", fmt.Errorf("failed to generate service ID: %w", err)
	}

	edgeService := &models.EdgeService{
		ID:         serverID,
		EdgeID:     edgeID,
		LocalID:    service.LocalID,
		Name:       service.Name,
		TunnelPort: service.TunnelPort,
		LocalHost:  service.LocalHost,
		LocalPort:  service.LocalPort,
		Protocol:   service.Protocol,
		Status:     service.Status,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := s.storage.CreateEdgeService(edgeService); err != nil {
		return "", fmt.Errorf("failed to create service: %w", err)
	}

	s.logger.Info("Service created",
		"edge", edgeID,
		"local_id", service.LocalID,
		"server_id", serverID,
		"name", service.Name)

	return serverID, nil
}

func (s *Server) updateService(edgeID string, service *models.ServiceData) (string, error) {
	existing, err := s.storage.GetEdgeServiceByLocalID(edgeID, service.LocalID)
	if err != nil {
		return "", fmt.Errorf("service not found: %w", err)
	}

	existing.Name = service.Name
	existing.TunnelPort = service.TunnelPort
	existing.LocalHost = service.LocalHost
	existing.LocalPort = service.LocalPort
	existing.Protocol = service.Protocol
	existing.Status = service.Status
	existing.UpdatedAt = time.Now()

	if err := s.storage.UpdateEdgeService(existing); err != nil {
		return "", fmt.Errorf("failed to update service: %w", err)
	}

	s.logger.Info("Service updated",
		"edge", edgeID,
		"local_id", service.LocalID,
		"name", service.Name)

	return existing.ID, nil
}

func (s *Server) deleteService(edgeID string, localID string) error {
	if err := s.storage.DeleteEdgeService(edgeID, localID); err != nil {
		return fmt.Errorf("failed to delete service: %w", err)
	}

	s.logger.Info("Service deleted", "edge", edgeID, "local_id", localID)
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

func (s *Server) parseServiceData(data map[string]interface{}) (*models.ServiceData, error) {
	// Marshal and unmarshal to convert map to struct
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal service data: %w", err)
	}

	var service models.ServiceData
	if err := json.Unmarshal(jsonData, &service); err != nil {
		return nil, fmt.Errorf("failed to unmarshal service data: %w", err)
	}

	return &service, nil
}
