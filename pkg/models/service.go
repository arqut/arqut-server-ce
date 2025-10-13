package models

import "time"

// EdgeService represents a service exposed by an edge device
type EdgeService struct {
	ID         string    `json:"id" gorm:"primaryKey"`
	EdgeID     string    `json:"edge_id" gorm:"not null;index"`
	LocalID    string    `json:"local_id" gorm:"not null"`
	Name       string    `json:"name" gorm:"not null"`
	TunnelPort int       `json:"tunnel_port" gorm:"not null"`
	LocalHost  string    `json:"local_host" gorm:"not null"`
	LocalPort  int       `json:"local_port" gorm:"not null"`
	Protocol   string    `json:"protocol" gorm:"not null"`
	Status     string    `json:"status" gorm:"default:'active'"`
	CreatedAt  time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt  time.Time `json:"updated_at" gorm:"autoUpdateTime"`
}

// ServiceData represents the service data sent/received via WebSocket
type ServiceData struct {
	LocalID    string `json:"localId"`
	Name       string `json:"name"`
	TunnelPort int    `json:"tunnelPort"` // Edge's local proxy port
	LocalHost  string `json:"localHost"`
	LocalPort  int    `json:"localPort"`
	Protocol   string `json:"protocol"`
	Status     string `json:"status"` // active|inactive
}

// ServiceSyncMessage represents a single service sync message
type ServiceSyncMessage struct {
	Type      string      `json:"type"`
	Operation string      `json:"operation"` // created|updated|deleted
	Service   ServiceData `json:"service"`
}

// ServiceSyncAckMessage represents acknowledgment of service sync
type ServiceSyncAckMessage struct {
	Type     string `json:"type"`
	LocalID  string `json:"localId"`  // Echo back edge's local ID
	ServerID string `json:"serverId"` // Server's UUID for this service
	Status   string `json:"status"`   // success|error
	Error    string `json:"error,omitempty"`
}

// ServiceSyncBatchMessage represents bulk service sync
type ServiceSyncBatchMessage struct {
	Type     string        `json:"type"`
	Services []ServiceData `json:"services"`
}

// ServiceListResponseMessage represents service list response
type ServiceListResponseMessage struct {
	Type     string        `json:"type"`
	Services []ServiceData `json:"services"`
}
