package models

import "time"

// EdgeService represents a service exposed by an edge device
type EdgeService struct {
	ID         string    `json:"id" gorm:"type:varchar(8);primaryKey"`
	EdgeID     string    `json:"edge_id" gorm:"type:varchar(64);index;not null"`
	Name       string    `json:"name" gorm:"type:varchar(128)"`
	TunnelPort int       `json:"tunnel_port"`
	LocalHost  string    `json:"local_host"`
	LocalPort  int       `json:"local_port"`
	Protocol   string    `json:"protocol" gorm:"type:varchar(10)"` // "http" or "websocket"
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// ServiceSyncMessage represents a single service sync message
type ServiceSyncMessage struct {
	Type      string       `json:"type"`
	Operation string       `json:"operation"` // created|updated|deleted
	Service   EdgeService  `json:"service"`
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
	Type     string         `json:"type"`
	Services []EdgeService  `json:"services"`
}

// ServiceListResponseMessage represents service list response
type ServiceListResponseMessage struct {
	Type     string         `json:"type"`
	Services []EdgeService  `json:"services"`
}
