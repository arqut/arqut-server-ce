package models

import "time"

// Peer represents a connected peer (edge device or client)
type Peer struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // "edge" or "client"
	AccountID string    `json:"account_id,omitempty"`
	PublicKey string    `json:"public_key,omitempty"`
	EdgeID    string    `json:"edge_id,omitempty"` // For clients: which edge they connect through
	Connected bool      `json:"connected"`
	LastPing  time.Time `json:"last_ping"`
	CreatedAt time.Time `json:"created_at"`
}

// SignalingMessage represents a WebRTC signaling message
type SignalingMessage struct {
	Type string      `json:"type"`
	From string      `json:"from,omitempty"`
	To   string      `json:"to,omitempty"`
	Data interface{} `json:"data,omitempty"`
}

// EdgeRegistration data sent by edge devices
type EdgeRegistration struct {
	EdgeID   string   `json:"edgeId"`
	Services []string `json:"services,omitempty"`
}

// ClientConnectRequest sent by clients via REST API
type ClientConnectRequest struct {
	ID        string `json:"id"`
	EdgeID    string `json:"edge_id"`
	PublicKey string `json:"public_key"`
}
