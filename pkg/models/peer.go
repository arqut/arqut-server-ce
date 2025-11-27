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
	ID         string `json:"id"`
	EdgeID     string `json:"edge_id"`
	PublicKey  string `json:"public_key"`
	AccountID  string `json:"account_id,omitempty"`
	ClientIP   string `json:"client_ip,omitempty"`
	EdgeIP     string `json:"edge_ip,omitempty"`
	Index      int    `json:"index,omitempty"`
}

// ConnectRequestData for peer-to-peer connection establishment
type ConnectRequestData struct {
	PeerID    string `json:"peer_id"`
	AccountID string `json:"account_id,omitempty"`
	Config    struct {
		Index     int    `json:"index,omitempty"`
		ID        string `json:"id,omitempty"`
		PublicKey string `json:"public_key,omitempty"`
	} `json:"config"`
}

// TurnCredentials represents TURN server credentials
type TurnCredentials struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	TTL      int      `json:"ttl"`
	Expires  string   `json:"expires"`
	URLs     []string `json:"urls"`
}
