package registry

import (
	"sync"
	"time"

	"github.com/arqut/arqut-server-ce/internal/pkg/models"
)

// Registry manages connected peers
type Registry struct {
	peers map[string]*models.Peer
	mu    sync.RWMutex
}

// New creates a new peer registry
func New() *Registry {
	return &Registry{
		peers: make(map[string]*models.Peer),
	}
}

// AddPeer adds or updates a peer in the registry
func (r *Registry) AddPeer(peer *models.Peer) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if peer.CreatedAt.IsZero() {
		peer.CreatedAt = time.Now()
	}
	peer.Connected = true
	peer.LastPing = time.Now()

	r.peers[peer.ID] = peer
}

// GetPeer retrieves a peer by ID
func (r *Registry) GetPeer(id string) (*models.Peer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	peer, exists := r.peers[id]
	return peer, exists
}

// RemovePeer removes a peer from the registry
func (r *Registry) RemovePeer(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if peer, exists := r.peers[id]; exists {
		peer.Connected = false
		delete(r.peers, id)
	}
}

// GetAllPeers returns all peers
func (r *Registry) GetAllPeers() []*models.Peer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	peers := make([]*models.Peer, 0, len(r.peers))
	for _, peer := range r.peers{
		peers = append(peers, peer)
	}

	return peers
}

// GetPeersByType returns all peers of a specific type
func (r *Registry) GetPeersByType(peerType string) []*models.Peer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	peers := make([]*models.Peer, 0)
	for _, peer := range r.peers {
		if peer.Type == peerType {
			peers = append(peers, peer)
		}
	}

	return peers
}

// UpdateLastPing updates the last ping time for a peer
func (r *Registry) UpdateLastPing(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if peer, exists := r.peers[id]; exists {
		peer.LastPing = time.Now()
	}
}

// GetPeerCount returns the total number of peers
func (r *Registry) GetPeerCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.peers)
}

// CleanupStale removes peers that haven't pinged in the specified timeout
func (r *Registry) CleanupStale(timeout time.Duration) []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	removed := []string{}
	now := time.Now()

	for id, peer := range r.peers {
		if now.Sub(peer.LastPing) > timeout {
			peer.Connected = false
			delete(r.peers, id)
			removed = append(removed, id)
		}
	}

	return removed
}
