package registry

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/arqut/arqut-server-ce/internal/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	reg := New()
	require.NotNil(t, reg)
	assert.NotNil(t, reg.peers)
	assert.Equal(t, 0, len(reg.peers))
}

func TestRegistry_AddPeer(t *testing.T) {
	reg := New()

	peer := &models.Peer{
		ID:        "peer-1",
		Type:      "edge",
		AccountID: "account-123",
		PublicKey: "key123",
	}

	reg.AddPeer(peer)

	// Verify peer was added
	assert.Equal(t, 1, reg.GetPeerCount())
	assert.True(t, peer.Connected)
	assert.False(t, peer.LastPing.IsZero())
	assert.False(t, peer.CreatedAt.IsZero())
}

func TestRegistry_AddPeer_Update(t *testing.T) {
	reg := New()

	// Add peer
	peer := &models.Peer{
		ID:        "peer-1",
		Type:      "edge",
		PublicKey: "key123",
	}
	reg.AddPeer(peer)

	// Update peer
	updatedPeer := &models.Peer{
		ID:        "peer-1",
		Type:      "edge",
		PublicKey: "new-key456",
	}
	reg.AddPeer(updatedPeer)

	// Verify update
	assert.Equal(t, 1, reg.GetPeerCount())
	retrieved, exists := reg.GetPeer("peer-1")
	require.True(t, exists)
	assert.Equal(t, "new-key456", retrieved.PublicKey)
}

func TestRegistry_GetPeer(t *testing.T) {
	reg := New()

	peer := &models.Peer{
		ID:        "peer-1",
		Type:      "edge",
		PublicKey: "key123",
	}
	reg.AddPeer(peer)

	t.Run("existing peer", func(t *testing.T) {
		retrieved, exists := reg.GetPeer("peer-1")
		require.True(t, exists)
		assert.Equal(t, "peer-1", retrieved.ID)
		assert.Equal(t, "edge", retrieved.Type)
		assert.Equal(t, "key123", retrieved.PublicKey)
	})

	t.Run("non-existent peer", func(t *testing.T) {
		retrieved, exists := reg.GetPeer("non-existent")
		assert.False(t, exists)
		assert.Nil(t, retrieved)
	})
}

func TestRegistry_RemovePeer(t *testing.T) {
	reg := New()

	peer := &models.Peer{
		ID:   "peer-1",
		Type: "edge",
	}
	reg.AddPeer(peer)
	assert.Equal(t, 1, reg.GetPeerCount())

	reg.RemovePeer("peer-1")

	assert.Equal(t, 0, reg.GetPeerCount())
	_, exists := reg.GetPeer("peer-1")
	assert.False(t, exists)
}

func TestRegistry_RemovePeer_NonExistent(t *testing.T) {
	reg := New()

	// Should not panic
	assert.NotPanics(t, func() {
		reg.RemovePeer("non-existent")
	})
}

func TestRegistry_GetAllPeers(t *testing.T) {
	reg := New()

	// Add multiple peers
	for i := 1; i <= 5; i++ {
		reg.AddPeer(&models.Peer{
			ID:   fmt.Sprintf("peer-%d", i),
			Type: "edge",
		})
	}

	peers := reg.GetAllPeers()
	assert.Len(t, peers, 5)

	// Verify all peers are present
	ids := make(map[string]bool)
	for _, p := range peers {
		ids[p.ID] = true
	}
	for i := 1; i <= 5; i++ {
		assert.True(t, ids[fmt.Sprintf("peer-%d", i)])
	}
}

func TestRegistry_GetAllPeers_Empty(t *testing.T) {
	reg := New()

	peers := reg.GetAllPeers()
	assert.NotNil(t, peers)
	assert.Len(t, peers, 0)
}

func TestRegistry_GetPeersByType(t *testing.T) {
	reg := New()

	// Add edges
	for i := 1; i <= 3; i++ {
		reg.AddPeer(&models.Peer{
			ID:   fmt.Sprintf("edge-%d", i),
			Type: "edge",
		})
	}

	// Add clients
	for i := 1; i <= 2; i++ {
		reg.AddPeer(&models.Peer{
			ID:   fmt.Sprintf("client-%d", i),
			Type: "client",
		})
	}

	t.Run("get edges", func(t *testing.T) {
		edges := reg.GetPeersByType("edge")
		assert.Len(t, edges, 3)
		for _, p := range edges {
			assert.Equal(t, "edge", p.Type)
		}
	})

	t.Run("get clients", func(t *testing.T) {
		clients := reg.GetPeersByType("client")
		assert.Len(t, clients, 2)
		for _, p := range clients {
			assert.Equal(t, "client", p.Type)
		}
	})

	t.Run("non-existent type", func(t *testing.T) {
		others := reg.GetPeersByType("other")
		assert.NotNil(t, others)
		assert.Len(t, others, 0)
	})
}

func TestRegistry_UpdateLastPing(t *testing.T) {
	reg := New()

	peer := &models.Peer{
		ID:   "peer-1",
		Type: "edge",
	}
	reg.AddPeer(peer)

	// Get initial ping time
	initialPing := peer.LastPing
	time.Sleep(10 * time.Millisecond)

	// Update ping
	reg.UpdateLastPing("peer-1")

	// Verify ping was updated
	updated, _ := reg.GetPeer("peer-1")
	assert.True(t, updated.LastPing.After(initialPing))
}

func TestRegistry_UpdateLastPing_NonExistent(t *testing.T) {
	reg := New()

	// Should not panic
	assert.NotPanics(t, func() {
		reg.UpdateLastPing("non-existent")
	})
}

func TestRegistry_GetPeerCount(t *testing.T) {
	reg := New()

	assert.Equal(t, 0, reg.GetPeerCount())

	reg.AddPeer(&models.Peer{ID: "peer-1", Type: "edge"})
	assert.Equal(t, 1, reg.GetPeerCount())

	reg.AddPeer(&models.Peer{ID: "peer-2", Type: "edge"})
	assert.Equal(t, 2, reg.GetPeerCount())

	reg.RemovePeer("peer-1")
	assert.Equal(t, 1, reg.GetPeerCount())

	reg.RemovePeer("peer-2")
	assert.Equal(t, 0, reg.GetPeerCount())
}

func TestRegistry_CleanupStale(t *testing.T) {
	reg := New()

	now := time.Now()

	// Add fresh peer
	freshPeer := &models.Peer{
		ID:       "fresh-peer",
		Type:     "edge",
		LastPing: now,
	}
	reg.AddPeer(freshPeer)

	// Manually add stale peer
	reg.mu.Lock()
	stalePeer := &models.Peer{
		ID:        "stale-peer",
		Type:      "edge",
		Connected: true,
		LastPing:  now.Add(-10 * time.Minute),
		CreatedAt: now.Add(-15 * time.Minute),
	}
	reg.peers[stalePeer.ID] = stalePeer
	reg.mu.Unlock()

	// Cleanup with 5 minute timeout
	removed := reg.CleanupStale(5 * time.Minute)

	// Verify stale peer was removed
	assert.Len(t, removed, 1)
	assert.Contains(t, removed, "stale-peer")

	// Verify fresh peer remains
	assert.Equal(t, 1, reg.GetPeerCount())
	_, exists := reg.GetPeer("fresh-peer")
	assert.True(t, exists)

	// Verify stale peer is gone
	_, exists = reg.GetPeer("stale-peer")
	assert.False(t, exists)
}

func TestRegistry_CleanupStale_Multiple(t *testing.T) {
	reg := New()

	now := time.Now()
	timeout := 5 * time.Minute

	// Add multiple stale peers
	reg.mu.Lock()
	for i := 1; i <= 3; i++ {
		reg.peers[fmt.Sprintf("stale-%d", i)] = &models.Peer{
			ID:        fmt.Sprintf("stale-%d", i),
			Type:      "edge",
			Connected: true,
			LastPing:  now.Add(-10 * time.Minute),
			CreatedAt: now,
		}
	}
	reg.mu.Unlock()

	// Add fresh peers
	for i := 1; i <= 2; i++ {
		reg.AddPeer(&models.Peer{
			ID:   fmt.Sprintf("fresh-%d", i),
			Type: "edge",
		})
	}

	removed := reg.CleanupStale(timeout)

	assert.Len(t, removed, 3)
	assert.Equal(t, 2, reg.GetPeerCount())
}

func TestRegistry_CleanupStale_NoneStale(t *testing.T) {
	reg := New()

	// Add fresh peers
	for i := 1; i <= 3; i++ {
		reg.AddPeer(&models.Peer{
			ID:   fmt.Sprintf("peer-%d", i),
			Type: "edge",
		})
	}

	removed := reg.CleanupStale(5 * time.Minute)

	assert.Len(t, removed, 0)
	assert.Equal(t, 3, reg.GetPeerCount())
}

func TestRegistry_ConcurrentAccess(t *testing.T) {
	reg := New()
	var wg sync.WaitGroup

	// Concurrent adds
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			reg.AddPeer(&models.Peer{
				ID:   fmt.Sprintf("edge-%d", i),
				Type: "edge",
			})
		}
	}()

	// Concurrent reads
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			reg.GetAllPeers()
			reg.GetPeersByType("edge")
			reg.GetPeerCount()
		}
	}()

	// Concurrent updates
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			reg.UpdateLastPing(fmt.Sprintf("edge-%d", i%50))
		}
	}()

	// Concurrent removes
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			reg.RemovePeer(fmt.Sprintf("edge-%d", i))
		}
	}()

	// Concurrent cleanup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			reg.CleanupStale(5 * time.Minute)
			time.Sleep(1 * time.Millisecond)
		}
	}()

	wg.Wait()

	// Test should complete without data races or deadlocks
}

func TestRegistry_PeerConnectedState(t *testing.T) {
	reg := New()

	peer := &models.Peer{
		ID:        "peer-1",
		Type:      "edge",
		Connected: false, // Initially disconnected
	}

	reg.AddPeer(peer)

	// Verify peer is marked as connected after add
	retrieved, _ := reg.GetPeer("peer-1")
	assert.True(t, retrieved.Connected)

	// Remove peer
	reg.RemovePeer("peer-1")

	// Verify peer is marked as disconnected (but already removed, so check count)
	assert.Equal(t, 0, reg.GetPeerCount())
}

func TestRegistry_CreatedAtTimestamp(t *testing.T) {
	reg := New()

	before := time.Now()

	// Peer without CreatedAt
	peer1 := &models.Peer{
		ID:   "peer-1",
		Type: "edge",
	}
	reg.AddPeer(peer1)

	after := time.Now()

	retrieved, _ := reg.GetPeer("peer-1")
	assert.False(t, retrieved.CreatedAt.IsZero())
	assert.True(t, retrieved.CreatedAt.After(before) || retrieved.CreatedAt.Equal(before))
	assert.True(t, retrieved.CreatedAt.Before(after) || retrieved.CreatedAt.Equal(after))

	// Peer with existing CreatedAt
	existingTime := time.Now().Add(-1 * time.Hour)
	peer2 := &models.Peer{
		ID:        "peer-2",
		Type:      "edge",
		CreatedAt: existingTime,
	}
	reg.AddPeer(peer2)

	retrieved2, _ := reg.GetPeer("peer-2")
	assert.Equal(t, existingTime, retrieved2.CreatedAt, "Should preserve existing CreatedAt")
}

func BenchmarkRegistry_AddPeer(b *testing.B) {
	reg := New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reg.AddPeer(&models.Peer{
			ID:   fmt.Sprintf("peer-%d", i),
			Type: "edge",
		})
	}
}

func BenchmarkRegistry_GetPeer(b *testing.B) {
	reg := New()

	// Prepare data
	for i := 0; i < 1000; i++ {
		reg.AddPeer(&models.Peer{
			ID:   fmt.Sprintf("peer-%d", i),
			Type: "edge",
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reg.GetPeer(fmt.Sprintf("peer-%d", i%1000))
	}
}

func BenchmarkRegistry_CleanupStale(b *testing.B) {
	reg := New()
	now := time.Now()

	// Prepare data with mix of stale and fresh peers
	reg.mu.Lock()
	for i := 0; i < 500; i++ {
		reg.peers[fmt.Sprintf("stale-%d", i)] = &models.Peer{
			ID:        fmt.Sprintf("stale-%d", i),
			Type:      "edge",
			LastPing:  now.Add(-10 * time.Minute),
			CreatedAt: now,
		}
		reg.peers[fmt.Sprintf("fresh-%d", i)] = &models.Peer{
			ID:        fmt.Sprintf("fresh-%d", i),
			Type:      "edge",
			LastPing:  now,
			CreatedAt: now,
		}
	}
	reg.mu.Unlock()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reg.CleanupStale(5 * time.Minute)
	}
}
