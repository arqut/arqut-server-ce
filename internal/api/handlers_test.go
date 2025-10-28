package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/arqut/arqut-server-ce/internal/apikey"
	"github.com/arqut/arqut-server-ce/internal/config"
	"github.com/arqut/arqut-server-ce/internal/registry"
	"github.com/arqut/arqut-server-ce/internal/pkg/logger"
	"github.com/arqut/arqut-server-ce/internal/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to extract data or error from new response structure
func getData(body map[string]interface{}) map[string]interface{} {
	// Check success field
	if success, ok := body["success"].(bool); ok && !success {
		return nil
	}
	if data, ok := body["data"].(map[string]interface{}); ok {
		return data
	}
	return nil
}

// Helper to extract array data from response
func getDataArray(body map[string]interface{}) []interface{} {
	// Check success field
	if success, ok := body["success"].(bool); ok && !success {
		return nil
	}
	if data, ok := body["data"].([]interface{}); ok {
		return data
	}
	return nil
}

func getError(body map[string]interface{}) string {
	// New structure: error is an object with message field
	if errObj, ok := body["error"].(map[string]interface{}); ok {
		if msg, ok := errObj["message"].(string); ok {
			return msg
		}
	}
	return ""
}

// setupTestServer creates a test server with a valid API key
func setupTestServer(t *testing.T) (*Server, string) {
	// Generate API key
	key, hash, err := apikey.GenerateWithHash()
	require.NoError(t, err)

	cfg := &config.APIConfig{
		Port: 9000,
		CORSOrigins: []string{
			"http://localhost:3000",
		},
		APIKey: config.APIKeyConfig{
			Hash:      hash,
			CreatedAt: apikey.GetCreatedAt(),
		},
	}

	turnCfg := &config.TurnConfig{
		PublicIP: "127.0.0.1",
		Ports: config.TurnPorts{
			UDP: 3478,
			TCP: 3478,
			TLS: 5349,
		},
		Auth: config.AuthConfig{
			Mode:       "rest",
			Secret:     "test-secret",
			TTLSeconds: 86400,
		},
	}

	reg := registry.New()
	log := logger.New(logger.Config{
		Level:  "error",
		Format: "text",
	})

	// Pass nil for signaling server and tlsConfig in tests (not needed for API tests)
	server := New(cfg, turnCfg, reg, nil, nil, nil, log.Logger)

	return server, key
}

// TestHealthEndpoint tests the health check endpoint
func TestHealthEndpoint(t *testing.T) {
	server, _ := setupTestServer(t)

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	resp, err := server.app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, 200, resp.StatusCode)

	var result map[string]interface{}
	body, _ := io.ReadAll(resp.Body)
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	data := getData(result)
	assert.NotNil(t, data)
	assert.Equal(t, "ok", data["status"])
	assert.NotEmpty(t, data["time"])
}

// TestGenerateCredentials tests the credential generation endpoint
func TestGenerateCredentials(t *testing.T) {
	server, apiKey := setupTestServer(t)

	tests := []struct {
		name           string
		payload        map[string]interface{}
		useAuth        bool
		expectedStatus int
		checkResponse  func(t *testing.T, body map[string]interface{})
	}{
		{
			name: "valid request with edge peer",
			payload: map[string]interface{}{
				"peer_type": "edge",
				"peer_id":   "edge-123",
			},
			useAuth:        true,
			expectedStatus: 200,
			checkResponse: func(t *testing.T, body map[string]interface{}) {
				data := getData(body)
				assert.NotNil(t, data)
				assert.NotEmpty(t, data["username"])
				assert.NotEmpty(t, data["password"])
				assert.Equal(t, float64(86400), data["ttl"])
				assert.NotEmpty(t, data["expires"])

				// Verify username format: peerType:peerID:timestamp
				username := data["username"].(string)
				assert.Contains(t, username, "edge:edge-123:")
			},
		},
		{
			name: "valid request with client peer",
			payload: map[string]interface{}{
				"peer_type": "client",
				"peer_id":   "client-456",
			},
			useAuth:        true,
			expectedStatus: 200,
			checkResponse: func(t *testing.T, body map[string]interface{}) {
				data := getData(body)
				assert.NotNil(t, data)
				username := data["username"].(string)
				assert.Contains(t, username, "client:client-456:")
			},
		},
		{
			name: "custom TTL",
			payload: map[string]interface{}{
				"peer_type": "client",
				"peer_id":   "client-789",
				"ttl":       3600,
			},
			useAuth:        true,
			expectedStatus: 200,
			checkResponse: func(t *testing.T, body map[string]interface{}) {
				data := getData(body)
				assert.NotNil(t, data)
				assert.Equal(t, float64(3600), data["ttl"])
			},
		},
		{
			name: "missing peer_type",
			payload: map[string]interface{}{
				"peer_id": "peer-123",
			},
			useAuth:        true,
			expectedStatus: 400,
			checkResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Contains(t, getError(body), "peer_type and peer_id are required")
			},
		},
		{
			name: "missing peer_id",
			payload: map[string]interface{}{
				"peer_type": "edge",
			},
			useAuth:        true,
			expectedStatus: 400,
			checkResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Contains(t, getError(body), "peer_type and peer_id are required")
			},
		},
		{
			name: "invalid peer_type",
			payload: map[string]interface{}{
				"peer_type": "invalid",
				"peer_id":   "peer-123",
			},
			useAuth:        true,
			expectedStatus: 400,
			checkResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Contains(t, getError(body), "peer_type must be 'edge' or 'client'")
			},
		},
		{
			name: "no authentication",
			payload: map[string]interface{}{
				"peer_type": "edge",
				"peer_id":   "peer-123",
			},
			useAuth:        false,
			expectedStatus: 401,
			checkResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Contains(t, getError(body), "Missing Authorization header")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloadBytes, _ := json.Marshal(tt.payload)
			req := httptest.NewRequest("POST", "/api/v1/credentials", bytes.NewReader(payloadBytes))
			req.Header.Set("Content-Type", "application/json")
			if tt.useAuth {
				req.Header.Set("Authorization", "Bearer "+apiKey)
			}

			resp, err := server.app.Test(req)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			var result map[string]interface{}
			body, _ := io.ReadAll(resp.Body)
			err = json.Unmarshal(body, &result)
			require.NoError(t, err)

			if tt.checkResponse != nil {
				tt.checkResponse(t, result)
			}
		})
	}
}

// TestGetICEServers tests the ICE servers endpoint
func TestGetICEServers(t *testing.T) {
	server, apiKey := setupTestServer(t)

	tests := []struct {
		name           string
		queryParams    string
		useAuth        bool
		expectedStatus int
		checkResponse  func(t *testing.T, body map[string]interface{})
	}{
		{
			name:           "valid request with peer_id",
			queryParams:    "?peer_id=test-peer",
			useAuth:        true,
			expectedStatus: 200,
			checkResponse: func(t *testing.T, body map[string]interface{}) {
				data := getData(body)
				assert.NotNil(t, data)
				iceServers := data["ice_servers"].([]interface{})
				assert.NotEmpty(t, iceServers)

				// Should have at least STUN and TURN servers
				assert.GreaterOrEqual(t, len(iceServers), 2)

				// Check STUN server
				stunServer := iceServers[0].(map[string]interface{})
				urls := stunServer["urls"].([]interface{})
				assert.Contains(t, urls[0].(string), "stun:")

				// Check TURN server
				turnServer := iceServers[1].(map[string]interface{})
				turnUrls := turnServer["urls"].([]interface{})
				assert.Contains(t, turnUrls[0].(string), "turn:")
				assert.NotEmpty(t, turnServer["username"])
				assert.NotEmpty(t, turnServer["credential"])

				assert.NotEmpty(t, data["expires"])
			},
		},
		{
			name:           "custom peer_type",
			queryParams:    "?peer_id=edge-123&peer_type=edge",
			useAuth:        true,
			expectedStatus: 200,
			checkResponse: func(t *testing.T, body map[string]interface{}) {
				data := getData(body)
				assert.NotNil(t, data)
				iceServers := data["ice_servers"].([]interface{})
				turnServer := iceServers[1].(map[string]interface{})
				username := turnServer["username"].(string)
				assert.Contains(t, username, "edge:")
			},
		},
		{
			name:           "missing peer_id",
			queryParams:    "",
			useAuth:        true,
			expectedStatus: 400,
			checkResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Contains(t, getError(body), "peer_id query parameter is required")
			},
		},
		{
			name:           "no authentication",
			queryParams:    "?peer_id=test-peer",
			useAuth:        false,
			expectedStatus: 401,
			checkResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Contains(t, getError(body), "Missing Authorization header")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/api/v1/ice-servers" + tt.queryParams
			req := httptest.NewRequest("GET", url, nil)
			if tt.useAuth {
				req.Header.Set("Authorization", "Bearer "+apiKey)
			}

			resp, err := server.app.Test(req)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			var result map[string]interface{}
			body, _ := io.ReadAll(resp.Body)
			err = json.Unmarshal(body, &result)
			require.NoError(t, err)

			if tt.checkResponse != nil {
				tt.checkResponse(t, result)
			}
		})
	}
}

// TestListPeers tests the peer listing endpoint
func TestListPeers(t *testing.T) {
	server, apiKey := setupTestServer(t)

	// Add test peers
	edgePeer := &models.Peer{
		ID:        "edge-1",
		Type:      "edge",
		AccountID: "account-1",
		Connected: true,
		LastPing:  time.Now(),
		CreatedAt: time.Now(),
	}
	clientPeer := &models.Peer{
		ID:        "client-1",
		Type:      "client",
		AccountID: "account-1",
		EdgeID:    "edge-1",
		Connected: false,
		LastPing:  time.Now(),
		CreatedAt: time.Now(),
	}

	server.registry.AddPeer(edgePeer)
	server.registry.AddPeer(clientPeer)

	tests := []struct {
		name           string
		queryParams    string
		useAuth        bool
		expectedStatus int
		checkResponse  func(t *testing.T, body map[string]interface{})
	}{
		{
			name:           "list all peers",
			queryParams:    "",
			useAuth:        true,
			expectedStatus: 200,
			checkResponse: func(t *testing.T, body map[string]interface{}) {
				peers := getDataArray(body)
				assert.NotNil(t, peers)
				assert.Len(t, peers, 2)
			},
		},
		{
			name:           "filter by type=edge",
			queryParams:    "?type=edge",
			useAuth:        true,
			expectedStatus: 200,
			checkResponse: func(t *testing.T, body map[string]interface{}) {
				peers := getDataArray(body)
				assert.NotNil(t, peers)
				assert.Len(t, peers, 1)

				peer := peers[0].(map[string]interface{})
				assert.Equal(t, "edge", peer["type"])
			},
		},
		{
			name:           "filter by type=client",
			queryParams:    "?type=client",
			useAuth:        true,
			expectedStatus: 200,
			checkResponse: func(t *testing.T, body map[string]interface{}) {
				peers := getDataArray(body)
				assert.NotNil(t, peers)
				assert.Len(t, peers, 1)

				peer := peers[0].(map[string]interface{})
				assert.Equal(t, "client", peer["type"])
			},
		},
		{
			name:           "no authentication",
			queryParams:    "",
			useAuth:        false,
			expectedStatus: 401,
			checkResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Contains(t, getError(body), "Missing Authorization header")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/api/v1/peers" + tt.queryParams
			req := httptest.NewRequest("GET", url, nil)
			if tt.useAuth {
				req.Header.Set("Authorization", "Bearer "+apiKey)
			}

			resp, err := server.app.Test(req)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			var result map[string]interface{}
			body, _ := io.ReadAll(resp.Body)
			err = json.Unmarshal(body, &result)
			require.NoError(t, err)

			if tt.checkResponse != nil {
				tt.checkResponse(t, result)
			}
		})
	}
}

// TestGetPeer tests the get specific peer endpoint
func TestGetPeer(t *testing.T) {
	server, apiKey := setupTestServer(t)

	// Add test peer
	peer := &models.Peer{
		ID:        "test-peer-123",
		Type:      "edge",
		AccountID: "account-1",
		PublicKey: "test-pubkey",
		Connected: true,
		LastPing:  time.Now(),
		CreatedAt: time.Now(),
	}
	server.registry.AddPeer(peer)

	tests := []struct {
		name           string
		peerID         string
		useAuth        bool
		expectedStatus int
		checkResponse  func(t *testing.T, body map[string]interface{})
	}{
		{
			name:           "get existing peer",
			peerID:         "test-peer-123",
			useAuth:        true,
			expectedStatus: 200,
			checkResponse: func(t *testing.T, body map[string]interface{}) {
				data := getData(body)
				assert.NotNil(t, data)
				assert.Equal(t, "test-peer-123", data["id"])
				assert.Equal(t, "edge", data["type"])
				assert.Equal(t, "account-1", data["account_id"])
				assert.Equal(t, "test-pubkey", data["public_key"])
				assert.Equal(t, true, data["connected"])
				assert.NotEmpty(t, data["last_ping"])
				assert.NotEmpty(t, data["created_at"])
			},
		},
		{
			name:           "peer not found",
			peerID:         "non-existent",
			useAuth:        true,
			expectedStatus: 404,
			checkResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Contains(t, getError(body), "Peer not found")
			},
		},
		{
			name:           "no authentication",
			peerID:         "test-peer-123",
			useAuth:        false,
			expectedStatus: 401,
			checkResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Contains(t, getError(body), "Missing Authorization header")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := fmt.Sprintf("/api/v1/peers/%s", tt.peerID)
			req := httptest.NewRequest("GET", url, nil)
			if tt.useAuth {
				req.Header.Set("Authorization", "Bearer "+apiKey)
			}

			resp, err := server.app.Test(req)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			var result map[string]interface{}
			body, _ := io.ReadAll(resp.Body)
			err = json.Unmarshal(body, &result)
			require.NoError(t, err)

			if tt.checkResponse != nil {
				tt.checkResponse(t, result)
			}
		})
	}
}

// TestGenerateTURNCredentials tests the TURN credential generation helper
func TestGenerateTURNCredentials(t *testing.T) {
	server, _ := setupTestServer(t)

	peerType := "edge"
	peerID := "test-peer"
	ttl := 3600

	username, password, expiry := server.generateTURNCredentials(peerType, peerID, ttl)

	// Check username format
	assert.Contains(t, username, fmt.Sprintf("%s:%s:", peerType, peerID))

	// Check password is base64 encoded
	assert.NotEmpty(t, password)

	// Check expiry is in the future
	now := time.Now().Unix()
	assert.Greater(t, expiry, now)
	assert.LessOrEqual(t, expiry, now+int64(ttl)+1) // Allow 1 second tolerance
}
