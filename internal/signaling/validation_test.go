package signaling

import (
	"testing"

	"github.com/arqut/arqut-server-ce/internal/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestValidateService(t *testing.T) {
	tests := []struct {
		name        string
		service     *models.EdgeService
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid service",
			service: &models.EdgeService{
				ID:         "svc-123",
				EdgeID:     "edge-1",
				Name:       "my-service",
				TunnelPort: 8080,
				LocalHost:  "localhost",
				LocalPort:  3000,
				Protocol:   "http",
				Enabled:    true,
			},
			expectError: false,
		},
		{
			name: "valid service with underscores and hyphens",
			service: &models.EdgeService{
				ID:         "svc-456",
				EdgeID:     "edge-1",
				Name:       "my_web-service_123",
				TunnelPort: 8080,
				LocalHost:  "localhost",
				LocalPort:  3000,
				Protocol:   "websocket",
				Enabled:    false,
			},
			expectError: false,
		},
		{
			name: "empty name",
			service: &models.EdgeService{
				ID:         "svc-123",
				EdgeID:     "edge-1",
				Name:       "",
				TunnelPort: 8080,
				LocalHost:  "localhost",
				LocalPort:  3000,
				Protocol:   "http",
			},
			expectError: true,
			errorMsg:    "service name is required",
		},
		{
			name: "name too long",
			service: &models.EdgeService{
				ID:         "svc-123",
				EdgeID:     "edge-1",
				Name:       string(make([]byte, 256)),
				TunnelPort: 8080,
				LocalHost:  "localhost",
				LocalPort:  3000,
				Protocol:   "http",
			},
			expectError: true,
			errorMsg:    "service name too long",
		},
		{
			name: "invalid name characters",
			service: &models.EdgeService{
				ID:         "svc-123",
				EdgeID:     "edge-1",
				Name:       "my service!",
				TunnelPort: 8080,
				LocalHost:  "localhost",
				LocalPort:  3000,
				Protocol:   "http",
			},
			expectError: true,
			errorMsg:    "service name must contain only alphanumeric",
		},
		{
			name: "empty ID",
			service: &models.EdgeService{
				ID:         "",
				EdgeID:     "edge-1",
				Name:       "my-service",
				TunnelPort: 8080,
				LocalHost:  "localhost",
				LocalPort:  3000,
				Protocol:   "http",
			},
			expectError: true,
			errorMsg:    "service ID is required",
		},
		{
			name: "empty edge ID",
			service: &models.EdgeService{
				ID:         "svc-123",
				EdgeID:     "",
				Name:       "my-service",
				TunnelPort: 8080,
				LocalHost:  "localhost",
				LocalPort:  3000,
				Protocol:   "http",
			},
			expectError: true,
			errorMsg:    "edge ID is required",
		},
		{
			name: "empty local host",
			service: &models.EdgeService{
				ID:         "svc-123",
				EdgeID:     "edge-1",
				Name:       "my-service",
				TunnelPort: 8080,
				LocalHost:  "",
				LocalPort:  3000,
				Protocol:   "http",
			},
			expectError: true,
			errorMsg:    "local host is required",
		},
		{
			name: "invalid tunnel port - too low",
			service: &models.EdgeService{
				ID:         "svc-123",
				EdgeID:     "edge-1",
				Name:       "my-service",
				TunnelPort: 0,
				LocalHost:  "localhost",
				LocalPort:  3000,
				Protocol:   "http",
			},
			expectError: true,
			errorMsg:    "invalid tunnel port",
		},
		{
			name: "invalid tunnel port - too high",
			service: &models.EdgeService{
				ID:         "svc-123",
				EdgeID:     "edge-1",
				Name:       "my-service",
				TunnelPort: 65536,
				LocalHost:  "localhost",
				LocalPort:  3000,
				Protocol:   "http",
			},
			expectError: true,
			errorMsg:    "invalid tunnel port",
		},
		{
			name: "invalid local port",
			service: &models.EdgeService{
				ID:         "svc-123",
				EdgeID:     "edge-1",
				Name:       "my-service",
				TunnelPort: 8080,
				LocalHost:  "localhost",
				LocalPort:  0,
				Protocol:   "http",
			},
			expectError: true,
			errorMsg:    "invalid local port",
		},
		{
			name: "invalid protocol",
			service: &models.EdgeService{
				ID:         "svc-123",
				EdgeID:     "edge-1",
				Name:       "my-service",
				TunnelPort: 8080,
				LocalHost:  "localhost",
				LocalPort:  3000,
				Protocol:   "grpc",
			},
			expectError: true,
			errorMsg:    "invalid protocol",
		},
		{
			name: "ID too long",
			service: &models.EdgeService{
				ID:         "svc-12345",
				EdgeID:     "edge-1",
				Name:       "my-service",
				TunnelPort: 8080,
				LocalHost:  "localhost",
				LocalPort:  3000,
				Protocol:   "http",
			},
			expectError: true,
			errorMsg:    "service ID too long",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateService(tt.service)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
