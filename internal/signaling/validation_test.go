package signaling

import (
	"testing"

	"github.com/arqut/arqut-server-ce/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestValidateService(t *testing.T) {
	tests := []struct {
		name        string
		service     *models.ServiceData
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid service",
			service: &models.ServiceData{
				LocalID:    "test-123",
				Name:       "my-service",
				TunnelPort: 8080,
				LocalHost:  "localhost",
				LocalPort:  3000,
				Protocol:   "http",
				Status:     "active",
			},
			expectError: false,
		},
		{
			name: "valid service with underscores and hyphens",
			service: &models.ServiceData{
				LocalID:    "test-123",
				Name:       "my_web-service_123",
				TunnelPort: 8080,
				LocalHost:  "localhost",
				LocalPort:  3000,
				Protocol:   "websocket",
				Status:     "inactive",
			},
			expectError: false,
		},
		{
			name: "empty name",
			service: &models.ServiceData{
				LocalID:    "test-123",
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
			service: &models.ServiceData{
				LocalID:    "test-123",
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
			service: &models.ServiceData{
				LocalID:    "test-123",
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
			name: "empty local ID",
			service: &models.ServiceData{
				LocalID:    "",
				Name:       "my-service",
				TunnelPort: 8080,
				LocalHost:  "localhost",
				LocalPort:  3000,
				Protocol:   "http",
			},
			expectError: true,
			errorMsg:    "local ID is required",
		},
		{
			name: "empty local host",
			service: &models.ServiceData{
				LocalID:    "test-123",
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
			service: &models.ServiceData{
				LocalID:    "test-123",
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
			service: &models.ServiceData{
				LocalID:    "test-123",
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
			service: &models.ServiceData{
				LocalID:    "test-123",
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
			service: &models.ServiceData{
				LocalID:    "test-123",
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
			name: "invalid status",
			service: &models.ServiceData{
				LocalID:    "test-123",
				Name:       "my-service",
				TunnelPort: 8080,
				LocalHost:  "localhost",
				LocalPort:  3000,
				Protocol:   "http",
				Status:     "pending",
			},
			expectError: true,
			errorMsg:    "invalid status",
		},
		{
			name: "empty status defaults to active",
			service: &models.ServiceData{
				LocalID:    "test-123",
				Name:       "my-service",
				TunnelPort: 8080,
				LocalHost:  "localhost",
				LocalPort:  3000,
				Protocol:   "http",
				Status:     "",
			},
			expectError: false,
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
				// Check that empty status was set to active
				if tt.service.Status == "" {
					assert.Equal(t, "active", tt.service.Status)
				}
			}
		})
	}
}
