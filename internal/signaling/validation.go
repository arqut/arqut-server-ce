package signaling

import (
	"fmt"
	"regexp"

	"github.com/arqut/arqut-server-ce/pkg/models"
)

var nameRegex = regexp.MustCompile(`^[a-zA-Z0-9 _-]+$`)

// validateService validates service data
func validateService(service *models.ServiceData) error {
	// Name: non-empty, max 255 chars, alphanumeric + hyphens/underscores
	if service.Name == "" {
		return fmt.Errorf("service name is required")
	}
	if len(service.Name) > 255 {
		return fmt.Errorf("service name too long (max 255 characters)")
	}
	if !nameRegex.MatchString(service.Name) {
		return fmt.Errorf("service name must contain only alphanumeric, hyphens, and underscores")
	}

	// LocalID: non-empty
	if service.LocalID == "" {
		return fmt.Errorf("local ID is required")
	}

	// LocalHost: non-empty
	if service.LocalHost == "" {
		return fmt.Errorf("local host is required")
	}

	// TunnelPort: 1-65535
	if service.TunnelPort < 1 || service.TunnelPort > 65535 {
		return fmt.Errorf("invalid tunnel port: %d (must be 1-65535)", service.TunnelPort)
	}

	// LocalPort: 1-65535
	if service.LocalPort < 1 || service.LocalPort > 65535 {
		return fmt.Errorf("invalid local port: %d (must be 1-65535)", service.LocalPort)
	}

	// Protocol: http|websocket
	validProtocols := map[string]bool{
		"http":      true,
		"websocket": true,
	}
	if !validProtocols[service.Protocol] {
		return fmt.Errorf("invalid protocol: %s (must be http or websocket)", service.Protocol)
	}

	// Status: active|inactive
	if service.Status != "" && service.Status != "active" && service.Status != "inactive" {
		return fmt.Errorf("invalid status: %s (must be active or inactive)", service.Status)
	}

	// Default to active if not specified
	if service.Status == "" {
		service.Status = "active"
	}

	return nil
}
