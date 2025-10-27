package signaling

import (
	"fmt"
	"regexp"

	"github.com/arqut/arqut-server-ce/internal/pkg/models"
)

var nameRegex = regexp.MustCompile(`^[a-zA-Z0-9 _-]+$`)

// validateService validates service data
func validateService(service *models.EdgeService) error {
	// ID: required, max 8 chars
	if service.ID == "" {
		return fmt.Errorf("service ID is required")
	}
	if len(service.ID) > 8 {
		return fmt.Errorf("service ID too long (max 8 characters)")
	}

	// EdgeID: required
	if service.EdgeID == "" {
		return fmt.Errorf("edge ID is required")
	}

	// Name: non-empty, max 128 chars, alphanumeric + hyphens/underscores/spaces
	if service.Name == "" {
		return fmt.Errorf("service name is required")
	}
	if len(service.Name) > 128 {
		return fmt.Errorf("service name too long (max 128 characters)")
	}
	if !nameRegex.MatchString(service.Name) {
		return fmt.Errorf("service name must contain only alphanumeric, hyphens, underscores, and spaces")
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

	return nil
}
