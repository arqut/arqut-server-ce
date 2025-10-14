package middleware

import (
	"strings"

	"github.com/arqut/arqut-server-ce/internal/apikey"
	"github.com/gofiber/fiber/v2"
)

// APIError represents a structured API error (for middleware use)
type APIError struct {
	Code    int         `json:"code,omitempty"`
	Message string      `json:"message,omitempty"`
	Detail  interface{} `json:"detail,omitempty"`
}

// APIResponse is the standard API response structure (for middleware use)
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *APIError   `json:"error,omitempty"`
}

// ErrorUnauthorizedResp returns a 401 Unauthorized error response
func ErrorUnauthorizedResp(c *fiber.Ctx, message string) error {
	return c.Status(fiber.StatusUnauthorized).JSON(&APIResponse{
		Success: false,
		Error: &APIError{
			Code:    fiber.StatusUnauthorized,
			Message: message,
		},
	})
}

// APIKeyAuth creates a middleware that validates API key authentication
func APIKeyAuth(apiKeyHash string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get Authorization header
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return ErrorUnauthorizedResp(c, "Missing Authorization header")
		}

		// Check if it's Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			return ErrorUnauthorizedResp(c, "Invalid Authorization header format. Expected: Bearer <api_key>")
		}

		providedKey := parts[1]

		// Validate API key format
		if !apikey.ValidateFormat(providedKey) {
			return ErrorUnauthorizedResp(c, "Invalid API key format")
		}

		// Validate against hash
		if !apikey.Validate(providedKey, apiKeyHash) {
			return ErrorUnauthorizedResp(c, "Invalid API key")
		}

		// API key is valid, continue
		return c.Next()
	}
}
