package middleware

import (
	"strings"

	"github.com/arqut/arqut-server-ce/internal/apikey"
	"github.com/gofiber/fiber/v2"
)

// Response represents the standard API response structure
type Response struct {
	Data    interface{} `json:"data,omitempty"`
	Error   interface{} `json:"error,omitempty"`
	Message string      `json:"message,omitempty"`
}

// MakeResponse creates a standard API response
func MakeResponse(data interface{}, err interface{}, message string) Response {
	return Response{
		Data:    data,
		Error:   err,
		Message: message,
	}
}

// APIKeyAuth creates a middleware that validates API key authentication
func APIKeyAuth(apiKeyHash string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get Authorization header
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(
				MakeResponse(nil, "Missing Authorization header", ""))
		}

		// Check if it's Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			return c.Status(fiber.StatusUnauthorized).JSON(
				MakeResponse(nil, "Invalid Authorization header format. Expected: Bearer <api_key>", ""))
		}

		providedKey := parts[1]

		// Validate API key format
		if !apikey.ValidateFormat(providedKey) {
			return c.Status(fiber.StatusUnauthorized).JSON(
				MakeResponse(nil, "Invalid API key format", ""))
		}

		// Validate against hash
		if !apikey.Validate(providedKey, apiKeyHash) {
			return c.Status(fiber.StatusUnauthorized).JSON(
				MakeResponse(nil, "Invalid API key", ""))
		}

		// API key is valid, continue
		return c.Next()
	}
}
