package middleware

import (
	"strings"

	"github.com/arqut/arqut-server-ce/internal/apikey"
	"github.com/gofiber/fiber/v2"
)

// APIKeyAuth creates a middleware that validates API key authentication
func APIKeyAuth(apiKeyHash string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get Authorization header
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Missing Authorization header",
			})
		}

		// Check if it's Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid Authorization header format. Expected: Bearer <api_key>",
			})
		}

		providedKey := parts[1]

		// Validate API key format
		if !apikey.ValidateFormat(providedKey) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid API key format",
			})
		}

		// Validate against hash
		if !apikey.Validate(providedKey, apiKeyHash) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid API key",
			})
		}

		// API key is valid, continue
		return c.Next()
	}
}
