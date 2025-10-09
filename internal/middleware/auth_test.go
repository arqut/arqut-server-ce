package middleware

import (
	"io"
	"net/http/httptest"
	"testing"

	"github.com/arqut/arqut-server-ce/internal/apikey"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIKeyAuth_Success(t *testing.T) {
	// Generate a valid API key
	key, hash, err := apikey.GenerateWithHash()
	require.NoError(t, err)

	// Create Fiber app with middleware
	app := fiber.New()
	app.Use(APIKeyAuth(hash))
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	// Create request with valid API key
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+key)

	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "success", string(body))
}

func TestAPIKeyAuth_MissingHeader(t *testing.T) {
	key, hash, err := apikey.GenerateWithHash()
	require.NoError(t, err)
	_ = key // Not used in this test

	app := fiber.New()
	app.Use(APIKeyAuth(hash))
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	// No Authorization header

	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestAPIKeyAuth_InvalidFormat(t *testing.T) {
	_, hash, err := apikey.GenerateWithHash()
	require.NoError(t, err)

	app := fiber.New()
	app.Use(APIKeyAuth(hash))
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	tests := []struct {
		name   string
		header string
	}{
		{
			name:   "missing Bearer prefix",
			header: "arq_1234567890123456789012345678901234567890123",
		},
		{
			name:   "wrong scheme",
			header: "Basic arq_1234567890123456789012345678901234567890123",
		},
		{
			name:   "empty bearer token",
			header: "Bearer ",
		},
		{
			name:   "malformed",
			header: "InvalidHeader",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", tt.header)

			resp, err := app.Test(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
		})
	}
}

func TestAPIKeyAuth_InvalidKey(t *testing.T) {
	_, hash, err := apikey.GenerateWithHash()
	require.NoError(t, err)

	app := fiber.New()
	app.Use(APIKeyAuth(hash))
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	// Generate a different key
	wrongKey, _, err := apikey.GenerateWithHash()
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+wrongKey)

	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestAPIKeyAuth_InvalidKeyFormat(t *testing.T) {
	_, hash, err := apikey.GenerateWithHash()
	require.NoError(t, err)

	app := fiber.New()
	app.Use(APIKeyAuth(hash))
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	// Key with invalid format
	invalidKey := "invalid_key_format"

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+invalidKey)

	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestAPIKeyAuth_MultipleRequests(t *testing.T) {
	key, hash, err := apikey.GenerateWithHash()
	require.NoError(t, err)

	app := fiber.New()
	app.Use(APIKeyAuth(hash))
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	// Make multiple requests with the same key
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+key)

		resp, err := app.Test(req)
		require.NoError(t, err)
		resp.Body.Close()

		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	}
}

func BenchmarkAPIKeyAuth(b *testing.B) {
	key, hash, err := apikey.GenerateWithHash()
	require.NoError(b, err)

	app := fiber.New()
	app.Use(APIKeyAuth(hash))
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("success")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, _ := app.Test(req)
		resp.Body.Close()
	}
}
