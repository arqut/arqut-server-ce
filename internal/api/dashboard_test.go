package api

import (
	"io"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServicesDashboard(t *testing.T) {
	server, _ := setupTestServer(t)

	t.Run("dashboard serves HTML page", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/dashboard/services", nil)
		resp, err := server.app.Test(req)
		require.NoError(t, err)

		assert.Equal(t, 200, resp.StatusCode)
		assert.Equal(t, "text/html; charset=utf-8", resp.Header.Get("Content-Type"))

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		// Verify it's HTML
		assert.Contains(t, string(body), "<!DOCTYPE html>")
		assert.Contains(t, string(body), "Arqut Services Dashboard")
		assert.Contains(t, string(body), "service-search")
	})

	t.Run("services API endpoint requires auth", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/services", nil)
		resp, err := server.app.Test(req)
		require.NoError(t, err)

		assert.Equal(t, 401, resp.StatusCode)
	})

	t.Run("services API endpoint exists", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/services", nil)
		resp, err := server.app.Test(req)
		require.NoError(t, err)

		// Should return 401 (unauthorized) not 404 (not found)
		assert.Equal(t, 401, resp.StatusCode)
	})
}

func TestEmbeddedHTML(t *testing.T) {
	t.Run("embedded HTML is not empty", func(t *testing.T) {
		assert.NotEmpty(t, servicesHTML)
		assert.Contains(t, string(servicesHTML), "<!DOCTYPE html>")
		assert.Contains(t, string(servicesHTML), "Arqut Services Dashboard")
	})

	t.Run("embedded HTML has required elements", func(t *testing.T) {
		html := string(servicesHTML)

		// Check for theme toggle
		assert.Contains(t, html, "toggleTheme")
		assert.Contains(t, html, "data-theme")

		// Check for API key modal
		assert.Contains(t, html, "api-key-input")
		assert.Contains(t, html, "saveAPIKey")
		assert.Contains(t, html, "clearAPIKey")
		assert.Contains(t, html, "API Authorization")
		assert.Contains(t, html, "openAuthModal")
		assert.Contains(t, html, "closeAuthModal")
		assert.Contains(t, html, "modal-overlay")

		// Check for authorize button
		assert.Contains(t, html, "authorize-btn")
		assert.Contains(t, html, "Authorize")

		// Check for filters
		assert.Contains(t, html, "edge-filter")
		assert.Contains(t, html, "service-search")
		assert.Contains(t, html, "status-filter")

		// Check for stats
		assert.Contains(t, html, "stat-total")
		assert.Contains(t, html, "stat-edges")
		assert.Contains(t, html, "stat-enabled")
		assert.Contains(t, html, "stat-filtered")

		// Check for API call with Authorization header
		assert.Contains(t, html, "/api/v1/services")
		assert.Contains(t, html, "Authorization")
		assert.Contains(t, html, "Bearer")
	})
}
