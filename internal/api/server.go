package api

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/arqut/arqut-server-ce/internal/middleware"
	"github.com/arqut/arqut-server-ce/pkg/api"
	"github.com/arqut/arqut-server-ce/pkg/config"
	"github.com/arqut/arqut-server-ce/pkg/registry"
	"github.com/arqut/arqut-server-ce/pkg/signaling"
	"github.com/arqut/arqut-server-ce/pkg/storage"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

// SignalingServer interface to avoid circular dependency
type SignalingServer interface {
	RegisterRoutes(router fiber.Router, authMiddleware fiber.Handler)
}

// Server represents the REST API server
type Server struct {
	app       *fiber.App
	cfg       *config.APIConfig
	turnCfg   *config.TurnConfig
	registry  *registry.Registry
	storage   storage.ServiceStorage
	signaling SignalingServer
	tlsConfig *tls.Config
	logger    *slog.Logger
}

// New creates a new API server
func New(cfg *config.APIConfig, turnCfg *config.TurnConfig, reg *registry.Registry, storage storage.ServiceStorage, sig *signaling.Server, tlsConfig *tls.Config, log *slog.Logger) *Server {
	app := fiber.New(fiber.Config{
		AppName:               "ArqTurn REST API",
		DisableStartupMessage: true,
		ErrorHandler:          errorHandler,
	})

	// Global middleware
	app.Use(recover.New())
	app.Use(logger.New(logger.Config{
		Format:     "${time} ARQUT [INFO] [API] ${status} ${method} ${path} ${latency}\n",
		TimeFormat: "2006/01/02 15:04:05",
		CustomTags: map[string]logger.LogFunc{
			"time": func(output logger.Buffer, c *fiber.Ctx, data *logger.Data, extraParam string) (int, error) {
				return output.WriteString(time.Now().Format("2006/01/02 15:04:05"))
			},
		},
	}))

	// CORS middleware
	if len(cfg.CORSOrigins) > 0 {
		app.Use(cors.New(cors.Config{
			AllowOrigins: joinOrigins(cfg.CORSOrigins),
			AllowMethods: "GET,POST,PUT,DELETE",
			AllowHeaders: "Origin,Content-Type,Accept,Authorization",
		}))
	}

	s := &Server{
		app:       app,
		cfg:       cfg,
		turnCfg:   turnCfg,
		registry:  reg,
		storage:   storage,
		signaling: sig,
		tlsConfig: tlsConfig,
		logger:    log,
	}

	s.setupRoutes()

	return s
}

// setupRoutes configures all API routes
func (s *Server) setupRoutes() {
	// Services dashboard UI (public, outside API group)
	s.app.Get("/dashboard/services", s.handleServicesDashboard)

	// API v1 group
	api := s.app.Group("/api/v1")

	// Public endpoints (no auth)
	api.Get("/health", s.handleHealth)

	// Protected endpoints (require API key)
	protected := api.Group("", middleware.APIKeyAuth(s.cfg.APIKey.Hash))
	{
		// TURN credentials
		protected.Post("/credentials", s.handleGenerateCredentials)

		// ICE servers configuration
		protected.Get("/ice-servers", s.handleGetICEServers)

		// Peer management
		protected.Get("/peers", s.handleListPeers)
		protected.Get("/peers/:id", s.handleGetPeer)

		// Edge service management
		protected.Get("/edge/services", s.handleListServices)
		protected.Delete("/edge/services/:id", s.handleDeleteService)

		// Mobile app binding
		protected.Get("/mobile/binding", s.handleMobileBinding)
	}

	// Admin endpoints (require API key)
	admin := api.Group("/admin", middleware.APIKeyAuth(s.cfg.APIKey.Hash))
	{
		admin.Post("/secrets", s.handleRotateSecrets)
	}

	// WebSocket signaling routes (under /api/v1/signaling)
	if s.signaling != nil {
		s.signaling.RegisterRoutes(api, nil)
	}
}

// Start starts the API server
func (s *Server) Start() error {
	addr := fmt.Sprintf("0.0.0.0:%d", s.cfg.Port)

	// Use HTTPS if TLS config is available
	if s.tlsConfig != nil {
		s.logger.Info("Starting HTTPS server with TLS", "addr", addr)

		// Create TCP listener
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("failed to create listener: %w", err)
		}

		// Wrap with TLS
		tlsListener := tls.NewListener(ln, s.tlsConfig)
		return s.app.Listener(tlsListener)
	}

	// Fall back to HTTP
	s.logger.Info("Starting HTTP server (no TLS)", "addr", addr)
	return s.app.Listen(addr)
}

// Stop gracefully stops the API server
func (s *Server) Stop() error {
	s.logger.Info("Stopping REST API server")
	return s.app.Shutdown()
}

// App returns the underlying Fiber app (useful for testing)
func (s *Server) App() *fiber.App {
	return s.app
}

// errorHandler is the global error handler
func errorHandler(c *fiber.Ctx, err error) error {
	message := "Internal Server Error"
	if e, ok := err.(*fiber.Error); ok {
		message = e.Message
	}

	return api.ErrorInternalServerErrorResp(c, message)
}

// Helper functions
func joinOrigins(origins []string) string {
	result := ""
	for i, origin := range origins {
		if i > 0 {
			result += ","
		}
		result += origin
	}
	return result
}
