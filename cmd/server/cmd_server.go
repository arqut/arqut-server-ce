package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/arqut/arqut-server-ce/internal/acme"
	"github.com/arqut/arqut-server-ce/internal/api"
	"github.com/arqut/arqut-server-ce/internal/config"
	"github.com/arqut/arqut-server-ce/internal/registry"
	"github.com/arqut/arqut-server-ce/internal/signaling"
	"github.com/arqut/arqut-server-ce/internal/storage"
	"github.com/arqut/arqut-server-ce/internal/turn"
	"github.com/arqut/arqut-server-ce/internal/pkg/logger"
)

// runServer starts the main server
func runServer() {
	// Load configuration
	cfg, err := config.Load(cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	log := logger.New(logger.Config{
		Level:  cfg.Logging.Level,
		Format: cfg.Logging.Format,
	})

	log.Info("Starting ArqTurn Server",
		"domain", cfg.Domain,
		"version", "0.1.0",
	)

	// Check API key configuration
	if cfg.API.APIKey.Hash == "" {
		log.Error("No API key configured in config.yaml")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "ERROR: No API key configured in config.yaml")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Generate an API key with:")
		fmt.Fprintf(os.Stderr, "    %s apikey generate -c %s\n", os.Args[0], cfgFile)
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "This will create a new API key and add it to your configuration.")
		os.Exit(1)
	}
	log.Info("API key validated", "created_at", cfg.API.APIKey.CreatedAt)

	// Initialize ACME manager (if enabled)
	acmeManager, err := acme.New(&cfg.ACME, cfg.Domain, cfg.Email, cfg.CertDir, log.Logger)
	if err != nil {
		log.Error("Failed to initialize ACME manager", "error", err)
		os.Exit(1)
	}
	if acmeManager != nil {
		acmeManager.Start()
		defer acmeManager.Stop()
	}

	// Get TLS config (nil if ACME disabled)
	var tlsConfig *tls.Config
	if acmeManager != nil {
		tlsConfig = acmeManager.GetTLSConfig()
	}

	// Initialize TURN server
	turnServer, err := turn.New(&cfg.Turn, tlsConfig, log.Logger)
	if err != nil {
		log.Error("Failed to initialize TURN server", "error", err)
		os.Exit(1)
	}

	if err := turnServer.Start(); err != nil {
		log.Error("Failed to start TURN server", "error", err)
		os.Exit(1)
	}
	defer turnServer.Stop()

	// Initialize peer registry
	peerRegistry := registry.New()

	// Initialize storage for service metadata
	dbPath := "data/services.db"

	// Ensure data directory exists
	if err := os.MkdirAll("data", 0o755); err != nil {
		log.Error("Failed to create data directory", "error", err)
		os.Exit(1)
	}

	store, err := storage.NewSQLiteStorage(dbPath)
	if err != nil {
		log.Error("Failed to initialize storage", "error", err)
		os.Exit(1)
	}
	if err := store.Init(); err != nil {
		log.Error("Failed to initialize database schema", "error", err)
		os.Exit(1)
	}
	defer store.Close()
	log.Info("Storage initialized", "path", dbPath)

	// Initialize signaling server (with TURN config and storage)
	signalingServer := signaling.New(&cfg.Signaling, &cfg.Turn, peerRegistry, store, log.Logger)
	signalingServer.Start()
	defer signalingServer.Stop()

	// Initialize REST API server (includes WebSocket signaling)
	apiServer := api.New(&cfg.API, &cfg.Turn, peerRegistry, store, signalingServer, tlsConfig, log.Logger)

	// Start unified HTTP/HTTPS server (REST API + WebSocket)
	if tlsConfig != nil {
		log.Info("Starting HTTPS server (REST API + WebSocket)", "port", cfg.API.Port)
	} else {
		log.Info("Starting HTTP server (REST API + WebSocket)", "port", cfg.API.Port)
	}
	go func() {
		if err := apiServer.Start(); err != nil {
			log.Error("HTTP server error", "error", err)
		}
	}()
	defer apiServer.Stop()

	log.Info("Server initialized successfully")

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Main loop
	for {
		sig := <-sigChan
		switch sig {
		case syscall.SIGHUP:
			log.Info("Received SIGHUP, reloading configuration")
			// Reload configuration
			newCfg, err := config.Load(cfgFile)
			if err != nil {
				log.Error("Failed to reload config", "error", err)
				continue
			}
			// Update TURN secrets
			turnServer.UpdateSecrets(
				newCfg.Turn.Auth.Secret,
				newCfg.Turn.Auth.OldSecrets,
				newCfg.Turn.Auth.TTLSeconds,
			)
			log.Info("Configuration reloaded successfully")

		case syscall.SIGINT, syscall.SIGTERM:
			log.Info("Received shutdown signal", "signal", sig)
			log.Info("Server stopped")
			return
		}
	}
}
