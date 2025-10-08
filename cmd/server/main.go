package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/arqut/arqut-server-ce/internal/acme"
	"github.com/arqut/arqut-server-ce/internal/config"
	"github.com/arqut/arqut-server-ce/internal/turn"
	"github.com/arqut/arqut-server-ce/pkg/logger"
)

func main() {
	// Parse command-line flags
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configPath)
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

	// TODO: Initialize remaining components
	// - Signaling server
	// - Peer registry
	// - REST API
	// - Admin API

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
			newCfg, err := config.Load(*configPath)
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
