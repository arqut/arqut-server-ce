package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/arqut/arqut-server-ce/internal/config"
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

	// TODO: Initialize components
	// - ACME manager
	// - TURN server
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
			// TODO: Implement config reload
		case syscall.SIGINT, syscall.SIGTERM:
			log.Info("Received shutdown signal", "signal", sig)
			// TODO: Graceful shutdown
			log.Info("Server stopped")
			return
		}
	}
}
