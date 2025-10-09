package main

import (
	"fmt"
	"os"

	"github.com/arqut/arqut-server-ce/internal/apikey"
	"github.com/arqut/arqut-server-ce/internal/config"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// handleAPIKeyCommand routes to the appropriate API key management command
func handleAPIKeyCommand() {
	if len(os.Args) < 3 {
		printAPIKeyUsage()
		os.Exit(1)
	}

	command := os.Args[2]
	configPath := "config.yaml"

	// Look for -config flag
	for i := 3; i < len(os.Args); i++ {
		if os.Args[i] == "-config" && i+1 < len(os.Args) {
			configPath = os.Args[i+1]
			break
		}
	}

	switch command {
	case "generate":
		generateAPIKey(configPath)
	case "rotate":
		rotateAPIKey(configPath)
	case "status":
		statusAPIKey(configPath)
	default:
		fmt.Fprintf(os.Stderr, "Unknown apikey command: %s\n\n", command)
		printAPIKeyUsage()
		os.Exit(1)
	}
}

func printAPIKeyUsage() {
	fmt.Println("Usage: arqut-server apikey <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  generate    Generate a new API key")
	fmt.Println("  rotate      Rotate (replace) the existing API key")
	fmt.Println("  status      Show API key status")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -config     Path to config file (default: config.yaml)")
}

func generateAPIKey(configPath string) {
	// Check if config file exists
	_, err := os.Stat(configPath)
	configExists := err == nil

	if !configExists {
		// Create default config file
		fmt.Printf("Config file not found. Creating default config at: %s\n", configPath)
		if err := os.WriteFile(configPath, []byte(config.DefaultConfigYAML), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating default config: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Default configuration created.")
		fmt.Println()
	} else {
		// Check if API key already exists
		cfg, err := loadConfigForAPIKey(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(1)
		}

		if cfg.API.APIKey.Hash != "" {
			fmt.Println("ERROR: An API key is already configured.")
			fmt.Println()
			fmt.Println("Use 'arqut-server apikey rotate' to replace it.")
			os.Exit(1)
		}
	}

	// Generate new API key
	key, hash, err := apikey.GenerateWithHash()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating API key: %v\n", err)
		os.Exit(1)
	}

	// Update config file
	if err := updateConfigWithAPIKey(configPath, hash, apikey.GetCreatedAt()); err != nil {
		fmt.Fprintf(os.Stderr, "Error updating config: %v\n", err)
		os.Exit(1)
	}

	// Set config file permissions to 0600
	if err := os.Chmod(configPath, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to set config file permissions: %v\n", err)
	}

	// Print success message
	fmt.Println("New API key generated:")
	fmt.Println()
	fmt.Printf("    %s\n", key)
	fmt.Println()
	fmt.Println("IMPORTANT: Save this key securely. It will not be shown again.")
	fmt.Printf("API key hash saved to: %s\n", configPath)
	fmt.Println()
	fmt.Println("The config file permissions have been set to 0600 (owner read/write only).")
}

func rotateAPIKey(configPath string) {
	// Check if API key exists
	cfg, err := loadConfigForAPIKey(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	if cfg.API.APIKey.Hash == "" {
		fmt.Println("ERROR: No API key is currently configured.")
		fmt.Println()
		fmt.Println("Use 'arqut-server apikey generate' to create one.")
		os.Exit(1)
	}

	fmt.Println("WARNING: This will invalidate the current API key.")
	fmt.Print("Are you sure you want to continue? (yes/no): ")

	var response string
	fmt.Scanln(&response)

	if response != "yes" {
		fmt.Println("Rotation cancelled.")
		os.Exit(0)
	}

	// Generate new API key
	key, hash, err := apikey.GenerateWithHash()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating API key: %v\n", err)
		os.Exit(1)
	}

	// Update config file
	if err := updateConfigWithAPIKey(configPath, hash, apikey.GetCreatedAt()); err != nil {
		fmt.Fprintf(os.Stderr, "Error updating config: %v\n", err)
		os.Exit(1)
	}

	// Print success message
	fmt.Println()
	fmt.Println("API key rotated successfully:")
	fmt.Println()
	fmt.Printf("    %s\n", key)
	fmt.Println()
	fmt.Println("IMPORTANT: Save this key securely. It will not be shown again.")
	fmt.Printf("API key hash saved to: %s\n", configPath)
	fmt.Println()
	fmt.Println("Remember to update all clients using the old API key.")
}

func statusAPIKey(configPath string) {
	cfg, err := loadConfigForAPIKey(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	if cfg.API.APIKey.Hash == "" {
		fmt.Println("Status: No API key configured")
		fmt.Println()
		fmt.Println("Generate an API key with:")
		fmt.Printf("    arqut-server apikey generate -config %s\n", configPath)
	} else {
		fmt.Println("Status: API key configured")
		if cfg.API.APIKey.CreatedAt != "" {
			fmt.Printf("Created: %s\n", cfg.API.APIKey.CreatedAt)
		}
		fmt.Printf("Hash: %s...\n", cfg.API.APIKey.Hash[:20])
	}
}

func loadConfigForAPIKey(configPath string) (*config.Config, error) {
	k := koanf.New(".")

	// Load config file
	if err := k.Load(file.Provider(configPath), yaml.Parser()); err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	var cfg config.Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

func updateConfigWithAPIKey(configPath, hash, createdAt string) error {
	// Load the current config as a map
	k := koanf.New(".")
	if err := k.Load(file.Provider(configPath), yaml.Parser()); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Update the api_key section
	k.Set("api.api_key.hash", hash)
	k.Set("api.api_key.created_at", createdAt)

	// Marshal back to YAML
	yamlBytes, err := k.Marshal(yaml.Parser())
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write back to file
	if err := os.WriteFile(configPath, yamlBytes, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}
