package acme

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/arqut/arqut-server-ce/internal/config"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
)

// setupHTTP01 sets up HTTP-01 challenge
func setupHTTP01(client *lego.Client, cfg *config.ACMEConfig, logger *slog.Logger) error {
	provider := http01.NewProviderServer("", cfg.HTTP01Listen)
	if err := client.Challenge.SetHTTP01Provider(provider); err != nil {
		return fmt.Errorf("setting HTTP-01 provider: %w", err)
	}

	logger.Info("ACME challenge configured", "type", "http-01", "listen", cfg.HTTP01Listen)
	return nil
}

// setupTLSALPN01 sets up TLS-ALPN-01 challenge
func setupTLSALPN01(client *lego.Client, cfg *config.ACMEConfig, logger *slog.Logger) error {
	provider := tlsalpn01.NewProviderServer("", cfg.TLSALPN01Listen)
	if err := client.Challenge.SetTLSALPN01Provider(provider); err != nil {
		return fmt.Errorf("setting TLS-ALPN-01 provider: %w", err)
	}

	logger.Info("ACME challenge configured", "type", "tls-alpn-01", "listen", cfg.TLSALPN01Listen)
	return nil
}

// setupDNS01 sets up DNS-01 challenge with dynamic provider
func setupDNS01(client *lego.Client, cfg *config.ACMEConfig, logger *slog.Logger) error {
	if cfg.DNSProvider == "" {
		return fmt.Errorf("DNS provider not specified")
	}

	// Store original environment variables for cleanup
	originalEnv := make(map[string]string)

	// Set environment variables from config
	for key, value := range cfg.DNSConfig {
		envKey := strings.ToUpper(key)

		// Store original value if it exists
		if originalValue, exists := os.LookupEnv(envKey); exists {
			originalEnv[envKey] = originalValue
		}

		// Set the new value
		if err := os.Setenv(envKey, value); err != nil {
			logger.Warn("Could not set environment variable", "key", envKey, "error", err)
		}
	}

	// Create the DNS provider dynamically
	provider, err := dns.NewDNSChallengeProviderByName(cfg.DNSProvider)
	if err != nil {
		// Restore original environment on error
		restoreEnvironment(originalEnv, logger)
		return fmt.Errorf("creating DNS provider '%s': %w\nSupported providers include: %v",
			cfg.DNSProvider, err, getAvailableProviders())
	}

	// Configure DNS propagation timeout
	if cfg.DNSPropagationTimeout != "" {
		os.Setenv("LEGO_DNS_PROPAGATION_TIMEOUT", cfg.DNSPropagationTimeout)
		logger.Info("DNS propagation timeout configured", "timeout", cfg.DNSPropagationTimeout)
	}

	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return fmt.Errorf("setting DNS-01 provider: %w", err)
	}

	logger.Info("ACME challenge configured", "type", "dns-01", "provider", cfg.DNSProvider)
	return nil
}

// restoreEnvironment restores original environment variables
func restoreEnvironment(originalEnv map[string]string, logger *slog.Logger) {
	for key, value := range originalEnv {
		if err := os.Setenv(key, value); err != nil {
			logger.Warn("Could not restore environment variable", "key", key, "error", err)
		}
	}
}

// getAvailableProviders returns a list of commonly available DNS providers
func getAvailableProviders() []string {
	return []string{
		"cloudflare", "route53", "gcloud", "digitalocean", "namecheap",
		"godaddy", "ovh", "linode", "vultr", "dnsimple", "dnsmadeeasy",
		"azure", "gandiv5", "inwx", "rackspace", "transip", "ionos",
		"hetzner", "hostingde", "netcup", "autodns", "servercow",
	}
}
