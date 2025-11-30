package config

import (
	"fmt"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// Config represents the complete server configuration
type Config struct {
	Domain  string `koanf:"domain"`
	Email   string `koanf:"email"`
	CertDir string `koanf:"cert_dir"`

	ACME      ACMEConfig      `koanf:"acme"`
	Turn      TurnConfig      `koanf:"turn"`
	Signaling SignalingConfig `koanf:"signaling"`
	API       APIConfig       `koanf:"api"`
	Admin     AdminConfig     `koanf:"admin"`
	Logging   LoggingConfig   `koanf:"logging"`
}

// ACMEConfig holds ACME/Let's Encrypt configuration
type ACMEConfig struct {
	Enabled               bool              `koanf:"enabled"`
	CAURL                 string            `koanf:"ca_url"`
	Challenge             string            `koanf:"challenge"`
	HTTP01Listen          string            `koanf:"http01_listen"`
	TLSALPN01Listen       string            `koanf:"tlsalpn01_listen"`
	DNSProvider           string            `koanf:"dns_provider"`
	DNSConfig             map[string]string `koanf:"dns_config"`
	DNSTimeout            string            `koanf:"dns_timeout"`
	DNSPropagationTimeout string            `koanf:"dns_propagation_timeout"`
}

// TurnConfig holds TURN/STUN server configuration
type TurnConfig struct {
	Realm    string     `koanf:"realm"`
	PublicIP string     `koanf:"public_ip"`
	Ports    TurnPorts  `koanf:"ports"`
	RelayPortRange PortRange `koanf:"relay_port_range"`
	Auth     AuthConfig `koanf:"auth"`
}

// TurnPorts defines TURN server port configuration
type TurnPorts struct {
	UDP int `koanf:"udp"`
	TCP int `koanf:"tcp"`
	TLS int `koanf:"tls"`
}

// PortRange defines a range of ports
type PortRange struct {
	Min int `koanf:"min"`
	Max int `koanf:"max"`
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	Mode        string   `koanf:"mode"`
	Secret      string   `koanf:"secret"`
	OldSecrets  []string `koanf:"old_secrets"`
	TTLSeconds  int      `koanf:"ttl_seconds"`
	StaticUsers []StaticUser `koanf:"static_users"`
}

// StaticUser represents a static username/password pair
type StaticUser struct {
	Username string `koanf:"username"`
	Password string `koanf:"password"`
}

// SignalingConfig holds WebRTC signaling configuration
type SignalingConfig struct {
	Ports           SignalingPorts `koanf:"ports"`
	MaxPeersPerRoom int            `koanf:"max_peers_per_room"`
	SessionTimeout  time.Duration  `koanf:"session_timeout"`
}

// SignalingPorts defines signaling server ports
type SignalingPorts struct {
	WS  int `koanf:"ws"`
	WSS int `koanf:"wss"`
}

// APIConfig holds REST API configuration
type APIConfig struct {
	Port        int      `koanf:"port"`
	CORSOrigins []string `koanf:"cors_origins"`
	APIKey      APIKeyConfig `koanf:"api_key"`
}

// APIKeyConfig holds API key configuration
type APIKeyConfig struct {
	Hash      string `koanf:"hash"`
	CreatedAt string `koanf:"created_at"`
}

// AdminConfig holds admin API configuration
type AdminConfig struct {
	Port  int    `koanf:"port"`
	Token string `koanf:"token"`
	Bind  string `koanf:"bind"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level  string `koanf:"level"`
	Format string `koanf:"format"`
}

// Load loads configuration from a YAML file
func Load(configPath string) (*Config, error) {
	k := koanf.New(".")

	// Load YAML config
	if err := k.Load(file.Provider(configPath), yaml.Parser()); err != nil {
		return nil, fmt.Errorf("loading config file: %w", err)
	}

	var cfg Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	// Apply defaults
	applyDefaults(&cfg)

	// Validate
	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return &cfg, nil
}

// applyDefaults sets default values for optional fields
func applyDefaults(cfg *Config) {
	if cfg.CertDir == "" {
		cfg.CertDir = "./certs"
	}

	// ACME defaults
	if cfg.ACME.Enabled {
		if cfg.ACME.CAURL == "" {
			cfg.ACME.CAURL = "https://acme-v02.api.letsencrypt.org/directory"
		}
		if cfg.ACME.Challenge == "" {
			cfg.ACME.Challenge = "http-01"
		}
		if cfg.ACME.HTTP01Listen == "" {
			cfg.ACME.HTTP01Listen = ":80"
		}
		if cfg.ACME.TLSALPN01Listen == "" {
			cfg.ACME.TLSALPN01Listen = ":443"
		}
		if cfg.ACME.DNSTimeout == "" {
			cfg.ACME.DNSTimeout = "60s"
		}
		if cfg.ACME.DNSPropagationTimeout == "" {
			cfg.ACME.DNSPropagationTimeout = "300s"
		}
	}

	// TURN defaults
	if cfg.Turn.Realm == "" {
		cfg.Turn.Realm = cfg.Domain
	}
	if cfg.Turn.Ports.UDP == 0 {
		cfg.Turn.Ports.UDP = 3478
	}
	if cfg.Turn.Ports.TCP == 0 {
		cfg.Turn.Ports.TCP = 3478
	}
	if cfg.Turn.Ports.TLS == 0 {
		cfg.Turn.Ports.TLS = 5349
	}
	if cfg.Turn.RelayPortRange.Min == 0 {
		cfg.Turn.RelayPortRange.Min = 49152
	}
	if cfg.Turn.RelayPortRange.Max == 0 {
		cfg.Turn.RelayPortRange.Max = 65535
	}
	if cfg.Turn.Auth.TTLSeconds == 0 {
		cfg.Turn.Auth.TTLSeconds = 86400
	}

	// Signaling defaults
	if cfg.Signaling.Ports.WS == 0 {
		cfg.Signaling.Ports.WS = 8080
	}
	if cfg.Signaling.Ports.WSS == 0 {
		cfg.Signaling.Ports.WSS = 8443
	}
	if cfg.Signaling.MaxPeersPerRoom == 0 {
		cfg.Signaling.MaxPeersPerRoom = 10
	}
	if cfg.Signaling.SessionTimeout == 0 {
		cfg.Signaling.SessionTimeout = 300 * time.Second
	}

	// API defaults
	if cfg.API.Port == 0 {
		cfg.API.Port = 9000
	}

	// Admin defaults
	if cfg.Admin.Port == 0 {
		cfg.Admin.Port = 9001
	}
	if cfg.Admin.Bind == "" {
		cfg.Admin.Bind = "127.0.0.1"
	}

	// Logging defaults
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "text"
	}
}

// validate checks the configuration for required fields and consistency
func validate(cfg *Config) error {
	if cfg.Domain == "" {
		return fmt.Errorf("domain is required")
	}

	if cfg.ACME.Enabled {
		if cfg.Email == "" {
			return fmt.Errorf("email is required when ACME is enabled")
		}
		if cfg.ACME.Challenge != "http-01" && cfg.ACME.Challenge != "tls-alpn-01" && cfg.ACME.Challenge != "dns-01" {
			return fmt.Errorf("invalid ACME challenge type: %s", cfg.ACME.Challenge)
		}
		if cfg.ACME.Challenge == "dns-01" && cfg.ACME.DNSProvider == "" {
			return fmt.Errorf("dns_provider is required for dns-01 challenge")
		}
	}

	if cfg.Turn.Auth.Mode != "rest" && cfg.Turn.Auth.Mode != "static" {
		return fmt.Errorf("invalid auth mode: %s (must be 'rest' or 'static')", cfg.Turn.Auth.Mode)
	}

	if cfg.Turn.Auth.Mode == "rest" && cfg.Turn.Auth.Secret == "" {
		return fmt.Errorf("auth secret is required for REST mode")
	}

	if cfg.Turn.Auth.Mode == "static" && len(cfg.Turn.Auth.StaticUsers) == 0 {
		return fmt.Errorf("at least one static user is required for static auth mode")
	}

	if cfg.Admin.Token == "" {
		return fmt.Errorf("admin token is required")
	}

	return nil
}
