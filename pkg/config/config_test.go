package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name        string
		configYAML  string
		wantErr     bool
		errContains string
		validate    func(*testing.T, *Config)
	}{
		{
			name: "valid config with all fields",
			configYAML: `
domain: "turn.example.com"
email: "admin@example.com"
cert_dir: "./test-certs"

acme:
  enabled: true
  challenge: "dns-01"
  dns_provider: "cloudflare"

turn:
  realm: "example.com"
  public_ip: "1.2.3.4"
  ports:
    udp: 3478
    tcp: 3478
    tls: 5349
  relay_port_range:
    min: 49152
    max: 65535
  auth:
    mode: "rest"
    secret: "test-secret"
    ttl_seconds: 86400

signaling:
  ports:
    ws: 8080
    wss: 8443
  max_peers_per_room: 10
  session_timeout: 300s

api:
  port: 9000
  cors_origins: ["https://example.com"]

admin:
  port: 9001
  token: "admin-token"
  bind: "127.0.0.1"

logging:
  level: "debug"
  format: "json"
`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "turn.example.com", cfg.Domain)
				assert.Equal(t, "admin@example.com", cfg.Email)
				assert.Equal(t, "./test-certs", cfg.CertDir)
				assert.True(t, cfg.ACME.Enabled)
				assert.Equal(t, "dns-01", cfg.ACME.Challenge)
				assert.Equal(t, "rest", cfg.Turn.Auth.Mode)
				assert.Equal(t, "test-secret", cfg.Turn.Auth.Secret)
				assert.Equal(t, 86400, cfg.Turn.Auth.TTLSeconds)
				assert.Equal(t, 300*time.Second, cfg.Signaling.SessionTimeout)
				assert.Equal(t, "debug", cfg.Logging.Level)
			},
		},
		{
			name: "minimal config with defaults",
			configYAML: `
domain: "turn.test.com"
email: "test@test.com"

turn:
  auth:
    mode: "rest"
    secret: "secret"

admin:
  token: "token"
`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				// Check defaults
				assert.Equal(t, "./certs", cfg.CertDir)
				assert.Equal(t, 3478, cfg.Turn.Ports.UDP)
				assert.Equal(t, 3478, cfg.Turn.Ports.TCP)
				assert.Equal(t, 5349, cfg.Turn.Ports.TLS)
				assert.Equal(t, 49152, cfg.Turn.RelayPortRange.Min)
				assert.Equal(t, 65535, cfg.Turn.RelayPortRange.Max)
				assert.Equal(t, 86400, cfg.Turn.Auth.TTLSeconds)
				assert.Equal(t, 8080, cfg.Signaling.Ports.WS)
				assert.Equal(t, 8443, cfg.Signaling.Ports.WSS)
				assert.Equal(t, 10, cfg.Signaling.MaxPeersPerRoom)
				assert.Equal(t, 300*time.Second, cfg.Signaling.SessionTimeout)
				assert.Equal(t, 9000, cfg.API.Port)
				assert.Equal(t, 9001, cfg.Admin.Port)
				assert.Equal(t, "127.0.0.1", cfg.Admin.Bind)
				assert.Equal(t, "info", cfg.Logging.Level)
				assert.Equal(t, "text", cfg.Logging.Format)
			},
		},
		{
			name: "static auth mode",
			configYAML: `
domain: "turn.test.com"
email: "test@test.com"

turn:
  auth:
    mode: "static"
    static_users:
      - username: "user1"
        password: "pass1"
      - username: "user2"
        password: "pass2"

admin:
  token: "token"
`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "static", cfg.Turn.Auth.Mode)
				assert.Len(t, cfg.Turn.Auth.StaticUsers, 2)
				assert.Equal(t, "user1", cfg.Turn.Auth.StaticUsers[0].Username)
				assert.Equal(t, "pass1", cfg.Turn.Auth.StaticUsers[0].Password)
			},
		},
		{
			name:        "missing domain",
			configYAML:  `email: "test@test.com"`,
			wantErr:     true,
			errContains: "domain is required",
		},
		{
			name: "missing email with ACME enabled",
			configYAML: `
domain: "turn.test.com"
acme:
  enabled: true
`,
			wantErr:     true,
			errContains: "email is required when ACME is enabled",
		},
		{
			name: "invalid ACME challenge",
			configYAML: `
domain: "turn.test.com"
email: "test@test.com"
acme:
  enabled: true
  challenge: "invalid"
`,
			wantErr:     true,
			errContains: "invalid ACME challenge type",
		},
		{
			name: "dns-01 without provider",
			configYAML: `
domain: "turn.test.com"
email: "test@test.com"
acme:
  enabled: true
  challenge: "dns-01"
`,
			wantErr:     true,
			errContains: "dns_provider is required for dns-01 challenge",
		},
		{
			name: "invalid auth mode",
			configYAML: `
domain: "turn.test.com"
email: "test@test.com"
turn:
  auth:
    mode: "invalid"
admin:
  token: "token"
`,
			wantErr:     true,
			errContains: "invalid auth mode",
		},
		{
			name: "rest mode without secret",
			configYAML: `
domain: "turn.test.com"
email: "test@test.com"
turn:
  auth:
    mode: "rest"
admin:
  token: "token"
`,
			wantErr:     true,
			errContains: "auth secret is required for REST mode",
		},
		{
			name: "static mode without users",
			configYAML: `
domain: "turn.test.com"
email: "test@test.com"
turn:
  auth:
    mode: "static"
admin:
  token: "token"
`,
			wantErr:     true,
			errContains: "at least one static user is required",
		},
		{
			name: "missing admin token",
			configYAML: `
domain: "turn.test.com"
email: "test@test.com"
turn:
  auth:
    mode: "rest"
    secret: "secret"
`,
			wantErr:     true,
			errContains: "admin token is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp config file
			tmpFile, err := os.CreateTemp("", "config-*.yaml")
			require.NoError(t, err)
			defer os.Remove(tmpFile.Name())

			_, err = tmpFile.WriteString(tt.configYAML)
			require.NoError(t, err)
			tmpFile.Close()

			// Load config
			cfg, err := Load(tmpFile.Name())

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, cfg)
				if tt.validate != nil {
					tt.validate(t, cfg)
				}
			}
		})
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("nonexistent.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loading config file")
}

func TestLoad_InvalidYAML(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString("invalid: yaml: content: [")
	require.NoError(t, err)
	tmpFile.Close()

	_, err = Load(tmpFile.Name())
	require.Error(t, err)
}

func TestApplyDefaults(t *testing.T) {
	cfg := &Config{
		Domain: "test.com",
		Email:  "test@test.com",
	}

	applyDefaults(cfg)

	// Test defaults
	assert.Equal(t, "./certs", cfg.CertDir)
	assert.Equal(t, 3478, cfg.Turn.Ports.UDP)
	assert.Equal(t, 3478, cfg.Turn.Ports.TCP)
	assert.Equal(t, 5349, cfg.Turn.Ports.TLS)
	assert.Equal(t, 86400, cfg.Turn.Auth.TTLSeconds)
	assert.Equal(t, "info", cfg.Logging.Level)
	assert.Equal(t, "text", cfg.Logging.Format)
}

func TestApplyDefaults_ACMEEnabled(t *testing.T) {
	cfg := &Config{
		Domain: "test.com",
		Email:  "test@test.com",
		ACME: ACMEConfig{
			Enabled: true,
		},
	}

	applyDefaults(cfg)

	// Test ACME defaults
	assert.Equal(t, "https://acme-v02.api.letsencrypt.org/directory", cfg.ACME.CAURL)
	assert.Equal(t, "http-01", cfg.ACME.Challenge)
	assert.Equal(t, ":80", cfg.ACME.HTTP01Listen)
	assert.Equal(t, ":443", cfg.ACME.TLSALPN01Listen)
	assert.Equal(t, "60s", cfg.ACME.DNSTimeout)
	assert.Equal(t, "300s", cfg.ACME.DNSPropagationTimeout)
}

func TestApplyDefaults_RealmFromDomain(t *testing.T) {
	cfg := &Config{
		Domain: "turn.example.com",
		Turn: TurnConfig{
			Realm: "",
		},
	}

	applyDefaults(cfg)

	assert.Equal(t, "turn.example.com", cfg.Turn.Realm)
}
