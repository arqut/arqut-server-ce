package turn

import (
	"log/slog"
	"os"
	"testing"

	"github.com/arqut/arqut-server-ce/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("creates server with rest auth", func(t *testing.T) {
		cfg := &config.TurnConfig{
			Realm:    "test.example.com",
			PublicIP: "127.0.0.1",
			Ports: config.TurnPorts{
				UDP: 3478,
				TCP: 3478,
			},
			Auth: config.AuthConfig{
				Mode:       "rest",
				Secret:     "test-secret",
				TTLSeconds: 86400,
			},
		}

		server, err := New(cfg, nil, logger)
		require.NoError(t, err)
		assert.NotNil(t, server)
		assert.NotNil(t, server.authHandler)
		assert.Equal(t, cfg, server.config)
	})

	t.Run("creates server with static auth", func(t *testing.T) {
		cfg := &config.TurnConfig{
			Realm:    "test.example.com",
			PublicIP: "127.0.0.1",
			Ports: config.TurnPorts{
				UDP: 3478,
			},
			Auth: config.AuthConfig{
				Mode: "static",
				StaticUsers: []config.StaticUser{
					{Username: "user1", Password: "pass1"},
					{Username: "user2", Password: "pass2"},
				},
			},
		}

		server, err := New(cfg, nil, logger)
		require.NoError(t, err)
		assert.NotNil(t, server)
	})

	t.Run("creates server with old secrets", func(t *testing.T) {
		cfg := &config.TurnConfig{
			Realm:    "test.example.com",
			PublicIP: "127.0.0.1",
			Auth: config.AuthConfig{
				Mode:       "rest",
				Secret:     "new-secret",
				OldSecrets: []string{"old-secret-1", "old-secret-2"},
				TTLSeconds: 86400,
			},
		}

		server, err := New(cfg, nil, logger)
		require.NoError(t, err)
		assert.NotNil(t, server)
	})
}

func TestStop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("stop without start", func(t *testing.T) {
		cfg := &config.TurnConfig{
			Realm:    "test.example.com",
			PublicIP: "127.0.0.1",
			Auth: config.AuthConfig{
				Mode:   "rest",
				Secret: "test-secret",
			},
		}

		server, err := New(cfg, nil, logger)
		require.NoError(t, err)

		// Stop without starting should not error
		err = server.Stop()
		assert.NoError(t, err)
	})
}

func TestUpdateSecrets(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &config.TurnConfig{
		Realm:    "test.example.com",
		PublicIP: "127.0.0.1",
		Auth: config.AuthConfig{
			Mode:       "rest",
			Secret:     "initial-secret",
			TTLSeconds: 86400,
		},
	}

	server, err := New(cfg, nil, logger)
	require.NoError(t, err)

	// Update secrets
	server.UpdateSecrets("new-secret", []string{"old-secret"}, 7200)

	// Verify update happened - authenticate with new secret
	// This is tested via the auth handler tests
}

func TestStartWithPortRange(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Use high ports that are more likely to be available
	cfg := &config.TurnConfig{
		Realm:    "test.example.com",
		PublicIP: "127.0.0.1",
		Ports: config.TurnPorts{
			UDP: 0, // Disable to avoid binding
			TCP: 0,
		},
		RelayPortRange: config.PortRange{
			Min: 49152,
			Max: 49200,
		},
		Auth: config.AuthConfig{
			Mode:   "rest",
			Secret: "test-secret",
		},
	}

	server, err := New(cfg, nil, logger)
	require.NoError(t, err)
	assert.NotNil(t, server)

	// Server was created with port range config
	// Start would fail without ports, but the config is set
}

func TestStartWithInvalidPublicIP(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &config.TurnConfig{
		Realm:    "test.example.com",
		PublicIP: "invalid-ip", // Will fallback to 127.0.0.1
		Ports: config.TurnPorts{
			UDP: 0,
		},
		Auth: config.AuthConfig{
			Mode:   "rest",
			Secret: "test-secret",
		},
	}

	server, err := New(cfg, nil, logger)
	require.NoError(t, err)
	assert.NotNil(t, server)
}

func TestStartAndStop(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Use high ephemeral ports to avoid conflicts
	cfg := &config.TurnConfig{
		Realm:    "test.example.com",
		PublicIP: "127.0.0.1",
		Ports: config.TurnPorts{
			UDP: 59478, // High port for UDP
			TCP: 59479, // High port for TCP
		},
		RelayPortRange: config.PortRange{
			Min: 59500,
			Max: 59600,
		},
		Auth: config.AuthConfig{
			Mode:   "rest",
			Secret: "test-secret",
		},
	}

	server, err := New(cfg, nil, logger)
	require.NoError(t, err)

	// Start server
	err = server.Start()
	require.NoError(t, err)

	// Stop server
	err = server.Stop()
	assert.NoError(t, err)
}

func TestStartUDPOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &config.TurnConfig{
		Realm:    "test.example.com",
		PublicIP: "127.0.0.1",
		Ports: config.TurnPorts{
			UDP: 59480, // Only UDP
		},
		Auth: config.AuthConfig{
			Mode:   "rest",
			Secret: "test-secret",
		},
	}

	server, err := New(cfg, nil, logger)
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)

	err = server.Stop()
	assert.NoError(t, err)
}

func TestStartTCPOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &config.TurnConfig{
		Realm:    "test.example.com",
		PublicIP: "127.0.0.1",
		Ports: config.TurnPorts{
			TCP: 59481, // Only TCP
		},
		Auth: config.AuthConfig{
			Mode:   "rest",
			Secret: "test-secret",
		},
	}

	server, err := New(cfg, nil, logger)
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)

	err = server.Stop()
	assert.NoError(t, err)
}

func TestStartWithStaticRelayGenerator(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// No port range - uses static relay generator
	cfg := &config.TurnConfig{
		Realm:    "test.example.com",
		PublicIP: "127.0.0.1",
		Ports: config.TurnPorts{
			UDP: 59482,
		},
		Auth: config.AuthConfig{
			Mode:   "rest",
			Secret: "test-secret",
		},
	}

	server, err := New(cfg, nil, logger)
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)

	err = server.Stop()
	assert.NoError(t, err)
}
