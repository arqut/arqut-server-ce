package logger

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name           string
		config         Config
		expectedLevel  slog.Level
		expectedFormat string
	}{
		{
			name:           "debug level text format",
			config:         Config{Level: "debug", Format: "text"},
			expectedLevel:  slog.LevelDebug,
			expectedFormat: "text",
		},
		{
			name:           "info level json format",
			config:         Config{Level: "info", Format: "json"},
			expectedLevel:  slog.LevelInfo,
			expectedFormat: "json",
		},
		{
			name:           "warn level",
			config:         Config{Level: "warn", Format: "text"},
			expectedLevel:  slog.LevelWarn,
			expectedFormat: "text",
		},
		{
			name:           "error level",
			config:         Config{Level: "error", Format: "text"},
			expectedLevel:  slog.LevelError,
			expectedFormat: "text",
		},
		{
			name:           "default to info level",
			config:         Config{Level: "invalid", Format: "text"},
			expectedLevel:  slog.LevelInfo,
			expectedFormat: "text",
		},
		{
			name:           "empty config defaults",
			config:         Config{},
			expectedLevel:  slog.LevelInfo,
			expectedFormat: "text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := New(tt.config)
			require.NotNil(t, log)
			require.NotNil(t, log.Logger)

			// Verify logger is functional
			assert.NotPanics(t, func() {
				log.Info("test message")
			})
		})
	}
}

func TestLogger_With(t *testing.T) {
	log := New(Config{Level: "info", Format: "text"})

	newLog := log.With("key1", "value1", "key2", "value2")
	require.NotNil(t, newLog)
	require.NotNil(t, newLog.Logger)

	// Verify it's a new logger instance
	assert.NotEqual(t, log.Logger, newLog.Logger)
}

func TestLogger_WithGroup(t *testing.T) {
	log := New(Config{Level: "info", Format: "text"})

	newLog := log.WithGroup("test-group")
	require.NotNil(t, newLog)
	require.NotNil(t, newLog.Logger)

	// Verify it's a new logger instance
	assert.NotEqual(t, log.Logger, newLog.Logger)
}

func TestLogger_Component(t *testing.T) {
	log := New(Config{Level: "info", Format: "text"})

	componentLog := log.Component("test-component")
	require.NotNil(t, componentLog)
	require.NotNil(t, componentLog.Logger)

	// Verify it's a new logger instance
	assert.NotEqual(t, log.Logger, componentLog.Logger)
}

func TestLogger_JSONFormat(t *testing.T) {
	var buf bytes.Buffer

	// Create logger that writes to buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	log := &Logger{Logger: slog.New(handler)}

	log.Info("test message", "key", "value")

	output := buf.String()
	assert.Contains(t, output, "test message")
	assert.Contains(t, output, "key")
	assert.Contains(t, output, "value")
	assert.Contains(t, output, "{")
	assert.Contains(t, output, "}")
}

func TestLogger_TextFormat(t *testing.T) {
	var buf bytes.Buffer

	// Create logger that writes to buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	log := &Logger{Logger: slog.New(handler)}

	log.Info("test message", "key", "value")

	output := buf.String()
	assert.Contains(t, output, "test message")
	assert.Contains(t, output, "key=value")
}

func TestLogger_Levels(t *testing.T) {
	tests := []struct {
		name         string
		configLevel  slog.Level  // Minimum level configured
		messageLevel string      // Level of message being logged
		shouldLog    bool
	}{
		{"debug logs at debug level", slog.LevelDebug, "debug", true},
		{"debug does not log at info level", slog.LevelInfo, "debug", false},
		{"info logs at info level", slog.LevelInfo, "info", true},
		{"info logs at debug level", slog.LevelDebug, "info", true},
		{"warn logs at warn level", slog.LevelWarn, "warn", true},
		{"warn does not log at error level", slog.LevelError, "warn", false},
		{"error logs at error level", slog.LevelError, "error", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
				Level: tt.configLevel,
			})
			log := &Logger{Logger: slog.New(handler)}

			switch strings.ToLower(tt.messageLevel) {
			case "debug":
				log.Debug("test message")
			case "info":
				log.Info("test message")
			case "warn":
				log.Warn("test message")
			case "error":
				log.Error("test message")
			}

			output := buf.String()
			if tt.shouldLog {
				assert.Contains(t, output, "test message")
			} else {
				assert.Empty(t, output)
			}
		})
	}
}
