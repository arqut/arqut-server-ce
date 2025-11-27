package turn

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"

	"github.com/arqut/arqut-server-ce/internal/config"
	"github.com/pion/turn/v4"
)

// Server represents the TURN server
type Server struct {
	config      *config.TurnConfig
	logger      *slog.Logger
	authHandler *AuthHandler
	turnServer  *turn.Server
	tlsConfig   *tls.Config
	ctx         context.Context
	cancel      context.CancelFunc
}

// New creates a new TURN server instance
func New(cfg *config.TurnConfig, tlsConfig *tls.Config, logger *slog.Logger) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Create static users map
	staticUsers := make(map[string]string)
	for _, user := range cfg.Auth.StaticUsers {
		staticUsers[user.Username] = user.Password
	}

	// Create auth handler
	authHandler := NewAuthHandler(
		cfg.Auth.Mode,
		cfg.Auth.Secret,
		cfg.Auth.OldSecrets,
		cfg.Auth.TTLSeconds,
		staticUsers,
		logger.With("component", "turn-auth"),
	)

	s := &Server{
		config:      cfg,
		logger:      logger.With("component", "turn"),
		authHandler: authHandler,
		tlsConfig:   tlsConfig,
		ctx:         ctx,
		cancel:      cancel,
	}

	return s, nil
}

// Start starts the TURN server
func (s *Server) Start() error {
	// Create relay address generator
	var relayAddressGenerator turn.RelayAddressGenerator

	if s.config.RelayPortRange.Min > 0 && s.config.RelayPortRange.Max > 0 {
		relayIP := net.ParseIP(s.config.PublicIP)
		if relayIP == nil {
			relayIP = net.ParseIP("127.0.0.1")
		}

		relayAddressGenerator = &turn.RelayAddressGeneratorPortRange{
			RelayAddress: relayIP,
			MinPort:      uint16(s.config.RelayPortRange.Min),
			MaxPort:      uint16(s.config.RelayPortRange.Max),
			Address:      relayIP.String(),
		}
		s.logger.Info("Using port range relay generator",
			"min", s.config.RelayPortRange.Min,
			"max", s.config.RelayPortRange.Max,
		)
	} else {
		relayIP := net.ParseIP(s.config.PublicIP)
		if relayIP == nil {
			relayIP = net.ParseIP("127.0.0.1")
		}

		relayAddressGenerator = &turn.RelayAddressGeneratorStatic{
			RelayAddress: relayIP,
			Address:      relayIP.String(),
		}
		s.logger.Info("Using static relay generator")
	}

	// Create packet conn configs for UDP
	var packetConnConfigs []turn.PacketConnConfig

	if s.config.Ports.UDP > 0 {
		// UDP4
		udpAddr := fmt.Sprintf("%s:%d", s.config.PublicIP, s.config.Ports.UDP)
		udpConn4, err := net.ListenPacket("udp4", udpAddr)
		if err != nil {
			return fmt.Errorf("creating UDP4 listener: %w", err)
		}

		packetConnConfigs = append(packetConnConfigs, turn.PacketConnConfig{
			PacketConn:            udpConn4,
			RelayAddressGenerator: relayAddressGenerator,
		})
		s.logger.Info("TURN UDP4 listener started", "addr", udpAddr)

		// Try UDP6 (non-fatal if it fails)
		udpConn6, err := net.ListenPacket("udp6", udpAddr)
		if err == nil {
			packetConnConfigs = append(packetConnConfigs, turn.PacketConnConfig{
				PacketConn:            udpConn6,
				RelayAddressGenerator: relayAddressGenerator,
			})
			s.logger.Info("TURN UDP6 listener started", "addr", udpAddr)
		} else {
			s.logger.Debug("IPv6 UDP not available", "error", err)
		}
	}

	// Create listener configs for TCP and TLS
	var listenerConfigs []turn.ListenerConfig

	// TCP listener
	if s.config.Ports.TCP > 0 {
		tcpAddr := fmt.Sprintf("%s:%d", s.config.PublicIP, s.config.Ports.TCP)

		// TCP4
		tcpListener4, err := net.Listen("tcp4", tcpAddr)
		if err != nil {
			return fmt.Errorf("creating TCP4 listener: %w", err)
		}

		listenerConfigs = append(listenerConfigs, turn.ListenerConfig{
			Listener:              tcpListener4,
			RelayAddressGenerator: relayAddressGenerator,
		})
		s.logger.Info("TURN TCP4 listener started", "addr", tcpAddr)

		// Try TCP6 (non-fatal if it fails)
		tcpListener6, err := net.Listen("tcp6", tcpAddr)
		if err == nil {
			listenerConfigs = append(listenerConfigs, turn.ListenerConfig{
				Listener:              tcpListener6,
				RelayAddressGenerator: relayAddressGenerator,
			})
			s.logger.Info("TURN TCP6 listener started", "addr", tcpAddr)
		} else {
			s.logger.Debug("IPv6 TCP not available", "error", err)
		}
	}

	// TLS listener
	if s.config.Ports.TLS > 0 && s.tlsConfig != nil {
		tlsAddr := fmt.Sprintf("%s:%d", s.config.PublicIP, s.config.Ports.TLS)

		tlsListener, err := tls.Listen("tcp4", tlsAddr, s.tlsConfig)
		if err != nil {
			return fmt.Errorf("creating TLS listener: %w", err)
		}

		// Use static relay generator for TLS
		tlsRelayGenerator := &turn.RelayAddressGeneratorStatic{
			RelayAddress: net.ParseIP(s.config.PublicIP),
			Address:      "0.0.0.0",
		}

		listenerConfigs = append(listenerConfigs, turn.ListenerConfig{
			Listener:              tlsListener,
			RelayAddressGenerator: tlsRelayGenerator,
		})
		s.logger.Info("TURNS TLS4 listener started", "addr", tlsAddr)
	}

	// Create TURN server config
	turnConfig := turn.ServerConfig{
		Realm:             s.config.Realm,
		AuthHandler:       s.authHandler.AuthenticateRequest,
		PacketConnConfigs: packetConnConfigs,
		ListenerConfigs:   listenerConfigs,
	}

	// Create and start TURN server
	turnServer, err := turn.NewServer(turnConfig)
	if err != nil {
		return fmt.Errorf("creating TURN server: %w", err)
	}

	s.turnServer = turnServer
	s.logger.Info("TURN server started successfully", "realm", s.config.Realm)

	return nil
}

// Stop gracefully stops the TURN server
func (s *Server) Stop() error {
	s.logger.Info("Stopping TURN server")
	s.cancel()

	if s.turnServer != nil {
		if err := s.turnServer.Close(); err != nil {
			s.logger.Error("Error closing TURN server", "error", err)
			return err
		}
	}

	s.logger.Info("TURN server stopped")
	return nil
}

// UpdateSecrets updates the authentication secrets
func (s *Server) UpdateSecrets(current string, old []string, ttl int) {
	s.authHandler.UpdateSecrets(current, old, ttl)
}
