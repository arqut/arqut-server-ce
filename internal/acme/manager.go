package acme

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/arqut/arqut-server-ce/internal/config"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// Manager handles ACME certificate management
type Manager struct {
	config     *config.ACMEConfig
	domain     string
	email      string
	certDir    string
	logger     *slog.Logger
	client     *lego.Client
	certMutex  sync.RWMutex
	currentCert *tls.Certificate
	ctx        context.Context
	cancel     context.CancelFunc
}

// ACMEUser implements registration.User for lego
type ACMEUser struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	key          crypto.PrivateKey
}

func (u *ACMEUser) GetEmail() string                        { return u.Email }
func (u *ACMEUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *ACMEUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// New creates a new ACME manager
func New(acmeCfg *config.ACMEConfig, domain, email, certDir string, logger *slog.Logger) (*Manager, error) {
	if !acmeCfg.Enabled {
		logger.Info("ACME disabled, skipping certificate management")
		return nil, nil
	}

	ctx, cancel := context.WithCancel(context.Background())

	m := &Manager{
		config:  acmeCfg,
		domain:  domain,
		email:   email,
		certDir: certDir,
		logger:  logger.With("component", "acme"),
		ctx:     ctx,
		cancel:  cancel,
	}

	// Ensure cert directory exists
	if err := os.MkdirAll(certDir, 0755); err != nil {
		cancel()
		return nil, fmt.Errorf("creating cert directory: %w", err)
	}

	// Load or create ACME user
	user, err := m.loadOrCreateUser()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("setting up ACME user: %w", err)
	}

	// Create lego client
	legoConfig := lego.NewConfig(user)
	legoConfig.CADirURL = acmeCfg.CAURL
	legoConfig.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(legoConfig)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("creating ACME client: %w", err)
	}

	m.client = client

	// Set up challenge provider
	if err := m.setupChallenge(); err != nil {
		cancel()
		return nil, fmt.Errorf("setting up ACME challenge: %w", err)
	}

	// Obtain or load certificate
	if err := m.obtainCertificate(); err != nil {
		cancel()
		return nil, fmt.Errorf("obtaining certificate: %w", err)
	}

	m.logger.Info("ACME manager initialized successfully")

	return m, nil
}

// Start starts the certificate renewal loop
func (m *Manager) Start() {
	if m == nil {
		return
	}

	go m.renewalLoop()
	m.logger.Info("Certificate renewal loop started")
}

// Stop stops the ACME manager
func (m *Manager) Stop() {
	if m == nil {
		return
	}

	m.logger.Info("Stopping ACME manager")
	m.cancel()
}

// GetTLSConfig returns a TLS config with certificate hot-reloading
func (m *Manager) GetTLSConfig() *tls.Config {
	if m == nil {
		return nil
	}

	return &tls.Config{
		GetCertificate: m.getCertificate,
	}
}

// getCertificate returns the current certificate (for TLS config)
func (m *Manager) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.certMutex.RLock()
	defer m.certMutex.RUnlock()

	if m.currentCert == nil {
		return nil, fmt.Errorf("no certificate available")
	}

	return m.currentCert, nil
}

// loadOrCreateUser loads an existing ACME user or creates a new one
func (m *Manager) loadOrCreateUser() (*ACMEUser, error) {
	userFile := filepath.Join(m.certDir, "user.json")
	keyFile := filepath.Join(m.certDir, "user.key")

	// Try to load existing user
	if _, err := os.Stat(userFile); err == nil {
		userData, err := os.ReadFile(userFile)
		if err != nil {
			return nil, fmt.Errorf("reading user file: %w", err)
		}

		keyData, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("reading key file: %w", err)
		}

		var user ACMEUser
		if err := json.Unmarshal(userData, &user); err != nil {
			return nil, fmt.Errorf("unmarshaling user: %w", err)
		}

		// Parse the PEM-encoded private key
		block, _ := pem.Decode(keyData)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block from key file")
		}

		var privateKey crypto.PrivateKey
		switch block.Type {
		case "RSA PRIVATE KEY":
			privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case "PRIVATE KEY":
			privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			privateKey, err = x509.ParseECPrivateKey(block.Bytes)
		default:
			return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
		}

		if err != nil {
			return nil, fmt.Errorf("parsing private key: %w", err)
		}

		user.key = privateKey
		m.logger.Info("Loaded existing ACME user", "email", user.Email)
		return &user, nil
	}

	// Create new user
	m.logger.Info("Creating new ACME user", "email", m.email)

	privateKey, err := certcrypto.GeneratePrivateKey(certcrypto.RSA2048)
	if err != nil {
		return nil, fmt.Errorf("generating private key: %w", err)
	}

	user := &ACMEUser{
		Email: m.email,
		key:   privateKey,
	}

	// Create temporary client for registration
	tempConfig := lego.NewConfig(user)
	tempConfig.CADirURL = m.config.CAURL
	tempClient, err := lego.NewClient(tempConfig)
	if err != nil {
		return nil, fmt.Errorf("creating client for registration: %w", err)
	}

	// Register
	reg, err := tempClient.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("registering with ACME: %w", err)
	}
	user.Registration = reg

	// Save user and key
	userData, err := json.Marshal(user)
	if err != nil {
		return nil, fmt.Errorf("marshaling user: %w", err)
	}

	if err := os.WriteFile(userFile, userData, 0600); err != nil {
		return nil, fmt.Errorf("writing user file: %w", err)
	}

	// Encode private key as PEM
	keyBytes := certcrypto.PEMEncode(privateKey)
	if err := os.WriteFile(keyFile, keyBytes, 0600); err != nil {
		return nil, fmt.Errorf("writing key file: %w", err)
	}

	m.logger.Info("ACME user created and registered successfully")
	return user, nil
}

// setupChallenge sets up the ACME challenge provider
func (m *Manager) setupChallenge() error {
	switch m.config.Challenge {
	case "http-01":
		return setupHTTP01(m.client, m.config, m.logger)
	case "tls-alpn-01":
		return setupTLSALPN01(m.client, m.config, m.logger)
	case "dns-01":
		return setupDNS01(m.client, m.config, m.logger)
	default:
		return fmt.Errorf("unsupported challenge type: %s", m.config.Challenge)
	}
}

// obtainCertificate obtains or renews the certificate
func (m *Manager) obtainCertificate() error {
	certFile := filepath.Join(m.certDir, m.domain+".crt")
	keyFile := filepath.Join(m.certDir, m.domain+".key")

	// Check if we have a valid certificate
	if certData, err := os.ReadFile(certFile); err == nil {
		if keyData, err := os.ReadFile(keyFile); err == nil {
			if cert, err := tls.X509KeyPair(certData, keyData); err == nil {
				// Parse the certificate to check expiry
				if cert.Leaf == nil {
					if parsed, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
						cert.Leaf = parsed
					}
				}
				if cert.Leaf != nil && time.Until(cert.Leaf.NotAfter) > 30*24*time.Hour {
					m.certMutex.Lock()
					m.currentCert = &cert
					m.certMutex.Unlock()
					m.logger.Info("Using existing certificate", "expires", cert.Leaf.NotAfter)
					return nil
				}
			}
		}
	}

	// Obtain new certificate
	request := certificate.ObtainRequest{
		Domains: []string{m.domain},
		Bundle:  true,
	}

	m.logger.Info("Requesting certificate", "domain", m.domain)
	cert, err := m.client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("obtaining certificate: %w", err)
	}

	// Save certificate and key
	if err := os.WriteFile(certFile, cert.Certificate, 0644); err != nil {
		return fmt.Errorf("writing certificate: %w", err)
	}

	if err := os.WriteFile(keyFile, cert.PrivateKey, 0600); err != nil {
		return fmt.Errorf("writing private key: %w", err)
	}

	// Load into memory
	tlsCert, err := tls.X509KeyPair(cert.Certificate, cert.PrivateKey)
	if err != nil {
		return fmt.Errorf("loading certificate pair: %w", err)
	}

	// Parse the certificate to set Leaf and get expiry info
	var expiryTime time.Time
	if parsed, err := x509.ParseCertificate(tlsCert.Certificate[0]); err == nil {
		tlsCert.Leaf = parsed
		expiryTime = parsed.NotAfter
	}

	m.certMutex.Lock()
	m.currentCert = &tlsCert
	m.certMutex.Unlock()

	m.logger.Info("Certificate obtained successfully", "expires", expiryTime)
	return nil
}

// renewalLoop runs the certificate renewal loop
func (m *Manager) renewalLoop() {
	ticker := time.NewTicker(12 * time.Hour) // Check twice daily
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			if err := m.checkAndRenew(); err != nil {
				m.logger.Error("Certificate renewal check failed", "error", err)
			}
		}
	}
}

// checkAndRenew checks if renewal is needed and renews if necessary
func (m *Manager) checkAndRenew() error {
	m.certMutex.RLock()
	needsRenewal := false
	if m.currentCert != nil {
		if m.currentCert.Leaf != nil {
			needsRenewal = time.Until(m.currentCert.Leaf.NotAfter) < 30*24*time.Hour
		} else {
			// Parse the certificate if Leaf is not set
			if parsed, err := x509.ParseCertificate(m.currentCert.Certificate[0]); err == nil {
				needsRenewal = time.Until(parsed.NotAfter) < 30*24*time.Hour
			}
		}
	}
	m.certMutex.RUnlock()

	if needsRenewal {
		m.logger.Info("Certificate needs renewal")
		if err := m.obtainCertificate(); err != nil {
			return fmt.Errorf("renewing certificate: %w", err)
		}
		m.logger.Info("Certificate renewed successfully")

		// Log new expiry
		m.certMutex.RLock()
		if m.currentCert != nil && m.currentCert.Leaf != nil {
			m.logger.Info("New certificate expires", "expiry", m.currentCert.Leaf.NotAfter)
		}
		m.certMutex.RUnlock()
	}

	return nil
}
