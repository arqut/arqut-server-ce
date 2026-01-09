package config

// DefaultConfigYAML is the default configuration template
const DefaultConfigYAML = `domain: "turn.example.com"
email: "admin@example.com"
cert_dir: "./certs"

acme:
  enabled: false
  challenge: "http-01"
  # ca_url: "https://acme-v02.api.letsencrypt.org/directory"
  # For DNS challenge:
  # challenge: "dns-01"
  # dns_provider: "cloudflare"
  # dns_config:
  #   CF_API_TOKEN: "your-token"

turn:
  realm: "example.com"
  public_ip: "127.0.0.1"
  ports:
    udp: 3478
    tcp: 3478
    tls: 5349
  relay_port_range:
    min: 49152
    max: 65535
  auth:
    mode: "rest"
    secret: "change-this-secret-in-production"
    ttl_seconds: 86400

signaling:
  max_peers_per_room: 10
  session_timeout: 300s

api:
  port: 9000  # Unified HTTP/HTTPS port for REST API and WebSocket signaling
              # Supports both WS (ws://) and WSS (wss://) when TLS is enabled
  cors_origins:
    - "http://localhost:3000"
    - "https://app.example.com"

admin:
  port: 9001
  token: "change-this-admin-token"
  bind: "127.0.0.1"

logging:
  level: "info"
  format: "text"
`
