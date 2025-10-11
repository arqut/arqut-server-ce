# ArqTurn Server - Community Edition

A self-contained WebRTC infrastructure server combining TURN/STUN, WebSocket signaling, and peer management in a single binary.

## Features

- **TURN/STUN Server** - Complete NAT traversal solution with UDP, TCP, and TLS support
- **WebSocket Signaling** - Built-in SDP/ICE exchange for WebRTC connections
- **Peer Registry** - Track and manage connected peers and sessions
- **REST API** - Credential generation, peer management, and ICE server configuration
- **Automatic TLS** - ACME/Let's Encrypt integration with auto-renewal
- **Secure by Default** - API key authentication with Argon2id hashing
- **Production Ready** - Graceful shutdown, hot reload, comprehensive logging

## Quick Start

### Installation

```bash
# Build from source
make build

# Generate API key (creates config.yaml)
./build/arqut-server apikey generate -c config.yaml

# Edit configuration
nano config.yaml

# Start server
./build/arqut-server -c config.yaml
```

### First-Time Setup

1. **Generate API Key**:
```bash
./build/arqut-server apikey generate -c config.yaml
```

Save the displayed API key securely - it won't be shown again.

2. **Configure** your domain and public IP in `config.yaml`:
```yaml
domain: "turn.yourdomain.com"
turn:
  public_ip: "YOUR_PUBLIC_IP"
```

3. **Enable TLS** (optional, recommended for production):
```yaml
acme:
  enabled: true
  challenge: "http-01"
email: "admin@yourdomain.com"
```

4. **Start Server**:
```bash
./build/arqut-server -c config.yaml
```

## API Usage

### Health Check
```bash
curl http://localhost:9000/api/v1/health
```

Response:
```json
{
  "data": {
    "status": "ok",
    "time": "2025-01-11T10:00:00Z"
  }
}
```

### Generate TURN Credentials
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -X POST http://localhost:9000/api/v1/credentials \
  -d '{"peer_type":"edge","peer_id":"peer-123"}'
```

Response:
```json
{
  "data": {
    "username": "edge:peer-123:1736590800",
    "password": "base64-encoded-hmac",
    "ttl": 86400,
    "expires": "2025-01-12T10:00:00Z"
  }
}
```

### Get ICE Servers Configuration
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  "http://localhost:9000/api/v1/ice-servers?peer_id=peer-123"
```

Response:
```json
{
  "data": {
    "ice_servers": [
      {
        "urls": ["stun:turn.yourdomain.com:3478"]
      },
      {
        "urls": [
          "turn:turn.yourdomain.com:3478?transport=udp",
          "turn:turn.yourdomain.com:3478?transport=tcp"
        ],
        "username": "edge:peer-123:1736590800",
        "credential": "base64-encoded-hmac"
      }
    ],
    "expires": "2025-01-12T10:00:00Z"
  }
}
```

### List Peers
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:9000/api/v1/peers
```

See [API Documentation](#api-reference) for full endpoint reference.

## WebSocket Signaling

Connect to WebSocket endpoint:
```
ws://localhost:9000/api/v1/signaling/ws/:type?id=peer-123
```

Where `:type` is either `edge` or `client`.

## Configuration

### Port Layout
- `3478` - TURN UDP/TCP
- `5349` - TURN TLS (TURNS)
- `9000` - REST API + WebSocket (unified)

### Sample Configuration
```yaml
domain: "turn.example.com"
email: "admin@example.com"

acme:
  enabled: false  # Set to true for automatic TLS

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
    secret: "change-this-secret"
    ttl_seconds: 86400

signaling:
  max_peers_per_room: 10
  session_timeout: 300s

api:
  port: 9000
  cors_origins:
    - "http://localhost:3000"
    - "https://app.example.com"

logging:
  level: "info"
  format: "text"
```

## API Key Management

### Generate New Key
```bash
./build/arqut-server apikey generate -c config.yaml
```

### Rotate Existing Key
```bash
./build/arqut-server apikey rotate -c config.yaml
```

### Check Status
```bash
./build/arqut-server apikey status -c config.yaml
```

## Development

### Build
```bash
make build          # Build to ./build/arqut-server
make test           # Run tests
make coverage-html  # Generate coverage report
```

### Test Coverage
```bash
make test           # Run all tests
make coverage       # Generate coverage report
make coverage-html  # Open HTML coverage report
```

Current coverage: 70%+ across all packages

## API Reference

### Authentication
All protected endpoints require API key authentication via Bearer token:
```
Authorization: Bearer YOUR_API_KEY
```

### Endpoints

#### Health Check
- **GET** `/api/v1/health`
- **Auth**: None
- **Response**: Server health status

#### Generate TURN Credentials
- **POST** `/api/v1/credentials`
- **Auth**: Required
- **Body**:
```json
{
  "peer_type": "edge|client",
  "peer_id": "string",
  "ttl": 86400  // optional
}
```
- **Response**: TURN username/password

#### Get ICE Servers
- **GET** `/api/v1/ice-servers?peer_id=XXX&peer_type=client`
- **Auth**: Required
- **Response**: Complete ICE server configuration

#### List Peers
- **GET** `/api/v1/peers?type=edge|client`
- **Auth**: Required
- **Response**: Array of connected peers

#### Get Peer
- **GET** `/api/v1/peers/:id`
- **Auth**: Required
- **Response**: Single peer details

#### Rotate TURN Secrets
- **POST** `/api/v1/admin/secrets`
- **Auth**: Required
- **Body**:
```json
{
  "secret": "new-secret",
  "old_secrets": ["old-secret-1"]
}
```
- **Response**: Confirmation

### Response Format
All responses follow a standardized format:
```json
{
  "data": { ... },      // Success data
  "error": "...",       // Error message (if any)
  "message": "..."      // Optional message
}
```

## Maintenance

### Signal Handling
- `SIGINT`/`SIGTERM` - Graceful shutdown
- `SIGHUP` - Reload TURN secrets without restart

### Reload Configuration
```bash
kill -HUP $(pgrep arqut-server)
```

### Logs
Structured JSON or text logging with configurable levels:
- `debug`, `info`, `warn`, `error`

## Security

### Best Practices
1. **Enable TLS** - Use ACME for automatic certificates
2. **Rotate Secrets** - Regularly rotate API keys and TURN secrets
3. **Restrict Access** - Use firewall rules and CORS configuration
4. **Monitor Logs** - Watch for suspicious activity
5. **Update Regularly** - Keep server updated with latest security patches

### API Key Storage
- Keys hashed with Argon2id (memory-hard, GPU-resistant)
- Config file permissions set to 0600 (owner read/write only)
- Constant-time comparison to prevent timing attacks
- No plaintext storage or logging

## Troubleshooting

### Server Won't Start
```bash
# Check config syntax
./build/arqut-server -c config.yaml --validate

# Check logs
./build/arqut-server -c config.yaml 2>&1 | tee server.log

# Verify API key exists
grep api_key config.yaml
```

### TURN Not Working
1. Check firewall allows UDP/TCP ports 3478, 5349
2. Verify `public_ip` is set correctly
3. Test with online TURN tester
4. Check relay port range is not blocked

### TLS Issues
1. Verify DNS points to your server
2. Check port 80 is open (for HTTP-01 challenge)
3. Review ACME logs in server output
4. Ensure email is configured

## Architecture

### Components
- **TURN Server** - Based on pion/turn library
- **ACME Manager** - Automatic certificate management
- **Signaling Server** - WebSocket-based SDP/ICE exchange
- **Peer Registry** - In-memory peer tracking
- **REST API** - Fiber-based HTTP server
- **Middleware** - Authentication, logging, CORS

### Data Flow
```
Client → REST API → Get ICE servers + TURN credentials
Client → WebSocket → Signaling → Peer Registry
Client → TURN/STUN → Media relay
```

## License

Community Edition - See LICENSE file for details

## Support

- Documentation: [docs/](docs/)
- Issues: GitHub Issues

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.
