# ArqTurn Server Setup Guide

Complete guide to setting up and running your ArqTurn server with automatic TLS certificates.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Initial Configuration](#initial-configuration)
4. [Domain and DNS Setup](#domain-and-dns-setup)
5. [Certificate Issuance](#certificate-issuance)
6. [Running the Server](#running-the-server)
7. [Testing Your Setup](#testing-your-setup)
8. [Production Deployment](#production-deployment)
9. [Troubleshooting](#troubleshooting)

## Prerequisites

### Server Requirements

- **OS**: Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+, or similar)
- **CPU**: 1+ cores (2+ recommended for production)
- **RAM**: 512MB minimum (2GB+ recommended for production)
- **Storage**: 1GB minimum
- **Go**: Version 1.24 or later (for building from source)

### Network Requirements

- **Public IP address**: Your server must be accessible from the internet
- **Open ports**:
  - `3478` - TURN UDP/TCP (required)
  - `5349` - TURN TLS/TURNS (required if using TLS)
  - `9000` - REST API + WebSocket (required)
  - `49152-65535` - Relay port range (required, configurable)
  - `80` - HTTP (temporary, for ACME HTTP-01 challenge)
  - `443` - HTTPS (optional, for TLS-ALPN-01 challenge)

### Domain Name

- A registered domain name (e.g., `yourdomain.com`)
- Access to DNS management
- Ability to create A/AAAA records

## Installation

### Option 1: Build from Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/arqut-server-ce.git
cd arqut-server-ce

# Build the server
make build

# Binary will be available at ./build/arqut-server
```

### Option 2: Download Pre-built Binary

```bash
# Download latest release
wget https://github.com/yourusername/arqut-server-ce/releases/latest/download/arqut-server-linux-amd64

# Make executable
chmod +x arqut-server-linux-amd64
sudo mv arqut-server-linux-amd64 /usr/local/bin/arqut-server
```

### Verify Installation

```bash
arqut-server --version
arqut-server --help
```

## Initial Configuration

### Step 1: Generate API Key

The server requires an API key for authentication. Generate one:

```bash
# Create config directory
mkdir -p /etc/arqut-server

# Generate API key (creates config.yaml)
arqut-server apikey generate -c /etc/arqut-server/config.yaml
```

**Output:**

```
New API key generated:

    arq_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

IMPORTANT: Save this key securely. It will not be shown again.
API key hash saved to: /etc/arqut-server/config.yaml
```

**IMPORTANT**: Copy and save this API key somewhere secure (password manager, encrypted file, etc.). You'll need it to access the REST API.

### Step 2: Configure Basic Settings

Edit the generated config file:

```bash
sudo nano /etc/arqut-server/config.yaml
```

Update these essential settings:

```yaml
# Your domain name
domain: "yourdomain.com"

# Your email for Let's Encrypt notifications
email: "admin@yourdomain.com"

# TURN server settings
turn:
  realm: "yourdomain.com"

  # YOUR PUBLIC IP ADDRESS (critical!)
  public_ip: "203.0.113.1" # Replace with your actual public IP

  # Ports configuration
  ports:
    udp: 3478
    tcp: 3478
    tls: 5349

  # Relay port range
  relay_port_range:
    min: 49152
    max: 65535

  # Authentication settings
  auth:
    mode: "rest"
    secret: "change-this-to-a-random-secret" # Generate with: openssl rand -base64 32
    ttl_seconds: 86400

# API settings
api:
  port: 9000
  cors_origins:
    - "https://yourdomain.com"
    - "http://localhost:3000" # For development

# Logging
logging:
  level: "info"
  format: "text"
```

### Step 3: Find Your Public IP

If you don't know your server's public IP:

```bash
curl ifconfig.me
# or
curl icanhazip.com
```

Update the `turn.public_ip` field in your config with this IP.

## Domain and DNS Setup

### Step 1: Choose a Subdomain

Pick a subdomain for your TURN server, typically:

- `turn.yourdomain.com` (recommended)
- `stun.yourdomain.com`
- `webrtc.yourdomain.com`

### Step 2: Create DNS Records

Log in to your DNS provider (Cloudflare, Route53, NameCheap, etc.) and create an **A record**:

| Type | Name | Value       | TTL |
| ---- | ---- | ----------- | --- |
| A    | turn | 203.0.113.1 | 300 |

Where:

- `203.0.113.1` is your server's public IP
- TTL of 300 (5 minutes) allows quick updates during setup

**For IPv6 support**, also add an AAAA record:

| Type | Name | Value       | TTL |
| ---- | ---- | ----------- | --- |
| AAAA | turn | 2001:db8::1 | 300 |

### Step 3: Verify DNS Propagation

Wait 5-10 minutes, then verify:

```bash
# Check A record
dig yourdomain.com A +short
# Should return: 203.0.113.1

# Check AAAA record (if using IPv6)
dig yourdomain.com AAAA +short

# Alternative using nslookup
nslookup yourdomain.com
```

**IMPORTANT**: Do not proceed until DNS resolves correctly! Certificate issuance will fail if DNS is not set up.

## Certificate Issuance

ArqTurn supports automatic TLS certificate issuance via Let's Encrypt using ACME. Choose the method that works best for your setup.

### Option 1: HTTP-01 Challenge (Easiest)

**Requirements:**

- Port 80 must be open and accessible from the internet
- DNS must point to your server

**Configuration:**

```yaml
acme:
  enabled: true
  challenge: "http-01"

# Rest of config...
domain: "yourdomain.com"
email: "admin@yourdomain.com"
```

**How it works:**

1. Server starts HTTP listener on port 80
2. Let's Encrypt sends challenge to `http://yourdomain.com/.well-known/acme-challenge/TOKEN`
3. Server responds with challenge response
4. Certificate issued and saved to `./certs/` directory

**Pros:**

- Simplest method
- No additional configuration needed
- Works with any DNS provider

**Cons:**

- Requires port 80 to be open
- Won't work if port 80 is already in use

### Option 2: TLS-ALPN-01 Challenge

**Requirements:**

- Port 443 must be open
- DNS must point to your server

**Configuration:**

```yaml
acme:
  enabled: true
  challenge: "tls-alpn-01"

domain: "yourdomain.com"
email: "admin@yourdomain.com"
```

**How it works:**

1. Server starts TLS listener on port 443
2. Let's Encrypt connects via TLS with special ALPN protocol
3. Server responds with challenge certificate
4. Certificate issued

**Pros:**

- No need for port 80
- Can work alongside other HTTPS services

**Cons:**

- Requires port 443 access
- Slightly more complex than HTTP-01

### Option 3: DNS-01 Challenge (Most Flexible)

**Requirements:**

- DNS provider API access
- API credentials from your DNS provider

**Supported DNS Providers:**

- Cloudflare
- Route53 (AWS)
- DigitalOcean
- Google Cloud DNS
- DNSimple
- And 40+ more (see [full list](https://go-acme.github.io/lego/dns/))

**Configuration Example (Cloudflare):**

```yaml
acme:
  enabled: true
  challenge: "dns-01"
  dns_provider: "cloudflare"
  dns_config:
    CLOUDFLARE_DNS_API_TOKEN: "your-api-token-here"
    CLOUDFLARE_ZONE_API_TOKEN: "your-zone-token-here"

domain: "yourdomain.com"
email: "admin@yourdomain.com"
```

**Configuration Example (AWS Route53):**

```yaml
acme:
  enabled: true
  challenge: "dns-01"
  dns_provider: "route53"
  dns_config:
    AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE"
    AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    AWS_REGION: "us-east-1"
```

**How it works:**

1. Server creates TXT record via DNS API
2. Let's Encrypt queries DNS for `_acme-challenge.yourdomain.com`
3. Server provides challenge response in TXT record
4. Certificate issued

**Pros:**

- No ports required beyond TURN ports
- Works behind firewalls/NAT
- Allows wildcard certificates
- Most reliable for complex network setups

**Cons:**

- Requires DNS provider API access
- Need to manage API credentials securely

#### Getting DNS Provider Credentials

**Cloudflare:**

1. Log in to Cloudflare dashboard
2. Go to "My Profile" → "API Tokens"
3. Create token with `Zone:DNS:Edit` permissions
4. Copy token to config

**AWS Route53:**

1. Create IAM user in AWS console
2. Attach policy: `AmazonRoute53FullAccess` (or custom with `route53:ChangeResourceRecordSets`)
3. Generate access key
4. Add to config

**DigitalOcean:**

1. Go to API section in DO control panel
2. Generate new token with write access
3. Add to config as `DO_AUTH_TOKEN`

### Testing Certificate Issuance (Staging)

Before using production Let's Encrypt (which has rate limits), test with staging:

```yaml
acme:
  enabled: true
  ca_url: "https://acme-staging-v02.api.letsencrypt.org/directory" # Staging
  challenge: "http-01"
```

Staging certificates won't be trusted by browsers but confirm your setup works.

### Certificate Storage

Certificates are stored in the `cert_dir` directory (default: `./certs/`):

```
certs/
├── yourdomain.com.crt      # Certificate
├── yourdomain.com.key      # Private key
└── yourdomain.com.json     # ACME metadata
```

**Set proper permissions:**

```bash
sudo chmod 700 /etc/arqut-server/certs
sudo chmod 600 /etc/arqut-server/certs/*
```

## Running the Server

### Development Mode

For testing and development:

```bash
arqut-server -c config.yaml
```

### Production Mode with Systemd

Create a systemd service for automatic startup and management:

**1. Create service file:**

```bash
sudo nano /etc/systemd/system/arqut-server.service
```

**2. Add service configuration:**

```ini
[Unit]
Description=ArqTurn TURN/STUN Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=arqut
Group=arqut
WorkingDirectory=/opt/arqut-server
ExecStart=/usr/local/bin/arqut-server -c /etc/arqut-server/config.yaml
Restart=always
RestartSec=10

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/arqut-server/certs /var/log/arqut-server

# Resource limits
LimitNOFILE=65536
LimitNPROC=512

[Install]
WantedBy=multi-user.target
```

**3. Create service user:**

```bash
sudo useradd -r -s /bin/false arqut
sudo mkdir -p /opt/arqut-server
sudo mkdir -p /var/log/arqut-server
sudo mkdir -p /etc/arqut-server/certs
sudo chown -R arqut:arqut /opt/arqut-server /var/log/arqut-server /etc/arqut-server
```

**4. Enable and start service:**

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable auto-start on boot
sudo systemctl enable arqut-server

# Start the service
sudo systemctl start arqut-server

# Check status
sudo systemctl status arqut-server
```

**5. View logs:**

```bash
# Follow logs in real-time
sudo journalctl -u arqut-server -f

# View recent logs
sudo journalctl -u arqut-server -n 100

# View logs since boot
sudo journalctl -u arqut-server -b
```

### Signal Handling

The server supports Unix signals for management:

```bash
# Graceful shutdown
sudo systemctl stop arqut-server
# or
kill -TERM $(pgrep arqut-server)

# Reload TURN secrets (no downtime)
kill -HUP $(pgrep arqut-server)
```

## Testing Your Setup

### 1. Check Server Health

```bash
curl http://localhost:9000/api/v1/health
```

Expected response:

```json
{
  "data": {
    "status": "ok",
    "time": "2025-01-11T10:00:00Z"
  }
}
```

### 2. Test TURN Credentials

```bash
export API_KEY="arq_your_api_key_here"

curl -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -X POST http://localhost:9000/api/v1/credentials \
  -d '{"peer_type":"client","peer_id":"test-123"}'
```

Expected response:

```json
{
  "data": {
    "username": "client:test-123:1736590800",
    "password": "base64-encoded-password",
    "ttl": 86400,
    "expires": "2025-01-12T10:00:00Z"
  }
}
```

### 3. Test TURN Server with Online Tools

Use [Trickle ICE](https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/):

1. Open https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/
2. Remove default servers
3. Add your TURN server:
   ```
   STUN: yourdomain.com:3478
   TURN: yourdomain.com:3478
   ```
4. Add credentials from step 2
5. Click "Gather candidates"
6. Look for `relay` candidates (indicates TURN is working)

### 4. Test with coturn Test Page

If you have the reference implementation, use the test page:

```bash
cd reference_projects/turn/local_test
python3 -m http.server 8000
```

Open `http://localhost:8000/turntest.html` in your browser.

### 5. Check TLS Certificate

If TLS is enabled:

```bash
# Check certificate validity
openssl s_client -connect yourdomain.com:5349 -servername yourdomain.com < /dev/null

# Verify certificate details
echo | openssl s_client -connect yourdomain.com:5349 -servername yourdomain.com 2>/dev/null | openssl x509 -noout -text
```

### 6. Test WebSocket Signaling

```bash
# Install wscat if needed
npm install -g wscat

# Connect to WebSocket
wscat -c "ws://localhost:9000/api/v1/signaling/ws/client?id=test-client"

# Should connect successfully
# Send a test message:
{"type":"ping"}
```

## Production Deployment

### Security Hardening

#### 1. Firewall Configuration

Using `ufw` (Ubuntu/Debian):

```bash
# Reset firewall
sudo ufw --force reset

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# SSH (adjust port if needed)
sudo ufw allow 22/tcp

# TURN/STUN
sudo ufw allow 3478/tcp
sudo ufw allow 3478/udp
sudo ufw allow 5349/tcp

# API/WebSocket
sudo ufw allow 9000/tcp

# Relay ports
sudo ufw allow 49152:65535/udp

# HTTP (for ACME HTTP-01 challenge)
sudo ufw allow 80/tcp

# Enable firewall
sudo ufw enable
```

Using `firewalld` (CentOS/RHEL):

```bash
# TURN/STUN
sudo firewall-cmd --permanent --add-port=3478/tcp
sudo firewall-cmd --permanent --add-port=3478/udp
sudo firewall-cmd --permanent --add-port=5349/tcp

# API
sudo firewall-cmd --permanent --add-port=9000/tcp

# Relay ports
sudo firewall-cmd --permanent --add-port=49152-65535/udp

# HTTP
sudo firewall-cmd --permanent --add-port=80/tcp

# Reload
sudo firewall-cmd --reload
```

#### 2. Rate Limiting

Add to your config:

```yaml
api:
  rate_limit:
    enabled: true
    requests_per_minute: 60
    burst: 10
```

#### 3. Restrict CORS Origins

```yaml
api:
  cors_origins:
    - "https://yourdomain.com"
    - "https://app.yourdomain.com"
  # Remove localhost origins in production
```

#### 4. Use Strong Secrets

Generate secure random secrets:

```bash
# TURN secret
openssl rand -base64 32

# Admin token
openssl rand -hex 32
```

Update config:

```yaml
turn:
  auth:
    secret: "your-generated-secret"

admin:
  token: "your-generated-admin-token"
```

#### 5. Certificate Permissions

```bash
sudo chown -R arqut:arqut /etc/arqut-server/certs
sudo chmod 700 /etc/arqut-server/certs
sudo chmod 600 /etc/arqut-server/certs/*
```

### Monitoring

#### Log Monitoring

```bash
# Set up log rotation
sudo nano /etc/logrotate.d/arqut-server
```

```
/var/log/arqut-server/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 arqut arqut
    sharedscripts
    postrotate
        systemctl reload arqut-server
    endscript
}
```

#### System Monitoring

Monitor key metrics:

- CPU usage
- Memory usage
- Network bandwidth
- Open file descriptors
- Active connections

```bash
# Check resource usage
sudo systemctl status arqut-server

# Check open files
sudo lsof -p $(pgrep arqut-server)

# Check network connections
sudo netstat -tunlp | grep arqut-server
```

### Backup

#### Configuration Backup

```bash
# Backup config
sudo cp /etc/arqut-server/config.yaml /etc/arqut-server/config.yaml.backup

# Automated daily backup
echo "0 2 * * * root cp /etc/arqut-server/config.yaml /etc/arqut-server/config.yaml.\$(date +\%Y\%m\%d)" | sudo tee -a /etc/crontab
```

#### Certificate Backup

Certificates auto-renew, but backup for disaster recovery:

```bash
sudo tar czf /backup/arqut-certs-$(date +%Y%m%d).tar.gz /etc/arqut-server/certs
```

## Troubleshooting

### Server Won't Start

**Check logs:**

```bash
sudo journalctl -u arqut-server -n 50
```

**Common issues:**

1. **Port already in use:**

   ```
   Error: listen tcp :3478: bind: address already in use
   ```

   Solution:

   ```bash
   # Find what's using the port
   sudo lsof -i :3478

   # Stop conflicting service or change port in config
   ```

2. **Permission denied:**

   ```
   Error: open /etc/arqut-server/certs: permission denied
   ```

   Solution:

   ```bash
   sudo chown -R arqut:arqut /etc/arqut-server
   sudo chmod 700 /etc/arqut-server/certs
   ```

3. **API key not configured:**

   ```
   ERROR: No API key configured
   ```

   Solution:

   ```bash
   arqut-server apikey generate -c /etc/arqut-server/config.yaml
   ```

### Certificate Issuance Fails

**HTTP-01 Challenge:**

1. **DNS not resolving:**

   ```bash
   dig yourdomain.com +short
   # Should return your IP
   ```

2. **Port 80 blocked:**

   ```bash
   # Test from external machine
   curl http://yourdomain.com

   # Check firewall
   sudo ufw status
   ```

3. **Rate limit hit:**
   - Wait 1 hour
   - Or use staging CA for testing

**DNS-01 Challenge:**

1. **Invalid API credentials:**

   - Double-check API token
   - Verify permissions

2. **DNS propagation slow:**
   - Wait 5-10 minutes
   - Check with `dig _acme-challenge.yourdomain.com TXT`

**General:**

```bash
# Enable debug logging
arqut-server -c config.yaml --log-level debug

# Check certificate files
ls -la /etc/arqut-server/certs/

# Manual certificate test with lego
lego --email admin@yourdomain.com \
     --domains yourdomain.com \
     --http \
     run
```

### TURN Not Working

**Test connectivity:**

```bash
# Test STUN
stunclient yourdomain.com 3478

# Test TURN with turnutils
turnutils_uclient -v -u "username" -w "password" yourdomain.com
```

**Common issues:**

1. **Wrong public IP:**

   ```bash
   # Verify public IP
   curl ifconfig.me

   # Update config
   turn:
     public_ip: "correct-ip-here"
   ```

2. **Firewall blocking UDP:**

   ```bash
   # Test UDP connectivity
   nc -u yourdomain.com 3478

   # Check firewall rules
   sudo ufw status verbose
   ```

3. **Relay ports blocked:**
   ```bash
   # Ensure relay port range is open
   sudo ufw allow 49152:65535/udp
   ```

### High CPU/Memory Usage

```bash
# Check resource usage
top -p $(pgrep arqut-server)

# Check connections
sudo netstat -an | grep ESTABLISHED | wc -l

# Adjust limits in config
signaling:
  max_peers_per_room: 5  # Reduce if needed
  session_timeout: 180s  # Shorter timeout

# Restart service
sudo systemctl restart arqut-server
```

### Certificate Not Renewing

Certificates auto-renew 30 days before expiry. Check:

```bash
# Check certificate expiry
echo | openssl s_client -connect yourdomain.com:5349 2>/dev/null | openssl x509 -noout -dates

# Check server logs for renewal attempts
sudo journalctl -u arqut-server | grep -i acme

# Manual renewal trigger
sudo systemctl restart arqut-server
```

### API Returns 401 Unauthorized

```bash
# Verify API key
arqut-server apikey status -c /etc/arqut-server/config.yaml

# Test with correct format
curl -H "Authorization: Bearer arq_your_key_here" \
  http://localhost:9000/api/v1/health
```

## Getting Help

- **Documentation**: [docs/](../)
- **API Reference**: [API.md](API.md)
- **Integration Guide**: [INTEGRATION.md](../INTEGRATION.md)
- **GitHub Issues**: Report bugs and request features
- **Community**: Join our Discord/Slack (if available)

## Next Steps

Once your server is running:

1. Read [API.md](API.md) for complete API documentation
2. Integrate with your application using the REST API
3. Set up monitoring and alerting
4. Configure automatic backups
5. Review logs regularly
6. Keep server updated

---

**Congratulations!** Your ArqTurn server is now set up and running with automatic TLS certificates.
