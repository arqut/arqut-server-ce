# ArqTurn Server - API Documentation

## Base URL

```
http://localhost:9000/api/v1
```

## Authentication

All protected endpoints require API key authentication using Bearer token:

```http
Authorization: Bearer arq_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Getting an API Key

```bash
./build/arqut-server apikey generate -c config.yaml
```

## Response Format

All API responses follow a standardized format with `success`, structured `error`, and optional `meta` fields.

### Success Response

```json
{
  "success": true,
  "data": {
    // Response data here
  },
  "meta": {
    "requestId": "optional-request-id",
    "timestamp": "2025-10-14T19:27:19Z",
    "pagination": {
      "page": 1,
      "perPage": 20,
      "total": 100,
      "totalPages": 5
    }
  }
}
```

### Error Response

```json
{
  "success": false,
  "error": {
    "code": 400,
    "message": "Error message here",
    "detail": "Optional additional error details"
  },
  "meta": {
    "requestId": "optional-request-id",
    "timestamp": "2025-10-14T19:27:19Z"
  }
}
```

### Response Structure Fields

- **`success`** (boolean): Indicates if the request was successful
- **`data`** (object, optional): Response data (present on success)
- **`error`** (object, optional): Error details (present on failure)
  - **`code`** (number): HTTP status code
  - **`message`** (string): Human-readable error message
  - **`detail`** (any, optional): Additional error context
- **`meta`** (object, optional): Response metadata
  - **`requestId`** (string, optional): Unique request identifier for tracking
  - **`timestamp`** (string, optional): Response timestamp (ISO 8601)
  - **`pagination`** (object, optional): Pagination info for list endpoints
  - **`ordering`** (object, optional): Sort order information

### Type Definitions

#### TypeScript

```typescript
interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: ApiError;
  meta?: ApiResponseMeta;
}

interface ApiError {
  code?: number;
  message?: string;
  detail?: any;
}

interface ApiResponseMeta {
  requestId?: string;
  timestamp?: string;
  pagination?: Pagination;
  ordering?: Record<string, any>;
}

interface Pagination {
  page: number;
  perPage: number;
  total: number;
  totalPages: number;
}
```

#### Go

```go
type ApiResponse struct {
    Success bool             `json:"success"`
    Data    interface{}      `json:"data,omitempty"`
    Error   *ApiError        `json:"error,omitempty"`
    Meta    *ApiResponseMeta `json:"meta,omitempty"`
}

type ApiError struct {
    Code    int         `json:"code,omitempty"`
    Message string      `json:"message,omitempty"`
    Detail  interface{} `json:"detail,omitempty"`
}

type ApiResponseMeta struct {
    RequestID  string      `json:"requestId,omitempty"`
    Timestamp  *time.Time  `json:"timestamp,omitempty"`
    Ordering   *Map        `json:"ordering,omitempty"`
    Pagination *Pagination `json:"pagination,omitempty"`
}

type Pagination struct {
    Page       int `json:"page"`
    PerPage    int `json:"perPage"`
    Total      int `json:"total"`
    TotalPages int `json:"totalPages"`
}
```

## Endpoints

### 1. Health Check

Check server health status.

**Endpoint**: `GET /health`

**Authentication**: None

**Response**:

```json
{
  "success": true,
  "data": {
    "status": "ok",
    "time": "2025-01-11T10:30:00Z"
  }
}
```

**Example**:

```bash
curl http://localhost:9000/api/v1/health
```

---

### 2. Generate TURN Credentials

Generate time-limited TURN credentials for a peer.

**Endpoint**: `POST /credentials`

**Authentication**: Required

**Request Body**:

```json
{
  "peer_type": "edge", // Required: "edge" or "client"
  "peer_id": "peer-123", // Required: Unique peer identifier
  "ttl": 86400 // Optional: Time-to-live in seconds (default: 86400)
}
```

**Response**:

```json
{
  "success": true,
  "data": {
    "username": "edge:peer-123:1736590800",
    "password": "iNL6ufmKb1BOo0R4qVAIYFyRpAfa6Br+fKTZYeMBSUI=",
    "ttl": 86400,
    "expires": "2025-01-12T10:00:00Z"
  }
}
```

**Errors**:

- `400 Bad Request` - Invalid peer_type or missing required fields
- `401 Unauthorized` - Missing or invalid API key

**Example**:

```bash
curl -X POST http://localhost:9000/api/v1/credentials \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "peer_type": "edge",
    "peer_id": "edge-001",
    "ttl": 3600
  }'
```

**Username Format**: `peerType:peerID:expiryTimestamp`

**Password**: Base64-encoded HMAC-SHA256(secret, username)

---

### 3. Get ICE Servers Configuration

Get complete ICE server configuration including STUN/TURN servers with credentials.

**Endpoint**: `GET /ice-servers`

**Authentication**: Required

**Query Parameters**:

- `peer_id` (required): Unique peer identifier
- `peer_type` (optional): "edge" or "client" (default: "client")

**Response**:

```json
{
  "success": true,
  "data": {
    "ice_servers": [
      {
        "urls": ["stun:turn.example.com:3478"]
      },
      {
        "urls": [
          "turn:turn.example.com:3478?transport=udp",
          "turn:turn.example.com:3478?transport=tcp"
        ],
        "username": "client:peer-123:1736590800",
        "credential": "6IlriZtE+2G0l0UqqqR2Vhh0Ata/Jyp94/PPlW+DVvY="
      },
      {
        "urls": ["turns:turn.example.com:5349?transport=tcp"],
        "username": "client:peer-123:1736590800",
        "credential": "6IlriZtE+2G0l0UqqqR2Vhh0Ata/Jyp94/PPlW+DVvY="
      }
    ],
    "expires": "2025-01-12T10:00:00Z"
  }
}
```

**Errors**:

- `400 Bad Request` - Missing peer_id parameter
- `401 Unauthorized` - Missing or invalid API key

**Example**:

```bash
curl "http://localhost:9000/api/v1/ice-servers?peer_id=peer-123&peer_type=client" \
  -H "Authorization: Bearer YOUR_API_KEY"
```

**Usage in WebRTC**:

```javascript
const response = await fetch(
  "http://localhost:9000/api/v1/ice-servers?peer_id=my-peer",
  {
    headers: {
      Authorization: "Bearer YOUR_API_KEY",
    },
  }
);
const { data } = await response.json();

const pc = new RTCPeerConnection({
  iceServers: data.ice_servers,
});
```

---

### 4. List Peers

Get list of all connected peers, optionally filtered by type.

**Endpoint**: `GET /peers`

**Authentication**: Required

**Query Parameters**:

- `type` (optional): Filter by peer type ("edge" or "client")

**Response**:

```json
{
  "success": true,
  "data": {
    "peers": [
      {
        "id": "edge-001",
        "type": "edge",
        "account_id": "account-123",
        "public_key": "ssh-rsa AAAA...",
        "edge_id": "",
        "connected": true,
        "last_ping": "2025-01-11T10:30:00Z",
        "created_at": "2025-01-11T10:00:00Z"
      },
      {
        "id": "client-001",
        "type": "client",
        "account_id": "account-123",
        "public_key": "",
        "edge_id": "edge-001",
        "connected": true,
        "last_ping": "2025-01-11T10:30:00Z",
        "created_at": "2025-01-11T10:15:00Z"
      }
    ],
    "count": 2
  }
}
```

**Errors**:

- `401 Unauthorized` - Missing or invalid API key

**Examples**:

```bash
# List all peers
curl http://localhost:9000/api/v1/peers \
  -H "Authorization: Bearer YOUR_API_KEY"

# List only edge peers
curl "http://localhost:9000/api/v1/peers?type=edge" \
  -H "Authorization: Bearer YOUR_API_KEY"

# List only client peers
curl "http://localhost:9000/api/v1/peers?type=client" \
  -H "Authorization: Bearer YOUR_API_KEY"
```

---

### 5. Get Peer by ID

Get detailed information about a specific peer.

**Endpoint**: `GET /peers/:id`

**Authentication**: Required

**Path Parameters**:

- `id` (required): Peer identifier

**Response**:

```json
{
  "success": true,
  "data": {
    "id": "edge-001",
    "type": "edge",
    "account_id": "account-123",
    "public_key": "ssh-rsa AAAA...",
    "edge_id": "",
    "connected": true,
    "last_ping": "2025-01-11T10:30:00Z",
    "created_at": "2025-01-11T10:00:00Z"
  }
}
```

**Errors**:

- `404 Not Found` - Peer not found
- `401 Unauthorized` - Missing or invalid API key

**Example**:

```bash
curl http://localhost:9000/api/v1/peers/edge-001 \
  -H "Authorization: Bearer YOUR_API_KEY"
```

---

### 6. Rotate TURN Secrets

Update TURN authentication secrets without restarting the server.

**Endpoint**: `POST /admin/secrets`

**Authentication**: Required

**Request Body**:

```json
{
  "secret": "new-secret-here",
  "old_secrets": ["old-secret-1", "old-secret-2"]
}
```

**Response**:

```json
{
  "success": true,
  "data": {
    "message": "Secrets rotation endpoint - to be implemented"
  }
}
```

**Note**: Currently returns a placeholder response. Full implementation requires TURN server instance integration.

**Errors**:

- `400 Bad Request` - Missing secret field
- `401 Unauthorized` - Missing or invalid API key

**Example**:

```bash
curl -X POST http://localhost:9000/api/v1/admin/secrets \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "secret": "new-secret-value",
    "old_secrets": ["old-secret-1"]
  }'
```

---

## WebSocket Signaling

### Connection

Connect to the WebSocket signaling server:

```
ws://localhost:9000/api/v1/signaling/ws/:type
```

**Path Parameters**:

- `type`: "edge" or "client"

**Query Parameters**:

- `id` (required): Unique peer identifier
- `edgeid` (required for clients): Edge server to connect through

**Examples**:

```javascript
// Edge peer connection
const ws = new WebSocket(
  "ws://localhost:9000/api/v1/signaling/ws/edge?id=edge-001"
);

// Client peer connection
const ws = new WebSocket(
  "ws://localhost:9000/api/v1/signaling/ws/client?id=client-001&edgeid=edge-001"
);
```

### Message Format

#### Peer List Update

Server broadcasts when peers connect/disconnect:

```json
{
  "type": "peer_list",
  "peers": ["peer-001", "peer-002"]
}
```

#### SDP Offer

```json
{
  "type": "offer",
  "from": "peer-001",
  "to": "peer-002",
  "sdp": "v=0\r\no=- ...",
  "ice_candidates": []
}
```

#### SDP Answer

```json
{
  "type": "answer",
  "from": "peer-002",
  "to": "peer-001",
  "sdp": "v=0\r\no=- ...",
  "ice_candidates": []
}
```

#### ICE Candidate

```json
{
  "type": "ice_candidate",
  "from": "peer-001",
  "to": "peer-002",
  "candidate": "candidate:..."
}
```

#### Error

```json
{
  "type": "error",
  "error": "Error message here"
}
```

---

## Error Codes

| Code | Description                               |
| ---- | ----------------------------------------- |
| 200  | Success                                   |
| 400  | Bad Request - Invalid parameters          |
| 401  | Unauthorized - Missing or invalid API key |
| 404  | Not Found - Resource not found            |
| 500  | Internal Server Error                     |

## Rate Limiting

Currently no rate limiting is implemented. This may be added in future versions.

## CORS

CORS origins are configured in `config.yaml`:

```yaml
api:
  cors_origins:
    - "http://localhost:3000"
    - "https://app.example.com"
```

## Best Practices

### API Key Security

1. Store API keys securely (environment variables, secrets manager)
2. Never commit API keys to version control
3. Rotate keys regularly
4. Use HTTPS in production

### TURN Credentials

1. Credentials are time-limited (default 24 hours)
2. Request new credentials before expiry
3. Each peer should have unique credentials
4. Monitor credential usage

### Peer Management

1. Clean up disconnected peers regularly
2. Monitor peer count for capacity planning
3. Implement reconnection logic in clients

### Error Handling

1. Always check response status codes
2. Handle authentication errors gracefully
3. Implement retry logic with exponential backoff
4. Log errors for debugging

## Examples

### Complete WebRTC Setup

```javascript
// 1. Get ICE servers configuration
async function getICEServers(peerId) {
  const response = await fetch(
    `http://localhost:9000/api/v1/ice-servers?peer_id=${peerId}`,
    {
      headers: {
        Authorization: "Bearer YOUR_API_KEY",
      },
    }
  );
  const result = await response.json();
  if (!result.success) {
    throw new Error(result.error.message);
  }
  return result.data.ice_servers;
}

// 2. Create peer connection
const iceServers = await getICEServers("my-peer-id");
const pc = new RTCPeerConnection({
  iceServers: iceServers,
});

// 3. Connect to signaling server
const ws = new WebSocket(
  "ws://localhost:9000/api/v1/signaling/ws/client?id=my-peer-id"
);

ws.onmessage = async (event) => {
  const msg = JSON.parse(event.data);

  switch (msg.type) {
    case "offer":
      await pc.setRemoteDescription(msg.sdp);
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      ws.send(
        JSON.stringify({
          type: "answer",
          to: msg.from,
          sdp: answer,
        })
      );
      break;

    case "ice_candidate":
      await pc.addIceCandidate(msg.candidate);
      break;
  }
};

// 4. Handle ICE candidates
pc.onicecandidate = (event) => {
  if (event.candidate) {
    ws.send(
      JSON.stringify({
        type: "ice_candidate",
        to: "target-peer-id",
        candidate: event.candidate,
      })
    );
  }
};
```
