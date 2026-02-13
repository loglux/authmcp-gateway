# AuthMCP Gateway - API Documentation

Complete API reference for developers integrating AuthMCP Gateway into their applications.

## Table of Contents

- [Authentication](#authentication)
- [Usage Examples](#usage-examples)
- [API Endpoints](#api-endpoints)
- [MCP Protocol](#mcp-protocol)
- [Error Handling](#error-handling)

---

## Authentication

AuthMCP Gateway supports multiple authentication methods:

### OAuth2 with PKCE

Recommended for web applications and clients like Claude.ai.

**Authorization Flow:**

1. **Authorization Request:**
   ```
   GET /authorize?
     response_type=code&
     client_id=your-client-id&
     redirect_uri=https://your-app.com/callback&
     scope=openid profile email&
     code_challenge=BASE64URL(SHA256(code_verifier))&
     code_challenge_method=S256
   ```

2. **Token Request:**
   ```
   POST /oauth/token
   Content-Type: application/json
   
   {
     "grant_type": "authorization_code",
     "code": "authorization-code",
     "redirect_uri": "https://your-app.com/callback",
     "code_verifier": "your-code-verifier"
   }
   ```

3. **Response:**
   ```json
   {
     "access_token": "eyJhbGciOiJIUzI1NiIs...",
     "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
     "token_type": "Bearer",
     "expires_in": 1800
   }
   ```

### Password Grant (Resource Owner)

For server-to-server communication and testing.

```bash
POST /oauth/token
Content-Type: application/json

{
  "grant_type": "password",
  "username": "your-username",
  "password": "your-password"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 1800
}
```

### Refresh Token

Renew access token without re-authentication:

```bash
POST /auth/refresh
Content-Type: application/json

{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

---

## Usage Examples

### Python Client

```python
import httpx

class AuthMCPClient:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.access_token = None
        self.refresh_token = None
    
    def login(self, username: str, password: str):
        """Authenticate and get tokens."""
        response = httpx.post(
            f"{self.base_url}/oauth/token",
            json={
                "grant_type": "password",
                "username": username,
                "password": password
            }
        )
        response.raise_for_status()
        data = response.json()
        
        self.access_token = data["access_token"]
        self.refresh_token = data["refresh_token"]
        return data
    
    def list_tools(self):
        """List all available MCP tools."""
        response = httpx.post(
            f"{self.base_url}/mcp",
            headers={"Authorization": f"Bearer {self.access_token}"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {}
            }
        )
        response.raise_for_status()
        return response.json()["result"]["tools"]
    
    def call_tool(self, tool_name: str, arguments: dict):
        """Call a specific MCP tool."""
        response = httpx.post(
            f"{self.base_url}/mcp",
            headers={"Authorization": f"Bearer {self.access_token}"},
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": arguments
                }
            }
        )
        response.raise_for_status()
        return response.json()["result"]

# Usage
client = AuthMCPClient("https://your-domain.com")
client.login("username", "password")

# List available tools
tools = client.list_tools()
print(f"Available tools: {len(tools)}")

# Call a tool
result = client.call_tool("rag_query", {"query": "What is MCP?"})
print(result)
```

### JavaScript/TypeScript

```typescript
interface AuthTokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

class AuthMCPClient {
  private baseUrl: string;
  private accessToken?: string;
  private refreshToken?: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  async login(username: string, password: string): Promise<AuthTokens> {
    const response = await fetch(`${this.baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'password',
        username,
        password
      })
    });

    if (!response.ok) {
      throw new Error(`Login failed: ${response.statusText}`);
    }

    const tokens: AuthTokens = await response.json();
    this.accessToken = tokens.access_token;
    this.refreshToken = tokens.refresh_token;
    return tokens;
  }

  async listTools(): Promise<any[]> {
    const response = await fetch(`${this.baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.accessToken}`
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/list',
        params: {}
      })
    });

    if (!response.ok) {
      throw new Error(`Failed to list tools: ${response.statusText}`);
    }

    const data = await response.json();
    return data.result.tools;
  }

  async callTool(name: string, args: Record<string, any>): Promise<any> {
    const response = await fetch(`${this.baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.accessToken}`
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name, arguments: args }
      })
    });

    if (!response.ok) {
      throw new Error(`Failed to call tool: ${response.statusText}`);
    }

    const data = await response.json();
    return data.result;
  }
}

// Usage
const client = new AuthMCPClient('https://your-domain.com');
await client.login('username', 'password');

const tools = await client.listTools();
console.log(`Available tools: ${tools.length}`);

const result = await client.callTool('rag_query', { query: 'What is MCP?' });
console.log(result);
```

### cURL Examples

**Login:**
```bash
# Get access token
TOKEN=$(curl -s -X POST https://your-domain.com/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "password",
    "username": "your-username",
    "password": "your-password"
  }' | jq -r .access_token)

echo "Access Token: $TOKEN"
```

**List Tools:**
```bash
curl -X POST https://your-domain.com/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list",
    "params": {}
  }' | jq .
```

**Call Tool:**
```bash
curl -X POST https://your-domain.com/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "rag_query",
      "arguments": {
        "query": "What is MCP?"
      }
    }
  }' | jq .
```

**Refresh Token:**
```bash
NEW_TOKEN=$(curl -s -X POST https://your-domain.com/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}" \
  | jq -r .access_token)
```

---

## API Endpoints

### Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/oauth/token` | Get access token (password/authorization_code grant) |
| `POST` | `/auth/refresh` | Refresh access token |
| `POST` | `/auth/logout` | Revoke access token |
| `GET` | `/authorize` | OAuth2 authorization (PKCE) |
| `GET` | `/auth/me` | Get current user profile |

### MCP Protocol Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/mcp` | Aggregated endpoint (all servers) |
| `GET` | `/mcp` | Streamable MCP endpoint (SSE/stream clients) |
| `POST` | `/mcp/{server_name}` | Server-specific endpoint |

### Admin API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/admin/api/users` | List all users |
| `GET` | `/admin/api/mcp-servers` | List all MCP servers |
| `GET` | `/admin/api/mcp-servers/token-status` | Get token expiration status |
| `GET` | `/admin/api/mcp-stats` | Get MCP request statistics (Dashboard) |
| `GET` | `/admin/api/logs` | Get authentication logs (file-based) |
| `DELETE` | `/admin/api/logs/cleanup` | Delete old authentication logs |
| `GET` | `/admin/api/mcp-requests` | Get MCP request logs (live monitoring) |
| `GET` | `/admin/api/stats` | Get system statistics |

---

### Authentication Logs API

**Get authentication logs:**

```http
GET /admin/api/logs?event_type=login&days=7&limit=50&page=1
Authorization: Cookie (admin session)
```

**Query Parameters:**
- `event_type` (optional) - Filter by event type: `login`, `admin_login`, `failed_login`, `logout`, `register`
- `days` (optional) - Time range in days (default: 7)
- `limit` (optional) - Results per page (default: 50)
- `page` (optional) - Page number (default: 1)

**Response:**
```json
{
  "logs": [
    {
      "timestamp": "2026-02-12T13:01:55.725163Z",
      "event_type": "admin_login",
      "user_id": 1,
      "username": "admin",
      "ip_address": "192.168.10.1",
      "user_agent": "Mozilla/5.0...",
      "success": true,
      "details": null
    }
  ],
  "total": 150,
  "page": 1,
  "pages": 3,
  "has_next": true,
  "has_prev": false
}
```

**Cleanup old logs:**

```http
DELETE /admin/api/logs/cleanup?days=30
Authorization: Cookie (admin session)
```

**Response:**
```json
{
  "message": "Deleted 1234 log entries older than 30 days"
}
```

---

### MCP Request Logs API

**Get recent MCP requests:**

```http
GET /admin/api/mcp-requests?last_seconds=60&limit=50&method=tools/call
Authorization: Cookie (admin session)
```

**Query Parameters:**
- `last_seconds` (optional) - Time window in seconds (default: 60)
- `limit` (optional) - Maximum results (default: 50)
- `method` (optional) - Filter by MCP method: `tools/list`, `tools/call`, `initialize`
- `success` (optional) - Filter by success: `true` or `false`

**Response:**
```json
{
  "requests": [
    {
      "id": 1,
      "user_id": 1,
      "username": "admin",
      "mcp_server_id": 3,
      "server_name": "RAG",
      "method": "tools/call",
      "tool_name": "rag_query",
      "success": true,
      "error_message": null,
      "response_time_ms": 245,
      "ip_address": "192.168.10.1",
      "is_suspicious": false,
      "timestamp": "2026-02-12T13:25:45.123456Z"
    }
  ]
}
```

---

### Token Status API

**Get token expiration status for all MCP servers:**

```http
GET /admin/api/mcp-servers/token-status
Authorization: Cookie (admin session)
```

**Response:**
```json
{
  "servers": [
    {
      "id": 1,
      "name": "RAG Server",
      "auth_type": "bearer",
      "token_status": {
        "expires_at": "2026-02-15T10:30:00Z",
        "days_left": 3,
        "status": "warning"
      }
    },
    {
      "id": 2,
      "name": "GitHub",
      "auth_type": "bearer",
      "token_status": {
        "status": "unknown"
      }
    }
  ]
}
```

**Status values:**
- `ok` - Token valid, >7 days remaining
- `warning` - Token expires within 7 days
- `expired` - Token has expired
- `unknown` - Non-JWT token or no expiration claim

---

### MCP Statistics API

**Get MCP request statistics (for Dashboard):**

```http
GET /admin/api/mcp-stats?last_hours=24&include_top_tools=true
Authorization: Cookie (admin session)
```

**Query Parameters:**
- `last_hours` (optional, default: 24) - Time window in hours
- `include_top_tools` (optional, default: false) - Include top 5 tools ranking

**Response:**
```json
{
  "requests_24h": 1542,
  "active_servers": 2,
  "total_servers": 3,
  "success_rate": 98.5,
  "avg_response_time": 245,
  "trend": "",
  "top_tools": [
    {
      "name": "rag_query",
      "count": 420,
      "server": "RAG"
    },
    {
      "name": "github_search",
      "count": 315,
      "server": "GitHub"
    }
  ]
}
```

**Response Fields:**
- `requests_24h` - Total MCP requests in time window
- `active_servers` - Number of online servers
- `total_servers` - Total configured servers
- `success_rate` - Success percentage (0-100)
- `avg_response_time` - Average response time in milliseconds
- `top_tools` - Top 5 most used tools (only if `include_top_tools=true`)

---

## MCP Protocol

AuthMCP Gateway implements the [Model Context Protocol](https://modelcontextprotocol.io/) specification.

### Supported MCP Methods

#### `tools/list`

List all available tools from connected MCP servers.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list",
  "params": {}
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "tools": [
      {
        "name": "rag_query",
        "description": "Query the RAG knowledge base",
        "inputSchema": {
          "type": "object",
          "properties": {
            "query": {
              "type": "string",
              "description": "Search query"
            }
          },
          "required": ["query"]
        }
      }
    ]
  }
}
```

#### `tools/call`

Execute a specific tool.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "rag_query",
    "arguments": {
      "query": "What is MCP?"
    }
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "MCP (Model Context Protocol) is a protocol for..."
      }
    ]
  }
}
```

---

## Error Handling

### HTTP Status Codes

| Code | Description |
|------|-------------|
| `200` | Success |
| `400` | Bad Request (invalid parameters) |
| `401` | Unauthorized (invalid/expired token) |
| `403` | Forbidden (insufficient permissions) |
| `404` | Not Found (endpoint/resource not found) |
| `500` | Internal Server Error |

### Error Response Format

```json
{
  "error": "Unauthorized",
  "detail": "Invalid or expired token"
}
```

### Common Error Scenarios

**Invalid Token:**
```json
{
  "detail": "Could not validate credentials"
}
```

**Expired Token:**
```json
{
  "detail": "Token has expired"
}
```

**Invalid Tool:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32602,
    "message": "Tool not found: unknown_tool"
  }
}
```

---

## Rate Limiting

AuthMCP Gateway supports optional rate limiting to prevent abuse.

**Headers:**
- `X-RateLimit-Limit`: Maximum requests per window
- `X-RateLimit-Remaining`: Requests remaining in current window
- `X-RateLimit-Reset`: Timestamp when the limit resets

**Example:**
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 87
X-RateLimit-Reset: 1709370000
```

**Rate Limit Exceeded:**
```json
{
  "error": "Rate limit exceeded",
  "detail": "Too many requests. Please try again later."
}
```

---

## Additional Resources

- [Main README](../README.md) - Installation and setup guide
- [MCP Protocol Specification](https://modelcontextprotocol.io/)
- [GitHub Repository](https://github.com/loglux/authmcp-gateway)

---

**Need help?** Open an issue on [GitHub](https://github.com/loglux/authmcp-gateway/issues).
