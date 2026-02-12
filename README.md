# AuthMCP Gateway

**Universal Authentication Gateway for MCP (Model Context Protocol) Servers**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🚀 Features

- **🔐 JWT/OAuth2 Authentication** - Built-in JWT (HS256/RS256) and OAuth2 Authorization Code Flow with PKCE
- **🌐 Multi-Server Gateway** - Aggregate and proxy multiple MCP servers through a single endpoint
- **🔀 Dynamic Endpoints** - Each backend server gets its own dedicated endpoint (`/mcp/{server_name}`)
- **👥 User Management** - SQLite-based user database with role-based access control
- **🎛️ Admin Panel** - Beautiful Tailwind CSS web UI for managing users, servers, and monitoring
- **🔍 Auto-Discovery** - Automatic tool discovery and routing from backend MCP servers
- **💚 Health Monitoring** - Background health checker for all connected servers
- **🔄 Token Refresh** - Automatic token refresh for both users and backend MCP servers
- **⏰ Token Expiration Tracking** - Proactive monitoring of JWT token expiration with visual warnings
- **🎯 Tool Aggregation** - Aggregate tools from multiple servers into single namespace with prefixes
- **🔑 Backend Token Management** - Automatic OAuth2 token refresh for backend MCP servers
- **📱 Mobile Responsive** - Fully responsive admin panel with drawer sidebar for mobile devices

## 📦 Installation

### Using Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/loglux/authmcp-gateway.git
cd authmcp-gateway

# Create .env file
cp .env.example .env
# Edit .env with your settings

# Start with Docker Compose
docker compose up -d --build
```

### From Source

```bash
# Clone repository
git clone https://github.com/loglux/authmcp-gateway.git
cd authmcp-gateway

# Install dependencies
pip install -e .

# Initialize database
python -m authmcp_gateway.cli init-db

# Start server
python -m authmcp_gateway.cli start
```

## 🚀 Quick Start

### 1. Configure Environment

Create `.env` file:

```bash
# JWT Configuration
JWT_ALGORITHM=HS256
JWT_SECRET_KEY=your-secret-key-min-32-chars
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# Gateway Configuration
GATEWAY_PORT=9105                    # Docker port
MCP_PUBLIC_URL=https://mcp.yourdomain.com  # Your HTTPS domain (required for Claude.ai)
AUTH_REQUIRED=true

# Database
AUTH_SQLITE_PATH=/app/data/users.db

# Backend Token Management
MCP_TOKEN_REFRESH_INTERVAL=300       # Check every 5 minutes
MCP_TOKEN_REFRESH_THRESHOLD=5        # Refresh if expires within 5 minutes

# Optional: Static tokens for backward compatibility
# STATIC_BEARER_TOKENS=token1,token2
```

### 2. Start Gateway

```bash
docker compose up -d --build
```

Gateway will start on `http://0.0.0.0:9105` (mapped from container's 8000)

### 3. Access Admin Panel

**Local access (admin panel):**
```
http://192.168.1.100:9105/admin
```

**Public access (Claude.ai MCP connector):**
```
https://mcp.yourdomain.com  (requires reverse proxy with HTTPS)
```

Create admin user via setup wizard: `http://localhost:9105/setup`

### 🔧 Changing Port

Change in `.env`:

```bash
GATEWAY_PORT=8080  # Change Docker port
```

If using reverse proxy (Nginx/Traefik), also update proxy config:
```nginx
# Nginx example
proxy_pass http://localhost:8080;  # Update port here
```

Restart:
```bash
docker compose down && docker compose up -d
```

## 🔒 HTTPS Requirement for Claude.ai

**Claude.ai requires HTTPS for MCP connectors.** You need a reverse proxy:

### Option 1: Nginx with Let's Encrypt (recommended)

Setup Nginx with Let's Encrypt SSL certificate:

```nginx
server {
    listen 443 ssl;
    server_name mcp.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/mcp.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mcp.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://localhost:9105;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

Then set in `.env`:
```bash
MCP_PUBLIC_URL=https://mcp.yourdomain.com
```

### Option 2: CloudFlare Tunnel

Use CloudFlare to get HTTPS without managing SSL certificates.

**Note:** Local admin panel access still works via HTTP (http://192.168.1.100:9105/admin)

## 🔌 Connecting MCP Servers

### Via Admin Panel

1. Open `http://localhost:9105/admin`
2. Login with admin credentials
3. Go to "MCP Servers" section
4. Click "Add Server"
5. Fill in server details:
   - **Name**: `My MCP Server`
   - **URL**: `http://localhost:8001/mcp`
   - **Tool Prefix**: `myserver_`
   - **Auth Type**: `none` / `bearer` / `basic`
   - **Auth Token**: Bearer token or Basic Auth credentials (if required)

## 🔀 Dynamic Server Endpoints

AuthMCP Gateway provides two ways to access your backend MCP servers:

### Aggregated Endpoint

Access **all** backend servers through a single endpoint:

```
POST https://your-domain.com/mcp
```

Tools from all servers are aggregated with their configured prefixes (e.g., `rag_query`, `ha_turn_on_light`).

**Use case**: Single MCP connector in Claude.ai that provides access to all tools.

### Server-Specific Endpoints

Each backend server gets its own dedicated endpoint:

```
POST https://your-domain.com/mcp/{server_name}
```

Examples:
- `https://your-domain.com/mcp/rag` - Only RAG server tools
- `https://your-domain.com/mcp/homeassistant` - Only Home Assistant tools
- `https://your-domain.com/mcp/n8n` - Only N8N tools

**Use case**: Multiple separate MCP connectors in Claude.ai, each accessing a specific backend server.

### Claude.ai Configuration Examples

**Single aggregated connector:**
```json
{
  "mcpServers": {
    "authmcp-all": {
      "url": "https://your-domain.com/mcp",
      "auth": {
        "type": "oauth2",
        "authorization_url": "https://your-domain.com/authorize",
        "token_url": "https://your-domain.com/oauth/token",
        "scope": "openid profile email"
      }
    }
  }
}
```

**Multiple separate connectors:**
```json
{
  "mcpServers": {
    "rag-knowledge-base": {
      "url": "https://your-domain.com/mcp/rag",
      "auth": {
        "type": "oauth2",
        "authorization_url": "https://your-domain.com/authorize",
        "token_url": "https://your-domain.com/oauth/token",
        "scope": "openid profile email"
      }
    },
    "home-assistant": {
      "url": "https://your-domain.com/mcp/homeassistant",
      "auth": {
        "type": "oauth2",
        "authorization_url": "https://your-domain.com/authorize",
        "token_url": "https://your-domain.com/oauth/token",
        "scope": "openid profile email"
      }
    }
  }
}
```

**Finding endpoint URLs**: The admin panel displays the exact endpoint URL for each server with a copy button.

## ⏰ Token Expiration Monitoring

AuthMCP Gateway includes proactive monitoring of JWT token expiration:

### Dashboard Warnings

The dashboard shows warnings for tokens expiring soon (< 7 days) or already expired:
- 🔴 **Expired tokens** - Shows how many days ago the token expired
- 🟡 **Expiring soon** - Shows how many days until expiration
- Displays exact expiration date and time

### Server Card Badges

Each MCP server card shows token status:
- 🔴 **Expired 2d ago** - Token has expired
- 🟡 **Expires in 3d** - Token expires within 7 days
- 🟢 **Valid (45d left)** - Token is valid with more than 7 days remaining
- 🔵 **Never expires** - JWT token without expiration claim
- ⚫ **Unknown expiration** - Non-JWT token (e.g., static API key)

Hover over badges to see exact expiration date and time.

## 🎯 Usage Examples

### Python Client

```python
import httpx

# Get token
response = httpx.post(
    "https://your-domain.com/oauth/token",
    json={
        "grant_type": "password",
        "username": "your-username",
        "password": "your-password"
    }
)
token = response.json()["access_token"]

# Call MCP tools
response = httpx.post(
    "https://your-domain.com/mcp",
    headers={"Authorization": f"Bearer {token}"},
    json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    }
)

tools = response.json()["result"]["tools"]
print(f"Available tools: {len(tools)}")
```

### cURL

```bash
# Get token
TOKEN=$(curl -s -X POST https://your-domain.com/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"password","username":"user","password":"pass"}' \
  | jq -r .access_token)

# List tools
curl -H "Authorization: Bearer $TOKEN" \
  -X POST https://your-domain.com/mcp \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

## 🏗️ Architecture

```
┌────────────────────────────────────────────┐
│  AuthMCP Gateway (Port 9105)               │
│  • JWT/OAuth Authentication                │
│  • Multi-server proxy & routing            │
│  • Admin Panel (Tailwind + Alpine.js)      │
│  • Token expiration monitoring             │
└────────────────────────────────────────────┘
              ↓ Connects to:
   ┌──────────┴─────┬──────────┬──────────┐
   ↓                ↓          ↓          ↓
┌────────┐    ┌──────────┐  ┌────┐   ┌────────┐
│ RAG    │    │ Home     │  │ N8N│   │ Custom │
│ Server │    │ Assistant│  │ AI │   │ Server │
└────────┘    └──────────┘  └────┘   └────────┘
```

## 🔒 Security Features

- **JWT Tokens** - Industry-standard JSON Web Tokens with HS256/RS256 algorithms
- **OAuth2 PKCE** - Authorization Code Flow with Proof Key for Code Exchange
- **Password Hashing** - Bcrypt with configurable rounds
- **Token Blacklist** - Revoke tokens on logout
- **Audit Logging** - Track all authentication events
- **Token Expiration Alerts** - Proactive monitoring and warnings
- **CORS Protection** - Configurable origin validation
- **Rate Limiting** - Optional protection against brute-force attacks

## 📊 Admin Panel

Access at `http://localhost:9105/admin`

Features:
- **Dashboard** - Overview of users, servers, activity, and token warnings
- **Users** - Manage users, roles, and permissions
- **MCP Servers** - Add, remove, and monitor backend servers with token status
- **Settings** - Configure JWT, password policy, and system settings
- **Auth Logs** - View authentication history and events
- **API Test** - Test MCP tools directly from browser
- **Mobile Responsive** - Full mobile support with drawer sidebar

## 🔧 Configuration

### Environment Variables

```bash
# JWT Settings
JWT_ALGORITHM=HS256                          # or RS256
JWT_SECRET_KEY=your-secret-key              # for HS256 (min 32 chars)
JWT_PRIVATE_KEY_PATH=/path/to/key.pem       # for RS256
JWT_PUBLIC_KEY_PATH=/path/to/key.pub        # for RS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# Gateway Settings
GATEWAY_PORT=9105                            # Docker port
MCP_PUBLIC_URL=https://mcp.yourdomain.com    # Public HTTPS URL for Claude.ai
AUTH_REQUIRED=true
AUTH_SQLITE_PATH=/app/data/users.db

# Password Policy
PASSWORD_MIN_LENGTH=8
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_DIGIT=true
PASSWORD_REQUIRE_SPECIAL=true

# Optional: Backward Compatibility
STATIC_BEARER_TOKENS=token1,token2
MCP_TRUSTED_IPS=127.0.0.1,::1

# Optional: User Registration
ALLOW_REGISTRATION=false                     # Allow public registration

# Backend Token Management
MCP_TOKEN_REFRESH_INTERVAL=300               # Check tokens every 5 minutes
MCP_TOKEN_REFRESH_THRESHOLD=5                # Refresh if expires within 5 minutes
```

## 🤝 Compatible MCP Servers

AuthMCP Gateway works with **any** MCP-compliant server:

- [FastMCP](https://github.com/jlowin/fastmcp) - Python framework for MCP servers
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) - Official MCP SDK
- Custom MCP implementations in any language

## 🐳 Docker

### Docker Compose

```yaml
services:
  authmcp-gateway:
    build: .
    container_name: authmcp-gateway
    ports:
      - "9105:8000"
    environment:
      - JWT_SECRET_KEY=your-secret-key-min-32-chars
      - MCP_PUBLIC_URL=https://your-domain.com
    volumes:
      - ./data:/app/data
      - ./templates:/app/templates  # For live template editing
      - ./src:/app/src              # For live code editing in development
    restart: unless-stopped
```

## 🧪 Development

```bash
# Clone repository
git clone https://github.com/loglux/authmcp-gateway.git
cd authmcp-gateway

# Install dev dependencies
pip install -e ".[dev]"

# Run with auto-reload
docker compose up --build

# Format code
black src/ tests/
isort src/ tests/

# Type checking
mypy src/
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Made with ❤️ for the MCP community**
