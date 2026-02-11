# AuthMCP Gateway

**Universal Authentication Gateway for MCP (Model Context Protocol) Servers**

[![PyPI version](https://badge.fury.io/py/fastmcp-auth.svg)](https://badge.fury.io/py/fastmcp-auth)
[![Python Version](https://img.shields.io/pypi/pyversions/fastmcp-auth.svg)](https://pypi.org/project/fastmcp-auth/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🚀 Features

- **🔐 JWT/OAuth2 Authentication** - Built-in JWT (HS256/RS256) and OAuth2 Authorization Code Flow with PKCE
- **🌐 Multi-Server Gateway** - Aggregate and proxy multiple MCP servers through a single endpoint
- **👥 User Management** - SQLite-based user database with role-based access control
- **🎛️ Admin Panel** - Beautiful web UI for managing users, servers, and monitoring
- **🔍 Auto-Discovery** - Automatic tool discovery and routing from backend MCP servers
- **💚 Health Monitoring** - Background health checker for all connected servers
- **🔄 Token Refresh** - Automatic token refresh for seamless user experience
- **🎯 Tool Aggregation** - Aggregate tools from multiple servers into single namespace

## 📦 Installation

```bash
# Install from PyPI
pip install fastmcp-auth

# Or install from source
git clone https://github.com/loglux/fastmcp-auth.git
cd fastmcp-auth
pip install -e .
```

## 🚀 Quick Start

### 1. Initialize Database

```bash
fastmcp-auth init-db
```

### 2. Create Admin User

```bash
fastmcp-auth create-admin --username admin --email admin@example.com
```

### 3. Create Configuration

Create `.env` file:

```bash
# JWT Configuration
JWT_ALGORITHM=HS256
JWT_SECRET_KEY=your-secret-key-min-32-chars
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# Gateway Configuration
MCP_PUBLIC_URL=https://your-domain.com
AUTH_REQUIRED=true

# Database
AUTH_SQLITE_PATH=data/auth.db

# Optional: Static tokens for backward compatibility
# STATIC_BEARER_TOKENS=token1,token2
```

### 4. Start Gateway

```bash
fastmcp-auth start
```

Gateway will start on `http://0.0.0.0:8000`

## 🔌 Connecting MCP Servers

### Via Admin Panel

1. Open `http://localhost:8000/admin`
2. Login with admin credentials
3. Go to "MCP Servers" section
4. Click "Add Server"
5. Fill in server details:
   - Name: `My MCP Server`
   - URL: `http://localhost:8001/mcp`
   - Tool Prefix: `myserver_`
   - Auth Type: `none` / `bearer` / `basic`

### Via Database

```python
from fastmcp_auth.mcp.store import create_mcp_server

server_id = create_mcp_server(
    db_path="data/auth.db",
    name="RAG Server",
    url="http://localhost:8001/mcp",
    description="RAG Knowledge Base",
    tool_prefix="rag_",
    enabled=True,
    auth_type="none",
    routing_strategy="prefix"
)
```

## 🎯 Usage Examples

### Claude Desktop Configuration

```json
{
  "mcpServers": {
    "fastmcp-auth": {
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
│  AuthMCP Gateway                      │
│  • JWT/OAuth Authentication                │
│  • Multi-server proxy & routing            │
│  • Admin Panel                             │
└────────────────────────────────────────────┘
              ↓ Connects to:
   ┌──────────┴─────┬──────────┬──────────┐
   ↓                ↓          ↓          ↓
┌────────┐    ┌──────────┐  ┌────┐   ┌────────┐
│ RAG    │    │ Home     │  │ N8N│   │ Custom │
│ Server │    │ Assistant│  │ AI │   │ Server │
└────────┘    └──────────┘  └────┘   └────────┘
```

## 🛠️ CLI Commands

```bash
# Start gateway
fastmcp-auth start [--host HOST] [--port PORT] [--reload]

# Initialize database
fastmcp-auth init-db [--db-path PATH]

# Create admin user
fastmcp-auth create-admin --username USERNAME --email EMAIL [--password PASSWORD]

# Show version
fastmcp-auth version
```

## 🔒 Security Features

- **JWT Tokens** - Industry-standard JSON Web Tokens
- **OAuth2 PKCE** - Authorization Code Flow with Proof Key for Code Exchange
- **Password Hashing** - Bcrypt with configurable rounds
- **Token Blacklist** - Revoke tokens on logout
- **Audit Logging** - Track all authentication events
- **CORS Protection** - Configurable origin validation
- **Rate Limiting** - (Optional) Prevent brute-force attacks

## 📊 Admin Panel

Access at `http://localhost:8000/admin`

Features:
- **Dashboard** - Overview of users, servers, and activity
- **Users** - Manage users, roles, and permissions
- **MCP Servers** - Add, remove, and monitor backend servers
- **Settings** - Configure JWT, password policy, and more
- **Auth Logs** - View authentication history
- **API Test** - Test MCP tools directly from browser

## 🔧 Configuration

### Environment Variables

```bash
# JWT Settings
JWT_ALGORITHM=HS256                          # or RS256
JWT_SECRET_KEY=your-secret-key              # for HS256
JWT_PRIVATE_KEY_PATH=/path/to/key.pem       # for RS256
JWT_PUBLIC_KEY_PATH=/path/to/key.pub        # for RS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# Gateway Settings
MCP_PUBLIC_URL=https://your-domain.com
AUTH_REQUIRED=true
AUTH_SQLITE_PATH=data/auth.db

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
```

## 🤝 Compatible MCP Servers

AuthMCP Gateway works with **any** MCP-compliant server:

- [FastMCP](https://github.com/jlowin/fastmcp) - Python framework for MCP servers
- [Home Assistant MCP](https://github.com/home-assistant/mcp) - Smart home integration
- [N8N AI MCP](https://github.com/n8n-io/n8n-mcp) - Workflow automation
- Your custom MCP server!

## 📚 Documentation

- [Installation Guide](https://github.com/loglux/fastmcp-auth/blob/main/docs/installation.md)
- [Configuration Guide](https://github.com/loglux/fastmcp-auth/blob/main/docs/configuration.md)
- [Adding MCP Servers](https://github.com/loglux/fastmcp-auth/blob/main/docs/adding-servers.md)
- [Security Best Practices](https://github.com/loglux/fastmcp-auth/blob/main/docs/security.md)
- [API Reference](https://github.com/loglux/fastmcp-auth/blob/main/docs/api-reference.md)

## 🐳 Docker

```bash
# Build image
docker build -t fastmcp-auth .

# Run container
docker run -d \
  -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  -e JWT_SECRET_KEY=your-secret \
  fastmcp-auth
```

### Docker Compose

```yaml
version: '3.8'

services:
  fastmcp-auth:
    image: loglux/fastmcp-auth:latest
    ports:
      - "8000:8000"
    environment:
      - JWT_SECRET_KEY=your-secret-key
      - MCP_PUBLIC_URL=https://your-domain.com
    volumes:
      - ./data:/app/data
    restart: unless-stopped
```

## 🧪 Development

```bash
# Clone repository
git clone https://github.com/loglux/fastmcp-auth.git
cd fastmcp-auth

# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with auto-reload
fastmcp-auth start --reload

# Format code
black src/ tests/
isort src/ tests/

# Type checking
mypy src/
```

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built on top of [FastMCP](https://github.com/jlowin/fastmcp) by Jeff Lowin
- Uses [Starlette](https://www.starlette.io/) for ASGI
- Inspired by the [Model Context Protocol](https://modelcontextprotocol.io/)

## 📮 Support

- 🐛 [Report Bug](https://github.com/loglux/fastmcp-auth/issues)
- 💡 [Request Feature](https://github.com/loglux/fastmcp-auth/issues)
- 💬 [Discussions](https://github.com/loglux/fastmcp-auth/discussions)

## ⭐ Star History

If you find this project useful, please consider giving it a star!

---

**Made with ❤️ by [loglux](https://github.com/loglux)**
