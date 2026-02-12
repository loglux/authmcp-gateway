# AuthMCP Gateway

**Secure authentication proxy for Model Context Protocol (MCP) servers**

[![PyPI version](https://badge.fury.io/py/authmcp-gateway.svg)](https://pypi.org/project/authmcp-gateway/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)](https://hub.docker.com/)
[![MCP](https://img.shields.io/badge/MCP-compatible-purple.svg)](https://modelcontextprotocol.io)

AuthMCP Gateway provides centralized authentication, authorization, and monitoring for MCP servers. It acts as a secure proxy between clients and your MCP backends, adding JWT-based authentication, rate limiting, real-time monitoring, and comprehensive security logging.

## 📋 Table of Contents

- [✨ Features](#-features)
- [📚 Documentation](#-documentation)
- [📸 Screenshots](#-screenshots)
- [🚀 Quick Start](#-quick-start)
- [⚙️ Configuration](#️-configuration)
- [💡 Usage](#-usage)
- [🏗️ Architecture](#️-architecture)
- [🔌 API Endpoints](#-api-endpoints)
- [🔐 Security](#-security)
- [🛠️ Development](#️-development)
- [📊 Monitoring](#-monitoring)
- [🔧 Troubleshooting](#-troubleshooting)

---

## ✨ Features

### 🔐 **Authentication & Authorization**
- **OAuth 2.0 + JWT** - Industry-standard authentication flow
- **User Management** - Multi-user support with role-based access
- **Backend Token Management** - Secure storage and auto-refresh of MCP server credentials
- **Rate Limiting** - Per-user request throttling with configurable limits

### 📊 **Real-Time Monitoring**
- **Live MCP Activity Monitor** - Real-time request feed with auto-refresh
- **Performance Metrics** - Response times, success rates, requests/minute
- **Security Event Logging** - Unauthorized access attempts, rate limiting, suspicious activity
- **Health Checking** - Automatic health checks for all connected MCP servers

### 🎛️ **Admin Dashboard**
- **User Management** - Create, edit, and manage users
- **MCP Server Configuration** - Add and configure backend MCP servers
- **Token Management** - Monitor token health and manual refresh
- **Security Events** - View and filter security events
- **API Testing** - Built-in MCP testing interface

### 🛡️ **Security**
- JWT token-based authentication with refresh tokens
- Secure credential storage with encrypted database support
- CORS protection and request validation
- Security event logging and monitoring
- **File-based logging** - No database bloat, 30-day rotation
- Built-in security testing guide

## 📚 Documentation

📚 **[Complete Documentation](docs/README.md)** - Full documentation index

**Quick Links:**
- **[Deployment Guide](docs/DEPLOYMENT.md)** - Production setup with HTTPS, Docker, cloud platforms
- **[Logging Architecture](docs/LOGGING.md)** - File-based logging, log formats, analysis
- **[API Reference](docs/API.md)** - REST API documentation with examples
- **[Security Testing](docs/SECURITY_TESTING.md)** - Security verification and testing
- **[Publishing Guide](docs/PUBLISHING.md)** - Publishing to PyPI

## 📸 Screenshots

<details>
<summary><b>🖥️ Dashboard - Real-time Overview</b></summary>

![Dashboard](https://raw.githubusercontent.com/loglux/authmcp-gateway/main/docs/screenshots/01-dashboard.png)

*Live statistics, server health monitoring, top tools usage, and recent activity feed*
</details>

<details>
<summary><b>🔧 MCP Servers - Connection Management</b></summary>

![MCP Servers](https://raw.githubusercontent.com/loglux/authmcp-gateway/main/docs/screenshots/02-mcp-servers.png)

*Manage backend MCP server connections with status monitoring and health checks*
</details>

<details>
<summary><b>📊 MCP Activity Monitor - Real-time Request Tracking</b></summary>

![MCP Activity](https://raw.githubusercontent.com/loglux/authmcp-gateway/main/docs/screenshots/03-mcp-activity.png)

*Monitor live MCP requests with detailed metrics, top tools ranking, and request feed*
</details>

<details>
<summary><b>🛡️ Security Events - Threat Detection</b></summary>

![Security Events](https://raw.githubusercontent.com/loglux/authmcp-gateway/main/docs/screenshots/04-security-events.png)

*Track security events, rate limiting, suspicious payloads, and unauthorized access attempts*
</details>

<details>
<summary><b>🔒 MCP Security Audit - Vulnerability Scanner</b></summary>

![MCP Security Audit](https://raw.githubusercontent.com/loglux/authmcp-gateway/main/docs/screenshots/05-mcp-security-audit.png)

*Test any MCP server for security vulnerabilities with comprehensive automated checks*
</details>

---

## 🚀 Quick Start

### Option 1: PyPI Package (Recommended)

Install from PyPI and run:

```bash
pip install authmcp-gateway
authmcp-gateway
```

Then access **http://localhost:8000/** to complete setup wizard.

### Option 2: Docker Compose

1. **Clone and configure:**
   ```bash
   git clone https://github.com/loglux/authmcp-gateway.git
   cd authmcp-gateway
   cp .env.example .env
   # Edit .env with your settings
   ```

2. **Start the gateway:**
   ```bash
   docker-compose up -d
   ```

3. **Access admin panel:**
   - Open http://localhost:9105/
   - Complete setup wizard to create admin user
   - Add your MCP servers

## ⚙️ Configuration

### Environment Variables

```bash
# Gateway Settings
GATEWAY_PORT=9105              # Gateway port (default: 8000)
JWT_SECRET=your-secret-key     # JWT signing key (auto-generated if not set)
REQUIRE_AUTH=true              # Enable authentication (default: true)

# Admin Settings
ADMIN_USERNAME=admin           # Initial admin username
ADMIN_PASSWORD=secure-password # Initial admin password
```

### Adding MCP Servers

Via Admin Panel:
1. Navigate to **MCP Servers** → **Add Server**
2. Enter server details:
   - Name (e.g., "GitHub MCP")
   - URL (e.g., "http://github-mcp:8000/mcp")
   - Backend token (if required)

Via API:
```bash
curl -X POST http://localhost:9105/admin/api/mcp-servers \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "GitHub MCP",
    "url": "http://github-mcp:8000/mcp",
    "backend_token": "optional-token"
  }'
```

## 💡 Usage

### For End Users

1. **Login to get access token:**
   ```bash
   curl -X POST http://localhost:9105/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"your-username","password":"your-password"}'
   ```

2. **Use token to access MCP endpoints:**
   ```bash
   curl -X POST http://localhost:9105/mcp \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
   ```

### For Administrators

**Admin Panel Features:**
- **Dashboard** - Overview of users, servers, and activity
- **MCP Activity** - Real-time monitoring of all MCP requests
- **Security Events** - View unauthorized access attempts and suspicious activity
- **User Management** - Create and manage user accounts
- **Token Management** - Monitor and refresh backend tokens

## 🏗️ Architecture

```
┌─────────────┐
│   Client    │
│  (Claude,   │
│   etc.)     │
└──────┬──────┘
       │ JWT Auth
       ▼
┌─────────────────────────────┐
│   AuthMCP Gateway           │
│                             │
│  • Authentication           │
│  • Rate Limiting            │
│  • Security Logging         │
│  • Request Routing          │
│  • Health Monitoring        │
└──────┬──────────────────────┘
       │
       ├──────────┬──────────┬──────────┐
       ▼          ▼          ▼          ▼
  ┌─────────┐ ┌────────┐ ┌────────┐ ┌────────┐
  │GitHub   │ │  RAG   │ │ Home   │ │Custom  │
  │MCP      │ │  MCP   │ │Assistant│ │ MCP    │
  └─────────┘ └────────┘ └────────┘ └────────┘
```

## 🔌 API Endpoints

### Public Endpoints
- `POST /auth/login` - User login
- `POST /auth/register` - User registration (if enabled)
- `POST /auth/refresh` - Refresh access token
- `GET /.well-known/oauth-authorization-server` - OAuth discovery

### Protected Endpoints
- `POST /mcp` - Aggregated MCP endpoint (all servers)
- `POST /mcp/{server_name}` - Specific MCP server endpoint
- `GET /auth/me` - Current user info
- `POST /auth/logout` - Logout

### Admin Endpoints
- `GET /admin` - Admin dashboard
- `GET /admin/mcp-activity` - Real-time MCP monitoring
- `GET /admin/security-logs` - Security events
- `GET /admin/users` - User management
- `GET /admin/mcp-servers` - MCP server configuration
- Plus full REST API for management

## 🔐 Security

### Testing Security

See [docs/SECURITY_TESTING.md](docs/SECURITY_TESTING.md) for:
- Manual security tests
- Automated testing script
- Production deployment checklist
- Security best practices

### Security Features
- ✅ JWT-based authentication with refresh tokens
- ✅ Rate limiting per user
- ✅ Security event logging
- ✅ MCP request tracking with suspicious activity detection
- ✅ Health monitoring for backend servers
- ✅ CORS protection
- ✅ Secure credential storage

## 🛠️ Development

### Local Development

```bash
# Clone repository
git clone https://github.com/loglux/authmcp-gateway.git
cd authmcp-gateway

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install dependencies
pip install -e .

# Run gateway
authmcp-gateway
```

### Running Tests

```bash
pytest tests/
```

### Project Structure

```
authmcp-gateway/
├── src/authmcp_gateway/
│   ├── admin/           # Admin panel routes and logic
│   ├── auth/            # Authentication & authorization
│   ├── mcp/             # MCP proxy and handlers
│   ├── security/        # Security logging and monitoring
│   ├── middleware.py    # Request middleware
│   └── app.py           # Main application
├── templates/           # Jinja2 templates (admin UI)
├── docs/                # Documentation
├── tests/               # Test suite
└── docker-compose.yml   # Docker deployment
```

## 📊 Monitoring

### Real-Time Dashboard

Access `/admin/mcp-activity` for:
- Live request feed (updates every 3 seconds)
- Requests per minute
- Average response times
- Success rates
- Top tools usage
- Per-server statistics

### Logs

View logs in real-time:
```bash
docker logs -f authmcp-gateway
```

## 🔧 Troubleshooting

**Cannot access admin panel:**
- Ensure you've completed the setup wizard at `/setup`
- Check that cookies are enabled
- Verify JWT_SECRET is set correctly

**MCP server shows as offline:**
- Check server URL is correct and reachable
- Verify backend token if required
- View error details in MCP Servers page

**401 Unauthorized errors:**
- Token may have expired - use refresh token
- Verify Authorization header format: `Bearer YOUR_TOKEN`
- Check user has permission for the MCP server

For more help, see [docs/SECURITY_TESTING.md](docs/SECURITY_TESTING.md).

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Roadmap

- [ ] Prometheus metrics export
- [ ] WebSocket support for real-time updates
- [ ] Per-tool rate limiting
- [ ] Enhanced security testing automation
- [ ] Multi-tenancy support
- [ ] API key authentication option

---

**Built with ❤️ for the MCP ecosystem**
