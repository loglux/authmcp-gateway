# AuthMCP Gateway Documentation

Complete documentation for AuthMCP Gateway - a secure authentication proxy for Model Context Protocol (MCP) servers.

## 📚 Documentation Index

### Getting Started
- **[Main README](../README.md)** - Project overview, quick start, and features
- **[Deployment Guide](DEPLOYMENT.md)** - Production deployment with HTTPS, reverse proxies, and cloud platforms

### Core Documentation
- **[API Reference](API.md)** - Complete REST API documentation with examples
- **[Logging Architecture](LOGGING.md)** - File-based logging system, log formats, and analysis
- **[Security Testing](SECURITY_TESTING.md)** - Security verification tests and best practices

### Development
- **[Publishing Guide](PUBLISHING.md)** - Publishing package to PyPI

### Archives
- **[Old README](archive/README_OLD.md)** - Previous version of main README (archived)

---

## Quick Links by Topic

### 🚀 Deployment

**Docker:**
- [Docker Quick Start](DEPLOYMENT.md#docker-deployment)
- [Production Docker Compose](DEPLOYMENT.md#production-docker-compose)
- [Changing Ports](DEPLOYMENT.md#changing-port)

**HTTPS Setup:**
- [Nginx + Let's Encrypt](DEPLOYMENT.md#option-1-nginx-with-lets-encrypt-recommended)
- [Cloudflare Tunnel](DEPLOYMENT.md#option-2-cloudflare-tunnel)
- [Traefik](DEPLOYMENT.md#option-3-traefik-docker)

**Cloud Platforms:**
- [Railway.app](DEPLOYMENT.md#railwayapp)
- [Render.com](DEPLOYMENT.md#rendercom)
- [DigitalOcean](DEPLOYMENT.md#digitalocean-app-platform)
- [AWS ECS](DEPLOYMENT.md#aws-ecs-fargate)

### 🔐 Authentication & Security

**Setup:**
- [JWT Configuration](../README.md#environment-variables)
- [OAuth2 Flow](API.md#authentication)
- [Security Hardening](DEPLOYMENT.md#security-hardening)

**Testing:**
- [Security Checklist](SECURITY_TESTING.md#quick-security-checklist)
- [Manual Tests](SECURITY_TESTING.md#manual-security-tests)
- [Automated Testing](SECURITY_TESTING.md#automated-security-testing)

### 📊 Logging & Monitoring

**File-Based Logging:**
- [Why Files?](LOGGING.md#why-file-based-logging)
- [Auth Logs](LOGGING.md#1-authentication-logs-datalogsauthlog)
- [MCP Request Logs](LOGGING.md#2-mcp-request-logs-datalogsmcp_requestslog)
- [Log Rotation](LOGGING.md#configuration)

**Viewing Logs:**
- [Admin Panel](LOGGING.md#via-admin-panel)
- [Command Line](LOGGING.md#via-command-line)
- [Log Analysis](LOGGING.md#log-analysis)

**Backup:**
- [Backup Strategies](LOGGING.md#backup--archiving)
- [Migration from DB](LOGGING.md#migration-from-database)

### 🔌 MCP Servers

**Configuration:**
- [Adding Servers](../README.md#connecting-mcp-servers)
- [Server-Specific Endpoints](../README.md#dynamic-server-endpoints)
- [Claude.ai Setup](../README.md#claude-desktop-configuration)

**Monitoring:**
- [Health Checks](../README.md#health-monitoring)
- [Token Expiration](../README.md#token-expiration-tracking)
- [Performance Metrics](../README.md#mcp-activity-monitoring)

### 🛠️ API Integration

**Authentication:**
- [OAuth2 Authorization Code](API.md#oauth2-authorization-code-flow)
- [Password Grant](API.md#password-grant-direct-login)
- [Token Refresh](API.md#token-refresh)

**MCP Protocol:**
- [tools/list](API.md#toolslist---list-all-tools)
- [tools/call](API.md#toolscall---execute-a-tool)
- [Server-Specific Calls](API.md#server-specific-endpoint)

**Admin API:**
- [User Management](API.md#admin-api-examples)
- [Server Management](API.md#admin-api-examples)
- [Logs Access](LOGGING.md#via-admin-panel)

---

## Documentation by Role

### 👤 End Users (Claude.ai, VS Code, etc.)

1. Ask admin for OAuth2 credentials
2. Configure MCP client:
   - Authorization URL: `https://your-domain.com/authorize`
   - Token URL: `https://your-domain.com/oauth/token`
   - MCP Endpoint: `https://your-domain.com/mcp`
3. Authenticate and start using tools

**See:** [Main README](../README.md#claude-desktop-configuration)

---

### 🔧 Administrators

**Initial Setup:**
1. [Deploy with Docker](DEPLOYMENT.md#docker-deployment)
2. [Configure HTTPS](DEPLOYMENT.md#https-setup)
3. [Create admin user](../README.md#initial-setup)
4. [Add MCP servers](../README.md#connecting-mcp-servers)

**Daily Tasks:**
- Monitor [Dashboard](../README.md#admin-dashboard)
- Review [Security Events](LOGGING.md#security-events-database)
- Check [Token Expiration](../README.md#token-expiration-tracking)
- Manage users and servers

**Maintenance:**
- [View logs](LOGGING.md#viewing-logs)
- [Backup data](LOGGING.md#backup--archiving)
- [Security testing](SECURITY_TESTING.md)

---

### 💻 Developers

**Integration:**
1. Read [API Reference](API.md)
2. Implement [OAuth2 flow](API.md#oauth2-authorization-code-flow) or [Password Grant](API.md#password-grant-direct-login)
3. Call [MCP endpoints](API.md#mcp-protocol-requests)
4. Handle [errors](API.md#error-handling)

**Examples:**
- [Python Client](API.md#python-example-oauth2-client)
- [JavaScript Client](API.md#javascript-example-oauth2-client)
- [cURL Examples](API.md#curl-examples)

**Development:**
- Clone repository
- Read [Contributing Guide](../README.md#development) (if exists)
- Run tests: `pytest tests/`

---

## Common Tasks

### 🔥 Quick Setup (5 minutes)

```bash
git clone https://github.com/loglux/authmcp-gateway.git
cd authmcp-gateway
cp .env.example .env
docker-compose up -d
# Open http://localhost:9105/admin
```

**See:** [Main README](../README.md#quick-start)

---

### 🔒 Enable HTTPS

**Nginx + Let's Encrypt:**
```bash
# Install
sudo apt install nginx certbot python3-certbot-nginx

# Configure
sudo nano /etc/nginx/sites-available/authmcp

# Get certificate
sudo certbot --nginx -d mcp.yourdomain.com
```

**See:** [Deployment Guide](DEPLOYMENT.md#option-1-nginx-with-lets-encrypt-recommended)

---

### 📝 View Logs

**Admin Panel:**
- Go to **Admin → Auth Logs**
- Filter by event type, time range
- Paginate through entries

**Command Line:**
```bash
# Live tail
tail -f data/logs/auth.log | jq .

# Search failed logins
cat data/logs/auth.log | jq 'select(.event_type == "failed_login")'
```

**See:** [Logging Guide](LOGGING.md#viewing-logs)

---

### 🧪 Test Security

```bash
# Test unauthorized access
curl -X POST http://localhost:9105/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
# Expected: 401 Unauthorized

# Test with valid token
curl -X POST http://localhost:9105/mcp \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
# Expected: 200 OK with tools list
```

**See:** [Security Testing Guide](SECURITY_TESTING.md#manual-security-tests)

---

### 🔄 Add MCP Server

1. Open Admin Panel: `http://localhost:9105/admin`
2. Go to **MCP Servers** → **Add Server**
3. Fill in:
   - Name: `My Server`
   - URL: `http://backend:8001/mcp`
   - Tool Prefix: `myserver_`
   - Auth Type: `bearer` / `none` / `basic`
   - Token: (if bearer/basic auth)
4. Click **Save**

**See:** [Main README](../README.md#connecting-mcp-servers)

---

## Troubleshooting

### Logs not appearing
→ [Logging Troubleshooting](LOGGING.md#troubleshooting)

### HTTPS not working
→ [Deployment Troubleshooting](DEPLOYMENT.md#troubleshooting)

### Authentication fails
→ [Security Testing](SECURITY_TESTING.md#troubleshooting)

### Performance issues
→ [Deployment Guide](DEPLOYMENT.md#performance-issues)

---

## Contributing

Contributions welcome! Please:
1. Read existing documentation
2. Follow documentation style
3. Update this index when adding new docs
4. Test examples before committing

---

## License

MIT License - see [LICENSE](../LICENSE)

---

## Support

- **Issues:** [GitHub Issues](https://github.com/loglux/authmcp-gateway/issues)
- **Discussions:** [GitHub Discussions](https://github.com/loglux/authmcp-gateway/discussions)
- **Email:** support@yourdomain.com (if available)
