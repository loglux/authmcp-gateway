# Security Testing Guide

This guide helps you verify that your AuthMCP Gateway installation is properly secured.

## 🚀 Quick Start - Automated Testing

We provide ready-to-use security testing scripts:

**Python script** (recommended - detailed output):
```bash
# Install httpx if needed
pip install httpx

# Test any MCP server
python scripts/test_mcp_security.py http://localhost:9105/mcp

# Test with authentication
python scripts/test_mcp_security.py https://mcp.example.com/mcp --bearer YOUR_TOKEN
```

**Bash script** (lightweight - no dependencies):
```bash
# Test any MCP server  
./scripts/test_mcp_security.sh http://localhost:9105/mcp

# Test with authentication
./scripts/test_mcp_security.sh https://mcp.example.com/mcp --token YOUR_TOKEN
```

Both scripts test:
- ✅ Unauthenticated access rejection
- ✅ Invalid token rejection  
- ✅ Tool execution authorization
- ✅ Information disclosure in errors
- ✅ Named server endpoints security

---

## Quick Security Checklist

After deploying AuthMCP Gateway, verify these essential security features:

- [ ] MCP endpoints require authentication
- [ ] Invalid tokens are rejected
- [ ] Missing tokens return 401 Unauthorized
- [ ] Failed login attempts are logged
- [ ] Rate limiting is active
- [ ] HTTPS is enabled (production only)

---

## Manual Security Tests

Run these tests to verify your installation is secure. Replace `http://localhost:9105` with your actual URL.

### Test 1: MCP Endpoint Without Token

**What it tests:** MCP endpoint rejects unauthenticated requests

```bash
curl -X POST http://localhost:9105/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  -w "\nHTTP Status: %{http_code}\n"
```

**Expected result:**
- HTTP Status: 401
- JSON error response indicating authentication is required

```json
{
  "detail": "Unauthorized"
}
```

---

### Test 2: MCP Endpoint With Invalid Token

**What it tests:** Invalid/fake tokens are rejected

```bash
curl -X POST http://localhost:9105/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Authorization: Bearer fake_token_12345" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  -w "\nHTTP Status: %{http_code}\n"
```

**Expected result:**
- HTTP Status: 401
- JSON error indicating invalid/expired token (401)

---

### Test 3: Login With Wrong Password

**What it tests:** Failed authentication is properly rejected

```bash
curl -X POST http://localhost:9105/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"WRONG_PASSWORD"}' \
  -w "\nHTTP Status: %{http_code}\n"
```

**Expected result:**
- HTTP Status: 401
- Error message about invalid credentials

---

### Test 4: Complete Valid Flow

**What it tests:** Proper authentication and MCP access work correctly

#### Step 1: Login with correct credentials

```bash
# Save response to extract token
curl -X POST http://localhost:9105/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"your_username","password":"your_password"}' \
  -s | jq .
```

**Expected result:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1...",
  "refresh_token": "eyJ0eXAiOiJKV1...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

#### Step 2: Use token to access MCP endpoint

```bash
# Replace YOUR_TOKEN with the access_token from step 1
curl -X POST http://localhost:9105/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  -s | jq .
```

**Expected result:**
- HTTP Status: 200
- Valid JSON-RPC response with tools list

---

### Test 5: Specific MCP Server Endpoint

**What it tests:** Named server endpoints also require authentication

```bash
# Without token - should fail
curl -X POST http://localhost:9105/mcp/github-mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  -w "\nHTTP Status: %{http_code}\n"
```

**Expected result:**
- HTTP Status: 401
- Authentication required error

---

### Test 6: Tools Execution Without Permission

**What it tests:** Tool calls require proper authorization

```bash
# First get a valid token (from Test 4)
# Then try to call a tool you don't have permission for

curl -X POST http://localhost:9105/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "restricted_tool",
      "arguments": {}
    }
  }' \
  -s | jq .
```

**Expected result:**
- Proper permission error if tool is restricted
- Should be logged as suspicious activity

---

## Automated Testing Script

Save this as `test_security.sh` for quick security verification:

```bash
#!/bin/bash

BASE_URL="${BASE_URL:-http://localhost:9105}"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🔒 AuthMCP Gateway Security Tests"
echo "Testing: $BASE_URL"
echo ""

# Test 1: No token
echo -n "Test 1: MCP without token... "
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST $BASE_URL/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')

if [ "$STATUS" = "401" ]; then
  echo -e "${GREEN}✓ PASS${NC} (401 Unauthorized)"
else
  echo -e "${RED}✗ FAIL${NC} (Got $STATUS, expected 401)"
fi

# Test 2: Fake token
echo -n "Test 2: MCP with fake token... "
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST $BASE_URL/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer fake_token_12345" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')

if [ "$STATUS" = "401" ]; then
  echo -e "${GREEN}✓ PASS${NC} (401 Unauthorized)"
else
  echo -e "${RED}✗ FAIL${NC} (Got $STATUS, expected 401)"
fi

# Test 3: Wrong password
echo -n "Test 3: Login with wrong password... "
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST $BASE_URL/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"WRONG"}')

if [ "$STATUS" = "401" ]; then
  echo -e "${GREEN}✓ PASS${NC} (401 Unauthorized)"
else
  echo -e "${RED}✗ FAIL${NC} (Got $STATUS, expected 401)"
fi

echo ""
echo "✓ Basic security tests completed"
echo ""
echo -e "${YELLOW}Note: This is not a comprehensive security audit.${NC}"
echo "For production deployments, also verify:"
echo "  • HTTPS is enabled"
echo "  • JWT secret is randomized"
echo "  • Rate limiting is configured"
echo "  • Logs are monitored"
```

Make it executable and run:

```bash
chmod +x test_security.sh
./test_security.sh
```

---

## Common Issues & Troubleshooting

### Issue: All requests return 200 even without token

**Diagnosis:** Authentication might be disabled

**Fix:**
1. Check `data/config.yaml` - ensure `require_auth: true`
2. Restart the gateway
3. Check logs for authentication middleware initialization

---

### Issue: Valid tokens are rejected

**Diagnosis:** JWT secret mismatch or token expired

**Fix:**
1. Generate new token with fresh login
2. Verify JWT secret hasn't changed in config
3. Check token expiration time

---

### Issue: No security events logged

**Diagnosis:** Security logging might not be initialized

**Fix:**
1. Check database has `security_events` table
2. Verify middleware is logging unauthorized attempts
3. Check `/admin/security-logs` page

---

## Production Deployment Checklist

Before deploying to production, ensure:

### ✓ HTTPS Configuration
- [ ] Valid SSL/TLS certificate installed
- [ ] HTTP redirects to HTTPS
- [ ] HSTS headers enabled (optional but recommended)

### ✓ Secrets Management
- [ ] `JWT_SECRET_KEY` is randomized (not default)
- [ ] Admin password is strong
- [ ] Credentials not in version control

### ✓ Rate Limiting
- [ ] Rate limits configured appropriately
- [ ] Rate limit events are logged
- [ ] Consider DDoS protection (CloudFlare, etc.)

### ✓ Monitoring
- [ ] Security events logging enabled
- [ ] MCP request tracking active
- [ ] Regular log reviews scheduled
- [ ] Alert notifications configured (optional)

### ✓ Database Security
- [ ] SQLite file permissions restricted (600)
- [ ] Regular backups configured
- [ ] Backup encryption enabled (if storing sensitive data)

### ✓ Network Security
- [ ] Firewall rules restrict access
- [ ] Internal MCP servers not publicly exposed
- [ ] Admin panel access restricted by IP (optional)

---

## Security Event Monitoring

AuthMCP Gateway logs all security-related events for audit and monitoring.

### Event Types

| Event Type | Severity | Description |
|------------|----------|-------------|
| `unauthorized_access` | MEDIUM | Attempted MCP access without valid token |
| `invalid_token` | MEDIUM | Malformed or invalid JWT token |
| `rate_limit_exceeded` | HIGH | User exceeded request rate limit |
| `failed_login` | LOW | Failed authentication attempt |
| `brute_force` | CRITICAL | Multiple failed logins detected |
| `suspicious_activity` | HIGH | Unusual request patterns |

### Viewing Security Events

**Admin Panel:**
1. Go to **Admin Panel → Security Events**
2. Filter by event type, severity, time range
3. Review details: IP address, user, timestamp, request details

**API Access:**
```bash
curl -b cookies.txt http://localhost:9105/admin/api/security-events?severity=high
```

### Authentication Logs

**File-based logging** (prevents database bloat):

```bash
# View live auth events
tail -f data/logs/auth.log | jq .

# Find failed logins
cat data/logs/auth.log | jq 'select(.event_type == "failed_login")'

# Count by event type
cat data/logs/auth.log | jq -r '.event_type' | sort | uniq -c

# Failed logins by IP
cat data/logs/auth.log | jq -r 'select(.success == false) | .ip_address' | sort | uniq -c | sort -rn
```

**See:** [Logging Documentation](LOGGING.md) for complete details.

### Monitoring Best Practices

1. **Daily Reviews**
   - Check `CRITICAL` and `HIGH` severity events
   - Investigate brute force attempts
   - Review unauthorized access patterns

2. **Set Up Alerts**
   - Alert on brute force detection
   - Alert on repeated unauthorized access
   - Monitor rate limit violations

3. **Trend Analysis**
   - Track failed login rates over time
   - Identify suspicious IP addresses
   - Monitor unusual request patterns

4. **Regular Audits**
   - Weekly review of all security events
   - Monthly analysis of authentication logs
   - Quarterly security assessment

After deployment, also monitor:

- **Admin Panel → MCP Activity** - Request patterns, response times, tool usage
- **Server Logs** - `docker logs authmcp-gateway --tail 100 --follow`

---

## Security Best Practices

### Do's ✓
- Always use HTTPS in production
- Rotate JWT secrets periodically
- Monitor security event logs
- Keep admin credentials secure
- Update dependencies regularly
- Use strong passwords for all accounts

### Don'ts ✗
- Never disable authentication in production
- Don't use default JWT secrets
- Don't expose SQLite database file
- Don't ignore security event alerts
- Don't share access tokens
- Don't log sensitive data

---

## Need Help?

If you discover a security vulnerability:
1. **Do not** open a public GitHub issue
2. Contact the maintainers privately
3. Provide details about the vulnerability
4. Allow time for a fix before public disclosure

For general security questions, check the main [README.md](../README.md) or open a discussion on GitHub.
