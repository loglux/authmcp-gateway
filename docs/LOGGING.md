# Logging Architecture

AuthMCP Gateway uses **file-based JSON logging** for authentication events and MCP requests. This prevents database bloat and provides better performance for high-traffic scenarios.

## Overview

### Why File-Based Logging?

**Database Logging Issues:**
- ❌ Database bloats rapidly with high-frequency events
- ❌ Write locks can block other operations
- ❌ Slow queries when tables grow large
- ❌ Difficult to rotate/archive old logs

**File-Based Benefits:**
- ✅ No database bloat - logs stay in files
- ✅ Daily rotation with automatic cleanup
- ✅ Fast writes (append-only)
- ✅ Standard log analysis tools work
- ✅ Easy to backup/archive

---

## Log Files

### 1. Authentication Logs (`data/logs/auth.log`)

**Purpose:** All authentication-related events

**Events logged:**
- `login` - Successful user login
- `admin_login` - Admin panel login
- `logout` - User logout
- `failed_login` - Failed login attempt
- `register` - New user registration
- `password_change` - Password updated
- `token_refresh` - Token refreshed

**Format (JSON):**
```json
{
  "timestamp": "2026-02-12T13:01:55.725163Z",
  "level": "INFO",
  "logger": "auth",
  "message": "Auth event: admin_login",
  "event_type": "admin_login",
  "user_id": 1,
  "username": "admin",
  "ip_address": "192.168.10.1",
  "user_agent": "Mozilla/5.0...",
  "success": true,
  "details": null
}
```

**Rotation:**
- Daily rotation at midnight UTC
- 30 days retention (configurable)
- Old logs automatically deleted

**Location:**
```bash
data/logs/
├── auth.log              # Current log
├── auth.log.2026-02-11   # Yesterday's log
├── auth.log.2026-02-10   # 2 days ago
└── ...                   # Up to 30 days
```

---

### 2. MCP Request Logs (`data/logs/mcp_requests.log`)

**Purpose:** All MCP protocol requests (tools/list, tools/call, etc.)

**Events logged:**
- `tools/list` - List available tools
- `tools/call` - Execute a tool
- `initialize` - MCP session initialization
- `prompts/list` - List prompts
- `resources/list` - List resources

**Format (JSON):**
```json
{
  "timestamp": "2026-02-12T13:25:45.123456Z",
  "level": "INFO",
  "logger": "mcp_requests",
  "message": "MCP request: tools/call",
  "event_type": "mcp_request",
  "method": "tools/call",
  "server_id": 3,
  "server_name": "RAG",
  "user_id": 1,
  "username": "admin",
  "tool_name": "rag_query",
  "response_time_ms": 245,
  "success": true,
  "error": null,
  "suspicious": false
}
```

**Rotation:**
- Daily rotation at midnight UTC
- 30 days retention
- Automatic cleanup

**Performance:**
- Handles high-frequency requests (100+ req/sec)
- No impact on database performance
- Async writes (non-blocking)

---

## Configuration

### Environment Variables

```bash
# No specific configuration needed - uses defaults
# Files are automatically created in data/logs/
```

### Retention Period

Default: **30 days**

To change retention, modify `backupCount` in `src/authmcp_gateway/logging_config.py`:

```python
def setup_file_logger(
    name: str,
    log_file: Path,
    level: int = logging.INFO,
    max_days: int = 30  # ← Change this
) -> logging.Logger:
```

---

## Viewing Logs

### Via Admin Panel

**Auth Logs:**
- Go to **Admin Panel → Auth Logs**
- Features:
  - Pagination (50 entries per page)
  - Filter by event type (login, admin_login, failed_login, etc.)
  - Filter by time range (Last 24h, 7d, 30d, All)
  - Manual cleanup (delete entries older than 30 days)

**MCP Activity:**
- Go to **Admin Panel → MCP Activity**
- Features:
  - Live feed (auto-refresh every 5 seconds)
  - Filter by method (tools/list, tools/call, etc.)
  - Filter by success/failure
  - Shows last 60 seconds by default

### Via Command Line

**View recent auth events:**
```bash
tail -f data/logs/auth.log | jq .
```

**View recent MCP requests:**
```bash
tail -f data/logs/mcp_requests.log | jq .
```

**Count events by type (auth):**
```bash
cat data/logs/auth.log | jq -r '.event_type' | sort | uniq -c
```

**Find failed logins:**
```bash
cat data/logs/auth.log | jq 'select(.event_type == "failed_login")'
```

**Check average response time (MCP):**
```bash
cat data/logs/mcp_requests.log | jq -r '.response_time_ms' | awk '{sum+=$1; count++} END {print sum/count}'
```

---

## Log Analysis

### Parse with `jq`

**Extract failed login attempts:**
```bash
cat data/logs/auth.log | jq 'select(.success == false)' | jq -r '[.timestamp, .username, .ip_address] | @tsv'
```

**Top 10 users by MCP requests:**
```bash
cat data/logs/mcp_requests.log | jq -r '.username' | sort | uniq -c | sort -rn | head -10
```

**Average response time by tool:**
```bash
cat data/logs/mcp_requests.log | jq -r '[.tool_name, .response_time_ms] | @tsv' | awk '{sum[$1]+=$2; count[$1]++} END {for (tool in sum) print tool, sum[tool]/count[tool]}'
```

### Import to ELK Stack

Since logs are in JSON format, they can be imported to Elasticsearch/Logstash/Kibana:

```yaml
# Logstash example
input {
  file {
    path => "/path/to/data/logs/*.log"
    codec => "json"
  }
}

filter {
  date {
    match => ["timestamp", "ISO8601"]
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "authmcp-%{+YYYY.MM.dd}"
  }
}
```

---

## Security Events (Database)

**Important:** Security events (unauthorized access, rate limiting, brute force attempts) are **NOT** stored in files. They remain in the SQLite database (`security_events` table) because:

- Need foreign keys to users table
- Critical audit trail (must not be rotated away)
- Lower frequency (only threats/blocks)
- Require relational queries for analysis

**View security events:**
- Admin Panel → Security Events
- Filters: severity, event type, time range
- Shows: unauthorized_access, rate_limit_exceeded, suspicious_activity, brute_force

---

## Backup & Archiving

### Manual Backup

```bash
# Backup all logs
tar -czf logs-backup-$(date +%Y%m%d).tar.gz data/logs/

# Backup to remote server
rsync -avz data/logs/ user@backup-server:/backups/authmcp-logs/
```

### Automatic Backup (Cron)

```bash
# Add to crontab
0 2 * * * cd /path/to/authmcp-gateway && tar -czf /backups/logs-$(date +\%Y\%m\%d).tar.gz data/logs/
```

### Docker Volume Backup

```bash
# Create volume backup
docker run --rm \
  -v authmcp-gateway_data:/data \
  -v $(pwd)/backups:/backup \
  alpine tar -czf /backup/logs-$(date +%Y%m%d).tar.gz /data/logs
```

---

## Troubleshooting

### Logs not appearing

**Check file permissions:**
```bash
ls -la data/logs/
# Should be writable by container user (root in most cases)
```

**Check if logger is initialized:**
```bash
docker-compose logs | grep "get_auth_logger\|get_mcp_logger"
```

**Manually test logging:**
```python
from src.authmcp_gateway.logging_config import get_auth_logger, log_auth_event_to_file

logger = get_auth_logger()
log_auth_event_to_file(
    logger=logger,
    event_type="test",
    username="test_user",
    success=True
)
```

### Log rotation not working

**Check TimedRotatingFileHandler:**
```python
# In logging_config.py
handler = TimedRotatingFileHandler(
    filename=str(log_file),
    when='midnight',    # ← Rotates at midnight
    interval=1,         # ← Every 1 day
    backupCount=30,     # ← Keep 30 days
    encoding='utf-8',
    utc=True           # ← Use UTC time
)
```

**Force rotation manually:**
```bash
# Rename current log
mv data/logs/auth.log data/logs/auth.log.$(date +%Y-%m-%d)
# Logger will create new auth.log on next write
docker-compose restart
```

---

## Migration from Database

If you have old logs in the database (`auth_audit_log` or `mcp_requests` tables), you can migrate them:

```python
import sqlite3
import json
from pathlib import Path

# Read from database
conn = sqlite3.connect('data/auth.db')
cursor = conn.cursor()
cursor.execute("SELECT * FROM auth_audit_log ORDER BY timestamp")

# Write to file
log_file = Path('data/logs/auth.log')
with open(log_file, 'a') as f:
    for row in cursor.fetchall():
        entry = {
            "timestamp": row[6],  # timestamp column
            "event_type": row[1],
            "user_id": row[2],
            "username": row[3],
            "success": bool(row[4]),
            "details": row[5]
        }
        f.write(json.dumps(entry) + '\n')

conn.close()
```

---

## Best Practices

1. **Monitor disk space:** Logs can grow large in high-traffic scenarios
   ```bash
   du -sh data/logs/
   ```

2. **Set up log rotation:** Ensure 30-day retention is adequate for your compliance needs

3. **Backup regularly:** Keep offsite backups of logs for audit trails

4. **Use structured queries:** JSON format enables powerful log analysis with `jq`

5. **Alert on anomalies:** Set up alerts for failed login spikes, slow responses, etc.

6. **Don't store PII:** Logs include usernames and IPs but not passwords or sensitive data

---

## Related Documentation

- [Security Testing Guide](SECURITY_TESTING.md) - Testing authentication security
- [API Reference](API.md) - API endpoints for log access
- [Architecture](ARCHITECTURE.md) - System architecture overview
