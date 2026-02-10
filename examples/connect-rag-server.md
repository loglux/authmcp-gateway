# Connecting RAG MCP Server to FastMCP Auth

This example shows how to connect a RAG (Retrieval-Augmented Generation) MCP server to FastMCP Auth Gateway.

## Architecture

```
┌─────────────────────────┐        ┌──────────────────────┐
│  FastMCP Auth Gateway   │        │  RAG MCP Server      │
│  Port: 8000             │───────>│  Port: 8001          │
│  /mcp (authenticated)   │        │  /mcp (internal)     │
└─────────────────────────┘        └──────────────────────┘
```

## Step 1: Deploy RAG MCP Server

```bash
# Clone RAG server
git clone https://github.com/loglux/rag-mcp-server.git
cd rag-mcp-server

# Configure
cp .env.example .env
# Edit .env with your settings

# Start server
docker-compose up -d

# Verify it's running
curl http://localhost:8001/mcp -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

## Step 2: Register Server in FastMCP Auth

### Option A: Via Admin Panel

1. Open `http://localhost:8000/admin`
2. Login with admin credentials
3. Navigate to **MCP Servers**
4. Click **Add Server**
5. Fill in details:
   - **Name**: `RAG Knowledge Base`
   - **URL**: `http://localhost:8001/mcp`
   - **Description**: `RAG server for knowledge base queries`
   - **Tool Prefix**: `rag_`
   - **Enabled**: Yes
   - **Auth Type**: `none` (if on same network) or `bearer` (if secured)
   - **Routing Strategy**: `prefix`
6. Click **Save**

### Option B: Via Python

```python
from fastmcp_auth.mcp.store import create_mcp_server

server_id = create_mcp_server(
    db_path="data/auth.db",
    name="RAG Knowledge Base",
    url="http://localhost:8001/mcp",
    description="RAG server for knowledge base queries",
    tool_prefix="rag_",
    enabled=True,
    auth_type="none",
    routing_strategy="prefix"
)

print(f"Server registered with ID: {server_id}")
```

### Option C: Via SQL

```sql
INSERT INTO mcp_servers (
    name, url, description, tool_prefix, enabled,
    auth_type, routing_strategy, status
) VALUES (
    'RAG Knowledge Base',
    'http://localhost:8001/mcp',
    'RAG server for knowledge base queries',
    'rag_',
    1,
    'none',
    'prefix',
    'unknown'
);
```

## Step 3: Verify Connection

### Check Health Status

```bash
# Via admin panel
open http://localhost:8000/admin/mcp-servers

# Via API
curl http://localhost:8000/admin/api/mcp-servers \
  -H "Cookie: admin_session=YOUR_SESSION_COOKIE"
```

### Test Tool Discovery

```bash
# Get token
TOKEN=$(curl -s -X POST http://localhost:8000/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"password","username":"admin","password":"your-password"}' \
  | jq -r .access_token)

# List all tools (should include RAG tools)
curl -H "Authorization: Bearer $TOKEN" \
  -X POST http://localhost:8000/mcp \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | jq '.result.tools[] | select(.name | startswith("rag_"))'
```

## Step 4: Use RAG Tools

```bash
# Query knowledge base
curl -H "Authorization: Bearer $TOKEN" \
  -X POST http://localhost:8000/mcp \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"tools/call",
    "params":{
      "name":"rag_query",
      "arguments":{
        "question":"What is FastMCP Auth?"
      }
    }
  }' | jq .
```

## Tool Prefix Routing

With `tool_prefix="rag_"`, all tools from RAG server will be prefixed:

- `list_knowledge_bases` → `rag_list_knowledge_bases`
- `query` → `rag_query`
- `retrieve_chunks` → `rag_retrieve_chunks`

This prevents naming conflicts when aggregating multiple servers.

## Docker Compose Example

```yaml
version: '3.8'

services:
  fastmcp-auth:
    image: loglux/fastmcp-auth:latest
    ports:
      - "8000:8000"
    environment:
      - JWT_SECRET_KEY=your-secret
      - MCP_PUBLIC_URL=http://localhost:8000
    volumes:
      - ./data:/app/data
    networks:
      - mcp-network

  rag-server:
    image: loglux/rag-mcp-server:latest
    ports:
      - "8001:8000"
    environment:
      - RAG_API_BASE_URL=http://rag-backend:8004
    networks:
      - mcp-network

networks:
  mcp-network:
    driver: bridge
```

## Troubleshooting

### Server shows as "offline"

1. Check server is running: `curl http://localhost:8001/mcp`
2. Check network connectivity from gateway container
3. Verify URL is correct (include `/mcp` path)
4. Check server logs for errors

### Tools not appearing

1. Verify server returns tools: `curl http://localhost:8001/mcp -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'`
2. Check health checker logs in gateway
3. Refresh admin panel (health check runs every 60s)

### Authentication errors

1. If using `auth_type="bearer"`, verify token is correct
2. Check server expects the auth format gateway sends
3. Test direct connection without gateway first

## Next Steps

- [Connect Home Assistant](./connect-home-assistant.md)
- [Create Custom MCP Server](./custom-mcp-server.md)
- [User Permissions](./user-permissions.md)
