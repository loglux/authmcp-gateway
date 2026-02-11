"""MCP Proxy - Routes tool calls to backend MCP servers."""

import asyncio
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone

import httpx

from .store import (
    list_mcp_servers,
    get_tool_mapping,
    check_user_mcp_access,
    update_server_health
)

logger = logging.getLogger(__name__)


class McpProxy:
    """MCP Gateway proxy that routes requests to backend MCP servers."""

    def __init__(self, db_path: str, timeout: int = 30):
        """Initialize MCP proxy.

        Args:
            db_path: Path to SQLite database
            timeout: Request timeout in seconds
        """
        self.db_path = db_path
        self.timeout = timeout
        self._tools_cache: Dict[int, List[Dict[str, Any]]] = {}
        self._cache_timestamp: Dict[int, datetime] = {}
        self._cache_ttl = 60  # Cache TTL in seconds

    async def list_tools(self, user_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Aggregate tools list from all backend MCP servers.

        Args:
            user_id: Optional user ID for permission filtering

        Returns:
            List of tool definitions from all enabled servers
        """
        servers = list_mcp_servers(
            self.db_path,
            enabled_only=True,
            user_id=user_id
        )

        if not servers:
            logger.warning("No enabled MCP servers found")
            return []

        # Fetch tools from all servers in parallel
        tasks = []
        for server in servers:
            tasks.append(self._fetch_tools_from_server(server))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Aggregate tools
        all_tools = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Failed to fetch tools from server {servers[i]['name']}: {result}")
                continue

            if result:
                all_tools.extend(result)

        logger.info(f"Aggregated {len(all_tools)} tools from {len(servers)} servers")
        return all_tools

    async def _fetch_tools_from_server(self, server: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fetch tools list from a backend MCP server.

        Args:
            server: Server dict from database

        Returns:
            List of tool definitions
        """
        server_id = server['id']
        server_name = server['name']
        server_url = server['url']

        # Check cache
        if self._is_cache_valid(server_id):
            logger.debug(f"Using cached tools for server {server_name}")
            return self._tools_cache[server_id]

        try:
            # Prepare auth headers
            headers = self._get_auth_headers(server)

            # Request tools from backend
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    server_url,
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/list",
                        "params": {}
                    },
                    headers=headers
                )

                # Handle 401 with token refresh (NEW)
                if response.status_code == 401 and server.get('refresh_token_hash'):
                    logger.warning(f"Got 401 from {server_name}, attempting token refresh")

                    try:
                        from .token_manager import get_token_manager
                        token_mgr = get_token_manager()
                        success, error = await token_mgr.refresh_server_token(
                            server_id,
                            triggered_by='reactive_401'
                        )

                        if success:
                            # Reload server with new token and retry
                            server = get_mcp_server(self.db_path, server_id)
                            headers = self._get_auth_headers(server)
                            response = await client.post(
                                server_url,
                                json={
                                    "jsonrpc": "2.0",
                                    "id": 1,
                                    "method": "tools/list",
                                    "params": {}
                                },
                                headers=headers
                            )
                            logger.info(f"Retry after token refresh succeeded for {server_name}")
                        else:
                            logger.error(f"Token refresh failed for {server_name}: {error}")
                    except Exception as refresh_error:
                        logger.error(f"Exception during token refresh: {refresh_error}")

                response.raise_for_status()
                data = response.json()

                if "result" in data and "tools" in data["result"]:
                    tools = data["result"]["tools"]

                    # Add server metadata to each tool
                    for tool in tools:
                        tool["_server_id"] = server_id
                        tool["_server_name"] = server_name

                    # Update cache
                    self._tools_cache[server_id] = tools
                    self._cache_timestamp[server_id] = datetime.now(timezone.utc)

                    # Update server health
                    update_server_health(
                        self.db_path,
                        server_id,
                        status="online",
                        tools_count=len(tools)
                    )

                    logger.info(f"Fetched {len(tools)} tools from {server_name}")
                    return tools

                else:
                    logger.warning(f"Invalid response from server {server_name}: {data}")
                    return []

        except httpx.HTTPError as e:
            logger.error(f"HTTP error fetching tools from {server_name}: {e}")
            update_server_health(
                self.db_path,
                server_id,
                status="error",
                error=str(e)
            )
            return []

        except Exception as e:
            logger.error(f"Error fetching tools from {server_name}: {e}")
            update_server_health(
                self.db_path,
                server_id,
                status="error",
                error=str(e)
            )
            return []

    def _is_cache_valid(self, server_id: int) -> bool:
        """Check if tools cache is still valid.

        Args:
            server_id: Server ID

        Returns:
            bool: True if cache is valid
        """
        if server_id not in self._cache_timestamp:
            return False

        age = (datetime.now(timezone.utc) - self._cache_timestamp[server_id]).total_seconds()
        return age < self._cache_ttl

    async def call_tool(
        self,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
        user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Route tool call to appropriate backend MCP server.

        Args:
            tool_name: Name of the tool to call
            arguments: Tool arguments
            user_id: Optional user ID for permission checking

        Returns:
            Tool call result

        Raises:
            ToolNotFoundError: If tool not found
            PermissionError: If user doesn't have access
            httpx.HTTPError: If backend request fails
        """
        # Find server for this tool
        server = await self._route_tool_to_server(tool_name, user_id)

        if not server:
            raise ToolNotFoundError(f"Tool '{tool_name}' not found in any MCP server")

        # Check user permissions
        if user_id and not check_user_mcp_access(self.db_path, user_id, server['id']):
            raise PermissionError(f"User {user_id} doesn't have access to server {server['name']}")

        # Proxy request to backend server
        return await self._proxy_tool_call(server, tool_name, arguments)

    async def _route_tool_to_server(
        self,
        tool_name: str,
        user_id: Optional[int] = None
    ) -> Optional[Dict[str, Any]]:
        """Determine which backend server should handle this tool.

        Routing strategy (in order):
        1. Prefix match (fast path)
        2. Explicit mapping (from database)
        3. Auto-discovery (search in cached tools)

        Args:
            tool_name: Tool name
            user_id: Optional user ID for filtering

        Returns:
            Server dict or None if not found
        """
        servers = list_mcp_servers(
            self.db_path,
            enabled_only=True,
            user_id=user_id
        )

        # Strategy 1: Prefix match
        for server in servers:
            prefix = server.get('tool_prefix')
            if prefix and tool_name.startswith(prefix):
                logger.debug(f"Routed '{tool_name}' to {server['name']} via prefix '{prefix}'")
                return server

        # Strategy 2: Explicit mapping
        server_id = get_tool_mapping(self.db_path, tool_name)
        if server_id:
            for server in servers:
                if server['id'] == server_id:
                    logger.debug(f"Routed '{tool_name}' to {server['name']} via explicit mapping")
                    return server

        # Strategy 3: Auto-discovery
        for server in servers:
            # Check if we have cached tools for this server
            if server['id'] in self._tools_cache:
                tools = self._tools_cache[server['id']]
                tool_names = [t['name'] for t in tools]
                if tool_name in tool_names:
                    logger.debug(f"Routed '{tool_name}' to {server['name']} via auto-discovery")
                    return server

        # Strategy 4: Broadcast (query all servers)
        logger.debug(f"Broadcasting tool discovery for '{tool_name}'")
        for server in servers:
            try:
                tools = await self._fetch_tools_from_server(server)
                tool_names = [t['name'] for t in tools]
                if tool_name in tool_names:
                    logger.info(f"Found '{tool_name}' in {server['name']} via broadcast")
                    return server
            except Exception as e:
                logger.error(f"Error broadcasting to {server['name']}: {e}")
                continue

        logger.warning(f"Tool '{tool_name}' not found in any server")
        return None

    async def _proxy_tool_call(
        self,
        server: Dict[str, Any],
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Proxy tool call to backend MCP server.

        Args:
            server: Server dict
            tool_name: Tool name
            arguments: Tool arguments

        Returns:
            Tool call result

        Raises:
            httpx.HTTPError: If request fails
        """
        server_url = server['url']
        server_name = server['name']

        try:
            headers = self._get_auth_headers(server)

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    server_url,
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": tool_name,
                            "arguments": arguments or {}
                        }
                    },
                    headers=headers
                )

                # Handle 401 with token refresh (NEW)
                if response.status_code == 401 and server.get('refresh_token_hash'):
                    logger.warning(f"Got 401 calling '{tool_name}' on {server_name}, attempting token refresh")

                    try:
                        from .token_manager import get_token_manager
                        token_mgr = get_token_manager()
                        success, error = await token_mgr.refresh_server_token(
                            server['id'],
                            triggered_by='reactive_401'
                        )

                        if success:
                            # Reload server with new token and retry
                            server = get_mcp_server(self.db_path, server['id'])
                            headers = self._get_auth_headers(server)
                            response = await client.post(
                                server_url,
                                json={
                                    "jsonrpc": "2.0",
                                    "id": 1,
                                    "method": "tools/call",
                                    "params": {
                                        "name": tool_name,
                                        "arguments": arguments or {}
                                    }
                                },
                                headers=headers
                            )
                            logger.info(f"Retry after token refresh succeeded for '{tool_name}' on {server_name}")
                        else:
                            logger.error(f"Token refresh failed for {server_name}: {error}")
                    except Exception as refresh_error:
                        logger.error(f"Exception during token refresh: {refresh_error}")

                response.raise_for_status()
                data = response.json()

                # Add metadata about which server handled the request
                if "result" in data:
                    if "_meta" not in data["result"]:
                        data["result"]["_meta"] = {}

                    data["result"]["_meta"]["server_id"] = server['id']
                    data["result"]["_meta"]["server_name"] = server_name
                    data["result"]["_meta"]["tool_name"] = tool_name

                logger.info(f"Tool '{tool_name}' executed on {server_name}")
                return data

        except httpx.HTTPError as e:
            logger.error(f"HTTP error calling tool '{tool_name}' on {server_name}: {e}")
            update_server_health(
                self.db_path,
                server['id'],
                status="error",
                error=str(e)
            )
            raise

        except Exception as e:
            logger.error(f"Error calling tool '{tool_name}' on {server_name}: {e}")
            raise

    def _get_auth_headers(self, server: Dict[str, Any]) -> Dict[str, str]:
        """Get authentication headers for backend MCP server.

        Args:
            server: Server dict

        Returns:
            Headers dict
        """
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        auth_type = server.get('auth_type', 'none')
        auth_token = server.get('auth_token')

        if auth_type == 'bearer' and auth_token:
            headers['Authorization'] = f'Bearer {auth_token}'
        elif auth_type == 'basic' and auth_token:
            headers['Authorization'] = f'Basic {auth_token}'

        return headers

    def invalidate_cache(self, server_id: Optional[int] = None):
        """Invalidate tools cache.

        Args:
            server_id: Optional server ID. If None, invalidate all.
        """
        if server_id:
            self._tools_cache.pop(server_id, None)
            self._cache_timestamp.pop(server_id, None)
            logger.info(f"Invalidated cache for server {server_id}")
        else:
            self._tools_cache.clear()
            self._cache_timestamp.clear()
            logger.info("Invalidated all cache")


class ToolNotFoundError(Exception):
    """Raised when tool is not found in any MCP server."""
    pass
