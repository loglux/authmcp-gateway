"""MCP Proxy - Routes requests to backend MCP servers.

Supports full MCP protocol: tools, resources, prompts, completions.
"""

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx

from .store import (
    check_user_mcp_access,
    get_mcp_server,
    get_tool_mapping,
    list_mcp_servers,
    update_server_health,
)

logger = logging.getLogger(__name__)
_MCP_DEBUG = os.getenv("MCP_DEBUG", "").lower() in ("1", "true", "yes", "on")


def normalize_server_name(name: str) -> str:
    """Normalize server name for comparison (lowercase, no spaces/special chars)."""
    return name.lower().replace(" ", "").replace("-", "").replace("_", "")


def get_auth_headers(server: Dict[str, Any]) -> Dict[str, str]:
    """Get authentication headers for a backend MCP server."""
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    auth_type = server.get("auth_type", "none")
    auth_token = server.get("auth_token")

    if auth_type == "bearer" and auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    elif auth_type == "basic" and auth_token:
        headers["Authorization"] = f"Basic {auth_token}"

    return headers


class McpProxy:
    """MCP Gateway proxy that routes requests to backend MCP servers."""

    def __init__(self, db_path: str, timeout: int = 30):
        self.db_path = db_path
        self.timeout = timeout
        # Caches: server_id → items
        self._tools_cache: Dict[int, List[Dict[str, Any]]] = {}
        self._resources_cache: Dict[int, List[Dict[str, Any]]] = {}
        self._prompts_cache: Dict[int, List[Dict[str, Any]]] = {}
        self._capabilities_cache: Dict[int, Dict[str, Any]] = {}
        self._cache_timestamp: Dict[int, datetime] = {}
        self._cache_ttl = 60  # seconds
        self._http_client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create shared httpx.AsyncClient."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(timeout=self.timeout)
        return self._http_client

    async def close(self) -> None:
        """Close shared HTTP client."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
            self._http_client = None

    # ========================================================================
    # GENERIC JSON-RPC PROXY
    # ========================================================================

    async def _proxy_jsonrpc(
        self,
        server: Dict[str, Any],
        method: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Send a JSON-RPC request to a backend server and return parsed response.

        Includes 401 token-refresh retry logic.

        Returns:
            Parsed JSON response dict (with "result" or "error" key).

        Raises:
            httpx.HTTPError: On HTTP-level failure.
        """
        server_url = server["url"]
        server_name = server["name"]
        server_id = server["id"]
        headers = self._get_auth_headers(server)

        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}

        client = await self._get_client()
        response = await client.post(server_url, json=payload, headers=headers)

        if _MCP_DEBUG:
            snippet = response.text[:300] if response.text else ""
            logger.debug(
                "MCP_DEBUG %s %s -> HTTP %s. Body: %s",
                method,
                server_url,
                response.status_code,
                snippet,
            )

        # Handle 401 with token refresh
        if response.status_code == 401 and server.get("refresh_token_hash"):
            logger.warning(f"Got 401 from {server_name} for {method}, attempting token refresh")
            try:
                from .token_manager import get_token_manager

                token_mgr = get_token_manager()
                success, error = await token_mgr.refresh_server_token(
                    server_id, triggered_by="reactive_401"
                )
                if success:
                    server = get_mcp_server(self.db_path, server_id)
                    headers = self._get_auth_headers(server)
                    response = await client.post(server_url, json=payload, headers=headers)
                    logger.info(
                        f"Retry after token refresh succeeded for {method} on {server_name}"
                    )
                else:
                    logger.error(f"Token refresh failed for {server_name}: {error}")
            except Exception as refresh_error:
                logger.error(f"Exception during token refresh: {refresh_error}")

        response.raise_for_status()
        return response.json()

    def _get_servers(
        self, user_id: Optional[int] = None, server_name: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get filtered list of enabled MCP servers."""
        servers = list_mcp_servers(self.db_path, enabled_only=True, user_id=user_id)
        if server_name:
            normalized = normalize_server_name(server_name)
            servers = [s for s in servers if normalize_server_name(s["name"]) == normalized]
        return servers

    def _is_cache_valid(self, server_id: int) -> bool:
        """Check if cache is still valid for a server."""
        if server_id not in self._cache_timestamp:
            return False
        age = (datetime.now(timezone.utc) - self._cache_timestamp[server_id]).total_seconds()
        return age < self._cache_ttl

    def _update_cache_timestamp(self, server_id: int) -> None:
        self._cache_timestamp[server_id] = datetime.now(timezone.utc)

    # ========================================================================
    # CAPABILITIES DISCOVERY
    # ========================================================================

    async def _fetch_capabilities_from_server(self, server: Dict[str, Any]) -> Dict[str, Any]:
        """Send initialize to a backend and extract its capabilities."""
        server_id = server["id"]

        if server_id in self._capabilities_cache and self._is_cache_valid(server_id):
            return self._capabilities_cache[server_id]

        try:
            data = await self._proxy_jsonrpc(
                server,
                "initialize",
                {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "authmcp-gateway", "version": "2.0.0"},
                },
            )
            caps = data.get("result", {}).get("capabilities", {})
            self._capabilities_cache[server_id] = caps

            # Send initialized notification (fire-and-forget)
            try:
                client = await self._get_client()
                headers = self._get_auth_headers(server)
                await client.post(
                    server["url"],
                    json={
                        "jsonrpc": "2.0",
                        "method": "notifications/initialized",
                    },
                    headers=headers,
                )
            except Exception:
                pass  # Best-effort notification

            return caps
        except Exception as e:
            logger.debug(f"Failed to fetch capabilities from {server['name']}: {e}")
            return {}

    async def get_aggregated_capabilities(
        self,
        user_id: Optional[int] = None,
        server_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Query backends and merge capabilities.

        Returns the union: if ANY backend supports a capability, we advertise it.
        """
        servers = self._get_servers(user_id=user_id, server_name=server_name)
        if not servers:
            return {"tools": {}}

        tasks = [self._fetch_capabilities_from_server(s) for s in servers]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        merged: Dict[str, Any] = {}
        for result in results:
            if isinstance(result, Exception):
                continue
            for cap_name, cap_value in result.items():
                if cap_name not in merged:
                    merged[cap_name] = cap_value if isinstance(cap_value, dict) else {}

        # Always advertise tools (our core feature)
        if "tools" not in merged:
            merged["tools"] = {}

        return merged

    # ========================================================================
    # TOOLS (existing logic, refactored to use _proxy_jsonrpc)
    # ========================================================================

    async def list_tools(
        self, user_id: Optional[int] = None, server_name: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Aggregate tools list from backend MCP servers."""
        servers = self._get_servers(user_id=user_id, server_name=server_name)
        if not servers:
            logger.warning("No enabled MCP servers found")
            return []

        tasks = [self._fetch_tools_from_server(s) for s in servers]
        results = await asyncio.gather(*tasks, return_exceptions=True)

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
        """Fetch tools list from a backend MCP server."""
        server_id = server["id"]
        server_name = server["name"]

        if self._is_cache_valid(server_id) and server_id in self._tools_cache:
            logger.debug(f"Using cached tools for server {server_name}")
            return self._tools_cache[server_id]

        try:
            data = await self._proxy_jsonrpc(server, "tools/list")

            if "result" in data and "tools" in data["result"]:
                tools = data["result"]["tools"]
                for tool in tools:
                    tool["_server_id"] = server_id
                    tool["_server_name"] = server_name

                self._tools_cache[server_id] = tools
                self._update_cache_timestamp(server_id)
                update_server_health(
                    self.db_path, server_id, status="online", tools_count=len(tools)
                )
                logger.info(f"Fetched {len(tools)} tools from {server_name}")
                return tools
            else:
                logger.warning(f"Invalid tools/list response from {server_name}: {data}")
                return []

        except httpx.HTTPError as e:
            logger.error(f"HTTP error fetching tools from {server_name}: {e}")
            update_server_health(self.db_path, server_id, status="error", error=str(e))
            return []
        except Exception as e:
            logger.error(f"Error fetching tools from {server_name}: {e}")
            update_server_health(self.db_path, server_id, status="error", error=str(e))
            return []

    async def call_tool(
        self,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
        user_id: Optional[int] = None,
        server_name: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Route tool call to appropriate backend MCP server."""
        server = await self._route_tool_to_server(tool_name, user_id, server_name)

        if not server:
            scope = f" in server '{server_name}'" if server_name else " in any MCP server"
            raise ToolNotFoundError(f"Tool '{tool_name}' not found{scope}")

        if user_id and not check_user_mcp_access(self.db_path, user_id, server["id"]):
            raise PermissionError(f"User {user_id} doesn't have access to server {server['name']}")

        data = await self._proxy_jsonrpc(
            server, "tools/call", {"name": tool_name, "arguments": arguments or {}}
        )

        # Add gateway metadata
        if "result" in data:
            if "_meta" not in data["result"]:
                data["result"]["_meta"] = {}
            data["result"]["_meta"]["server_id"] = server["id"]
            data["result"]["_meta"]["server_name"] = server["name"]
            data["result"]["_meta"]["tool_name"] = tool_name

        logger.info(f"Tool '{tool_name}' executed on {server['name']}")
        return data, server

    async def _route_tool_to_server(
        self, tool_name: str, user_id: Optional[int] = None, server_name: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Determine which backend server should handle this tool."""
        servers = self._get_servers(user_id=user_id, server_name=server_name)
        if not servers:
            return None

        # Strategy 1: Prefix match
        for server in servers:
            prefix = server.get("tool_prefix")
            if prefix and tool_name.startswith(prefix):
                logger.debug(f"Routed '{tool_name}' to {server['name']} via prefix '{prefix}'")
                return server

        # Strategy 2: Explicit mapping
        server_id = get_tool_mapping(self.db_path, tool_name)
        if server_id:
            for server in servers:
                if server["id"] == server_id:
                    logger.debug(f"Routed '{tool_name}' to {server['name']} via explicit mapping")
                    return server

        # Strategy 3: Auto-discovery (cached)
        for server in servers:
            if server["id"] in self._tools_cache:
                tool_names = [t["name"] for t in self._tools_cache[server["id"]]]
                if tool_name in tool_names:
                    logger.debug(f"Routed '{tool_name}' to {server['name']} via auto-discovery")
                    return server

        # Strategy 4: Broadcast
        logger.debug(f"Broadcasting tool discovery for '{tool_name}'")
        for server in servers:
            try:
                tools = await self._fetch_tools_from_server(server)
                if any(t["name"] == tool_name for t in tools):
                    logger.info(f"Found '{tool_name}' in {server['name']} via broadcast")
                    return server
            except Exception as e:
                logger.error(f"Error broadcasting to {server['name']}: {e}")

        logger.warning(f"Tool '{tool_name}' not found in any server")
        return None

    # ========================================================================
    # RESOURCES
    # ========================================================================

    async def list_resources(
        self, user_id: Optional[int] = None, server_name: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Aggregate resources from all backend servers."""
        servers = self._get_servers(user_id=user_id, server_name=server_name)
        if not servers:
            return []

        tasks = [self._fetch_resources_from_server(s) for s in servers]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_resources = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Failed to fetch resources from {servers[i]['name']}: {result}")
                continue
            if result:
                all_resources.extend(result)

        logger.info(f"Aggregated {len(all_resources)} resources from {len(servers)} servers")
        return all_resources

    async def _fetch_resources_from_server(self, server: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fetch resources list from a single backend."""
        server_id = server["id"]
        server_name = server["name"]

        if self._is_cache_valid(server_id) and server_id in self._resources_cache:
            return self._resources_cache[server_id]

        try:
            data = await self._proxy_jsonrpc(server, "resources/list")

            if "result" in data and "resources" in data["result"]:
                resources = data["result"]["resources"]
                for r in resources:
                    r["_server_id"] = server_id
                    r["_server_name"] = server_name

                self._resources_cache[server_id] = resources
                self._update_cache_timestamp(server_id)
                logger.info(f"Fetched {len(resources)} resources from {server_name}")
                return resources
            else:
                return []

        except Exception as e:
            logger.debug(f"resources/list not supported by {server_name}: {e}")
            return []

    async def read_resource(
        self,
        uri: str,
        user_id: Optional[int] = None,
        server_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Route resources/read to the server that owns the URI.

        Returns:
            JSON-RPC response dict.

        Raises:
            ResourceNotFoundError: If URI not found in any server.
        """
        server = await self._route_resource_to_server(uri, user_id, server_name)
        if not server:
            scope = f" in server '{server_name}'" if server_name else " in any server"
            raise ResourceNotFoundError(f"Resource '{uri}' not found{scope}")

        if user_id and not check_user_mcp_access(self.db_path, user_id, server["id"]):
            raise PermissionError(f"User {user_id} doesn't have access to server {server['name']}")

        data = await self._proxy_jsonrpc(server, "resources/read", {"uri": uri})
        logger.info(f"Resource '{uri}' read from {server['name']}")
        return data, server

    async def _route_resource_to_server(
        self, uri: str, user_id: Optional[int] = None, server_name: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Find which server owns this resource URI."""
        servers = self._get_servers(user_id=user_id, server_name=server_name)

        # Check cached resources first
        for server in servers:
            if server["id"] in self._resources_cache:
                uris = [r["uri"] for r in self._resources_cache[server["id"]]]
                if uri in uris:
                    return server

        # Broadcast resources/list to find URI
        for server in servers:
            try:
                resources = await self._fetch_resources_from_server(server)
                if any(r["uri"] == uri for r in resources):
                    return server
            except Exception:
                continue

        return None

    async def list_resource_templates(
        self, user_id: Optional[int] = None, server_name: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Aggregate resource templates from all backend servers."""
        servers = self._get_servers(user_id=user_id, server_name=server_name)
        if not servers:
            return []

        async def fetch_one(server: Dict[str, Any]) -> List[Dict[str, Any]]:
            try:
                data = await self._proxy_jsonrpc(server, "resources/templates/list")
                templates = data.get("result", {}).get("resourceTemplates", [])
                for t in templates:
                    t["_server_id"] = server["id"]
                    t["_server_name"] = server["name"]
                return templates
            except Exception:
                return []

        results = await asyncio.gather(*[fetch_one(s) for s in servers], return_exceptions=True)

        all_templates = []
        for result in results:
            if isinstance(result, list):
                all_templates.extend(result)
        return all_templates

    # ========================================================================
    # PROMPTS
    # ========================================================================

    async def list_prompts(
        self, user_id: Optional[int] = None, server_name: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Aggregate prompts from all backend servers."""
        servers = self._get_servers(user_id=user_id, server_name=server_name)
        if not servers:
            return []

        tasks = [self._fetch_prompts_from_server(s) for s in servers]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_prompts = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Failed to fetch prompts from {servers[i]['name']}: {result}")
                continue
            if result:
                all_prompts.extend(result)

        logger.info(f"Aggregated {len(all_prompts)} prompts from {len(servers)} servers")
        return all_prompts

    async def _fetch_prompts_from_server(self, server: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fetch prompts list from a single backend."""
        server_id = server["id"]
        server_name = server["name"]

        if self._is_cache_valid(server_id) and server_id in self._prompts_cache:
            return self._prompts_cache[server_id]

        try:
            data = await self._proxy_jsonrpc(server, "prompts/list")

            if "result" in data and "prompts" in data["result"]:
                prompts = data["result"]["prompts"]
                for p in prompts:
                    p["_server_id"] = server_id
                    p["_server_name"] = server_name

                self._prompts_cache[server_id] = prompts
                self._update_cache_timestamp(server_id)
                logger.info(f"Fetched {len(prompts)} prompts from {server_name}")
                return prompts
            else:
                return []

        except Exception as e:
            logger.debug(f"prompts/list not supported by {server_name}: {e}")
            return []

    async def get_prompt(
        self,
        name: str,
        arguments: Optional[Dict[str, Any]] = None,
        user_id: Optional[int] = None,
        server_name: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Route prompts/get to the server that owns the prompt.

        Returns:
            (JSON-RPC response dict, server dict).

        Raises:
            PromptNotFoundError: If prompt not found.
        """
        server = await self._route_prompt_to_server(name, user_id, server_name)
        if not server:
            scope = f" in server '{server_name}'" if server_name else " in any server"
            raise PromptNotFoundError(f"Prompt '{name}' not found{scope}")

        if user_id and not check_user_mcp_access(self.db_path, user_id, server["id"]):
            raise PermissionError(f"User {user_id} doesn't have access to server {server['name']}")

        params: Dict[str, Any] = {"name": name}
        if arguments:
            params["arguments"] = arguments

        data = await self._proxy_jsonrpc(server, "prompts/get", params)
        logger.info(f"Prompt '{name}' retrieved from {server['name']}")
        return data, server

    async def _route_prompt_to_server(
        self, name: str, user_id: Optional[int] = None, server_name: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Find which server owns this prompt name."""
        servers = self._get_servers(user_id=user_id, server_name=server_name)

        # Check cached prompts first
        for server in servers:
            if server["id"] in self._prompts_cache:
                names = [p["name"] for p in self._prompts_cache[server["id"]]]
                if name in names:
                    return server

        # Broadcast prompts/list to find name
        for server in servers:
            try:
                prompts = await self._fetch_prompts_from_server(server)
                if any(p["name"] == name for p in prompts):
                    return server
            except Exception:
                continue

        return None

    # ========================================================================
    # COMPLETION
    # ========================================================================

    async def complete(
        self,
        ref: Dict[str, Any],
        argument: Dict[str, Any],
        user_id: Optional[int] = None,
        server_name: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
        """Route completion/complete to the appropriate server.

        Routing depends on ref type:
        - ref/prompt → route by prompt name
        - ref/resource → route by resource URI
        """
        ref_type = ref.get("type")
        server = None

        if ref_type == "ref/prompt":
            server = await self._route_prompt_to_server(ref.get("name", ""), user_id, server_name)
        elif ref_type == "ref/resource":
            server = await self._route_resource_to_server(ref.get("uri", ""), user_id, server_name)

        if not server:
            # Try first available server as fallback
            servers = self._get_servers(user_id=user_id, server_name=server_name)
            if servers:
                server = servers[0]

        if not server:
            raise ResourceNotFoundError("No server available for completion")

        data = await self._proxy_jsonrpc(
            server, "completion/complete", {"ref": ref, "argument": argument}
        )
        return data, server

    # ========================================================================
    # CACHE MANAGEMENT
    # ========================================================================

    def invalidate_cache(self, server_id: Optional[int] = None):
        """Invalidate all caches for a server (or all servers)."""
        if server_id:
            self._tools_cache.pop(server_id, None)
            self._resources_cache.pop(server_id, None)
            self._prompts_cache.pop(server_id, None)
            self._capabilities_cache.pop(server_id, None)
            self._cache_timestamp.pop(server_id, None)
            logger.info(f"Invalidated cache for server {server_id}")
        else:
            self._tools_cache.clear()
            self._resources_cache.clear()
            self._prompts_cache.clear()
            self._capabilities_cache.clear()
            self._cache_timestamp.clear()
            logger.info("Invalidated all cache")

    def _get_auth_headers(self, server: Dict[str, Any]) -> Dict[str, str]:
        """Get authentication headers for backend MCP server."""
        return get_auth_headers(server)


class ToolNotFoundError(Exception):
    """Raised when tool is not found in any MCP server."""

    pass


class ResourceNotFoundError(Exception):
    """Raised when resource is not found in any MCP server."""

    pass


class PromptNotFoundError(Exception):
    """Raised when prompt is not found in any MCP server."""

    pass
