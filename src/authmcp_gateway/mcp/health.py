"""Health check mechanism for backend MCP servers."""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

import httpx

from .proxy import get_auth_headers, parse_sse_response
from .store import list_mcp_servers, update_server_health

logger = logging.getLogger(__name__)


class HealthChecker:
    """Periodic health checker for backend MCP servers."""

    def __init__(
        self,
        db_path: str,
        interval: int = 60,
        timeout: int = 10,
        shared_session_ids: Dict[int, str] | None = None,
    ):
        """Initialize health checker.

        Args:
            db_path: Path to SQLite database
            interval: Check interval in seconds
            timeout: Request timeout in seconds
            shared_session_ids: Optional shared session dict (from McpProxy) to
                avoid creating competing sessions on single-session backends
        """
        self.db_path = db_path
        self.interval = interval
        self.timeout = timeout
        self._running = False
        self._task = None
        self._session_ids: Dict[int, str] = (
            shared_session_ids if shared_session_ids is not None else {}
        )

    def start(self):
        """Start health checking background task."""
        if self._running:
            logger.warning("Health checker already running")
            return

        self._running = True
        self._task = asyncio.create_task(self._health_check_loop())
        logger.info(f"Health checker started (interval={self.interval}s)")

    async def stop(self):
        """Stop health checking background task."""
        if not self._running:
            return

        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

        logger.info("Health checker stopped")

    async def _health_check_loop(self):
        """Background loop that performs health checks."""
        # Initial delay to let the application finish startup
        await asyncio.sleep(5)

        while self._running:
            try:
                await self.check_all_servers()
            except Exception as e:
                logger.error(f"Error in health check loop: {e}")

            # Wait for next check
            await asyncio.sleep(self.interval)

    async def check_all_servers(self) -> List[Dict[str, Any]]:
        """Check health of all enabled MCP servers.

        Returns:
            List of health check results
        """
        servers = list_mcp_servers(self.db_path, enabled_only=True)

        if not servers:
            logger.debug("No enabled servers to check")
            return []

        # Check all servers in parallel
        tasks = []
        for server in servers:
            tasks.append(self.check_server(server))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Log summary
        online_count = sum(
            1 for r in results if not isinstance(r, Exception) and r["status"] == "online"
        )
        logger.info(f"Health check: {online_count}/{len(servers)} servers online")

        return [r for r in results if not isinstance(r, Exception)]

    async def check_server(self, server: Dict[str, Any]) -> Dict[str, Any]:
        """Check health of a single MCP server.

        Args:
            server: Server dict from database

        Returns:
            Health check result dict
        """
        server_id = server["id"]
        server_name = server["name"]
        server_url = server["url"]

        start_time = datetime.now(timezone.utc)

        try:
            # Prepare auth headers
            headers = self._get_auth_headers(server)

            # Per-server timeout override (DB field → global default)
            server_timeout = server.get("timeout") or self.timeout

            # Ping server with tools/list request
            async with httpx.AsyncClient(timeout=server_timeout) as client:
                # Include mcp-session-id if we have one
                session_id = self._session_ids.get(server_id)
                if session_id:
                    headers["mcp-session-id"] = session_id

                try:
                    response = await client.post(
                        server_url,
                        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                        headers=headers,
                    )
                except httpx.TimeoutException:
                    # Stale session can cause backends to hang instead of returning 400.
                    # If we had a session, clear it and retry with fresh initialize.
                    if session_id:
                        logger.info(
                            f"Health check: {server_name} timed out with session, "
                            "retrying with fresh initialize"
                        )
                        del self._session_ids[server_id]
                        headers.pop("mcp-session-id", None)
                        session_id = await self._initialize_session(
                            client, server_url, headers, server_id, server_name
                        )
                        if session_id:
                            headers["mcp-session-id"] = session_id
                            response = await client.post(
                                server_url,
                                json={
                                    "jsonrpc": "2.0",
                                    "id": 1,
                                    "method": "tools/list",
                                    "params": {},
                                },
                                headers=headers,
                            )
                        else:
                            raise  # Re-raise timeout if init also failed
                    else:
                        raise  # No session to clear, genuine timeout

                # Handle 400 "no valid session" — initialize first
                if response.status_code == 400:
                    body_text = response.text[:200] if response.text else ""
                    if "session" in body_text.lower():
                        logger.info(f"Health check: {server_name} requires session, initializing")
                        self._session_ids.pop(server_id, None)
                        headers.pop("mcp-session-id", None)
                        session_id = await self._initialize_session(
                            client, server_url, headers, server_id, server_name
                        )
                        if session_id:
                            headers["mcp-session-id"] = session_id
                            response = await client.post(
                                server_url,
                                json={
                                    "jsonrpc": "2.0",
                                    "id": 1,
                                    "method": "tools/list",
                                    "params": {},
                                },
                                headers=headers,
                            )

                # Handle 401 with token refresh
                if response.status_code == 401 and server.get("refresh_token_hash"):
                    logger.warning(
                        f"Got 401 during health check for {server_name}, attempting token refresh"
                    )

                    try:
                        from .store import get_mcp_server
                        from .token_manager import get_token_manager

                        token_mgr = get_token_manager()
                        success, error = await token_mgr.refresh_server_token(
                            server_id, triggered_by="reactive_401"
                        )

                        if success:
                            # Reload server with new token and retry
                            server = get_mcp_server(self.db_path, server_id)
                            headers = self._get_auth_headers(server)
                            session_id = self._session_ids.get(server_id)
                            if session_id:
                                headers["mcp-session-id"] = session_id
                            response = await client.post(
                                server_url,
                                json={
                                    "jsonrpc": "2.0",
                                    "id": 1,
                                    "method": "tools/list",
                                    "params": {},
                                },
                                headers=headers,
                            )
                            logger.info(
                                f"Health check retry after token refresh succeeded for {server_name}"
                            )
                        else:
                            logger.error(
                                f"Token refresh failed during health check for {server_name}: {error}"
                            )
                    except Exception as refresh_error:
                        logger.error(
                            f"Exception during token refresh in health check: {refresh_error}"
                        )

                response.raise_for_status()
                data = parse_sse_response(response)

                # Calculate response time
                response_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

                # Extract tools count
                tools_count = 0
                if "result" in data and "tools" in data["result"]:
                    tools_count = len(data["result"]["tools"])

                # Update database
                update_server_health(
                    self.db_path, server_id, status="online", tools_count=tools_count
                )

                result = {
                    "server_id": server_id,
                    "server_name": server_name,
                    "status": "online",
                    "response_time_ms": response_time,
                    "tools_count": tools_count,
                    "error": None,
                    "checked_at": datetime.now(timezone.utc),
                }

                logger.debug(
                    f"Health check: {server_name} is online "
                    f"({response_time:.0f}ms, {tools_count} tools)"
                )

                return result

        except httpx.TimeoutException:
            error_msg = f"Timeout after {server_timeout}s"
            logger.warning(f"Health check: {server_name} - {error_msg}")

            update_server_health(self.db_path, server_id, status="offline", error=error_msg)

            return {
                "server_id": server_id,
                "server_name": server_name,
                "status": "offline",
                "response_time_ms": None,
                "tools_count": None,
                "error": error_msg,
                "checked_at": datetime.now(timezone.utc),
            }

        except httpx.HTTPStatusError as e:
            error_msg = f"HTTP {e.response.status_code}: {e.response.text[:100]}"
            logger.warning(f"Health check: {server_name} - {error_msg}")

            update_server_health(self.db_path, server_id, status="error", error=error_msg)

            return {
                "server_id": server_id,
                "server_name": server_name,
                "status": "error",
                "response_time_ms": None,
                "tools_count": None,
                "error": error_msg,
                "checked_at": datetime.now(timezone.utc),
            }

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Health check: {server_name} - Unexpected error: {error_msg}")

            update_server_health(self.db_path, server_id, status="error", error=error_msg)

            return {
                "server_id": server_id,
                "server_name": server_name,
                "status": "error",
                "response_time_ms": None,
                "tools_count": None,
                "error": error_msg,
                "checked_at": datetime.now(timezone.utc),
            }

    async def _initialize_session(
        self,
        client: httpx.AsyncClient,
        server_url: str,
        headers: Dict[str, str],
        server_id: int,
        server_name: str,
    ) -> str:
        """Send initialize to get mcp-session-id from a Streamable HTTP backend.

        Returns:
            Session ID string, or empty string if not available.
        """
        try:
            # Remove stale session ID for the init request
            init_headers = {k: v for k, v in headers.items() if k != "mcp-session-id"}
            resp = await client.post(
                server_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "authmcp-gateway", "version": "2.0.0"},
                    },
                },
                headers=init_headers,
            )
            session_id = resp.headers.get("mcp-session-id", "")
            if session_id:
                self._session_ids[server_id] = session_id
                logger.info(f"Health check: got session ID for {server_name}")

                # Send initialized notification (best-effort)
                try:
                    notify_headers = dict(init_headers)
                    notify_headers["mcp-session-id"] = session_id
                    await client.post(
                        server_url,
                        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                        headers=notify_headers,
                    )
                except Exception:
                    pass

            return session_id
        except Exception as e:
            logger.debug(f"Health check: initialize failed for {server_name}: {e}")
            return ""

    def _get_auth_headers(self, server: Dict[str, Any]) -> Dict[str, str]:
        """Get authentication headers for backend MCP server."""
        return get_auth_headers(server)


# Global health checker instance
_health_checker: HealthChecker = None


def get_health_checker() -> HealthChecker:
    """Get global health checker instance.

    Returns:
        HealthChecker instance

    Raises:
        RuntimeError: If not initialized
    """
    if _health_checker is None:
        raise RuntimeError("Health checker not initialized")
    return _health_checker


def initialize_health_checker(
    db_path: str,
    interval: int = 60,
    timeout: int = 10,
    shared_session_ids: Dict[int, str] | None = None,
) -> HealthChecker:
    """Initialize global health checker.

    Args:
        db_path: Path to SQLite database
        interval: Check interval in seconds
        timeout: Request timeout in seconds
        shared_session_ids: Optional shared session dict from McpProxy

    Returns:
        HealthChecker instance
    """
    global _health_checker
    _health_checker = HealthChecker(db_path, interval, timeout, shared_session_ids)
    return _health_checker
