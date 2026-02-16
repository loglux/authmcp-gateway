"""Health check mechanism for backend MCP servers."""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

import httpx

from .store import list_mcp_servers, update_server_health

logger = logging.getLogger(__name__)


class HealthChecker:
    """Periodic health checker for backend MCP servers."""

    def __init__(self, db_path: str, interval: int = 60, timeout: int = 10):
        """Initialize health checker.

        Args:
            db_path: Path to SQLite database
            interval: Check interval in seconds
            timeout: Request timeout in seconds
        """
        self.db_path = db_path
        self.interval = interval
        self.timeout = timeout
        self._running = False
        self._task = None

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

            # Ping server with tools/list request
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    server_url,
                    json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                    headers=headers,
                )

                # Handle 401 with token refresh (NEW)
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
                data = response.json()

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
            error_msg = f"Timeout after {self.timeout}s"
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

    def _get_auth_headers(self, server: Dict[str, Any]) -> Dict[str, str]:
        """Get authentication headers for backend MCP server.

        Args:
            server: Server dict

        Returns:
            Headers dict
        """
        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        auth_type = server.get("auth_type", "none")
        auth_token = server.get("auth_token")

        if auth_type == "bearer" and auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        elif auth_type == "basic" and auth_token:
            headers["Authorization"] = f"Basic {auth_token}"

        return headers


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


def initialize_health_checker(db_path: str, interval: int = 60, timeout: int = 10) -> HealthChecker:
    """Initialize global health checker.

    Args:
        db_path: Path to SQLite database
        interval: Check interval in seconds
        timeout: Request timeout in seconds

    Returns:
        HealthChecker instance
    """
    global _health_checker
    _health_checker = HealthChecker(db_path, interval, timeout)
    return _health_checker
