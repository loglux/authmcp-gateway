"""Token management for backend MCP servers.

Handles OAuth2 refresh token flow for automatic token renewal.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, Tuple
from hashlib import sha256
import asyncio

import httpx

from .store import (
    get_mcp_server,
    update_mcp_server_token,
    log_token_audit
)

logger = logging.getLogger(__name__)


def hash_refresh_token(token: str) -> str:
    """Hash refresh token for secure storage.

    Args:
        token: Plaintext refresh token

    Returns:
        str: SHA256 hash of the token
    """
    return sha256(token.encode()).hexdigest()


class TokenManager:
    """Manages OAuth2 token refresh for backend MCP servers."""

    def __init__(self, db_path: str, timeout: int = 30):
        """Initialize token manager.

        Args:
            db_path: Path to SQLite database
            timeout: HTTP request timeout in seconds
        """
        self.db_path = db_path
        self.timeout = timeout

        # In-memory cache for plaintext refresh tokens
        # server_id -> plaintext refresh_token
        self._refresh_tokens_cache: Dict[int, str] = {}

        # Lock per server to prevent concurrent refresh attempts
        self._refresh_locks: Dict[int, asyncio.Lock] = {}

    def cache_refresh_token(self, server_id: int, refresh_token: str) -> None:
        """Cache plaintext refresh token in memory.

        Args:
            server_id: MCP server ID
            refresh_token: Plaintext refresh token
        """
        self._refresh_tokens_cache[server_id] = refresh_token
        logger.debug(f"Cached refresh token for server {server_id}")

    def get_cached_refresh_token(self, server_id: int) -> Optional[str]:
        """Get cached plaintext refresh token.

        Args:
            server_id: MCP server ID

        Returns:
            Optional[str]: Plaintext refresh token or None if not cached
        """
        return self._refresh_tokens_cache.get(server_id)

    def clear_cached_token(self, server_id: int) -> None:
        """Clear cached refresh token.

        Args:
            server_id: MCP server ID
        """
        if server_id in self._refresh_tokens_cache:
            del self._refresh_tokens_cache[server_id]
            logger.debug(f"Cleared cached token for server {server_id}")

    def _get_lock(self, server_id: int) -> asyncio.Lock:
        """Get or create lock for server.

        Args:
            server_id: MCP server ID

        Returns:
            asyncio.Lock: Lock for this server
        """
        if server_id not in self._refresh_locks:
            self._refresh_locks[server_id] = asyncio.Lock()
        return self._refresh_locks[server_id]

    async def refresh_server_token(
        self,
        server_id: int,
        triggered_by: str = "manual"
    ) -> Tuple[bool, Optional[str]]:
        """Refresh access token for backend MCP server.

        Process:
        1. Get server config from DB
        2. Get cached plaintext refresh_token
        3. Call backend OAuth2 token endpoint
        4. Update access_token and expires_at in DB
        5. Log audit event

        Args:
            server_id: MCP server ID
            triggered_by: What triggered refresh ('proactive', 'reactive_401', 'manual', 'startup')

        Returns:
            Tuple[bool, Optional[str]]: (success, error_message)
        """
        # Acquire lock to prevent concurrent refreshes
        lock = self._get_lock(server_id)
        async with lock:
            return await self._do_refresh(server_id, triggered_by)

    async def _do_refresh(
        self,
        server_id: int,
        triggered_by: str
    ) -> Tuple[bool, Optional[str]]:
        """Internal refresh implementation (lock already acquired).

        Args:
            server_id: MCP server ID
            triggered_by: What triggered refresh

        Returns:
            Tuple[bool, Optional[str]]: (success, error_message)
        """
        # Get server config
        server = get_mcp_server(self.db_path, server_id)
        if not server:
            error_msg = f"Server {server_id} not found"
            logger.error(error_msg)
            return False, error_msg

        server_name = server['name']
        old_expires_at = None
        if server.get('token_expires_at'):
            try:
                old_expires_at = datetime.fromisoformat(server['token_expires_at'])
            except (ValueError, TypeError):
                pass

        # Check if refresh is possible
        if not server.get('refresh_token_hash'):
            error_msg = "No refresh token configured"
            logger.warning(f"{server_name}: {error_msg}")
            log_token_audit(
                self.db_path,
                server_id,
                event_type='refresh_failed',
                success=False,
                error_message=error_msg,
                old_expires_at=old_expires_at,
                triggered_by=triggered_by
            )
            return False, error_msg

        refresh_endpoint = server.get('refresh_endpoint') or '/oauth/token'

        # Get cached plaintext refresh token
        refresh_token = self.get_cached_refresh_token(server_id)
        if not refresh_token:
            error_msg = "Refresh token not in cache (server restart? re-configure via admin UI)"
            logger.warning(f"{server_name}: {error_msg}")
            log_token_audit(
                self.db_path,
                server_id,
                event_type='refresh_failed',
                success=False,
                error_message=error_msg,
                old_expires_at=old_expires_at,
                triggered_by=triggered_by
            )
            return False, error_msg

        # Build full URL for token endpoint
        base_url = server['url'].rstrip('/mcp').rstrip('/')
        token_url = f"{base_url}{refresh_endpoint}"

        try:
            # Call OAuth2 token endpoint
            logger.info(f"Refreshing token for {server_name} via {token_url}")

            access_token, new_refresh_token, expires_in = await self._call_token_endpoint(
                token_url,
                refresh_token
            )

            # Calculate new expiration
            new_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

            # Check if backend rotated refresh token
            refresh_token_hash = None
            if new_refresh_token:
                logger.info(f"{server_name}: Backend rotated refresh token")
                refresh_token_hash = hash_refresh_token(new_refresh_token)
                # Update cache with new token
                self.cache_refresh_token(server_id, new_refresh_token)

            # Update database
            update_mcp_server_token(
                self.db_path,
                server_id,
                access_token,
                new_expires_at,
                refresh_token_hash
            )

            # Log success
            log_token_audit(
                self.db_path,
                server_id,
                event_type='refresh',
                success=True,
                old_expires_at=old_expires_at,
                new_expires_at=new_expires_at,
                triggered_by=triggered_by
            )

            logger.info(
                f"✓ Token refreshed for {server_name}: "
                f"expires {new_expires_at.isoformat()}, "
                f"triggered_by={triggered_by}"
            )

            return True, None

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Failed to refresh token for {server_name}: {error_msg}")

            # Log failure
            log_token_audit(
                self.db_path,
                server_id,
                event_type='refresh_failed',
                success=False,
                error_message=error_msg,
                old_expires_at=old_expires_at,
                triggered_by=triggered_by
            )

            return False, error_msg

    async def _call_token_endpoint(
        self,
        token_url: str,
        refresh_token: str
    ) -> Tuple[str, Optional[str], int]:
        """Call OAuth2 token endpoint to refresh access token.

        Args:
            token_url: Full URL to token endpoint
            refresh_token: Plaintext refresh token

        Returns:
            Tuple[str, Optional[str], int]: (access_token, new_refresh_token, expires_in)

        Raises:
            httpx.HTTPError: If request fails
            ValueError: If response is invalid
        """
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                token_url,
                data={
                    'grant_type': 'refresh_token',
                    'refresh_token': refresh_token
                },
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json'
                }
            )

            # Raise for HTTP errors (4xx, 5xx)
            response.raise_for_status()

            # Parse JSON response
            data = response.json()

            # Extract tokens
            access_token = data.get('access_token')
            new_refresh_token = data.get('refresh_token')  # May be None (no rotation)
            expires_in = data.get('expires_in', 3600)  # Default 1 hour

            if not access_token:
                raise ValueError("Token endpoint did not return access_token")

            logger.debug(
                f"Token endpoint response: "
                f"access_token={access_token[:20]}..., "
                f"expires_in={expires_in}s, "
                f"rotated={new_refresh_token is not None}"
            )

            return access_token, new_refresh_token, expires_in

    def needs_refresh(
        self,
        server: Dict[str, Any],
        threshold_minutes: int = 5
    ) -> bool:
        """Check if server token needs proactive refresh.

        Args:
            server: Server dict from database
            threshold_minutes: Refresh if expires within this many minutes

        Returns:
            bool: True if token should be refreshed
        """
        # Skip if no refresh support
        if not server.get('refresh_token_hash'):
            return False

        # Skip if disabled
        if not server.get('enabled'):
            return False

        # Check if token expires soon
        token_expires_at = server.get('token_expires_at')
        if not token_expires_at:
            # No expiration set - skip
            return False

        try:
            expires_at = datetime.fromisoformat(token_expires_at)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            logger.warning(f"Invalid token_expires_at for server {server['name']}: {token_expires_at}")
            return False

        # Check if expires within threshold
        threshold = datetime.now(timezone.utc) + timedelta(minutes=threshold_minutes)
        needs_refresh = expires_at <= threshold

        if needs_refresh:
            time_left = (expires_at - datetime.now(timezone.utc)).total_seconds()
            logger.debug(
                f"Server {server['name']} token expires in {time_left:.0f}s "
                f"(threshold={threshold_minutes*60}s) - refresh needed"
            )

        return needs_refresh


# Global singleton instance
_token_manager: Optional[TokenManager] = None


def get_token_manager() -> TokenManager:
    """Get global token manager instance.

    Returns:
        TokenManager: Global instance

    Raises:
        RuntimeError: If not initialized
    """
    if _token_manager is None:
        raise RuntimeError("Token manager not initialized. Call initialize_token_manager() first.")
    return _token_manager


def initialize_token_manager(db_path: str, timeout: int = 30) -> TokenManager:
    """Initialize global token manager.

    Args:
        db_path: Path to SQLite database
        timeout: HTTP request timeout in seconds

    Returns:
        TokenManager: Initialized instance
    """
    global _token_manager
    _token_manager = TokenManager(db_path, timeout)
    logger.info(f"✓ Token manager initialized (timeout={timeout}s)")
    return _token_manager
