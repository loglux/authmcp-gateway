"""Background task for proactive token refresh.

Periodically checks all MCP servers and refreshes tokens that will expire soon.
"""

import asyncio
import logging
from typing import Optional

from .store import get_servers_needing_refresh
from .token_manager import get_token_manager

logger = logging.getLogger(__name__)


class TokenRefresher:
    """Background task that proactively refreshes backend MCP tokens before expiration."""

    def __init__(
        self,
        db_path: str,
        interval: int = 300,  # Check every 5 minutes
        threshold_minutes: int = 5,  # Refresh if expires within 5 minutes
    ):
        """Initialize token refresher.

        Args:
            db_path: Path to SQLite database
            interval: Seconds between refresh checks
            threshold_minutes: Refresh if token expires within N minutes
        """
        self.db_path = db_path
        self.interval = interval
        self.threshold_minutes = threshold_minutes
        self._running = False
        self._task: Optional[asyncio.Task] = None

    def start(self) -> None:
        """Start background refresh task."""
        if self._running:
            logger.warning("Token refresher already running")
            return

        self._running = True
        self._task = asyncio.create_task(self._refresh_loop())
        logger.info(
            f"✓ Token refresher started "
            f"(interval={self.interval}s, threshold={self.threshold_minutes}min)"
        )

    async def stop(self) -> None:
        """Stop background refresh task gracefully."""
        if not self._running:
            return

        self._running = False

        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

        logger.info("✓ Token refresher stopped")

    async def _refresh_loop(self) -> None:
        """Background loop that refreshes tokens."""
        # Wait a bit after startup before first check
        await asyncio.sleep(10)

        while self._running:
            try:
                await self._check_and_refresh_tokens()
            except Exception as e:
                logger.error(f"Error in token refresh loop: {e}", exc_info=True)

            # Sleep until next check
            await asyncio.sleep(self.interval)

    async def _check_and_refresh_tokens(self) -> None:
        """Check all servers and refresh tokens that expire soon."""
        try:
            # Get servers with expiring tokens
            servers = get_servers_needing_refresh(self.db_path, self.threshold_minutes)

            if not servers:
                logger.debug("No tokens need refresh")
                return

            logger.info(f"Proactively refreshing {len(servers)} expiring tokens")

            # Get token manager
            try:
                token_mgr = get_token_manager()
            except RuntimeError as e:
                logger.error(f"Token manager not available: {e}")
                return

            # Refresh in parallel
            tasks = []
            for server in servers:
                task = token_mgr.refresh_server_token(server["id"], triggered_by="proactive")
                tasks.append(task)

            # Wait for all refreshes to complete
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Count successes
            success_count = 0
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"Exception refreshing server {servers[i]['name']}: {result}")
                elif result[0]:  # result = (success, error_message)
                    success_count += 1

            logger.info(f"Proactive refresh complete: " f"{success_count}/{len(servers)} succeeded")

        except Exception as e:
            logger.error(f"Error checking servers for refresh: {e}", exc_info=True)


# Global singleton instance
_token_refresher: Optional[TokenRefresher] = None


def get_token_refresher() -> TokenRefresher:
    """Get global token refresher instance.

    Returns:
        TokenRefresher: Global instance

    Raises:
        RuntimeError: If not initialized
    """
    if _token_refresher is None:
        raise RuntimeError(
            "Token refresher not initialized. Call initialize_token_refresher() first."
        )
    return _token_refresher


def initialize_token_refresher(
    db_path: str, interval: int = 300, threshold_minutes: int = 5
) -> TokenRefresher:
    """Initialize global token refresher.

    Args:
        db_path: Path to SQLite database
        interval: Seconds between refresh checks
        threshold_minutes: Refresh if token expires within N minutes

    Returns:
        TokenRefresher: Initialized instance
    """
    global _token_refresher
    _token_refresher = TokenRefresher(db_path, interval, threshold_minutes)
    logger.info(
        f"✓ Token refresher initialized "
        f"(interval={interval}s, threshold={threshold_minutes}min)"
    )
    return _token_refresher
