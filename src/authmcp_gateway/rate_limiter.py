"""Simple in-memory rate limiter using fixed window algorithm."""

import logging
from collections import defaultdict
from datetime import datetime, timedelta
from threading import Lock
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)


class RateLimiter:
    """Thread-safe in-memory rate limiter using fixed window algorithm.

    This implementation uses a fixed time window approach where requests
    are counted within discrete time windows. When a window expires,
    the counter resets.

    Example:
        limiter = RateLimiter()
        allowed, retry_after = limiter.check_limit(
            identifier="192.168.1.1",
            limit=5,
            window=60
        )
        if not allowed:
            # Too many requests
            pass
    """

    def __init__(self):
        """Initialize rate limiter with empty state."""
        # {identifier: {"count": int, "window_start": datetime}}
        self._limits: Dict[str, Dict] = defaultdict(dict)
        self._lock = Lock()

    def check_limit(
        self,
        identifier: str,
        limit: int = 5,
        window: int = 60
    ) -> Tuple[bool, int]:
        """Check if request is allowed within rate limit.

        Args:
            identifier: Unique identifier (IP address, username, etc.)
            limit: Maximum number of requests allowed in window
            window: Time window in seconds

        Returns:
            Tuple of (allowed: bool, retry_after: int seconds)
            - allowed=True: Request is allowed
            - allowed=False: Rate limit exceeded, retry_after tells when to retry
        """
        with self._lock:
            now = datetime.now()

            # First request from this identifier
            if identifier not in self._limits:
                self._limits[identifier] = {
                    "count": 1,
                    "window_start": now
                }
                logger.debug(f"Rate limit: new identifier {identifier} (1/{limit})")
                return True, 0

            data = self._limits[identifier]
            window_start = data.get("window_start", now)
            current_count = data.get("count", 0)

            elapsed = (now - window_start).total_seconds()

            # Window expired - reset counter
            if elapsed >= window:
                self._limits[identifier] = {
                    "count": 1,
                    "window_start": now
                }
                logger.debug(f"Rate limit: window reset for {identifier} (1/{limit})")
                return True, 0

            # Check if limit exceeded
            if current_count >= limit:
                retry_after = int(window - elapsed) + 1
                logger.warning(
                    f"Rate limit exceeded for {identifier}: "
                    f"{current_count}/{limit} in {elapsed:.1f}s, "
                    f"retry after {retry_after}s"
                )
                return False, retry_after

            # Increment counter
            data["count"] = current_count + 1
            logger.debug(
                f"Rate limit: {identifier} allowed "
                f"({data['count']}/{limit})"
            )
            return True, 0

    def reset(self, identifier: str) -> bool:
        """Reset rate limit for specific identifier.

        Args:
            identifier: The identifier to reset

        Returns:
            True if identifier was found and reset, False otherwise
        """
        with self._lock:
            if identifier in self._limits:
                del self._limits[identifier]
                logger.info(f"Rate limit reset for {identifier}")
                return True
            return False

    def cleanup_expired(self, max_age_seconds: int = 3600) -> int:
        """Remove expired entries to free memory.

        This should be called periodically to prevent unbounded memory growth.

        Args:
            max_age_seconds: Remove entries older than this (default: 1 hour)

        Returns:
            Number of entries removed
        """
        with self._lock:
            now = datetime.now()
            to_delete = []

            for identifier, data in self._limits.items():
                window_start = data.get("window_start")
                if not window_start:
                    to_delete.append(identifier)
                    continue

                age = (now - window_start).total_seconds()
                if age > max_age_seconds:
                    to_delete.append(identifier)

            for identifier in to_delete:
                del self._limits[identifier]

            if to_delete:
                logger.info(f"Rate limiter: cleaned up {len(to_delete)} expired entries")

            return len(to_delete)

    def get_stats(self) -> Dict:
        """Get current rate limiter statistics.

        Returns:
            Dictionary with stats: total_identifiers, active_limits
        """
        with self._lock:
            return {
                "total_identifiers": len(self._limits),
                "active_limits": sum(
                    1 for data in self._limits.values()
                    if data.get("count", 0) > 0
                )
            }


# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Get the global rate limiter instance.

    Returns:
        RateLimiter: The global rate limiter
    """
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


def reset_rate_limiter():
    """Reset the global rate limiter (mainly for testing)."""
    global _rate_limiter
    _rate_limiter = RateLimiter()
