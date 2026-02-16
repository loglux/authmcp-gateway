"""Logging configuration for file-based logs with rotation."""

import json
import logging
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Optional


class JSONFormatter(logging.Formatter):
    """Format log records as JSON."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON string."""
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add extra fields if present
        if hasattr(record, "event_type"):
            log_data["event_type"] = record.event_type
        if hasattr(record, "user_id"):
            log_data["user_id"] = record.user_id
        if hasattr(record, "username"):
            log_data["username"] = record.username
        if hasattr(record, "ip_address"):
            log_data["ip_address"] = record.ip_address
        if hasattr(record, "success"):
            log_data["success"] = record.success
        if hasattr(record, "details"):
            log_data["details"] = record.details
        if hasattr(record, "user_agent"):
            log_data["user_agent"] = record.user_agent

        # MCP request fields
        if hasattr(record, "method"):
            log_data["method"] = record.method
        if hasattr(record, "server_id"):
            log_data["server_id"] = record.server_id
        if hasattr(record, "server_name"):
            log_data["server_name"] = record.server_name
        if hasattr(record, "tool_name"):
            log_data["tool_name"] = record.tool_name
        if hasattr(record, "response_time_ms"):
            log_data["response_time_ms"] = record.response_time_ms
        if hasattr(record, "error"):
            log_data["error"] = record.error
        if hasattr(record, "suspicious"):
            log_data["suspicious"] = record.suspicious

        return json.dumps(log_data)


def setup_file_logger(
    name: str, log_file: Path, level: int = logging.INFO, max_days: int = 30
) -> logging.Logger:
    """Setup a logger that writes to a rotating file.

    Args:
        name: Logger name
        log_file: Path to log file
        level: Log level
        max_days: Number of days to keep logs

    Returns:
        Configured logger
    """
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False  # Don't propagate to root logger

    # Remove existing handlers
    logger.handlers.clear()

    # Create logs directory if needed
    log_file.parent.mkdir(parents=True, exist_ok=True)

    # Create rotating file handler (daily rotation)
    handler = TimedRotatingFileHandler(
        filename=str(log_file),
        when="midnight",
        interval=1,
        backupCount=max_days,
        encoding="utf-8",
        utc=True,
    )

    # Set JSON formatter
    formatter = JSONFormatter()
    handler.setFormatter(formatter)

    # Add handler to logger
    logger.addHandler(handler)

    return logger


# Singleton loggers
_auth_logger = None
_mcp_logger = None


def get_auth_logger() -> logging.Logger:
    """Get or create auth logger singleton."""
    global _auth_logger
    if _auth_logger is None:
        log_dir = Path("data/logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        _auth_logger = setup_file_logger(name="auth", log_file=log_dir / "auth.log")
    return _auth_logger


def get_mcp_logger() -> logging.Logger:
    """Get or create MCP logger singleton."""
    global _mcp_logger
    if _mcp_logger is None:
        log_dir = Path("data/logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        _mcp_logger = setup_file_logger(name="mcp_requests", log_file=log_dir / "mcp_requests.log")
    return _mcp_logger


def log_auth_event_to_file(
    logger: logging.Logger,
    event_type: str,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    success: bool = True,
    details: Optional[str] = None,
):
    """Log authentication event to file.

    Args:
        logger: Logger instance
        event_type: Type of event (e.g., "login", "logout", "failed_login")
        user_id: Optional user ID
        username: Optional username
        ip_address: Optional client IP address
        user_agent: Optional client user agent
        success: Whether the event was successful
        details: Optional additional details
    """
    logger.info(
        f"Auth event: {event_type}",
        extra={
            "event_type": event_type,
            "user_id": user_id,
            "username": username,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "success": success,
            "details": details,
        },
    )


def log_mcp_request_to_file(
    logger: logging.Logger,
    method: str,
    server_id: Optional[int] = None,
    server_name: Optional[str] = None,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    tool_name: Optional[str] = None,
    response_time_ms: Optional[float] = None,
    success: bool = True,
    error: Optional[str] = None,
    suspicious: bool = False,
):
    """Log MCP request to file.

    Args:
        logger: Logger instance
        method: MCP method name
        server_id: Backend server ID
        server_name: Backend server name
        user_id: User ID
        username: Username
        tool_name: Tool name if method is tools/call
        response_time_ms: Response time in milliseconds
        success: Whether request succeeded
        error: Error message if failed
        suspicious: Whether request is suspicious
    """
    logger.info(
        f"MCP request: {method}",
        extra={
            "event_type": "mcp_request",
            "method": method,
            "server_id": server_id,
            "server_name": server_name,
            "user_id": user_id,
            "username": username,
            "tool_name": tool_name,
            "response_time_ms": response_time_ms,
            "success": success,
            "error": error,
            "suspicious": suspicious,
        },
    )
