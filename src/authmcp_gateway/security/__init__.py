"""Security module for AuthMCP Gateway.

Provides:
- Security event logging
- MCP request logging
- Built-in security tests
- Input validation
"""

from .logger import cleanup_old_logs, log_mcp_request, log_security_event

__all__ = [
    "log_security_event",
    "log_mcp_request",
    "cleanup_old_logs",
]
