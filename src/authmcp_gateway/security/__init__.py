"""Security module for AuthMCP Gateway.

Provides:
- Security event logging
- MCP request logging
- Built-in security tests
- Input validation
"""

from .logger import log_security_event, log_mcp_request, cleanup_old_logs

__all__ = [
    "log_security_event",
    "log_mcp_request",
    "cleanup_old_logs",
]
