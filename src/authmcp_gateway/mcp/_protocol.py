"""Shared MCP protocol constants.

Centralises the protocol revision string sent on ``initialize`` across
``mcp/proxy.py``, ``mcp/health.py``, ``mcp/handler.py``, and
``security/mcp_auditor.py`` so that moving to a newer MCP spec revision
only requires editing one place.

    from authmcp_gateway.mcp._protocol import MCP_PROTOCOL_VERSION
"""

#: Streamable HTTP revision this gateway negotiates with backends.
#: See https://modelcontextprotocol.io/specification/2025-03-26/basic/transports#session-management
MCP_PROTOCOL_VERSION = "2025-03-26"
