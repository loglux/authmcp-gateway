"""Pydantic models for MCP server management."""

from datetime import datetime
from typing import Optional, List, Literal
from pydantic import BaseModel, Field, HttpUrl


class McpServerBase(BaseModel):
    """Base MCP server model."""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    url: str = Field(..., description="Backend MCP server URL (e.g., http://rag-mcp:8001/mcp)")
    tool_prefix: Optional[str] = Field(None, description="Tool prefix for routing (e.g., 'rag_', 'ha_')")

    # Status
    enabled: bool = Field(True, description="Whether this MCP server is active")

    # Auth to backend MCP
    auth_type: Literal["none", "bearer", "basic"] = Field("none", description="Auth method for backend MCP")
    auth_token: Optional[str] = Field(None, description="Token for backend MCP authentication")

    # Refresh token support (NEW)
    refresh_token: Optional[str] = Field(None, description="OAuth2 refresh token (will be hashed in storage)")
    token_expires_at: Optional[datetime] = Field(None, description="Access token expiration time")
    refresh_endpoint: Optional[str] = Field(default="/oauth/token", description="OAuth2 token endpoint URL")

    # Routing
    routing_strategy: Literal["prefix", "explicit", "auto"] = Field(
        "prefix",
        description="How to route tools to this server"
    )


class McpServerCreate(McpServerBase):
    """Create MCP server request."""
    pass


class McpServerUpdate(BaseModel):
    """Update MCP server request (all fields optional)."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    url: Optional[str] = None
    tool_prefix: Optional[str] = None
    enabled: Optional[bool] = None
    auth_type: Optional[Literal["none", "bearer", "basic"]] = None
    auth_token: Optional[str] = None
    # Refresh token support (NEW)
    refresh_token: Optional[str] = None
    token_expires_at: Optional[datetime] = None
    refresh_endpoint: Optional[str] = None
    routing_strategy: Optional[Literal["prefix", "explicit", "auto"]] = None


class McpServerResponse(McpServerBase):
    """MCP server response."""
    id: int
    status: Literal["unknown", "online", "offline", "error"] = "unknown"
    last_health_check: Optional[datetime] = None
    last_error: Optional[str] = None
    tools_count: int = 0
    token_last_refreshed: Optional[datetime] = None  # NEW
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class McpServerHealth(BaseModel):
    """MCP server health check result."""
    server_id: int
    server_name: str
    status: Literal["online", "offline", "error"]
    response_time_ms: Optional[float] = None
    tools_count: Optional[int] = None
    error: Optional[str] = None
    checked_at: datetime


class ToolMapping(BaseModel):
    """Explicit tool to MCP server mapping."""
    tool_name: str
    mcp_server_id: int
    created_at: datetime

    class Config:
        from_attributes = True


class ToolMappingCreate(BaseModel):
    """Create tool mapping request."""
    tool_name: str = Field(..., min_length=1)
    mcp_server_id: int = Field(..., gt=0)


class UserMcpPermission(BaseModel):
    """User permission for MCP server."""
    id: int
    user_id: int
    mcp_server_id: int
    can_access: bool = True
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class UserMcpPermissionCreate(BaseModel):
    """Create user MCP permission."""
    user_id: int = Field(..., gt=0)
    mcp_server_id: int = Field(..., gt=0)
    can_access: bool = True


class UserMcpPermissionUpdate(BaseModel):
    """Update user MCP permission."""
    can_access: bool


# MCP Protocol models
class McpToolInfo(BaseModel):
    """MCP tool information from backend server."""
    name: str
    description: Optional[str] = None
    inputSchema: dict


class McpToolsListResponse(BaseModel):
    """Aggregated tools list from all backend servers."""
    tools: List[McpToolInfo]
    _meta: Optional[dict] = Field(
        default=None,
        description="Metadata about servers and routing"
    )


class McpToolCallRequest(BaseModel):
    """Tool call request (MCP protocol)."""
    name: str
    arguments: Optional[dict] = None


class McpToolCallResponse(BaseModel):
    """Tool call response (MCP protocol)."""
    content: List[dict]
    isError: bool = False
    _meta: Optional[dict] = Field(
        default=None,
        description="Metadata about which server handled the request"
    )


# Token Management Models (NEW)
class McpServerTokenStatus(BaseModel):
    """Token status for backend MCP server (admin UI)."""
    server_id: int
    server_name: str
    auth_type: str
    has_refresh_token: bool
    token_expires_at: Optional[datetime] = None
    token_expired: bool = False
    time_until_expiry_seconds: Optional[int] = None
    last_refreshed: Optional[datetime] = None
    can_auto_refresh: bool = False  # True if has refresh_token and endpoint


class TokenAuditLog(BaseModel):
    """Token audit log entry."""
    id: int
    mcp_server_id: int
    server_name: Optional[str] = None  # Joined from mcp_servers
    event_type: str
    success: bool
    error_message: Optional[str] = None
    old_expires_at: Optional[datetime] = None
    new_expires_at: Optional[datetime] = None
    triggered_by: str
    timestamp: datetime

    class Config:
        from_attributes = True
