"""MCP Protocol handler - Gateway endpoint for MCP requests."""

import logging
from typing import Dict, Any, Optional

from starlette.requests import Request
from starlette.responses import JSONResponse

from .proxy import McpProxy, ToolNotFoundError

logger = logging.getLogger(__name__)


class McpHandler:
    """Handles MCP jsonrpc requests and routes to backend servers."""

    def __init__(self, db_path: str):
        """Initialize MCP handler.

        Args:
            db_path: Path to SQLite database
        """
        self.db_path = db_path
        self.proxy = McpProxy(db_path)

    async def handle_request(self, request: Request, server_name: Optional[str] = None) -> JSONResponse:
        """Handle MCP jsonrpc request.

        Args:
            request: Starlette request
            server_name: Optional server name to filter tools/calls

        Returns:
            JSONResponse with jsonrpc result
        """
        try:
            # Parse jsonrpc request
            data = await request.json()
            jsonrpc_id = data.get("id", 1)
            method = data.get("method")
            params = data.get("params", {})

            logger.debug(f"MCP request: method={method}, params={params}, server_name={server_name}")

            # Extract user_id from request state (set by auth middleware)
            user_id = getattr(request.state, "user_id", None)

            # Handle different MCP methods
            if method == "tools/list":
                return await self._handle_tools_list(jsonrpc_id, user_id, server_name)

            elif method == "tools/call":
                tool_name = params.get("name")
                arguments = params.get("arguments", {})
                return await self._handle_tool_call(jsonrpc_id, tool_name, arguments, user_id, server_name)

            elif method == "initialize":
                return await self._handle_initialize(jsonrpc_id, params, server_name)

            else:
                return self._error_response(
                    jsonrpc_id,
                    -32601,
                    f"Method not found: {method}"
                )

        except Exception as e:
            logger.exception(f"Error handling MCP request: {e}")
            return self._error_response(
                1,
                -32603,
                f"Internal error: {str(e)}"
            )

    async def _handle_tools_list(self, jsonrpc_id: int, user_id: Optional[int], server_name: Optional[str] = None) -> JSONResponse:
        """Handle tools/list request.

        Args:
            jsonrpc_id: JSON-RPC request ID
            user_id: Optional user ID for filtering
            server_name: Optional server name to filter tools

        Returns:
            JSONResponse with tools list
        """
        try:
            tools = await self.proxy.list_tools(user_id=user_id, server_name=server_name)

            # Format tools according to MCP protocol
            formatted_tools = []
            for tool in tools:
                formatted_tool = {
                    "name": tool.get("name"),
                    "description": tool.get("description"),
                    "inputSchema": tool.get("inputSchema", {})
                }

                # Add metadata (optional)
                if "_server_id" in tool:
                    if "x-gateway" not in formatted_tool:
                        formatted_tool["x-gateway"] = {}
                    formatted_tool["x-gateway"]["server_id"] = tool["_server_id"]
                    formatted_tool["x-gateway"]["server_name"] = tool["_server_name"]

                formatted_tools.append(formatted_tool)

            logger.info(f"Returning {len(formatted_tools)} tools")

            return JSONResponse({
                "jsonrpc": "2.0",
                "id": jsonrpc_id,
                "result": {
                    "tools": formatted_tools
                }
            })

        except Exception as e:
            logger.exception(f"Error in tools/list: {e}")
            return self._error_response(jsonrpc_id, -32603, str(e))

    async def _handle_tool_call(
        self,
        jsonrpc_id: int,
        tool_name: str,
        arguments: Dict[str, Any],
        user_id: Optional[int],
        server_name: Optional[str] = None
    ) -> JSONResponse:
        """Handle tools/call request.

        Args:
            jsonrpc_id: JSON-RPC request ID
            tool_name: Tool name
            arguments: Tool arguments
            user_id: Optional user ID
            server_name: Optional server name to restrict tool calls

        Returns:
            JSONResponse with tool call result
        """
        try:
            if not tool_name:
                return self._error_response(
                    jsonrpc_id,
                    -32602,
                    "Missing required parameter: name"
                )

            logger.info(f"Calling tool: {tool_name} (server: {server_name or 'any'})")

            # Route and execute tool call via proxy
            result = await self.proxy.call_tool(
                tool_name=tool_name,
                arguments=arguments,
                user_id=user_id,
                server_name=server_name
            )

            # Return result from backend server
            if "result" in result:
                return JSONResponse({
                    "jsonrpc": "2.0",
                    "id": jsonrpc_id,
                    "result": result["result"]
                })
            elif "error" in result:
                return JSONResponse({
                    "jsonrpc": "2.0",
                    "id": jsonrpc_id,
                    "error": result["error"]
                })
            else:
                return self._error_response(
                    jsonrpc_id,
                    -32603,
                    "Invalid response from backend server"
                )

        except ToolNotFoundError as e:
            logger.warning(f"Tool not found: {tool_name}")
            return self._error_response(jsonrpc_id, -32601, str(e))

        except PermissionError as e:
            logger.warning(f"Permission denied: {e}")
            return self._error_response(jsonrpc_id, -32000, str(e))

        except Exception as e:
            logger.exception(f"Error calling tool '{tool_name}': {e}")
            return self._error_response(jsonrpc_id, -32603, str(e))

    async def _handle_initialize(self, jsonrpc_id: int, params: Dict[str, Any], server_name: Optional[str] = None) -> JSONResponse:
        """Handle initialize request.

        Args:
            jsonrpc_id: JSON-RPC request ID
            params: Initialize parameters
            server_name: Optional server name for scoped endpoint

        Returns:
            JSONResponse with initialize result
        """
        logger.info(f"Handling initialize request (server: {server_name or 'all'})")

        # Customize server name if scoped to specific backend
        display_name = "fastmcp-auth-gateway"
        if server_name:
            display_name = f"{server_name}"

        return JSONResponse({
            "jsonrpc": "2.0",
            "id": jsonrpc_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {},
                    "resources": {},
                    "prompts": {}
                },
                "serverInfo": {
                    "name": display_name,
                    "version": "2.0.0"
                }
            }
        })

    def _error_response(self, jsonrpc_id: int, code: int, message: str) -> JSONResponse:
        """Create JSON-RPC error response.

        Args:
            jsonrpc_id: JSON-RPC request ID
            code: Error code
            message: Error message

        Returns:
            JSONResponse with error
        """
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": jsonrpc_id,
            "error": {
                "code": code,
                "message": message
            }
        }, status_code=200)  # JSON-RPC errors use 200 status
