"""MCP Protocol handler - Gateway endpoint for MCP requests.

Supports full MCP protocol: tools, resources, prompts, completions, ping.
"""

import logging
import time
from typing import Any, Dict, Optional

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from authmcp_gateway.utils import get_request_ip

from .proxy import McpProxy, PromptNotFoundError, ResourceNotFoundError, ToolNotFoundError

logger = logging.getLogger(__name__)


class McpHandler:
    """Handles MCP JSON-RPC requests and routes to backend servers."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.proxy = McpProxy(db_path)

    async def handle_request(
        self, request: Request, server_name: Optional[str] = None
    ) -> JSONResponse:
        """Handle MCP JSON-RPC request."""
        try:
            data = await request.json()
            jsonrpc_id = data.get("id")
            method = data.get("method")
            params = data.get("params", {})

            logger.debug(
                f"MCP request: method={method}, params={params}, server_name={server_name}"
            )

            user_id = getattr(request.state, "user_id", None)

            # --- Dispatch ---
            if method == "initialize":
                return await self._handle_initialize(
                    jsonrpc_id, params, user_id, server_name, request
                )

            elif method == "ping":
                return JSONResponse({"jsonrpc": "2.0", "id": jsonrpc_id, "result": {}})

            elif method in {"notifications/initialized", "initialized"}:
                if jsonrpc_id is not None:
                    return JSONResponse({"jsonrpc": "2.0", "id": jsonrpc_id, "result": {}})
                # 204 must not include a response body
                return Response(status_code=204)

            elif method == "tools/list":
                return await self._handle_tools_list(jsonrpc_id, user_id, server_name, request)

            elif method == "tools/call":
                tool_name = params.get("name")
                arguments = params.get("arguments", {})
                return await self._handle_tool_call(
                    jsonrpc_id, tool_name, arguments, user_id, server_name, request
                )

            elif method == "resources/list":
                return await self._handle_resources_list(jsonrpc_id, user_id, server_name, request)

            elif method == "resources/read":
                return await self._handle_resource_read(
                    jsonrpc_id, params, user_id, server_name, request
                )

            elif method == "resources/templates/list":
                return await self._handle_resource_templates_list(
                    jsonrpc_id, user_id, server_name, request
                )

            elif method == "prompts/list":
                return await self._handle_prompts_list(jsonrpc_id, user_id, server_name, request)

            elif method == "prompts/get":
                return await self._handle_prompt_get(
                    jsonrpc_id, params, user_id, server_name, request
                )

            elif method == "completion/complete":
                return await self._handle_completion(
                    jsonrpc_id, params, user_id, server_name, request
                )

            elif method == "logging/setLevel":
                # Accept the level but we don't use it for backend routing
                logger.info(f"Client set log level: {params.get('level')}")
                return JSONResponse({"jsonrpc": "2.0", "id": jsonrpc_id, "result": {}})

            elif method and method.startswith("notifications/"):
                # Gracefully ignore any other notifications
                if jsonrpc_id is not None:
                    return JSONResponse({"jsonrpc": "2.0", "id": jsonrpc_id, "result": {}})
                return JSONResponse(status_code=204, content={})

            else:
                # Codex-style direct JSON-RPC: tool name as method, params as arguments
                # See: https://github.com/openai/codex/pull/2264
                # Only for non-namespaced methods (no "/") — namespaced unknowns get -32601
                if method and "/" not in method:
                    logger.info(f"Direct JSON-RPC tool call: {method} (Codex-style)")
                    return await self._handle_tool_call(
                        jsonrpc_id, method, params, user_id, server_name, request
                    )

                logger.warning(f"Unknown MCP method: {method}")
                return self._error_response(jsonrpc_id or 1, -32601, f"Method not found: {method}")

        except Exception as e:
            logger.exception(f"Error handling MCP request: {e}")
            return self._error_response(1, -32603, f"Internal error: {str(e)}")

    # ========================================================================
    # INITIALIZE
    # ========================================================================

    async def _handle_initialize(
        self,
        jsonrpc_id: int,
        params: Dict[str, Any],
        user_id: Optional[int],
        server_name: Optional[str] = None,
        request: Optional[Request] = None,
    ) -> JSONResponse:
        """Handle initialize with dynamic capabilities from backends."""
        logger.info(f"Handling initialize request (server: {server_name or 'all'})")

        display_name = "authmcp-gateway"
        if server_name:
            display_name = server_name

        # Discover actual capabilities from backends
        try:
            capabilities = await self.proxy.get_aggregated_capabilities(
                user_id=user_id, server_name=server_name
            )
        except Exception as e:
            logger.error(f"Failed to discover capabilities: {e}")
            capabilities = {"tools": {}}

        self._log_mcp(
            method="initialize",
            user_id=user_id,
            success=True,
            request_id=jsonrpc_id,
            request=request,
        )

        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": jsonrpc_id,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": capabilities,
                    "serverInfo": {"name": display_name, "version": "2.0.0"},
                },
            }
        )

    # ========================================================================
    # TOOLS
    # ========================================================================

    async def _handle_tools_list(
        self,
        jsonrpc_id: int,
        user_id: Optional[int],
        server_name: Optional[str] = None,
        request: Optional[Request] = None,
    ) -> JSONResponse:
        """Handle tools/list request."""
        start_time = time.time()

        try:
            tools = await self.proxy.list_tools(user_id=user_id, server_name=server_name)

            formatted_tools = []
            for tool in tools:
                formatted_tool = {
                    "name": tool.get("name"),
                    "description": tool.get("description"),
                    "inputSchema": tool.get("inputSchema", {}),
                }
                if tool.get("annotations"):
                    formatted_tool["annotations"] = tool["annotations"]
                formatted_tools.append(formatted_tool)

            logger.info(f"Returning {len(formatted_tools)} tools")
            self._log_mcp(
                method="tools/list",
                user_id=user_id,
                success=True,
                response_time_ms=self._elapsed(start_time),
                request_id=jsonrpc_id,
                request=request,
            )
            return JSONResponse(
                {"jsonrpc": "2.0", "id": jsonrpc_id, "result": {"tools": formatted_tools}}
            )

        except Exception as e:
            logger.exception(f"Error in tools/list: {e}")
            self._log_mcp(
                method="tools/list",
                user_id=user_id,
                success=False,
                error_message=str(e),
                response_time_ms=self._elapsed(start_time),
                request_id=jsonrpc_id,
                request=request,
            )
            return self._error_response(jsonrpc_id, -32603, str(e))

    async def _handle_tool_call(
        self,
        jsonrpc_id: int,
        tool_name: str,
        arguments: Dict[str, Any],
        user_id: Optional[int],
        server_name: Optional[str] = None,
        request: Optional[Request] = None,
    ) -> JSONResponse:
        """Handle tools/call request."""
        if not tool_name:
            return self._error_response(jsonrpc_id, -32602, "Missing required parameter: name")

        logger.info(f"Calling tool: {tool_name} (server: {server_name or 'any'})")
        start_time = time.time()

        try:
            result, server = await self.proxy.call_tool(
                tool_name=tool_name,
                arguments=arguments,
                user_id=user_id,
                server_name=server_name,
            )
            server_id = server.get("id") if server else None

            if "result" in result:
                self._log_mcp(
                    method="tools/call",
                    tool_name=tool_name,
                    user_id=user_id,
                    mcp_server_id=server_id,
                    success=True,
                    response_time_ms=self._elapsed(start_time),
                    request_id=jsonrpc_id,
                    request=request,
                )
                return JSONResponse(
                    {"jsonrpc": "2.0", "id": jsonrpc_id, "result": result["result"]}
                )
            elif "error" in result:
                error_msg = str(result.get("error"))
                self._log_mcp(
                    method="tools/call",
                    tool_name=tool_name,
                    user_id=user_id,
                    mcp_server_id=server_id,
                    success=False,
                    error_message=error_msg,
                    response_time_ms=self._elapsed(start_time),
                    request_id=jsonrpc_id,
                    request=request,
                )
                return JSONResponse({"jsonrpc": "2.0", "id": jsonrpc_id, "error": result["error"]})
            else:
                error_msg = "Invalid response from backend server"
                self._log_mcp(
                    method="tools/call",
                    tool_name=tool_name,
                    user_id=user_id,
                    mcp_server_id=server_id,
                    success=False,
                    error_message=error_msg,
                    response_time_ms=self._elapsed(start_time),
                    request_id=jsonrpc_id,
                    request=request,
                )
                return self._error_response(jsonrpc_id, -32603, error_msg)

        except ToolNotFoundError as e:
            logger.warning(f"Tool not found: {tool_name}")
            self._log_mcp(
                method="tools/call",
                tool_name=tool_name,
                user_id=user_id,
                success=False,
                error_message=str(e),
                response_time_ms=self._elapsed(start_time),
                request_id=jsonrpc_id,
                request=request,
            )
            return self._error_response(jsonrpc_id, -32601, str(e))

        except PermissionError as e:
            logger.warning(f"Permission denied: {e}")
            return self._error_response(jsonrpc_id, -32000, str(e))

        except ValueError as e:
            logger.warning(f"Invalid params: {e}")
            return self._error_response(jsonrpc_id, -32602, str(e))

        except Exception as e:
            logger.exception(f"Error calling tool '{tool_name}': {e}")
            return self._error_response(jsonrpc_id, -32603, str(e))

    # ========================================================================
    # RESOURCES
    # ========================================================================

    async def _handle_resources_list(
        self,
        jsonrpc_id: int,
        user_id: Optional[int],
        server_name: Optional[str] = None,
        request: Optional[Request] = None,
    ) -> JSONResponse:
        """Handle resources/list request."""
        start_time = time.time()

        try:
            resources = await self.proxy.list_resources(user_id=user_id, server_name=server_name)

            # Strip internal metadata before returning
            formatted = []
            for r in resources:
                item = {k: v for k, v in r.items() if not k.startswith("_")}
                formatted.append(item)

            logger.info(f"Returning {len(formatted)} resources")
            self._log_mcp(
                method="resources/list",
                user_id=user_id,
                success=True,
                response_time_ms=self._elapsed(start_time),
                request=request,
            )
            return JSONResponse(
                {"jsonrpc": "2.0", "id": jsonrpc_id, "result": {"resources": formatted}}
            )

        except Exception as e:
            logger.exception(f"Error in resources/list: {e}")
            self._log_mcp(
                method="resources/list",
                user_id=user_id,
                success=False,
                error_message=str(e),
                response_time_ms=self._elapsed(start_time),
                request=request,
            )
            return self._error_response(jsonrpc_id, -32603, str(e))

    async def _handle_resource_read(
        self,
        jsonrpc_id: int,
        params: Dict[str, Any],
        user_id: Optional[int],
        server_name: Optional[str] = None,
        request: Optional[Request] = None,
    ) -> JSONResponse:
        """Handle resources/read request."""
        uri = params.get("uri")
        if not uri:
            return self._error_response(jsonrpc_id, -32602, "Missing required parameter: uri")

        start_time = time.time()

        try:
            data, server = await self.proxy.read_resource(
                uri=uri, user_id=user_id, server_name=server_name
            )
            server_id = server.get("id") if server else None

            if "result" in data:
                self._log_mcp(
                    method="resources/read",
                    user_id=user_id,
                    mcp_server_id=server_id,
                    success=True,
                    response_time_ms=self._elapsed(start_time),
                    request=request,
                )
                return JSONResponse({"jsonrpc": "2.0", "id": jsonrpc_id, "result": data["result"]})
            elif "error" in data:
                self._log_mcp(
                    method="resources/read",
                    user_id=user_id,
                    mcp_server_id=server_id,
                    success=False,
                    error_message=str(data["error"]),
                    response_time_ms=self._elapsed(start_time),
                    request=request,
                )
                return JSONResponse({"jsonrpc": "2.0", "id": jsonrpc_id, "error": data["error"]})
            else:
                return self._error_response(jsonrpc_id, -32603, "Invalid backend response")

        except ResourceNotFoundError as e:
            logger.warning(f"Resource not found: {uri}")
            self._log_mcp(
                method="resources/read",
                user_id=user_id,
                success=False,
                error_message=str(e),
                response_time_ms=self._elapsed(start_time),
                request=request,
            )
            return self._error_response(jsonrpc_id, -32602, str(e))

        except PermissionError as e:
            return self._error_response(jsonrpc_id, -32000, str(e))

        except Exception as e:
            logger.exception(f"Error reading resource '{uri}': {e}")
            return self._error_response(jsonrpc_id, -32603, str(e))

    async def _handle_resource_templates_list(
        self,
        jsonrpc_id: int,
        user_id: Optional[int],
        server_name: Optional[str] = None,
        request: Optional[Request] = None,
    ) -> JSONResponse:
        """Handle resources/templates/list request."""
        start_time = time.time()

        try:
            templates = await self.proxy.list_resource_templates(
                user_id=user_id, server_name=server_name
            )

            formatted = []
            for t in templates:
                item = {k: v for k, v in t.items() if not k.startswith("_")}
                formatted.append(item)

            self._log_mcp(
                method="resources/templates/list",
                user_id=user_id,
                success=True,
                response_time_ms=self._elapsed(start_time),
                request=request,
            )
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": jsonrpc_id,
                    "result": {"resourceTemplates": formatted},
                }
            )

        except Exception as e:
            logger.exception(f"Error in resources/templates/list: {e}")
            return self._error_response(jsonrpc_id, -32603, str(e))

    # ========================================================================
    # PROMPTS
    # ========================================================================

    async def _handle_prompts_list(
        self,
        jsonrpc_id: int,
        user_id: Optional[int],
        server_name: Optional[str] = None,
        request: Optional[Request] = None,
    ) -> JSONResponse:
        """Handle prompts/list request."""
        start_time = time.time()

        try:
            prompts = await self.proxy.list_prompts(user_id=user_id, server_name=server_name)

            formatted = []
            for p in prompts:
                item = {k: v for k, v in p.items() if not k.startswith("_")}
                formatted.append(item)

            logger.info(f"Returning {len(formatted)} prompts")
            self._log_mcp(
                method="prompts/list",
                user_id=user_id,
                success=True,
                response_time_ms=self._elapsed(start_time),
                request=request,
            )
            return JSONResponse(
                {"jsonrpc": "2.0", "id": jsonrpc_id, "result": {"prompts": formatted}}
            )

        except Exception as e:
            logger.exception(f"Error in prompts/list: {e}")
            self._log_mcp(
                method="prompts/list",
                user_id=user_id,
                success=False,
                error_message=str(e),
                response_time_ms=self._elapsed(start_time),
                request=request,
            )
            return self._error_response(jsonrpc_id, -32603, str(e))

    async def _handle_prompt_get(
        self,
        jsonrpc_id: int,
        params: Dict[str, Any],
        user_id: Optional[int],
        server_name: Optional[str] = None,
        request: Optional[Request] = None,
    ) -> JSONResponse:
        """Handle prompts/get request."""
        name = params.get("name")
        if not name:
            return self._error_response(jsonrpc_id, -32602, "Missing required parameter: name")

        arguments = params.get("arguments")
        start_time = time.time()

        try:
            data, server = await self.proxy.get_prompt(
                name=name, arguments=arguments, user_id=user_id, server_name=server_name
            )
            server_id = server.get("id") if server else None

            if "result" in data:
                self._log_mcp(
                    method="prompts/get",
                    user_id=user_id,
                    mcp_server_id=server_id,
                    success=True,
                    response_time_ms=self._elapsed(start_time),
                    request=request,
                )
                return JSONResponse({"jsonrpc": "2.0", "id": jsonrpc_id, "result": data["result"]})
            elif "error" in data:
                self._log_mcp(
                    method="prompts/get",
                    user_id=user_id,
                    mcp_server_id=server_id,
                    success=False,
                    error_message=str(data["error"]),
                    response_time_ms=self._elapsed(start_time),
                    request=request,
                )
                return JSONResponse({"jsonrpc": "2.0", "id": jsonrpc_id, "error": data["error"]})
            else:
                return self._error_response(jsonrpc_id, -32603, "Invalid backend response")

        except PromptNotFoundError as e:
            logger.warning(f"Prompt not found: {name}")
            self._log_mcp(
                method="prompts/get",
                user_id=user_id,
                success=False,
                error_message=str(e),
                response_time_ms=self._elapsed(start_time),
                request=request,
            )
            return self._error_response(jsonrpc_id, -32602, str(e))

        except PermissionError as e:
            return self._error_response(jsonrpc_id, -32000, str(e))

        except Exception as e:
            logger.exception(f"Error getting prompt '{name}': {e}")
            return self._error_response(jsonrpc_id, -32603, str(e))

    # ========================================================================
    # COMPLETION
    # ========================================================================

    async def _handle_completion(
        self,
        jsonrpc_id: int,
        params: Dict[str, Any],
        user_id: Optional[int],
        server_name: Optional[str] = None,
        request: Optional[Request] = None,
    ) -> JSONResponse:
        """Handle completion/complete request."""
        ref = params.get("ref")
        argument = params.get("argument")
        if not ref or not argument:
            return self._error_response(
                jsonrpc_id, -32602, "Missing required parameters: ref, argument"
            )

        start_time = time.time()

        try:
            data, server = await self.proxy.complete(
                ref=ref, argument=argument, user_id=user_id, server_name=server_name
            )
            server_id = server.get("id") if server else None

            if "result" in data:
                self._log_mcp(
                    method="completion/complete",
                    user_id=user_id,
                    mcp_server_id=server_id,
                    success=True,
                    response_time_ms=self._elapsed(start_time),
                    request=request,
                )
                return JSONResponse({"jsonrpc": "2.0", "id": jsonrpc_id, "result": data["result"]})
            elif "error" in data:
                return JSONResponse({"jsonrpc": "2.0", "id": jsonrpc_id, "error": data["error"]})
            else:
                return self._error_response(jsonrpc_id, -32603, "Invalid backend response")

        except (ResourceNotFoundError, PromptNotFoundError) as e:
            return self._error_response(jsonrpc_id, -32602, str(e))

        except Exception as e:
            logger.exception(f"Error in completion/complete: {e}")
            return self._error_response(jsonrpc_id, -32603, str(e))

    # ========================================================================
    # HELPERS
    # ========================================================================

    @staticmethod
    def _elapsed(start_time: float) -> int:
        """Return elapsed milliseconds since start_time."""
        return int((time.time() - start_time) * 1000)

    def _log_mcp(
        self,
        method: str,
        user_id: Optional[int] = None,
        mcp_server_id: Optional[int] = None,
        tool_name: Optional[str] = None,
        success: bool = True,
        error_message: Optional[str] = None,
        response_time_ms: Optional[int] = None,
        request_id: Optional[str] = None,
        request: Optional[Request] = None,
    ) -> None:
        """Log MCP request to security logger (best-effort)."""
        try:
            from authmcp_gateway.security.logger import log_mcp_request

            log_mcp_request(
                db_path=self.db_path,
                user_id=user_id,
                mcp_server_id=mcp_server_id,
                method=method,
                tool_name=tool_name,
                success=success,
                error_message=error_message,
                response_time_ms=response_time_ms,
                ip_address=get_request_ip(request),
                client_id=getattr(request.state, "client_id", None) if request else None,
                user_agent=request.headers.get("user-agent") if request else None,
                request_id=str(request_id) if request_id is not None else None,
                path=request.url.path if request else None,
                event_kind="work" if method == "tools/call" else "system",
            )
        except Exception as log_err:
            logger.error(f"Failed to log MCP request: {log_err}")

    def _error_response(self, jsonrpc_id: int, code: int, message: str) -> JSONResponse:
        """Create JSON-RPC error response."""
        return JSONResponse(
            {"jsonrpc": "2.0", "id": jsonrpc_id, "error": {"code": code, "message": message}},
            status_code=200,
        )
