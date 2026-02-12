"""SSE (Server-Sent Events) transport for MCP protocol."""

import json
import logging
import asyncio
from typing import Optional, AsyncGenerator
from starlette.requests import Request
from starlette.responses import StreamingResponse

logger = logging.getLogger(__name__)


async def mcp_sse_endpoint(request: Request, handler, server_name: Optional[str] = None) -> StreamingResponse:
    """Handle MCP SSE transport.
    
    SSE is the standard transport for HTTP-based MCP servers.
    Client sends messages via POST to /mcp/{server_name}/messages
    Server sends responses via GET to /mcp/{server_name} as SSE stream
    
    Args:
        request: Starlette request
        handler: McpHandler instance
        server_name: Optional server name
        
    Returns:
        StreamingResponse with text/event-stream
    """
    
    async def event_stream() -> AsyncGenerator[str, None]:
        """Generate SSE events."""
        try:
            # Send initial connection event
            yield f"event: endpoint\ndata: /mcp/{server_name or 'all'}\n\n"
            
            # Keep connection alive
            while True:
                await asyncio.sleep(30)
                # Send keepalive ping
                yield ": keepalive\n\n"
                
        except asyncio.CancelledError:
            logger.info(f"SSE connection closed for {server_name}")
        except Exception as e:
            logger.error(f"SSE error: {e}")
            yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
    
    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        }
    )


async def handle_sse_message(request: Request, handler, server_name: Optional[str] = None):
    """Handle SSE message POST (client sends JSON-RPC via POST).
    
    Args:
        request: Starlette request with JSON-RPC body
        handler: McpHandler instance
        server_name: Optional server name
        
    Returns:
        JSONResponse with result
    """
    # SSE transport: client sends messages via POST, receives via SSE stream
    # For now, we'll process synchronously and return result
    return await handler.handle_request(request, server_name=server_name)
