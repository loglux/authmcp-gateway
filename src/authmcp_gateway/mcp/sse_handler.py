"""SSE (Server-Sent Events) transport for MCP protocol."""

import asyncio
import json
import logging
from typing import AsyncGenerator, Dict, Optional, Set

from starlette.requests import Request
from starlette.responses import StreamingResponse

logger = logging.getLogger(__name__)

_sse_channels: Dict[str, Set[asyncio.Queue]] = {}
_sse_lock = asyncio.Lock()


def _channel_key(server_name: Optional[str]) -> str:
    return server_name or "all"


async def _register_queue(server_name: Optional[str]) -> asyncio.Queue:
    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    key = _channel_key(server_name)
    async with _sse_lock:
        if key not in _sse_channels:
            _sse_channels[key] = set()
        _sse_channels[key].add(queue)
    return queue


async def _unregister_queue(server_name: Optional[str], queue: asyncio.Queue) -> None:
    key = _channel_key(server_name)
    async with _sse_lock:
        channels = _sse_channels.get(key)
        if channels and queue in channels:
            channels.remove(queue)
            if not channels:
                _sse_channels.pop(key, None)


async def _broadcast(server_name: Optional[str], payload: str) -> None:
    key = _channel_key(server_name)
    async with _sse_lock:
        queues = list(_sse_channels.get(key, set()))
    for q in queues:
        try:
            q.put_nowait(payload)
        except asyncio.QueueFull:
            logger.warning("SSE queue full; dropping message for %s", key)


async def mcp_sse_endpoint(
    request: Request, handler, server_name: Optional[str] = None
) -> StreamingResponse:
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
        queue = await _register_queue(server_name)
        try:
            # Send initial connection event
            yield f"event: endpoint\ndata: /mcp/{server_name or 'all'}\n\n"

            # Keep connection alive
            while True:
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield f"event: message\ndata: {payload}\n\n"
                except asyncio.TimeoutError:
                    # Send keepalive ping
                    yield ": keepalive\n\n"

        except asyncio.CancelledError:
            logger.info(f"SSE connection closed for {server_name}")
        except Exception as e:
            logger.error(f"SSE error: {e}")
            yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
        finally:
            await _unregister_queue(server_name, queue)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
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
    # SSE transport: client sends messages via POST, receives via SSE stream.
    # We process synchronously and also broadcast the response to any open SSE clients.
    response = await handler.handle_request(request, server_name=server_name)
    try:
        body = (
            response.body.decode("utf-8") if isinstance(response.body, (bytes, bytearray)) else ""
        )
        if body:
            await _broadcast(server_name, body)
    except Exception as e:
        logger.debug(f"Failed to broadcast SSE response: {e}")
    return response
