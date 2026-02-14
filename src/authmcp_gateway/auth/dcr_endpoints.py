"""OAuth Dynamic Client Registration endpoints (RFC 7591/7592)."""

import json
import logging
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlparse

from starlette.requests import Request
from starlette.responses import JSONResponse

from .client_store import (
    create_oauth_client,
    get_oauth_client_by_client_id,
    get_oauth_client_by_registration_token,
    update_oauth_client,
    delete_oauth_client,
)
from .models import ClientRegistrationRequest, ClientRegistrationResponse, ErrorResponse
from .user_store import log_auth_event
from ..config import AppConfig
from ..rate_limiter import get_rate_limiter

logger = logging.getLogger(__name__)

_config: Optional[AppConfig] = None


def set_config(config: AppConfig):
    """Set the global config for DCR endpoints."""
    global _config
    _config = config


def _get_config() -> AppConfig:
    if _config is None:
        raise RuntimeError("Config not initialized")
    return _config


def _error_response(status_code: int, detail: str, error_code: Optional[str] = None) -> JSONResponse:
    error = ErrorResponse(detail=detail, error_code=error_code)
    return JSONResponse(status_code=status_code, content=error.model_dump())


def _get_client_ip(request: Request) -> Optional[str]:
    if request.client:
        return request.client.host
    return None


def _parse_bearer_token(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth:
        return None
    parts = auth.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def _validate_redirect_uris(redirect_uris) -> Optional[str]:
    if not isinstance(redirect_uris, list) or not redirect_uris:
        return "redirect_uris must be a non-empty list"
    for uri in redirect_uris:
        if not isinstance(uri, str) or not uri.strip():
            return "redirect_uris must contain valid URIs"
        parsed = urlparse(uri)
        if not parsed.scheme:
            return f"redirect_uri missing scheme: {uri}"
        if parsed.fragment:
            return f"redirect_uri must not contain fragment: {uri}"
        if parsed.scheme in {"http", "https"} and not parsed.netloc:
            return f"redirect_uri must include host: {uri}"
    return None


def _normalize_metadata(data: Dict[str, Any]) -> Dict[str, Any]:
    """Apply defaults and normalize client metadata."""
    metadata = dict(data)
    metadata["token_endpoint_auth_method"] = metadata.get("token_endpoint_auth_method") or "none"
    metadata["grant_types"] = metadata.get("grant_types") or ["authorization_code"]
    metadata["response_types"] = metadata.get("response_types") or ["code"]
    return metadata


def _registration_response(
    base: Dict[str, Any],
    metadata: Dict[str, Any],
    status_code: int = 200,
) -> JSONResponse:
    response = ClientRegistrationResponse(
        client_id=base["client_id"],
        client_secret=base.get("client_secret"),
        client_id_issued_at=base.get("client_id_issued_at"),
        client_secret_expires_at=base.get("client_secret_expires_at", 0),
        registration_access_token=base.get("registration_access_token"),
        registration_client_uri=base.get("registration_client_uri"),
        redirect_uris=metadata["redirect_uris"],
        token_endpoint_auth_method=metadata.get("token_endpoint_auth_method"),
        grant_types=metadata.get("grant_types"),
        response_types=metadata.get("response_types"),
        client_name=metadata.get("client_name"),
        client_uri=metadata.get("client_uri"),
        logo_uri=metadata.get("logo_uri"),
        scope=metadata.get("scope"),
        contacts=metadata.get("contacts"),
        tos_uri=metadata.get("tos_uri"),
        policy_uri=metadata.get("policy_uri"),
        jwks_uri=metadata.get("jwks_uri"),
        jwks=metadata.get("jwks"),
        software_id=metadata.get("software_id"),
        software_version=metadata.get("software_version"),
    )
    return JSONResponse(response.model_dump(), status_code=status_code)


async def register_client(request: Request) -> JSONResponse:
    """POST /oauth/register - Dynamic client registration."""
    config = _get_config()

    if not config.auth.allow_dcr:
        return _error_response(403, "Dynamic client registration is disabled", "DCR_DISABLED")

    if config.auth.dcr_require_initial_token:
        token = _parse_bearer_token(request)
        if not token or token != config.auth.dcr_initial_access_token:
            return _error_response(401, "Invalid initial access token", "INVALID_TOKEN")

    # Rate limit
    if config.rate_limit.enabled:
        limiter = get_rate_limiter()
        client_ip = _get_client_ip(request) or "unknown"
        identifier = f"dcr:{client_ip}"
        allowed, retry_after = limiter.check_limit(
            identifier=identifier,
            limit=config.rate_limit.dcr_limit,
            window=config.rate_limit.dcr_window,
        )
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many registration attempts. Please try again later.",
                    "error_code": "RATE_LIMIT_EXCEEDED",
                    "retry_after": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

    try:
        body = await request.json()
        req = ClientRegistrationRequest(**body)
    except ValueError as e:
        return _error_response(400, f"Validation error: {str(e)}", "VALIDATION_ERROR")
    except Exception:
        return _error_response(400, "Invalid request body", "INVALID_REQUEST")

    err = _validate_redirect_uris(req.redirect_uris)
    if err:
        return _error_response(400, err, "INVALID_REDIRECT_URI")

    metadata = _normalize_metadata(req.model_dump())
    token_auth_method = metadata.get("token_endpoint_auth_method")
    if token_auth_method not in {"none", "client_secret_basic", "client_secret_post"}:
        return _error_response(
            400,
            f"Unsupported token_endpoint_auth_method: {token_auth_method}",
            "UNSUPPORTED_AUTH_METHOD",
        )

    registration_client_uri_base = f"{config.mcp_public_url}/oauth/register"
    base = create_oauth_client(
        db_path=config.auth.sqlite_path,
        metadata=metadata,
        registration_client_uri_base=registration_client_uri_base,
    )

    log_auth_event(
        db_path=config.auth.sqlite_path,
        event_type="dcr_register",
        ip_address=_get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        success=True,
        details=f"client_id={base['client_id']}",
    )

    return _registration_response(base, metadata, status_code=201)


def _require_registration_token(request: Request, client_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[JSONResponse]]:
    config = _get_config()
    token = _parse_bearer_token(request)
    if not token:
        return None, _error_response(401, "Missing registration access token", "MISSING_TOKEN")
    client = get_oauth_client_by_registration_token(config.auth.sqlite_path, client_id, token)
    if not client:
        return None, _error_response(401, "Invalid registration access token", "INVALID_TOKEN")
    return client, None


async def get_client(request: Request) -> JSONResponse:
    """GET /oauth/register/{client_id} - Retrieve client metadata."""
    config = _get_config()
    client_id = request.path_params.get("client_id")
    if not client_id:
        return _error_response(400, "Missing client_id", "INVALID_REQUEST")

    client, error = _require_registration_token(request, client_id)
    if error:
        return error

    metadata = _normalize_metadata(client)
    base = {
        "client_id": client["client_id"],
        "registration_client_uri": client.get("registration_client_uri"),
        "client_id_issued_at": None,
        "client_secret_expires_at": 0,
    }
    return _registration_response(base, metadata)


async def update_client(request: Request) -> JSONResponse:
    """PUT /oauth/register/{client_id} - Replace client metadata."""
    config = _get_config()
    client_id = request.path_params.get("client_id")
    if not client_id:
        return _error_response(400, "Missing client_id", "INVALID_REQUEST")

    _, error = _require_registration_token(request, client_id)
    if error:
        return error

    try:
        body = await request.json()
        req = ClientRegistrationRequest(**body)
    except ValueError as e:
        return _error_response(400, f"Validation error: {str(e)}", "VALIDATION_ERROR")
    except Exception:
        return _error_response(400, "Invalid request body", "INVALID_REQUEST")

    err = _validate_redirect_uris(req.redirect_uris)
    if err:
        return _error_response(400, err, "INVALID_REDIRECT_URI")

    metadata = _normalize_metadata(req.model_dump())
    token_auth_method = metadata.get("token_endpoint_auth_method")
    if token_auth_method not in {"none", "client_secret_basic", "client_secret_post"}:
        return _error_response(
            400,
            f"Unsupported token_endpoint_auth_method: {token_auth_method}",
            "UNSUPPORTED_AUTH_METHOD",
        )

    updated = update_oauth_client(config.auth.sqlite_path, client_id, metadata)
    if not updated:
        return _error_response(404, "Client not found", "NOT_FOUND")

    base = {
        "client_id": client_id,
        "registration_client_uri": updated.get("registration_client_uri"),
        "client_id_issued_at": None,
        "client_secret_expires_at": 0,
    }

    log_auth_event(
        db_path=config.auth.sqlite_path,
        event_type="dcr_update",
        ip_address=_get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        success=True,
        details=f"client_id={client_id}",
    )

    return _registration_response(base, metadata)


async def delete_client(request: Request) -> JSONResponse:
    """DELETE /oauth/register/{client_id} - Delete client."""
    config = _get_config()
    client_id = request.path_params.get("client_id")
    if not client_id:
        return _error_response(400, "Missing client_id", "INVALID_REQUEST")

    _, error = _require_registration_token(request, client_id)
    if error:
        return error

    deleted = delete_oauth_client(config.auth.sqlite_path, client_id)
    if not deleted:
        return _error_response(404, "Client not found", "NOT_FOUND")

    log_auth_event(
        db_path=config.auth.sqlite_path,
        event_type="dcr_delete",
        ip_address=_get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        success=True,
        details=f"client_id={client_id}",
    )

    return JSONResponse(status_code=204, content={})
