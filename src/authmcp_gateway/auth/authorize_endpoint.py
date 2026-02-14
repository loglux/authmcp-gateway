"""OAuth Authorization endpoint."""

import logging
from urllib.parse import urlencode, urlparse
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from .oauth_code_flow import generate_authorization_code
from .user_store import get_user_by_username
from .password import verify_password
from .client_store import get_oauth_client_by_client_id, is_redirect_uri_allowed, update_oauth_client_last_seen
from ..config import get_config

logger = logging.getLogger(__name__)


async def authorize_page(request: Request) -> Response:
    """Authorization endpoint - shows login form or generates code.

    Handles both GET (show form) and POST (process login).

    Query params:
        response_type: must be "code"
        client_id: OAuth client ID
        redirect_uri: Where to redirect after auth
        code_challenge: PKCE challenge
        code_challenge_method: PKCE method (S256 or plain)
        state: OAuth state parameter
        scope: OAuth scope
        resource: Resource server URL
    """
    # Extract OAuth parameters
    response_type = request.query_params.get('response_type')
    client_id = request.query_params.get('client_id')
    redirect_uri = request.query_params.get('redirect_uri')
    code_challenge = request.query_params.get('code_challenge')
    code_challenge_method = request.query_params.get('code_challenge_method', 'plain')
    state = request.query_params.get('state', '')
    scope = request.query_params.get('scope', 'openid profile email')
    resource = request.query_params.get('resource', '')

    # Validate required parameters
    if response_type != 'code':
        return HTMLResponse(
            "<h1>Error</h1><p>Invalid response_type. Must be 'code'.</p>",
            status_code=400
        )

    if not client_id or not redirect_uri:
        return HTMLResponse(
            "<h1>Error</h1><p>Missing client_id or redirect_uri.</p>",
            status_code=400
        )

    # Validate redirect_uri (basic check)
    try:
        parsed = urlparse(redirect_uri)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid redirect_uri")
    except Exception:
        return HTMLResponse(
            "<h1>Error</h1><p>Invalid redirect_uri format.</p>",
            status_code=400
        )

    # Enforce registered clients if DCR is enabled
    try:
        config = get_config()
        if config.auth.allow_dcr:
            client = get_oauth_client_by_client_id(config.auth.sqlite_path, client_id)
            if not client:
                return HTMLResponse(
                    "<h1>Error</h1><p>Unknown client_id.</p>",
                    status_code=400
                )
            if not is_redirect_uri_allowed(client, redirect_uri):
                return HTMLResponse(
                    "<h1>Error</h1><p>redirect_uri not registered for this client.</p>",
                    status_code=400
                )
    except Exception as e:
        logger.error(f"DCR validation failed: {e}")
        return HTMLResponse(
            "<h1>Error</h1><p>Client validation failed.</p>",
            status_code=400
        )

    # GET request: show login form
    if request.method == 'GET':
        return _show_login_form(
            client_id, redirect_uri, code_challenge,
            code_challenge_method, state, scope, resource
        )

    # POST request: process login
    elif request.method == 'POST':
        response = await _process_login(
            request, client_id, redirect_uri, code_challenge,
            code_challenge_method, state, scope
        )
        try:
            config = get_config()
            update_oauth_client_last_seen(
                config.auth.sqlite_path,
                client_id,
                request.client.host if request.client else None,
                request.headers.get("user-agent"),
            )
        except Exception as e:
            logger.debug(f"Failed to update client last_seen: {e}")
        return response

    return HTMLResponse("Method not allowed", status_code=405)


def _show_login_form(
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str,
    state: str,
    scope: str,
    resource: str
) -> HTMLResponse:
    """Show HTML login form."""
    # Parse client_id to show friendly name
    client_name = urlparse(client_id).netloc or client_id

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>RAG MCP Gateway - Login</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                padding: 20px;
            }}
            .container {{
                background: white;
                border-radius: 16px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                max-width: 420px;
                width: 100%;
                padding: 40px;
            }}
            h1 {{
                color: #333;
                margin-bottom: 8px;
                font-size: 28px;
            }}
            .subtitle {{
                color: #666;
                margin-bottom: 32px;
                font-size: 14px;
            }}
            .app-info {{
                background: #f8f9fa;
                padding: 16px;
                border-radius: 8px;
                margin-bottom: 24px;
                border-left: 4px solid #667eea;
            }}
            .app-info strong {{
                color: #667eea;
                display: block;
                margin-bottom: 4px;
            }}
            .app-info span {{
                color: #666;
                font-size: 14px;
            }}
            .form-group {{
                margin-bottom: 20px;
            }}
            label {{
                display: block;
                margin-bottom: 8px;
                color: #333;
                font-weight: 500;
                font-size: 14px;
            }}
            input[type="text"],
            input[type="password"] {{
                width: 100%;
                padding: 12px 16px;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                font-size: 15px;
                transition: all 0.3s;
            }}
            input[type="text"]:focus,
            input[type="password"]:focus {{
                outline: none;
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }}
            button {{
                width: 100%;
                padding: 14px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: transform 0.2s, box-shadow 0.2s;
            }}
            button:hover {{
                transform: translateY(-2px);
                box-shadow: 0 8px 20px rgba(102, 126, 234, 0.4);
            }}
            button:active {{
                transform: translateY(0);
            }}
            .error {{
                background: #fee;
                border: 1px solid #fcc;
                color: #c33;
                padding: 12px;
                border-radius: 8px;
                margin-bottom: 20px;
                font-size: 14px;
            }}
            .scope {{
                font-size: 12px;
                color: #888;
                margin-top: 16px;
                text-align: center;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Authorization Required</h1>
            <p class="subtitle">Sign in to continue to {client_name}</p>

            <div class="app-info">
                <strong>{client_name}</strong>
                <span>is requesting access to your account</span>
            </div>

            <form method="POST" action="/authorize?{urlencode({
                'response_type': 'code',
                'client_id': client_id,
                'redirect_uri': redirect_uri,
                'code_challenge': code_challenge,
                'code_challenge_method': code_challenge_method,
                'state': state,
                'scope': scope
            })}">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required autofocus>
                </div>

                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>

                <button type="submit">Continue</button>
            </form>

            <p class="scope">
                Requested permissions: {scope}
            </p>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(html)


async def _process_login(
    request: Request,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str,
    state: str,
    scope: str
) -> Response:
    """Process login and generate authorization code."""
    # Get database path from app state
    db_path = request.app.state.auth_db_path

    # Parse form data
    form = await request.form()
    username = form.get('username')
    password = form.get('password')

    if not username or not password:
        return _show_login_form_with_error(
            "Username and password are required",
            client_id, redirect_uri, code_challenge,
            code_challenge_method, state, scope
        )

    # Verify credentials
    user = get_user_by_username(db_path, username)
    if not user or not verify_password(password, user['password_hash']):
        logger.warning(f"Failed login attempt for user: {username}")
        from .user_store import log_auth_event
        log_auth_event(
            db_path=db_path,
            event_type="mcp_oauth_error",
            username=username,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            success=False,
            details=f"Authorization failed (invalid credentials). client_id={client_id} redirect_uri={redirect_uri}"
        )
        return _show_login_form_with_error(
            "Invalid username or password",
            client_id, redirect_uri, code_challenge,
            code_challenge_method, state, scope
        )

    # Check if user is active
    if not user['is_active']:
        from .user_store import log_auth_event
        log_auth_event(
            db_path=db_path,
            event_type="mcp_oauth_error",
            user_id=user["id"],
            username=user["username"],
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            success=False,
            details=f"Authorization failed (inactive user). client_id={client_id} redirect_uri={redirect_uri}"
        )
        return _show_login_form_with_error(
            "Account is disabled",
            client_id, redirect_uri, code_challenge,
            code_challenge_method, state, scope
        )

    # Generate authorization code
    try:
        code = generate_authorization_code(
            db_path=db_path,
            user_id=user['id'],
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope=scope,
            expires_in_seconds=600  # 10 minutes
        )

        logger.info(f"Authorization successful for user {username} (id={user['id']})")
        from .user_store import log_auth_event
        log_auth_event(
            db_path=db_path,
            event_type="mcp_oauth_authorize",
            user_id=user["id"],
            username=user["username"],
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            success=True,
            details=f"Authorization code issued. client_id={client_id} redirect_uri={redirect_uri} scope={scope}"
        )

        # Redirect back to client with code and state
        params = {'code': code}
        if state:
            params['state'] = state

        redirect_url = f"{redirect_uri}?{urlencode(params)}"
        return RedirectResponse(url=redirect_url, status_code=302)

    except Exception as e:
        logger.exception(f"Error generating authorization code: {e}")
        from .user_store import log_auth_event
        log_auth_event(
            db_path=db_path,
            event_type="mcp_oauth_error",
            username=username,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            success=False,
            details=f"Authorization error. client_id={client_id} redirect_uri={redirect_uri}"
        )
        return _show_login_form_with_error(
            "Internal server error. Please try again.",
            client_id, redirect_uri, code_challenge,
            code_challenge_method, state, scope
        )


def _show_login_form_with_error(
    error: str,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str,
    state: str,
    scope: str
) -> HTMLResponse:
    """Show login form with error message."""
    form_html = _show_login_form(
        client_id, redirect_uri, code_challenge,
        code_challenge_method, state, scope, ""
    )

    # Inject error message
    error_html = f'<div class="error">{error}</div>'
    html_with_error = form_html.body.decode('utf-8').replace(
        '<form method="POST"',
        f'{error_html}<form method="POST"'
    )

    return HTMLResponse(html_with_error, status_code=400)
