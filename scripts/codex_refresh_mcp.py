#!/usr/bin/env python3
import json
import os
import sys
import urllib.parse
import urllib.request
from urllib.error import HTTPError, URLError


def _usage() -> None:
    print("Usage: codex_refresh_mcp.py <server_name> <oauth_token_url>", file=sys.stderr)
    print("Example: codex_refresh_mcp.py rag https://mcp.log7.uk/oauth/token", file=sys.stderr)
    print(
        "Optional fallback env vars for password grant: CODEX_REFRESH_USERNAME, CODEX_REFRESH_PASSWORD",
        file=sys.stderr,
    )


def _load_credentials(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_credentials(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)


def _request_token(
    token_url: str,
    payload: dict,
    content_type: str = "application/x-www-form-urlencoded",
) -> dict:
    if content_type == "application/json":
        body = json.dumps(payload).encode("utf-8")
    else:
        body = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(
        token_url,
        data=body,
        headers={"Content-Type": content_type},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            data = json.loads(body)
        except Exception:
            data = {"error": "http_error", "error_description": body or str(e)}
        data["_http_status"] = e.code
        return data
    except URLError as e:
        return {"error": "network_error", "error_description": str(e)}


def _refresh_token(token_url: str, client_id: str, refresh_token: str) -> dict:
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
    }
    # Use form-encoded for maximum OAuth compatibility.
    return _request_token(token_url, payload, "application/x-www-form-urlencoded")


def _password_grant(token_url: str, username: str, password: str) -> dict:
    payload = {
        "grant_type": "password",
        "username": username,
        "password": password,
    }
    return _request_token(token_url, payload, "application/x-www-form-urlencoded")


def main() -> int:
    if len(sys.argv) != 3:
        _usage()
        return 2

    server_name = sys.argv[1]
    token_url = sys.argv[2]

    codex_home = os.environ.get("CODEX_HOME", os.path.expanduser("~/.codex"))
    cred_path = os.path.join(codex_home, ".credentials.json")

    if not os.path.exists(cred_path):
        print(f"Credentials file not found: {cred_path}", file=sys.stderr)
        return 1

    creds = _load_credentials(cred_path)
    entry_key = None
    entry = None
    for key, value in creds.items():
        if value.get("server_name") == server_name:
            entry_key = key
            entry = value
            break

    if not entry:
        print(f"Server not found in credentials: {server_name}", file=sys.stderr)
        return 1

    client_id = entry.get("client_id")
    refresh_token = entry.get("refresh_token")
    if not client_id or not refresh_token:
        print("Missing client_id or refresh_token in credentials", file=sys.stderr)
        return 1

    token_resp = _refresh_token(token_url, client_id, refresh_token)
    if not token_resp.get("access_token"):
        if token_resp.get("error") == "invalid_grant":
            username = os.environ.get("CODEX_REFRESH_USERNAME")
            password = os.environ.get("CODEX_REFRESH_PASSWORD")
            if username and password:
                token_resp = _password_grant(token_url, username, password)
    access_token = token_resp.get("access_token")
    expires_in = token_resp.get("expires_in")
    new_refresh = token_resp.get("refresh_token")

    if not access_token:
        status = token_resp.get("_http_status")
        err = token_resp.get("error")
        desc = token_resp.get("error_description")
        status_part = f"HTTP {status} " if status else ""
        print(
            f"No access_token in refresh response. {status_part}{err or ''} {desc or ''}".strip(),
            file=sys.stderr,
        )
        return 1

    entry["access_token"] = access_token
    if expires_in:
        entry["expires_at"] = int(expires_in * 1000) + int(__import__("time").time() * 1000)
    if new_refresh:
        entry["refresh_token"] = new_refresh

    creds[entry_key] = entry
    _save_credentials(cred_path, creds)
    print("OK: access_token refreshed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
