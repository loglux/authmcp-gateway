#!/usr/bin/env python3
import json
import os
import sys
import urllib.request


def _usage() -> None:
    print("Usage: codex_refresh_mcp.py <server_name> <oauth_token_url>", file=sys.stderr)
    print("Example: codex_refresh_mcp.py rag https://mcp.log7.uk/oauth/token", file=sys.stderr)


def _load_credentials(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_credentials(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)


def _refresh_token(token_url: str, client_id: str, refresh_token: str) -> dict:
    payload = json.dumps(
        {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        token_url,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


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
    access_token = token_resp.get("access_token")
    expires_in = token_resp.get("expires_in")
    new_refresh = token_resp.get("refresh_token")

    if not access_token:
        print("No access_token in refresh response", file=sys.stderr)
        return 1

    entry["access_token"] = access_token
    if expires_in:
        entry["expires_at"] = int(expires_in * 1000) + int(
            __import__("time").time() * 1000
        )
    if new_refresh:
        entry["refresh_token"] = new_refresh

    creds[entry_key] = entry
    _save_credentials(cred_path, creds)
    print("OK: access_token refreshed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
