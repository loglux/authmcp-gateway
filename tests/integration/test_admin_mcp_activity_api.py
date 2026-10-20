"""Contract tests for admin/mcp_activity_api.py::api_mcp_stats.

Not CRUD happy-path tests (admin modules are otherwise intentionally
untested — see CLAUDE.md). This is specifically a regression test for a
response-shape bug: `api_mcp_stats` renames fields for the Dashboard
(`total_requests` -> `requests_24h`, `avg_response_time_ms` ->
`avg_response_time`), but `mcp_activity.html` reads the same endpoint
expecting the original names. The rename shipped in commit 6efb183
(Feb 2026, admin-routes split) and went unnoticed for ~8 months because
nothing asserted on the actual JSON keys. Fixed in 1.2.73.

Request objects are hand-rolled, matching the pattern in
test_setup_wizard.py: `requires_admin` is a no-op marker (real auth is
AdminAuthMiddleware, not exercised here), so only `request.app.state.config`
and `request.query_params` need to be real enough for the handler to run.

Imports go through `authmcp_gateway.admin.routes` (as `app.py` does —
`from .admin import routes as admin_routes`), not straight into
`mcp_activity_api`: `routes.py` resolves a circular import by star-importing
its submodules at its own bottom, after defining the helpers (api_error_handler,
get_config, requires_admin) those submodules import from it at module load
time. Importing a submodule first, before anything has imported `routes`,
hits that circular import mid-resolution and `routes` ends up missing
attributes — reproduced while writing this file.
"""

import json
from dataclasses import dataclass, field
from types import SimpleNamespace

import pytest

from authmcp_gateway.admin import routes as admin_routes
from authmcp_gateway.config import AuthConfig
from authmcp_gateway.mcp import store
from authmcp_gateway.security.logger import log_mcp_request


@dataclass
class _FakeAppConfig:
    auth: AuthConfig = field(default_factory=AuthConfig)


def _make_request(db_path, query_params=None):
    config = _FakeAppConfig()
    config.auth.sqlite_path = db_path
    app = SimpleNamespace(state=SimpleNamespace(config=config))
    return SimpleNamespace(app=app, query_params=query_params or {})


@pytest.fixture
def mcp_db(initialized_db):
    store.init_mcp_database(initialized_db)
    return initialized_db


@pytest.fixture
def seeded_db(mcp_db):
    """One server, two logged requests, both within the stats window."""
    server_id = store.create_mcp_server(mcp_db, "GitHub Tools", "http://192.0.2.10/mcp")
    log_mcp_request(
        mcp_db,
        user_id=1,
        mcp_server_id=server_id,
        method="tools/call",
        tool_name="gh_search_issues",
        success=True,
        response_time_ms=120,
    )
    log_mcp_request(
        mcp_db,
        user_id=1,
        mcp_server_id=server_id,
        method="tools/call",
        tool_name="gh_search_issues",
        success=False,
        response_time_ms=300,
    )
    return mcp_db, server_id


@pytest.mark.asyncio
async def test_api_mcp_stats_includes_both_field_name_variants(seeded_db):
    """The MCP Activity page reads total_requests/avg_response_time; the
    Dashboard reads requests_24h/avg_response_time. Both must be present
    and consistent, or one of the two pages silently shows zeros."""
    db_path, _ = seeded_db
    request = _make_request(db_path, {"last_hours": "24"})

    response = await admin_routes.api_mcp_stats(request)
    payload = json.loads(response.body)

    assert payload["total_requests"] == 2
    assert payload["requests_24h"] == 2
    assert payload["total_requests"] == payload["requests_24h"]

    assert payload["avg_response_time"] == payload["avg_response_time_ms"]
    assert payload["avg_response_time"] == pytest.approx(210, abs=0.01)

    assert payload["success_rate"] == 50.0


@pytest.mark.asyncio
async def test_api_mcp_stats_by_server_breakdown(seeded_db):
    """By Server (1h) panel has no data unless this key is populated."""
    db_path, _ = seeded_db
    request = _make_request(db_path, {"last_hours": "24"})

    response = await admin_routes.api_mcp_stats(request)
    payload = json.loads(response.body)

    assert payload["by_server"] == {"GitHub Tools": 2}


@pytest.mark.asyncio
async def test_api_mcp_stats_top_tools_only_when_requested(seeded_db):
    """Dashboard's loadMCPStats() call omits include_top_tools and must not
    pay for the extra query; mcp_activity.html's loadStats() passes it and
    must get real data back, not an empty/missing key."""
    db_path, _ = seeded_db

    without_flag = await admin_routes.api_mcp_stats(_make_request(db_path, {"last_hours": "24"}))
    assert "top_tools" not in json.loads(without_flag.body)

    with_flag = await admin_routes.api_mcp_stats(
        _make_request(db_path, {"last_hours": "24", "include_top_tools": "true"})
    )
    payload = json.loads(with_flag.body)
    assert payload["top_tools"] == [
        {"name": "gh_search_issues", "count": 2, "server": "GitHub Tools"}
    ]


@pytest.mark.asyncio
async def test_api_mcp_stats_empty_db_returns_zeros_not_errors(mcp_db):
    """No requests logged yet — every numeric field should be a clean zero,
    not a KeyError/500 from a query assuming at least one row exists."""
    request = _make_request(mcp_db, {"last_hours": "24"})

    response = await admin_routes.api_mcp_stats(request)
    assert response.status_code == 200
    payload = json.loads(response.body)

    assert payload["total_requests"] == 0
    assert payload["requests_24h"] == 0
    assert payload["success_rate"] == 0
    assert payload["by_server"] == {}
