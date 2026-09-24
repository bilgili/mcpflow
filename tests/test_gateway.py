"""End-to-end gateway over Streamable HTTP at `/mcp`.

Scenarios from `specs/mcp-gateway/spec.md` (Streamable HTTP endpoint,
Namespaced tool names, Only running enabled children are visible) and
`specs/auth/spec.md` (Bearer tokens for /mcp, Failure isolation).
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
from conftest import fake_child_spec
from mcp.shared.exceptions import MCPError

from mcpflow.auth import TokenStore
from mcpflow.registry import Registry, ServerSpec


def _seed(*specs: ServerSpec, holder: dict):
    def seed(data_dir):
        reg = Registry(data_dir / "servers.json")
        reg.load()
        for spec in specs:
            reg.add(spec)
        store = TokenStore(data_dir / "tokens.json")
        store.load()
        record, clear = store.create("test")
        holder["clear"] = clear
        holder["id"] = record.id

    return seed


async def _connect(base: str, token: str):
    from fastmcp import Client
    from fastmcp.client.transports import StreamableHttpTransport

    transport = StreamableHttpTransport(
        base + "/mcp", headers={"Authorization": f"Bearer {token}"}
    )
    return Client(transport)


def mcp_session(base: str, token: str) -> tuple[str, list[str]]:
    async def run():
        client = await _connect(base, token)
        async with client as c:
            tools = await c.list_tools()
            return c.server_info.name, [t.name for t in tools]

    return asyncio.run(run())


def mcp_call(base: str, token: str, name: str, args: dict):
    async def run():
        client = await _connect(base, token)
        async with client as c:
            result = await c.call_tool(name, args)
            return result.data

    return asyncio.run(run())


# --- Namespaced tool names (12.11) -------------------------------------------


def test_client_initialises_a_session(server_factory):
    holder: dict = {}
    server = server_factory(_seed(fake_child_spec("time", "good"), holder=holder))
    server.wait(running=1)
    name, _tools = mcp_session(server.base_url, holder["clear"])
    assert name == "mcpflow"


def test_tool_list_shows_namespaced_names(server_factory):
    holder: dict = {}
    server = server_factory(_seed(fake_child_spec("time", "good"), holder=holder))
    server.wait(running=1)
    _name, tools = mcp_session(server.base_url, holder["clear"])
    assert "time_get_current_time" in tools


def test_tool_call_routes_to_the_child(server_factory):
    holder: dict = {}
    server = server_factory(_seed(fake_child_spec("time", "good"), holder=holder))
    server.wait(running=1)
    result = mcp_call(
        server.base_url, holder["clear"], "time_get_current_time", {"timezone": "UTC"}
    )
    assert result == "2026-01-01T00:00:00Z"


def test_disabled_child_disappears(server_factory):
    holder: dict = {}
    server = server_factory(_seed(fake_child_spec("time", "good"), holder=holder))
    server.wait(running=1)
    client = server.login()
    resp = client.post("/servers/time/disable")
    assert resp.status_code in (200, 303)
    client.close()
    _name, tools = mcp_session(server.base_url, holder["clear"])
    assert not any(t.startswith("time_") for t in tools)


def test_failed_child_is_not_visible(server_factory):
    holder: dict = {}
    server = server_factory(
        _seed(
            fake_child_spec("time", "good"),
            fake_child_spec("broken", "fail"),
            holder=holder,
        )
    )
    server.wait(running=1)
    _name, tools = mcp_session(server.base_url, holder["clear"])
    assert any(t.startswith("time_") for t in tools)
    assert not any(t.startswith("broken_") for t in tools)


# --- Bearer tokens for /mcp and failure isolation (12.12) --------------------


def test_valid_token(server_factory):
    holder: dict = {}
    server = server_factory(_seed(fake_child_spec("time", "good"), holder=holder))
    server.wait(running=1)
    _name, tools = mcp_session(server.base_url, holder["clear"])
    assert tools  # the request was served


def test_missing_token(server_factory):
    holder: dict = {}
    server = server_factory(_seed(fake_child_spec("time", "good"), holder=holder))
    resp = httpx.post(server.base_url + "/mcp", json={})
    assert resp.status_code == 401
    assert resp.headers.get("www-authenticate") == "Bearer"


def test_revoked_token(server_factory):
    holder: dict = {}
    server = server_factory(_seed(fake_child_spec("time", "good"), holder=holder))
    server.wait(running=1)
    # The token works first.
    _name, tools = mcp_session(server.base_url, holder["clear"])
    assert tools
    # The admin revokes it through the UI, on the app's own token store.
    client = server.login()
    resp = client.post(f"/tokens/{holder['id']}/delete")
    assert resp.status_code == 303
    client.close()
    # The revoked token no longer authorises the MCP request.
    with pytest.raises(MCPError):
        mcp_session(server.base_url, holder["clear"])


def test_all_children_fail_at_startup(server_factory):
    holder: dict = {}
    server = server_factory(
        _seed(
            fake_child_spec("a", "fail"),
            fake_child_spec("b", "fail"),
            holder=holder,
        )
    )
    server.wait(failed=2)
    # /health returns 200 with a JSON body.
    health = httpx.get(server.base_url + "/health")
    assert health.status_code == 200
    # /mcp serves an empty tool list.
    _name, tools = mcp_session(server.base_url, holder["clear"])
    assert tools == []


# --- Child catalog freshness (child-catalog-freshness) -----------------------


def _grow(server_factory, tmp_path, cache_ttl: float):
    """Start child `grow` and return (server, token, grow file)."""
    from test_visibility import _seed as _seed_logged

    grow = tmp_path / "grow"
    holder: dict = {}
    spec = fake_child_spec(
        "grow", "grow", cache_ttl=cache_ttl, env={"MCPFLOW_GROW": str(grow)}
    )
    server = server_factory(_seed_logged(spec, holder=holder))
    server.wait(running=1)
    return server, holder["clear"], grow


def _get_prompt(base: str, token: str, name: str) -> str:
    async def run():
        client = await _connect(base, token)
        async with client as c:
            return (await c.get_prompt(name)).messages[0].content.text

    return asyncio.run(run())


def test_new_tool_callable_under_ttl_zero(server_factory, tmp_path):
    server, token, grow = _grow(server_factory, tmp_path, 0)
    mcp_call(server.base_url, token, "grow_get_current_time", {})
    grow.touch()
    assert mcp_call(server.base_url, token, "grow_extra", {}) == "extra"


def test_new_prompt_resolvable_under_ttl_zero(server_factory, tmp_path):
    server, token, grow = _grow(server_factory, tmp_path, 0)
    assert _get_prompt(server.base_url, token, "grow_get_current_time") == "time"
    grow.touch()
    assert _get_prompt(server.base_url, token, "grow_extra") == "extra"


def test_new_tool_not_callable_under_long_ttl(server_factory, tmp_path):
    from test_visibility import call_log

    server, token, grow = _grow(server_factory, tmp_path, 300)
    mcp_call(server.base_url, token, "grow_get_current_time", {})
    grow.touch()
    with pytest.raises(Exception, match="grow_extra"):
        mcp_call(server.base_url, token, "grow_extra", {})
    assert "extra" not in call_log(server)


def test_list_is_fresh_under_long_ttl(server_factory, tmp_path):
    server, token, grow = _grow(server_factory, tmp_path, 300)
    _name, tools = mcp_session(server.base_url, token)
    assert "grow_extra" not in tools
    grow.touch()
    _name, tools = mcp_session(server.base_url, token)
    assert "grow_extra" in tools


def test_dashboard_probe_ignores_the_cache(server_factory, tmp_path):
    server, token, grow = _grow(server_factory, tmp_path, 300)
    mcp_call(server.base_url, token, "grow_get_current_time", {})
    client = server.login()
    try:
        assert "grow_extra" not in client.get("/").text
        grow.touch()
        assert "grow_extra" in client.get("/").text
    finally:
        client.close()
