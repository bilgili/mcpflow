"""The built-in admin MCP server and its scope filter.

Scenarios from `specs/mcp-gateway/spec.md` (Built-in admin server, Admin tools
are visible to admin sessions only, Admin tool errors,
Unique namespaces), `specs/auth/spec.md` (Bearer tokens
for /mcp), `specs/server-registry/spec.md` (Reserved namespaces), and
`specs/tool-visibility/spec.md` (Visibility resolution).

The scope-visibility and end-to-end tests drive the real `build_app` over
Streamable HTTP with a bearer token, because the filter reads
`get_access_token()`, which is only set inside an HTTP request. The tool-body
and error tests drive `build_admin_server` in process, where no filter hides
the tools.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from conftest import ADMIN_ACTOR, FAKE_SERVER, fake_child_spec
from fastmcp import Client

from mcpflow.admin_mcp import ScopeFilter, build_admin_server
from mcpflow.auth import TokenStore
from mcpflow.registry import Registry, ServerSpec

# --- seeds and MCP client helpers --------------------------------------------


def _seed(holder: dict, *specs: ServerSpec):
    def seed(data_dir):
        reg = Registry(data_dir / "servers.json", data_dir / "user_servers.json")
        reg.load()
        for spec in specs:
            reg.add(spec)
        store = TokenStore(data_dir / "tokens.json", data_dir / "user_tokens.json")
        store.load()
        _a, admin = store.create("admin", "admin", "admin")
        _m, mcp = store.create("mcp", "mcp", "admin")
        holder["admin"] = admin
        holder["mcp"] = mcp

    return seed


async def _connect(base: str, token: str):
    from fastmcp.client.transports import StreamableHttpTransport

    transport = StreamableHttpTransport(
        base + "/mcp", headers={"Authorization": f"Bearer {token}"}
    )
    return Client(transport)


def list_tools(base: str, token: str) -> list[str]:
    async def run():
        client = await _connect(base, token)
        async with client as c:
            return [t.name for t in await c.list_tools()]

    return asyncio.run(run())


def call_tool(base: str, token: str, name: str, args: dict):
    async def run():
        client = await _connect(base, token)
        async with client as c:
            result = await c.call_tool(name, args)
            return result.data

    return asyncio.run(run())


def _custom_spec_body(namespace: str, mode: str = "good") -> dict:
    import sys

    return {
        "namespace": namespace,
        "kind": "custom",
        "command": sys.executable,
        "args": [FAKE_SERVER, mode],
    }


# --- Bearer tokens for /mcp; admin session sees the tools (4.3) ---------------


def test_admin_session_lists_and_calls_admin_tools(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder, fake_child_spec("time", "good")))
    server.wait(running=1)
    tools = list_tools(server.base_url, holder["admin"])
    assert "mcpflow_list_servers" in tools
    data = call_tool(server.base_url, holder["admin"], "mcpflow_list_servers", {})
    assert [c["namespace"] for c in data] == ["time"]


# --- Admin tools are visible to admin sessions only (4.4) --------------------


def test_mcp_session_sees_no_admin_tool(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder, fake_child_spec("time", "good")))
    server.wait(running=1)
    tools = list_tools(server.base_url, holder["mcp"])
    assert not any(t.startswith("mcpflow_") for t in tools)
    assert "time_get_current_time" in tools


def test_mcp_session_cannot_call_admin_tool(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder, fake_child_spec("time", "good")))
    server.wait(running=1)
    with pytest.raises(Exception):
        call_tool(server.base_url, holder["mcp"], "mcpflow_list_servers", {})


def test_scope_filter_no_token_hides_everything():
    f = ScopeFilter()

    async def _next_tool(name, *, version=None):
        raise AssertionError("call_next must not run without admin")

    async def run():
        # No HTTP request context, so get_access_token() is None: not admin.
        assert list(await f.list_tools(["x"])) == []
        assert list(await f.list_resources(["x"])) == []
        assert list(await f.list_resource_templates(["x"])) == []
        assert list(await f.list_prompts(["x"])) == []
        assert await f.get_tool("t", _next_tool) is None
        assert await f.get_resource("u", _next_tool) is None
        assert await f.get_resource_template("u", _next_tool) is None
        assert await f.get_prompt("p", _next_tool) is None

    asyncio.run(run())


# --- Reserved namespace over MCP and the web form (4.5) ----------------------


def test_reserved_namespace_over_mcp(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder))
    with pytest.raises(Exception) as exc:
        call_tool(
            server.base_url,
            holder["admin"],
            "mcpflow_add_server",
            {"spec": {"namespace": "mcpflow", "kind": "custom", "command": "x"}},
        )
    assert "namespace mcpflow is reserved" in str(exc.value)
    assert not (server.data_dir / "servers.json").exists()


def test_reserved_prefix_over_mcp(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder))
    with pytest.raises(Exception) as exc:
        call_tool(
            server.base_url,
            holder["admin"],
            "mcpflow_add_server",
            {"spec": {"namespace": "mcpflow_list", "kind": "custom", "command": "x"}},
        )
    assert "namespace mcpflow_list is reserved" in str(exc.value)
    assert not (server.data_dir / "servers.json").exists()


def test_reserved_namespace_on_rest_api(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder))
    resp = server.post(
        "/api/servers",
        headers={"Authorization": f"Bearer {holder['admin']}"},
        json={"namespace": "mcpflow", "kind": "python", "package": "x"},
    )
    assert resp.status_code == 400
    body = resp.json()
    assert "namespace" in body["error"]
    assert "namespace mcpflow is reserved" in body["error"]


def test_reserved_namespace_on_web_form(server_factory):
    server = server_factory(_seed({}))
    client = server.login()
    resp = client.post(
        "/servers",
        data={"namespace": "mcpflow", "kind": "python", "package": "x"},
    )
    client.close()
    assert resp.status_code == 400
    assert "namespace mcpflow is reserved" in resp.text


# --- Built-in admin server end to end (4.6) ----------------------------------


def test_add_server_over_mcp_starts_child(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder))
    data = call_tool(
        server.base_url,
        holder["admin"],
        "mcpflow_add_server",
        {"spec": _custom_spec_body("time")},
    )
    assert data["namespace"] == "time"
    assert data["status"] == "starting"
    on_disk = json.loads((server.data_dir / "servers.json").read_text())
    assert [s["namespace"] for s in on_disk["servers"]] == ["time"]


def test_get_unknown_namespace_over_mcp(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder))
    with pytest.raises(Exception) as exc:
        call_tool(server.base_url, holder["admin"], "mcpflow_get_server", {"namespace": "nope"})
    assert "nope not found" in str(exc.value)


def test_internal_error_stays_masked():
    sup = MagicMock()
    sup.restart = AsyncMock(side_effect=RuntimeError("secret internal detail"))
    admin = build_admin_server(sup)

    async def run():
        async with Client(admin) as c:
            with pytest.raises(Exception) as exc:
                await c.call_tool("restart_server", {"namespace": "x"})
            assert "secret internal detail" not in str(exc.value)

    asyncio.run(run())


def test_no_admin_tool_sets_ui_visibility():
    admin = build_admin_server(MagicMock())

    async def run():
        for tool in await admin._list_tools():
            meta = getattr(tool, "meta", None) or {}
            ui = (meta.get("ui") if isinstance(meta, dict) else None) or {}
            assert "visibility" not in ui, tool.name

    asyncio.run(run())


# --- Root mute keeps the admin tools (4.8) -----------------------------------


def test_root_mute_hides_child_tools_but_not_admin_tools(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder, fake_child_spec("time", "good")))
    server.wait(running=1)

    muted = call_tool(
        server.base_url, holder["admin"], "mcpflow_set_root_muted", {"muted": True}
    )
    assert muted["root_muted"] is True
    tools = list_tools(server.base_url, holder["admin"])
    assert not any(t.startswith("time_") for t in tools)
    assert "mcpflow_set_root_muted" in tools

    call_tool(server.base_url, holder["admin"], "mcpflow_set_root_muted", {"muted": False})
    tools = list_tools(server.base_url, holder["admin"])
    assert any(t.startswith("time_") for t in tools)


# --- 10.13 Admin tools act on admin-owned servers only (multi-user-access) ----
#
# Fixture `router_live.py`: admin-owned `time` and `github`, user-owned
# `github@alice` (`x`, `alice_only`) and `github@bob`. Each docstring names the
# TLA+ invariant of `specs/tla/multi_user_access.tla` that the test guards.

import time

import httpx
from fastmcp.exceptions import ToolError
from router_live import start_live


@pytest.fixture(scope="module")
def live(tmp_path_factory):
    lv, stop = start_live(tmp_path_factory.mktemp("admin_mcp"))
    yield lv
    stop()


@pytest.fixture
def env(live):
    live.reset()
    yield live
    live.reset()


def _admin_call(env, name: str, args: dict | None = None) -> str:
    """Call an admin tool in an `admin` session; return the result as JSON text."""
    async def go():
        async with env.client("admin") as c:
            res = await c.call_tool(name, args or {})
            return json.dumps(res.structured_content, default=str)
    return asyncio.run(go())


def test_the_admin_tool_list_excludes_user_servers_ac4(env):
    """The admin tool list excludes user servers (AC-4).
    Invariant: AdminMcpExcludesPrivate."""
    body = _admin_call(env, "mcpflow_list_tools")
    assert "time_get_current_time" in body  # control
    assert "alice_only" not in body and "github@alice" not in body
    resp = httpx.get(env.base_url + "/api/tools",
                     headers={"Authorization": f"Bearer {env.tokens['admin']}"})
    assert resp.status_code == 200
    assert "alice_only" in resp.text


def test_a_mute_result_body_excludes_user_servers_ac4(env):
    """A mute result body excludes user servers (AC-4).
    Invariant: AdminMcpExcludesPrivate."""
    args = {"namespace": "time", "tool": "convert_time"}
    try:
        body = _admin_call(env, "mcpflow_set_tool_muted", {**args, "muted": True})
    finally:
        _admin_call(env, "mcpflow_set_tool_muted", {**args, "muted": False})
    assert "time_get_current_time" in body  # control
    assert "alice_only" not in body and "github@alice" not in body


def test_the_admin_mcp_tools_do_not_see_a_user_server_ac4(env):
    """The admin MCP tools do not see a user server (AC-4).
    Invariant: AdminMcpExcludesPrivate."""
    body = _admin_call(env, "mcpflow_list_servers")
    assert "time" in body  # control
    assert "alice" not in body and "bob" not in body


def test_a_reference_with_an_owner_is_not_found_over_mcp(env):
    """A reference with an owner is not found over MCP.
    Invariant: AdminMcpExcludesPrivate."""
    with pytest.raises(ToolError) as err:
        _admin_call(env, "mcpflow_restart_server", {"namespace": "github@alice"})
    assert str(err.value) == "github@alice not found"
    # A start probes the child with `tools/list`. `github@alice` has
    # `cache_ttl` 0 and no session asked it, so a `list` line means a restart.
    time.sleep(1.0)
    assert env.log("github@alice") == []
    assert env.health()["running"] == 4
    # Control: a real restart of the same child does log the probe.
    key = env.children["github@alice"].key
    env.run(env.supervisor.restart(key, ADMIN_ACTOR))
    deadline = time.time() + 30
    while (env.health()["running"] < 4 or "list" not in env.log("github@alice")) \
            and time.time() < deadline:
        time.sleep(0.2)
    assert "list" in env.log("github@alice")
    assert env.health()["running"] == 4


def test_one_provider_for_the_children(env):
    """One provider for the children. Invariant: NoMcpLeak (the router is the
    only reader of the child table)."""
    from mcpflow.router import CallerRouter

    providers = env.gateway.providers
    table = env.supervisor.table
    assert table not in providers
    assert all(getattr(p, "_inner", None) is not table for p in providers)
    added = [p for p in providers if type(p).__name__ != "LocalProvider"]
    assert len(added) == 2, providers
    assert sum(isinstance(p, CallerRouter) for p in added) == 1
    admin_provider = next(p for p in added if not isinstance(p, CallerRouter))

    async def names(p):
        from fastmcp.server.auth.auth import AccessToken
        from mcp.server.auth.middleware.auth_context import auth_context_var
        from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser

        reset = auth_context_var.set(AuthenticatedUser(AccessToken(
            token="", client_id="verifier", scopes=["admin"], subject="admin")))
        try:
            return {t.name for t in await p.list_tools()}
        finally:
            auth_context_var.reset(reset)

    local = [p for p in providers if type(p).__name__ == "LocalProvider"]
    assert all(env.run(names(p)) == set() for p in local)
    assert env.run(names(admin_provider)) >= {"mcpflow_list_servers"}


def test_a_ui_action_call_names_the_admin(env):
    """A UI action call names the admin. Invariant: AdminViewExcludesPrivate,
    NoMcpLeak (call)."""
    from mcpflow.actions import call_tool_as_admin

    root = env.user("root")
    env.identity.resolved.clear()
    result = env.run(call_tool_as_admin(env.gateway, "time_get_current_time", {}, root))
    assert result.structured_content == {"result": "time:get_current_time"}
    assert "root" in env.identity.resolved
    assert env.identity.resolved and set(env.identity.resolved) <= {"root"}
    # The router resolved the admin view: a user server is out of it.
    with pytest.raises(Exception, match="Unknown tool"):
        env.run(call_tool_as_admin(env.gateway, "github_alice_only", {}, root))
    assert env.calls("github@alice") == []
    with pytest.raises(PermissionError):
        env.run(call_tool_as_admin(env.gateway, "time_get_current_time", {},
                                   env.user("alice")))


# --- A malformed reference is not found (ServerKey shape, 1317096) -----------


@pytest.mark.parametrize("ref", ["github@alice", "Bad"])
def test_a_malformed_namespace_is_not_found_over_mcp(server_factory, ref):
    holder: dict = {}
    server = server_factory(_seed(holder, fake_child_spec("github", "good", enabled=False)))
    for tool in ("mcpflow_get_server", "mcpflow_restart_server"):
        with pytest.raises(Exception) as exc:
            call_tool(server.base_url, holder["admin"], tool, {"namespace": ref})
        assert f"{ref} not found" in str(exc.value)
