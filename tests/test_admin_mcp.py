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
from conftest import FAKE_SERVER, fake_child_spec
from fastmcp import Client

from mcpflow.admin_mcp import ScopeFilter, build_admin_server
from mcpflow.auth import TokenStore
from mcpflow.registry import Registry, ServerSpec

# --- seeds and MCP client helpers --------------------------------------------


def _seed(holder: dict, *specs: ServerSpec):
    def seed(data_dir):
        reg = Registry(data_dir / "servers.json")
        reg.load()
        for spec in specs:
            reg.add(spec)
        store = TokenStore(data_dir / "tokens.json")
        store.load()
        _a, admin = store.create("admin", "admin")
        _m, mcp = store.create("mcp", "mcp")
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
    with pytest.raises(Exception):  # noqa: B017 - unknown tool, any client error
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
