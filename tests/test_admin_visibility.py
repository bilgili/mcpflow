"""Visibility of the built-in admin server.

Scenarios from `specs/tool-visibility/spec.md` (Three-level visibility
hierarchy, Visibility resolution, A hidden tool is not callable, Visibility
survives a restart, The built-in visibility state has its own store, Two admin
tools are always published), `specs/mcp-gateway/spec.md` (Admin tools are
visible to admin sessions only), `specs/admin-api/spec.md` (Tool and
visibility resources), and `specs/web-ui/spec.md` (Tools dashboard).

The gateway tests drive the real app over Streamable HTTP with a bearer token,
because both filters read the request: the scope filter reads
`get_access_token()`, and only a real session carries a scope.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re

import pytest
from conftest import fake_child_spec
from fastmcp.exceptions import ToolError

from mcpflow.auth import TokenStore
from mcpflow.registry import PINNED_ADMIN_TOOLS, Registry, ServerSpec

PINNED_NAMES = {f"mcpflow_{t}" for t in PINNED_ADMIN_TOOLS}
ADMIN_TOOL_COUNT = 14


# --- seeds and clients -------------------------------------------------------


def _seed(holder: dict, *specs: ServerSpec, admin_setup=None):
    def seed(data_dir):
        reg = Registry(data_dir / "servers.json")
        reg.load()
        for spec in specs:
            reg.add(spec)
        if admin_setup is not None:
            admin_setup(reg)
        store = TokenStore(data_dir / "tokens.json")
        store.load()
        _a, admin_token = store.create("admin", "admin")
        _m, mcp_token = store.create("mcp", "mcp")
        holder["admin"] = admin_token
        holder["mcp"] = mcp_token

    return seed


def _client(base: str, token: str):
    from fastmcp import Client
    from fastmcp.client.transports import StreamableHttpTransport

    return Client(
        StreamableHttpTransport(
            base + "/mcp", headers={"Authorization": f"Bearer {token}"}
        )
    )


def list_tools(base: str, token: str) -> list[str]:
    async def run():
        async with _client(base, token) as c:
            return [t.name for t in await c.list_tools()]

    return asyncio.run(run())


def call_tool(base: str, token: str, name: str, args: dict):
    async def run():
        async with _client(base, token) as c:
            return (await c.call_tool(name, args)).data

    return asyncio.run(run())


def mcpflow_tools(names: list[str]) -> set[str]:
    return {n for n in names if n.startswith("mcpflow_")}


def api_tools(server, token: str) -> dict:
    resp = server.get("/api/tools", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200, resp.text
    return resp.json()


def put(server, token: str, path: str, body: dict):
    import httpx

    return httpx.put(
        server.base_url + path,
        json=body,
        headers={"Authorization": f"Bearer {token}"},
    )


@contextlib.contextmanager
def admin(server):
    """A logged-in admin client. `login()` already opened it, so it cannot be
    re-entered as a context manager itself."""
    client = server.login()
    try:
        yield client
    finally:
        client.close()


def mute_tool(client, tool: str) -> None:
    resp = client.post("/visibility/namespaces/mcpflow/tool", data={"tool": tool})
    assert resp.status_code == 200, resp.text


def mute_namespace(client) -> None:
    resp = client.post("/visibility/namespaces/mcpflow", data={})
    assert resp.status_code == 200, resp.text


# --- 6.1 The registry store --------------------------------------------------


@pytest.fixture
def registry(tmp_path):
    reg = Registry(tmp_path / "servers.json")
    reg.load()
    reg.add(fake_child_spec("time", "two"))
    return reg


def reread(reg) -> Registry:
    fresh = Registry(reg._path)
    fresh.load()
    return fresh


def test_a_file_without_the_admin_object_loads_as_nothing_muted(tmp_path):
    path = tmp_path / "servers.json"
    path.write_text(json.dumps({"version": 1, "muted": False, "servers": []}))
    reg = Registry(path)
    reg.load()
    assert reg.admin_muted() is False
    assert reg.admin_visibility() == (False, set())


def test_an_admin_mute_writes_the_admin_object(registry):
    registry.set_admin_tool_muted("write_source", True)
    data = json.loads(registry._path.read_text())
    assert data["admin"] == {"muted": False, "disabled_tools": ["write_source"]}
    assert all(s["namespace"] != "mcpflow" for s in data["servers"])


def test_a_child_mutation_preserves_the_admin_object(registry):
    registry.set_admin_tool_muted("write_source", True)
    registry.set_enabled("time", False)
    registry.set_root_muted(True)
    data = json.loads(registry._path.read_text())
    assert data["admin"]["disabled_tools"] == ["write_source"]
    assert reread(registry).admin_visibility() == (False, {"write_source"})


def test_a_failed_write_leaves_the_admin_state_unchanged(registry, monkeypatch):
    def boom(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(registry, "_write", boom)
    with pytest.raises(OSError):
        registry.set_admin_tool_muted("write_source", True)
    assert registry.admin_visibility() == (False, set())
    assert reread(registry).admin_visibility() == (False, set())


def test_the_root_flag_does_not_reach_the_admin_resolution(registry):
    registry.set_root_muted(True)
    assert registry.admin_visibility() == (False, set())


def test_a_muted_admin_namespace_hides_all(registry):
    registry.set_admin_tool_muted("write_source", True)
    registry.set_admin_muted(True)
    assert registry.admin_visibility() == (True, set())
    # The stored name outlives the namespace mute.
    registry.set_admin_muted(False)
    assert registry.admin_visibility() == (False, {"write_source"})


# --- 6.2 One muted admin tool ------------------------------------------------


def test_a_muted_admin_tool_disappears_and_the_others_stay(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder))
    with admin(server) as client:
        mute_tool(client, "write_source")

    names = mcpflow_tools(list_tools(server.base_url, holder["admin"]))
    assert "mcpflow_write_source" not in names
    assert "mcpflow_list_servers" in names


def test_a_muted_admin_tool_is_not_callable(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder))
    with admin(server) as client:
        mute_tool(client, "list_servers")

    with pytest.raises(ToolError):
        call_tool(server.base_url, holder["admin"], "mcpflow_list_servers", {})


# --- 6.3 The pinned tools ----------------------------------------------------


def test_a_muted_mcpflow_namespace_publishes_exactly_the_pinned_tools(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder))
    with admin(server) as client:
        mute_namespace(client)

    assert mcpflow_tools(list_tools(server.base_url, holder["admin"])) == PINNED_NAMES


def test_an_admin_session_unmutes_the_mcpflow_namespace_over_mcp(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder))
    before = mcpflow_tools(list_tools(server.base_url, holder["admin"]))
    with admin(server) as client:
        mute_namespace(client)

    call_tool(
        server.base_url,
        holder["admin"],
        "mcpflow_set_namespace_muted",
        {"namespace": "mcpflow", "muted": False},
    )
    assert mcpflow_tools(list_tools(server.base_url, holder["admin"])) == before


def test_a_pinned_tool_cannot_be_muted_away(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder))
    with admin(server) as client:
        mute_tool(client, "set_tool_muted")

    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    assert "set_tool_muted" in reg.admin_visibility()[1]
    assert "mcpflow_set_tool_muted" in list_tools(server.base_url, holder["admin"])


# --- 6.4 The root level and the scope filter ---------------------------------


def test_a_muted_root_hides_every_child_tool_and_no_admin_tool(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder, fake_child_spec("time", "two")))
    server.wait(running=1)
    with admin(server) as client:
        resp = client.post("/visibility/root", data={})
        assert resp.status_code == 200

    names = list_tools(server.base_url, holder["admin"])
    assert not any(n.startswith("time_") for n in names)
    assert len(mcpflow_tools(names)) == ADMIN_TOOL_COUNT


def test_an_mcp_session_never_sees_an_admin_tool(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder))
    assert mcpflow_tools(list_tools(server.base_url, holder["mcp"])) == set()
    # Not even when the pin re-enables the two tools under a muted namespace.
    with admin(server) as client:
        mute_namespace(client)
    assert mcpflow_tools(list_tools(server.base_url, holder["mcp"])) == set()


def test_an_mcp_session_cannot_call_a_pinned_tool(server_factory):
    """The call path, not the list path.

    `Visibility.get_tool` marks whatever `call_next` returns, so the pin runs
    on a lookup too. Only the scope filter, which is innermost and returns
    `None`, stops an `mcp` session here. A pin installed inside the scope
    filter would answer this call.
    """
    holder: dict = {}
    server = server_factory(_seed(holder))
    with admin(server) as client:
        mute_namespace(client)

    for name, args in (
        ("mcpflow_set_namespace_muted", {"namespace": "mcpflow", "muted": False}),
        ("mcpflow_set_tool_muted", {"namespace": "mcpflow", "tool": "write_source",
                                 "muted": False}),
    ):
        with pytest.raises(ToolError):
            call_tool(server.base_url, holder["mcp"], name, args)

    # The refused calls changed no policy: the namespace is still muted.
    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    assert reg.admin_muted() is True
    assert mcpflow_tools(list_tools(server.base_url, holder["admin"])) == PINNED_NAMES


# --- 6.5 Restart -------------------------------------------------------------


def test_a_started_gateway_honours_a_persisted_admin_tool_mute(server_factory):
    holder: dict = {}
    server = server_factory(
        _seed(
            holder,
            admin_setup=lambda reg: reg.set_admin_tool_muted("write_source", True),
        )
    )
    names = mcpflow_tools(list_tools(server.base_url, holder["admin"]))
    assert "mcpflow_write_source" not in names
    assert "mcpflow_list_servers" in names


def test_a_started_gateway_honours_a_persisted_mcpflow_namespace_mute(server_factory):
    holder: dict = {}
    server = server_factory(
        _seed(holder, admin_setup=lambda reg: reg.set_admin_muted(True))
    )
    assert mcpflow_tools(list_tools(server.base_url, holder["admin"])) == PINNED_NAMES


# --- 6.6 The built-in server is not a child ----------------------------------


def test_the_built_in_server_is_not_a_child(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder))
    listed = call_tool(server.base_url, holder["admin"], "mcpflow_list_servers", {})
    assert all(entry["namespace"] != "mcpflow" for entry in listed)

    # A muted namespace changes none of that: the mount is not a child, so no
    # child view can ever hold it. `mcpflow_list_servers` is itself hidden under
    # the mute, so the same read runs before it.
    with admin(server) as client:
        mute_namespace(client)

    assert all(c.spec.namespace != "mcpflow" for c in server.supervisor.children())
    resp = server.get(
        "/api/servers", headers={"Authorization": f"Bearer {holder['admin']}"}
    )
    assert all(entry["namespace"] != "mcpflow" for entry in resp.json())


def test_no_lifecycle_operation_accepts_the_mcpflow_namespace(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder))
    for tool, args in (
        ("mcpflow_remove_server", {"namespace": "mcpflow"}),
        ("mcpflow_disable_server", {"namespace": "mcpflow"}),
        ("mcpflow_restart_server", {"namespace": "mcpflow"}),
        ("mcpflow_get_server", {"namespace": "mcpflow"}),
    ):
        with pytest.raises(ToolError):
            call_tool(server.base_url, holder["admin"], tool, args)


# --- 6.7 The REST contract ---------------------------------------------------


def test_the_tools_body_holds_the_admin_rows_and_the_flags(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder))
    body = api_tools(server, holder["admin"])
    assert body["root_muted"] is False
    assert body["mcpflow_muted"] is False
    rows = [t for t in body["tools"] if t["namespace"] == "mcpflow"]
    assert len(rows) == ADMIN_TOOL_COUNT
    # The admin rows come first.
    assert body["tools"][: len(rows)] == rows
    by_name = {t["name"]: t for t in rows}
    assert by_name["mcpflow_set_tool_muted"]["pinned"] is True
    assert by_name["mcpflow_write_source"]["pinned"] is False
    assert by_name["mcpflow_write_source"]["tool"] == "write_source"


def test_the_visibility_routes_accept_the_mcpflow_namespace(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder))
    token = holder["admin"]

    resp = put(
        server,
        token,
        "/api/visibility/namespaces/mcpflow/tools",
        {"tool": "write_source", "muted": True},
    )
    assert resp.status_code == 200, resp.text
    rows = {t["name"]: t for t in resp.json()["tools"]}
    assert rows["mcpflow_write_source"]["visible"] is False

    resp = put(server, token, "/api/visibility/namespaces/mcpflow", {"muted": True})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["mcpflow_muted"] is True
    rows = {t["name"]: t for t in body["tools"] if t["namespace"] == "mcpflow"}
    assert {n for n, t in rows.items() if t["visible"]} == PINNED_NAMES


def test_a_muted_root_leaves_the_admin_rows_alone(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder, fake_child_spec("time", "two")))
    server.wait(running=1)
    resp = put(server, holder["admin"], "/api/visibility/root", {"muted": True})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    child = [t for t in body["tools"] if t["namespace"] != "mcpflow"]
    assert child and all(t["visible"] is False for t in child)
    assert all(t["visible"] for t in body["tools"] if t["namespace"] == "mcpflow")


# --- 6.8 The dashboard -------------------------------------------------------


def _groups(body: str) -> list[str]:
    return re.findall(r"<details[^>]*class=\"ns-group\"[^>]*>", body)


def _row(body: str, name: str) -> str:
    match = re.search(
        r"<tr[^>]*>(?:(?!</tr>).)*" + name + r".*?</tr>", body, re.DOTALL
    )
    assert match is not None, f"no row for {name}"
    return match.group(0)


def test_the_dashboard_renders_the_mcpflow_group_first(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder, fake_child_spec("time", "two")))
    server.wait(running=1)
    with admin(server) as client:
        body = client.get("/").text

    headers = re.findall(r"<summary>(.*?)</summary>", body, re.DOTALL)
    assert len(headers) == 2
    assert '<span class="ns">mcpflow</span>' in headers[0]
    assert "built-in" in headers[0]
    assert f"{ADMIN_TOOL_COUNT} of {ADMIN_TOOL_COUNT} tools" in headers[0]
    assert "time" in headers[1]
    assert len(_groups(body)) == 2


def test_the_dashboard_renders_a_pinned_row_as_disabled(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder))
    with admin(server) as client:
        body = client.get("/").text

    row = _row(body, "mcpflow_set_tool_muted")
    assert "checked disabled" in row
    assert 'name="tool" value="set_tool_muted"' not in row
    assert "pinned" in row


def test_a_muted_root_leaves_the_mcpflow_controls_operable(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder, fake_child_spec("time", "two")))
    server.wait(running=1)
    with admin(server) as client:
        body = client.post("/visibility/root", data={}).text

    home = body.split('<span class="ns">mcpflow</span>')[1].split("</details>")[0]
    assert "disabled" not in _row(home, "mcpflow_write_source")
    # The child rows are disabled by the same render.
    child = body.split('<span class="ns">time</span>')[1]
    assert "disabled" in child


def test_the_mcpflow_tool_control_posts_to_the_mcpflow_route(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder))
    with admin(server) as client:
        body = client.get("/").text
        mute_tool(client, "write_source")
        after = client.get("/").text

    assert 'hx-post="/visibility/namespaces/mcpflow/tool"' in body
    assert "hidden-tool" in _row(after, "mcpflow_write_source")
