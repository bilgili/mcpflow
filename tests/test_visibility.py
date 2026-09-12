"""The three-level tool visibility hierarchy.

Scenarios from `specs/tool-visibility/spec.md`, plus the modified requirements
in `specs/mcp-gateway/spec.md` and `specs/server-registry/spec.md`.

The tests drive the gateway through its own HTTP surface: the admin posts a
visibility control, and a real MCP client over `/mcp` reads the result. That
is the pair the spec talks about, so nothing here asserts on internals except
where a requirement names one (the mount table, the persisted file).
"""

from __future__ import annotations

import asyncio
import contextlib
import json

import pytest
from conftest import fake_child_spec
from fastmcp.exceptions import ToolError

from mcpflow.auth import TokenStore
from mcpflow.registry import Registry, ServerSpec


def _seed(*specs: ServerSpec, holder: dict):
    def seed(data_dir):
        reg = Registry(data_dir / "servers.json")
        reg.load()
        for spec in specs:
            # The child appends one line per tool call, so a test can prove a
            # refused call never reached it.
            reg.add(
                spec.model_copy(
                    update={
                        "env": {
                            **spec.env,
                            "MCPFLOW_CALL_LOG": str(data_dir / "calls.log"),
                            "MCPFLOW_RELEASE": str(data_dir / "release"),
                        }
                    }
                )
            )
        store = TokenStore(data_dir / "tokens.json")
        store.load()
        _record, clear = store.create("test")
        holder["clear"] = clear

    return seed


def tool_names(base: str, token: str) -> list[str]:
    async def run():
        from fastmcp import Client
        from fastmcp.client.transports import StreamableHttpTransport

        transport = StreamableHttpTransport(
            base + "/mcp", headers={"Authorization": f"Bearer {token}"}
        )
        async with Client(transport) as c:
            return [t.name for t in await c.list_tools()]

    return asyncio.run(run())


def call(base: str, token: str, name: str, args: dict):
    async def run():
        from fastmcp import Client
        from fastmcp.client.transports import StreamableHttpTransport

        transport = StreamableHttpTransport(
            base + "/mcp", headers={"Authorization": f"Bearer {token}"}
        )
        async with Client(transport) as c:
            return (await c.call_tool(name, args)).data

    return asyncio.run(run())


@contextlib.contextmanager
def admin(server):
    """A logged-in admin client. `login()` already opened it, so it cannot be
    re-entered as a context manager itself."""
    client = server.login()
    try:
        yield client
    finally:
        client.close()


ROOT = "/visibility/root"


def ns_path(ns: str) -> str:
    return f"/visibility/namespaces/{ns}"


def tool_path(ns: str) -> str:
    return f"/visibility/namespaces/{ns}/tool"


def mute(client, path: str, **body) -> None:
    """Post a visibility control with the box cleared."""
    resp = client.post(path, data=body)
    assert resp.status_code == 200, resp.text


def unmute(client, path: str, **body) -> None:
    """Post a visibility control with the box checked."""
    resp = client.post(path, data={**body, "visible": "on"})
    assert resp.status_code == 200, resp.text


def call_log(server) -> list[str]:
    """Every tool call the child actually served, in order."""
    path = server.data_dir / "calls.log"
    if not path.exists():
        return []
    return path.read_text().split()


# --- Visibility resolution ---------------------------------------------------


def test_muted_tool_disappears_and_sibling_stays(server_factory):
    holder: dict = {}
    server = server_factory(_seed(fake_child_spec("time", "two"), holder=holder))
    server.wait(running=1)
    assert "time_get_current_time" in tool_names(server.base_url, holder["clear"])

    with admin(server) as client:
        mute(client, tool_path("time"), tool="get_current_time")

    tools = tool_names(server.base_url, holder["clear"])
    assert "time_get_current_time" not in tools
    assert "time_convert_time" in tools


def test_muted_namespace_hides_every_tool_of_that_child(server_factory):
    holder: dict = {}
    server = server_factory(
        _seed(
            fake_child_spec("time", "two"),
            fake_child_spec("other", "good"),
            holder=holder,
        )
    )
    server.wait(running=2)

    with admin(server) as client:
        mute(client, ns_path("time"))

    tools = tool_names(server.base_url, holder["clear"])
    assert not any(t.startswith("time_") for t in tools)
    assert "other_get_current_time" in tools


def test_muted_root_gives_an_empty_tool_list(server_factory):
    holder: dict = {}
    server = server_factory(
        _seed(
            fake_child_spec("time", "two"),
            fake_child_spec("other", "good"),
            holder=holder,
        )
    )
    server.wait(running=2)
    assert tool_names(server.base_url, holder["clear"])

    with admin(server) as client:
        mute(client, ROOT)

    assert tool_names(server.base_url, holder["clear"]) == []


def test_namespace_mute_wins_over_an_unmuted_tool(server_factory):
    holder: dict = {}
    server = server_factory(_seed(fake_child_spec("time", "two"), holder=holder))
    server.wait(running=1)

    with admin(server) as client:
        mute(client, ns_path("time"))
        # Every tool of the child is individually unmuted.
        unmute(client, tool_path("time"), tool="get_current_time")
        unmute(client, tool_path("time"), tool="convert_time")

    assert not any(
        t.startswith("time_") for t in tool_names(server.base_url, holder["clear"])
    )


def test_unmuting_restores_the_tool(server_factory):
    holder: dict = {}
    server = server_factory(_seed(fake_child_spec("time", "two"), holder=holder))
    server.wait(running=1)

    with admin(server) as client:
        mute(client, tool_path("time"), tool="get_current_time")
        assert "time_get_current_time" not in tool_names(
            server.base_url, holder["clear"]
        )
        unmute(client, tool_path("time"), tool="get_current_time")

    assert "time_get_current_time" in tool_names(server.base_url, holder["clear"])


# --- A hidden tool is not callable -------------------------------------------


def test_call_to_a_muted_tool_is_refused(server_factory):
    holder: dict = {}
    server = server_factory(_seed(fake_child_spec("time", "two"), holder=holder))
    server.wait(running=1)
    assert call(
        server.base_url, holder["clear"], "time_get_current_time", {"timezone": "UTC"}
    )

    with admin(server) as client:
        mute(client, tool_path("time"), tool="get_current_time")

    before = call_log(server)
    with pytest.raises(ToolError):
        call(
            server.base_url,
            holder["clear"],
            "time_get_current_time",
            {"timezone": "UTC"},
        )
    # The gateway refused it; the child never saw it.
    assert call_log(server) == before
    # The sibling still routes to the child.
    assert call(
        server.base_url, holder["clear"], "time_convert_time", {"timezone": "UTC"}
    )
    assert call_log(server) == [*before, "convert_time"]


def test_call_to_a_tool_of_a_muted_namespace_is_refused(server_factory):
    holder: dict = {}
    server = server_factory(_seed(fake_child_spec("time", "two"), holder=holder))
    server.wait(running=1)

    with admin(server) as client:
        mute(client, ns_path("time"))

    with pytest.raises(ToolError):
        call(
            server.base_url,
            holder["clear"],
            "time_convert_time",
            {"timezone": "UTC"},
        )


# --- Visibility does not change the child lifecycle --------------------------


def test_mute_keeps_the_child_running_and_enabled(server_factory):
    holder: dict = {}
    server = server_factory(_seed(fake_child_spec("time", "two"), holder=holder))
    server.wait(running=1)

    with admin(server) as client:
        mute(client, ns_path("time"))

    assert server.health()["running"] == 1
    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    assert reg.get("time").enabled is True
    assert reg.get("time").muted is True
    # The subprocess is still alive: unmuting publishes again with no restart.
    with admin(server) as client:
        unmute(client, ns_path("time"))
    assert "time_convert_time" in tool_names(server.base_url, holder["clear"])


def test_mount_table_keeps_the_same_provider_across_a_mute(server_factory):
    """The requirement names the mount table, so this test reads it.

    A visibility change mutates the live transform. It must not build a
    provider, and must not add to or remove from the table.
    """
    holder: dict = {}
    server = server_factory(_seed(fake_child_spec("time", "two"), holder=holder))
    server.wait(running=1)

    sup = server.supervisor
    before = list(sup.table.providers)
    assert len(before) == 1

    with admin(server) as client:
        mute(client, ns_path("time"))

    after = list(sup.table.providers)
    assert len(after) == 1
    assert after[0] is before[0]


# --- Persistence -------------------------------------------------------------


def test_registry_file_matches_after_each_operation(server_factory):
    holder: dict = {}
    server = server_factory(_seed(fake_child_spec("time", "two"), holder=holder))
    server.wait(running=1)

    with admin(server) as client:
        mute(client, tool_path("time"), tool="get_current_time")
        reg = Registry(server.data_dir / "servers.json")
        reg.load()
        assert reg.get("time").disabled_tools == ["get_current_time"]
        assert reg.root_muted() is False

        mute(client, ROOT)
        reg = Registry(server.data_dir / "servers.json")
        reg.load()
        assert reg.root_muted() is True


def test_a_started_gateway_honours_the_persisted_tool_mute(server_factory):
    """The restart path: the state is on disk before the process starts."""
    holder: dict = {}
    server = server_factory(
        _seed(
            fake_child_spec("time", "two", disabled_tools=["get_current_time"]),
            holder=holder,
        )
    )
    server.wait(running=1)

    tools = tool_names(server.base_url, holder["clear"])
    assert "time_get_current_time" not in tools
    assert "time_convert_time" in tools


def test_a_started_gateway_honours_a_persisted_root_mute(server_factory):
    holder: dict = {}

    def seed(data_dir):
        _seed(fake_child_spec("time", "two"), holder=holder)(data_dir)
        reg = Registry(data_dir / "servers.json")
        reg.load()
        reg.set_root_muted(True)

    server = server_factory(seed)
    server.wait(running=1)
    assert tool_names(server.base_url, holder["clear"]) == []


def test_a_mute_during_starting_is_not_lost(server_factory):
    """Guards the `child.spec` read in `_build_provider`.

    The child is slow to serve, so the mutation lands while the status is
    still `starting` and the provider does not exist yet. The probe must
    commit a provider built from the spec as it stands then, not from the one
    `_run_start` captured on entry.
    """
    holder: dict = {}
    server = server_factory(_seed(fake_child_spec("time", "slow"), holder=holder))
    # The child blocks until the test releases it, so the window is not timed.
    assert server.health()["starting"] == 1
    with admin(server) as client:
        mute(client, tool_path("time"), tool="get_current_time")
        assert server.supervisor.get("time").status == "starting"

    (server.data_dir / "release").write_text("go")
    server.wait(running=1)
    tools = tool_names(server.base_url, holder["clear"])
    assert "time_get_current_time" not in tools
    assert "time_convert_time" in tools


def test_file_without_the_new_fields_loads_fully_visible(tmp_path):
    path = tmp_path / "servers.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "servers": [
                    {
                        "namespace": "time",
                        "kind": "custom",
                        "command": "true",
                        "enabled": True,
                    }
                ],
            }
        )
    )
    reg = Registry(path)
    reg.load()
    spec = reg.get("time")
    assert reg.root_muted() is False
    assert spec.muted is False
    assert spec.disabled_tools == []
    assert reg.visibility(spec) == (False, set())


def test_update_through_the_web_form_keeps_the_visibility_state(server_factory):
    holder: dict = {}
    server = server_factory(_seed(fake_child_spec("time", "two"), holder=holder))
    server.wait(running=1)

    with admin(server) as client:
        mute(client, tool_path("time"), tool="get_current_time")
        resp = client.post(
            "/servers/time",
            data={
                "namespace": "time",
                "kind": "custom",
                "command": "true",
                "args": "",
                "enabled": "on",
                "description": "edited",
            },
        )
        assert resp.status_code == 303, resp.text

    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    assert reg.get("time").description == "edited"
    assert reg.get("time").disabled_tools == ["get_current_time"]


def test_a_muted_name_the_child_no_longer_publishes_is_inert(server_factory):
    holder: dict = {}
    server = server_factory(
        _seed(
            fake_child_spec("time", "two", disabled_tools=["gone_tool"]),
            holder=holder,
        )
    )
    server.wait(running=1)

    tools = tool_names(server.base_url, holder["clear"])
    assert "time_get_current_time" in tools
    assert "time_convert_time" in tools

    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    assert reg.get("time").disabled_tools == ["gone_tool"]


# --- Routes ------------------------------------------------------------------


def test_visibility_route_on_an_unknown_namespace_is_404(server_factory):
    holder: dict = {}
    server = server_factory(_seed(fake_child_spec("time", "good"), holder=holder))
    server.wait(running=1)

    with admin(server) as client:
        assert client.post(ns_path("nope"), data={}).status_code == 404
        assert (
            client.post(tool_path("nope"), data={"tool": "x"}).status_code == 404
        )
        # A tool control with no tool name in the body is a bad request.
        assert client.post(tool_path("time"), data={}).status_code == 400


# --- Dashboard ---------------------------------------------------------------


def test_dashboard_renders_the_three_controls(server_factory):
    holder: dict = {}
    server = server_factory(_seed(fake_child_spec("time", "two"), holder=holder))
    server.wait(running=1)

    with admin(server) as client:
        body = client.get("/").text

    assert 'hx-post="/visibility/root"' in body
    assert 'hx-post="/visibility/namespaces/time"' in body
    assert 'hx-post="/visibility/namespaces/time/tool"' in body
    # The child names the tool, so the name rides in the body, not the path.
    assert '<input type="hidden" name="tool" value="get_current_time">' in body
    assert "2 of 2 tools" in body


def test_dashboard_keeps_the_row_of_a_muted_tool(server_factory):
    holder: dict = {}
    server = server_factory(_seed(fake_child_spec("time", "two"), holder=holder))
    server.wait(running=1)

    with admin(server) as client:
        mute(client, tool_path("time"), tool="get_current_time")
        body = client.get("/").text

    # The row survives, marked, so the admin can unmute it from the same page.
    assert "time_get_current_time" in body
    assert "hidden-tool" in body
    assert "1 of 2 tools" in body


def test_a_control_answer_renders_every_group_collapsed(server_factory):
    """The server renders no open state. The browser records the open groups
    before the swap and restores them after, so a group the admin collapsed
    during the round trip stays collapsed."""
    holder: dict = {}
    server = server_factory(
        _seed(
            fake_child_spec("time", "two"),
            fake_child_spec("other", "good"),
            holder=holder,
        )
    )
    server.wait(running=2)

    with admin(server) as client:
        # The page itself opens nothing.
        assert "open>" not in client.get("/").text
        body = client.post(
            tool_path("time"), data={"tool": "get_current_time"}
        ).text

    # Neither does the control answer.
    assert "open>" not in body


def test_a_form_edit_does_not_republish_a_muted_tool(server_factory):
    """The registry merges the visibility state on update. The supervisor must
    install that merged record, not the fresh spec the form built."""
    holder: dict = {}
    server = server_factory(_seed(fake_child_spec("time", "two"), holder=holder))
    server.wait(running=1)
    spec = server.supervisor.get("time").spec

    with admin(server) as client:
        mute(client, tool_path("time"), tool="get_current_time")
        resp = client.post(
            "/servers/time",
            data={
                "namespace": "time",
                "kind": "custom",
                "command": spec.command,
                "args": " ".join(spec.args),
                "enabled": "on",
                "description": "edited",
            },
        )
        assert resp.status_code == 303, resp.text

    server.wait(running=1)
    tools = tool_names(server.base_url, holder["clear"])
    assert "time_get_current_time" not in tools, "the edit republished a muted tool"
    assert "time_convert_time" in tools


def test_a_namespace_named_root_is_addressable(server_factory):
    """`root` matches the namespace pattern, so the two levels must not share
    a path shape. The gateway control must not answer for the namespace."""
    holder: dict = {}
    server = server_factory(
        _seed(
            fake_child_spec("root", "two"),
            fake_child_spec("other", "good"),
            holder=holder,
        )
    )
    server.wait(running=2)

    with admin(server) as client:
        mute(client, ns_path("root"))

    # The namespace is muted; the gateway as a whole is not.
    tools = tool_names(server.base_url, holder["clear"])
    assert not any(t.startswith("root_") for t in tools)
    assert "other_get_current_time" in tools

    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    assert reg.get("root").muted is True
    assert reg.root_muted() is False


def test_a_failed_child_still_offers_its_namespace_control(server_factory):
    """The control is not gated on the group having tools."""
    holder: dict = {}
    server = server_factory(
        _seed(
            fake_child_spec("broken", "fail"),
            fake_child_spec("other", "good"),
            holder=holder,
        )
    )
    server.wait(running=1, failed=1)

    with admin(server) as client:
        body = client.get("/").text

    assert 'hx-post="/visibility/namespaces/broken"' in body
    assert 'hx-post="/visibility/namespaces/other"' in body


def test_the_tool_control_keeps_the_name_verbatim(server_factory):
    """The route must not trim a child-owned name: matching is exact, so a
    trimmed name would persist something that hides nothing."""
    holder: dict = {}
    server = server_factory(_seed(fake_child_spec("time", "two"), holder=holder))
    server.wait(running=1)

    with admin(server) as client:
        mute(client, tool_path("time"), tool="  spaced  ")
        # An empty name is a bad request, not a silent no-op.
        assert client.post(tool_path("time"), data={"tool": ""}).status_code == 400

    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    assert reg.get("time").disabled_tools == ["  spaced  "]


def test_a_failed_write_leaves_the_published_set_unchanged(server_factory,
                                                           monkeypatch):
    """The third view. The registry tests cover the file and the memory; this
    one covers the live transform, which is what /mcp actually enforces."""
    holder: dict = {}
    server = server_factory(_seed(fake_child_spec("time", "two"), holder=holder))
    server.wait(running=1)
    before = tool_names(server.base_url, holder["clear"])
    assert "time_get_current_time" in before

    def boom(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(server.supervisor.registry, "_write", boom)

    with admin(server) as client:
        # The route surfaces the failure rather than reporting success.
        resp = client.post(
            tool_path("time"), data={"tool": "get_current_time"}
        )
        assert resp.status_code >= 500

    # File, memory and live transform all still agree on the old policy.
    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    assert reg.get("time").disabled_tools == []
    assert server.supervisor.registry.get("time").disabled_tools == []
    assert tool_names(server.base_url, holder["clear"]) == before
