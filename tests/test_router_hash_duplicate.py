"""The hashed path decides ambiguity inside the caller's view (Codex finding 3).

A child that mounts one app twice publishes `left_save` and `right_save` with
one identity. FastMCP's `ProxyProvider.get_tool_by_hash` refuses that over the
raw inventory, so a hidden copy used to make the visible one unreachable by
hash. `CallerRouter.get_tool_by_hash` re-decides over the tools that pass the
caller's `Reach` and the chain mute. Invariants: NoMcpLeak (hash),
OneServerPerToolName.
"""

from __future__ import annotations

import httpx
import pytest
from fastmcp.exceptions import ToolError
from fastmcp.server.providers.addressing import hash_tool
from router_live import Child, start_live

DUP = (Child("dup", "crm", ("left_save", "right_save"), args=("--hash-as", "save")),)
SAVE = f"{hash_tool('crm', 'save')}_save"


@pytest.fixture(scope="module")
def live(tmp_path_factory):
    lv, stop = start_live(tmp_path_factory.mktemp("router_dup"), DUP)
    yield lv
    stop()


@pytest.fixture
def env(live):
    live.reset()
    yield live
    live.reset()


def test_a_denied_duplicate_does_not_make_the_allowed_copy_ambiguous(env):
    env.grant("user", "alice", "server", "allow", "dup")
    env.grant("user", "alice", "tool", "deny", "dup", "right_save")
    assert env.call("alice", SAVE) == "dup:left_save"
    assert env.calls("dup") == ["call:left_save"]


def test_a_muted_duplicate_does_not_make_the_allowed_copy_ambiguous(env):
    env.grant("user", "alice", "server", "allow", "dup")
    with httpx.Client(base_url=env.base_url) as web:
        assert web.post("/login", data={"password": "secret", "next": "/"}).status_code == 303
        path = "/visibility/namespaces/dup/tool"
        assert web.post(path, data={"tool": "right_save"}).status_code == 200
        try:
            assert env.call("alice", SAVE) == "dup:left_save"
        finally:
            web.post(path, data={"tool": "right_save", "visible": "on"})


def test_two_allowed_copies_stay_ambiguous(env):
    env.grant("user", "alice", "server", "allow", "dup")
    with pytest.raises(ToolError, match="Ambiguous app tool"):
        env.call("alice", SAVE)
    assert env.calls("dup") == []


def test_two_denied_copies_resolve_to_nothing(env):
    # No rule: `dup` is outside alice's Reach. A server-level allow with both
    # tools denied reaches the provider and must still answer unknown.
    with pytest.raises(ToolError, match="Unknown tool"):
        env.call("alice", SAVE)
    env.grant("user", "alice", "server", "allow", "dup")
    env.grant("user", "alice", "tool", "deny", "dup", "left_save")
    env.grant("user", "alice", "tool", "deny", "dup", "right_save")
    with pytest.raises(ToolError, match="Unknown tool"):
        env.call("alice", SAVE)
    assert env.calls("dup") == []
