"""Group 8 (usage-stats): call record, attribution, policy forget, lifespan.

Derived from `specs/usage-stats/spec.md` (Call record, Call attribution,
A re-created user starts clean, Usage store lifecycle, Usage faults) and the
frozen interfaces of `design.md`. Counts are read through the public
`UsageStore.totals` with an admin or user `Reach`.
"""

from __future__ import annotations

import asyncio
import sqlite3
from datetime import date, timedelta
from types import SimpleNamespace

import httpx
import pytest
from conftest import ADMIN_ACTOR, fake_child_spec, make_policy, make_user
from fastmcp.exceptions import NotFoundError, ToolError
from fastmcp.server.auth.auth import AccessToken
from fastmcp.server.providers.addressing import hashed_backend_name
from fastmcp.tools.base import InputRequiredToolResult, ToolResult
from mcp import types as mcp_types
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from router_live import Child, start_live

from mcpflow.registry import Registry, ServerKey
from mcpflow.router import CallerRouter
from mcpflow.usage import (
    CALL_ATTRIBUTION,
    UsageAttribution,
    UsageMiddleware,
    UsageRange,
    attribute,
)


def as_token(subject: str | None):
    return auth_context_var.set(AuthenticatedUser(AccessToken(
        token="in-process", client_id="verifier", scopes=["mcp"], subject=subject)))


def rng() -> UsageRange:
    today = date.today()  # noqa: DTZ011 -- the range is in local days (D9)
    return UsageRange(today - timedelta(days=1), today + timedelta(days=1), "day")


def read(policy, user=None, store=None) -> dict:
    """`by_tool` of the store as `user` (admin when `None`)."""
    store = store or policy._usage
    reach = policy.keys_for(user or ADMIN_ACTOR, "dashboard")
    return asyncio.run(store.totals(rng(), reach)).by_tool


@pytest.fixture
def policy(tmp_path):
    reg = Registry(tmp_path / "servers.json", tmp_path / "user_servers.json")
    reg.load()
    reg.add(fake_child_spec("time"))
    reg.add(fake_child_spec("gitlab"))
    pol = make_policy(tmp_path, reg)
    make_user(pol, "alice")
    return pol


def drive(policy, call_next, uid="alice"):
    """Run one call through the middleware as `uid`."""
    mw = UsageMiddleware(policy._usage, policy)

    async def go():
        token = as_token(uid)
        try:
            return await mw.on_call_tool(SimpleNamespace(), call_next)
        finally:
            auth_context_var.reset(token)

    return asyncio.run(go())


def ok_tool(ref="gitlab", tool="list_commits", result=None):
    async def call_next(_ctx):
        attribute(ref, tool)
        return result if result is not None else "fine"
    return call_next


# --- Call record ---------------------------------------------------------


def test_a_child_tool_call_is_counted(policy):
    drive(policy, ok_tool())
    c = read(policy)[("gitlab", "list_commits")]
    assert (c.calls, c.errors) == (1, 0)


def test_an_error_result_is_counted_as_an_error(policy):
    drive(policy, ok_tool(result=ToolResult(content="x", is_error=True)))
    c = read(policy)[("gitlab", "list_commits")]
    assert (c.calls, c.errors) == (1, 1)


def test_a_raised_tool_error_is_counted_as_an_error(policy):
    async def call_next(_ctx):
        attribute("gitlab", "list_commits")
        raise ToolError("boom")

    with pytest.raises(ToolError, match="boom"):
        drive(policy, call_next)
    c = read(policy)[("gitlab", "list_commits")]
    assert (c.calls, c.errors) == (1, 1)


def test_a_non_tool_result_return_counts_as_ok(policy):
    drive(policy, ok_tool(result=ToolResult(content="x")))
    c = read(policy)[("gitlab", "list_commits")]
    assert (c.calls, c.errors) == (1, 0)


def test_an_unknown_name_is_not_counted(policy):
    async def call_next(_ctx):
        raise NotFoundError("Unknown tool")

    with pytest.raises(NotFoundError):
        drive(policy, call_next)
    assert read(policy) == {}


def test_a_cancelled_call_is_not_counted(policy):
    async def call_next(_ctx):
        attribute("gitlab", "list_commits")
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        drive(policy, call_next)
    assert read(policy) == {}


def test_a_call_that_resolves_no_tool_is_not_counted(policy):
    async def call_next(_ctx):
        return "x"

    drive(policy, call_next)
    assert read(policy) == {}


def test_a_multi_round_call_counts_once(policy):
    asking = InputRequiredToolResult(mcp_types.InputRequiredResult(request_state="r1"))
    drive(policy, ok_tool(result=asking))
    assert read(policy) == {}
    drive(policy, ok_tool())
    assert read(policy)[("gitlab", "list_commits")].calls == 1


def grant_alice(policy, server):
    policy.add_rule(ADMIN_ACTOR, subject_kind="user", subject="alice",
                    level="server", server=server, tool=None, effect="allow")


def test_a_call_by_a_current_user_is_visible_to_them(policy):
    grant_alice(policy, "gitlab")
    drive(policy, ok_tool())
    alice = policy._identity.get_user("alice")
    assert read(policy, alice)[("gitlab", "list_commits")].calls == 1


def test_a_call_that_outlives_its_user(policy):
    async def call_next(_ctx):
        attribute("gitlab", "list_commits")
        policy.delete_user(ADMIN_ACTOR, "alice")
        make_user(policy, "alice")
        return "fine"

    drive(policy, call_next)
    grant_alice(policy, "gitlab")
    new_alice = policy._identity.get_user("alice")
    assert read(policy, new_alice) == {}
    assert read(policy)[("gitlab", "list_commits")].calls == 1


def test_is_current(policy):
    alice = policy._identity.get_user("alice")
    assert policy.is_current(alice) is True
    policy.delete_user(ADMIN_ACTOR, "alice")
    assert policy.is_current(alice) is False
    make_user(policy, "alice")
    assert policy.is_current(alice) is False  # same id, new incarnation

    fresh = policy._identity.get_user("alice")

    def boom(_uid):
        raise RuntimeError("provider down")

    policy._identity.get_user = boom
    assert policy.is_current(fresh) is False


# --- Call attribution ----------------------------------------------------


def test_attribute_outside_a_call_writes_nothing():
    assert CALL_ATTRIBUTION.get() is None
    attribute("gitlab", "x")  # raises nothing
    assert CALL_ATTRIBUTION.get() is None


def test_a_list_writes_no_holder():
    """`UsageAttribution.get_tool` with no holder set leaves no state."""
    sentinel = SimpleNamespace(name="list_servers")

    async def call_next(*a, **k):
        return sentinel

    async def go():
        assert await UsageAttribution().get_tool("list_servers", call_next) is sentinel
        assert CALL_ATTRIBUTION.get() is None

    asyncio.run(go())


def test_bare_is_the_filter_rule():
    for ref, name, bare in (
        ("github", "github_get_issue", "get_issue"),
        ("github@alice", "github_get_issue", "get_issue"),
        ("my_srv", "my_srv_do_it", "do_it"),
        ("time", "time_get_current_time", "get_current_time"),
    ):
        assert CallerRouter._bare(ServerKey.parse(ref), name) == bare


def test_delete_and_create_forget_the_id(policy, monkeypatch):
    seen: list[str] = []
    monkeypatch.setattr(policy._usage, "forget_user", seen.append)
    policy.delete_user(ADMIN_ACTOR, "alice")
    assert seen == ["alice"]
    seen.clear()
    policy.create_user(ADMIN_ACTOR, "alice")
    assert seen == ["alice"]
    seen.clear()
    with pytest.raises(Exception):  # noqa: B017 -- any refusal
        policy.create_user(ADMIN_ACTOR, "alice")  # id taken
    assert seen == []


# --- Router and gateway (live) -------------------------------------------

CHILDREN = (
    Child("time", "time", ("get_current_time",)),
    Child("github", "gh", ("x",)),
    Child("github@alice", "gh", ("x",)),
)


@pytest.fixture(scope="module")
def live(tmp_path_factory):
    lv, stop = start_live(tmp_path_factory.mktemp("usage_rec"), CHILDREN)
    yield lv
    stop()


def live_totals(live) -> dict:
    reach = live.policy.keys_for(ADMIN_ACTOR, "dashboard")
    return live.run(live.policy._usage.totals(rng(), reach)).by_tool


def delta(live, before: dict, key) -> int:
    after = live_totals(live)
    return (after[key].calls if key in after else 0) - (before[key].calls if key in before else 0)


def test_two_servers_publish_the_same_name(live):
    before = live_totals(live)
    assert live.call("alice", "github_x") == "github@alice:x"
    assert live.call("root", "github_x") == "github:x"
    assert delta(live, before, ("github@alice", "x")) == 1
    assert delta(live, before, ("github", "x")) == 1


def test_a_hashed_call_is_attributed(live):
    rule = live.grant("user", "alice", "server", "allow", "time")
    try:
        before = live_totals(live)
        name = hashed_backend_name("time", "get_current_time")
        assert live.call("alice", name) == "time:get_current_time"
        assert delta(live, before, ("time", "get_current_time")) == 1
    finally:
        live.revoke(rule)


def test_a_builtin_tool_is_attributed(live):
    before = live_totals(live)
    live.call("root", "mcpflow_list_servers")
    assert delta(live, before, ("mcpflow", "list_servers")) == 1
    # A non-admin session cannot reach it and nothing is counted.
    with pytest.raises(ToolError):
        live.call("bob", "mcpflow_list_servers")
    assert delta(live, before, ("mcpflow", "list_servers")) == 1


def test_a_list_through_mcp_counts_nothing(live):
    before = live_totals(live)
    live.names("root")
    live.names("alice")
    assert live_totals(live) == before


def test_the_gateway_counts_a_call_end_to_end(live):
    before = live_totals(live)
    live.call("root", "time_get_current_time")
    assert delta(live, before, ("time", "get_current_time")) == 1
    with httpx.Client(base_url=live.base_url) as web:
        assert web.post("/login", data={"password": "secret", "next": "/"}).status_code == 303
        html = web.get("/tools/tree").text
    assert "call" in html and "Usage is not available." not in html


def test_the_lifespan_flushes_at_stop(tmp_path):
    lv, stop = start_live(tmp_path, (Child("time", "time", ("get_current_time",)),))
    try:
        assert lv.call("root", "time_get_current_time") == "time:get_current_time"
    finally:
        stop()
    con = sqlite3.connect(tmp_path / "usage.sqlite3")
    try:
        rows = con.execute(
            "SELECT server, tool, SUM(calls) FROM usage GROUP BY server, tool"
        ).fetchall()
    except sqlite3.OperationalError:
        rows = con.execute("SELECT name FROM sqlite_master").fetchall()
        pytest.fail(f"no usage table found: {rows}")
    finally:
        con.close()
    assert ("time", "get_current_time", 1) in rows


def test_a_broken_database_file_does_not_stop_the_gateway(server_factory):
    srv = server_factory(seed=lambda d: (d / "usage.sqlite3").mkdir())
    with httpx.Client(base_url=srv.base_url) as web:
        assert web.post("/login", data={"password": "secret", "next": "/"}).status_code == 303
        assert web.get("/").status_code == 200
        assert "Usage is not available." in web.get("/tools/tree").text + web.get("/").text
