"""`run_action` checks its actor and keeps transport errors (bind-actor-to-server-writes, T9, finding C-1).

Requirement "Server writes check the actor at write time" of
`specs/access-policy/spec.md`: scenarios "A revoke before an action refuses it"
and "A transport permission error in an action stays a transport outcome". The
decision comes at entry and again right before the child call. The entry
refusal comes before any outcome, lease, or listing. Only the second refusal is
held until the lease ends. Any other error inside the lease, a
`PermissionError` too, stays an outcome of the kind `transport` that keeps the
posted password in its secrets. Model: `WriteByCurrentAdmin`.
"""

from __future__ import annotations

import asyncio

import fastmcp
import pytest
import pytest_asyncio
from action_browser import action_post
from conftest import ADMIN_ACTOR, make_policy, make_settings, make_user
from test_child_actions import PAGE, start, store_spec
from test_visibility import admin, call_log

from mcpflow.identity import ADMINS_GROUP, User
from mcpflow.oauth import CredStore, PendingFlows
from mcpflow.policy import ADMIN_REQUIRED, UNKNOWN_ACTOR
from mcpflow.registry import Registry, ServerKey
from mcpflow.supervisor import Supervisor

STORE = ServerKey(None, "store")
FORM = {"name": "x", "kind": "git", "secret_key": "pw-123"}
PASSWORD = "pw-123"


@pytest_asyncio.fixture
async def supervisors(tmp_path):
    """`make()` builds a supervisor over its own data dir; every one is shut down."""
    created: list[Supervisor] = []

    def make() -> Supervisor:
        data = tmp_path / f"sup{len(created)}"
        data.mkdir()
        reg = Registry(data / "servers.json", data / "user_servers.json")
        reg.load()
        sup = Supervisor(reg, make_settings(data), CredStore(data), PendingFlows(),
                         make_policy(data, reg))
        created.append(sup)
        return sup

    yield make
    for sup in created:
        await sup.shutdown()


async def action_world(supervisors):
    """A running action child `store`, a spy on its raw call, and the admin `carol`."""
    sup = supervisors()
    child = await sup.add(store_spec(), ADMIN_ACTOR)
    await child.task
    assert child.status == "running"
    carol = make_user(sup.policy.local_identity(), "carol", admin=True)
    calls: list[tuple] = []
    orig = child.session.client.call_tool_mcp

    async def spy(*a, **k):
        calls.append(a)
        return await orig(*a, **k)

    child.session.client.call_tool_mcp = spy
    return sup, child, carol, calls


@pytest.mark.asyncio
async def test_a_current_admin_runs_the_action(supervisors):
    """Control: the same call by a current admin reaches the child once."""
    sup, _child, carol, calls = await action_world(supervisors)
    run = await sup.run_action(STORE, "add_store", FORM, carol)
    assert run.kind == "ran", (run.kind, run.detail)
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_a_revoked_actor_makes_run_action_raise_with_no_call(supervisors):
    """Scenario "A revoke before an action refuses it"."""
    sup, _child, carol, calls = await action_world(supervisors)
    sup.policy.set_admin(ADMIN_ACTOR, "carol", False)
    with pytest.raises(PermissionError) as exc:
        await sup.run_action(STORE, "add_store", FORM, carol)
    assert str(exc.value) == ADMIN_REQUIRED == "the admin role is required"
    assert calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("cause", ["deleted", "re-used", "ghost", "non-admin"])
async def test_a_deleted_or_non_admin_actor_is_refused_with_no_call(supervisors, cause):
    sup, _child, carol, calls = await action_world(supervisors)
    text = UNKNOWN_ACTOR
    actor = carol
    if cause == "deleted":
        sup.policy.delete_user(ADMIN_ACTOR, "carol")
    elif cause == "re-used":
        sup.policy.delete_user(ADMIN_ACTOR, "carol")
        make_user(sup.policy.local_identity(), "carol", admin=True)
    elif cause == "ghost":
        actor = User(id="ghost", name="ghost", groups=frozenset({ADMINS_GROUP}), provider="local")
    else:
        actor = sup.policy.local_identity().get_user("bob") or make_user(
            sup.policy.local_identity(), "bob")
        text = ADMIN_REQUIRED
    with pytest.raises(PermissionError) as exc:
        await sup.run_action(STORE, "add_store", FORM, actor)
    assert str(exc.value) == text
    assert calls == []


@pytest.mark.asyncio
async def test_a_revoke_during_the_listing_refuses_before_the_call(supervisors):
    """The decision falls right before the call, after the listing."""
    sup, child, carol, calls = await action_world(supervisors)
    client = child.session.client
    orig = client.list_tools
    fired: list[int] = []

    async def listing(*a, **k):
        if not fired:
            fired.append(1)
            sup.policy.set_admin(ADMIN_ACTOR, "carol", False)
        return await orig(*a, **k)

    client.list_tools = listing
    with pytest.raises(PermissionError, match=ADMIN_REQUIRED):
        await sup.run_action(STORE, "add_store", FORM, carol)
    assert fired, "the revoke never ran: the window was not exercised"
    assert calls == []


@pytest.mark.asyncio
async def test_the_refusal_holds_no_lease(supervisors):
    """The refusal leaves after the lease ends: a `disable` that drains leases finishes.

    The demote falls during the listing, so the test hits the held refusal and not
    the entry refusal."""
    sup, child, carol, calls = await action_world(supervisors)
    client = child.session.client
    orig = client.list_tools
    fired: list[int] = []

    async def listing(*a, **k):
        if not fired:
            fired.append(1)
            sup.policy.set_admin(ADMIN_ACTOR, "carol", False)
        return await orig(*a, **k)

    client.list_tools = listing
    with pytest.raises(PermissionError):
        await sup.run_action(STORE, "add_store", FORM, carol)
    assert fired, "the demote never ran: the held refusal was not exercised"
    await asyncio.wait_for(sup.disable(STORE, ADMIN_ACTOR), 5)
    assert sup.registry.get(STORE).enabled is False
    assert calls == []


@pytest.mark.asyncio
async def test_a_transport_permission_error_stays_a_transport_outcome(supervisors):
    """Scenario "A transport permission error in an action stays a transport outcome"."""
    sup, child, carol, _calls = await action_world(supervisors)

    async def boom(*a, **k):
        raise PermissionError(PASSWORD)

    child.session.client.call_tool_mcp = boom
    run = await sup.run_action(STORE, "add_store", FORM, carol)  # nothing is raised
    assert run.kind == "transport"
    assert PASSWORD in run.secrets
    assert run.result is None


@pytest.mark.asyncio
async def test_a_list_tools_permission_error_stays_a_transport_outcome(supervisors):
    sup, child, carol, calls = await action_world(supervisors)

    async def boom(*a, **k):
        raise PermissionError(PASSWORD)

    child.session.client.list_tools = boom
    # The listing is the source of the password keys; the page that rendered the
    # form hands them in, so the posted password is a secret before the listing.
    run = await sup.run_action(
        STORE, "add_store", FORM, carol, rendered_password_keys=frozenset({"secret_key"}))
    assert run.kind == "transport"
    assert PASSWORD in run.secrets
    assert calls == []


@pytest.mark.asyncio
async def test_a_transport_error_of_a_revoked_actor_is_still_the_refusal(supervisors):
    """The refusal wins over the call: a revoked actor never reaches the transport."""
    sup, child, carol, _calls = await action_world(supervisors)
    reached: list[int] = []

    async def boom(*a, **k):
        reached.append(1)
        raise PermissionError(PASSWORD)

    child.session.client.call_tool_mcp = boom
    sup.policy.set_admin(ADMIN_ACTOR, "carol", False)
    with pytest.raises(PermissionError, match=ADMIN_REQUIRED):
        await sup.run_action(STORE, "add_store", FORM, carol)
    assert reached == []


def test_a_transport_permission_error_over_http_is_not_403(server_factory, monkeypatch):
    """Scenario "A transport permission error in an action stays a transport outcome", over HTTP."""
    server, _holder = start(server_factory, store_spec())

    async def boom(self, *a, **k):
        raise PermissionError(PASSWORD)

    monkeypatch.setattr(fastmcp.Client, "call_tool_mcp", boom)
    with admin(server) as client:
        resp = action_post(client, PAGE + "/add_store", data=FORM)
    assert resp.status_code != 403, resp.text
    assert resp.status_code < 500, resp.text
    assert PASSWORD not in resp.text
    assert call_log(server) == []
