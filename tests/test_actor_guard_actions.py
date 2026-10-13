"""`run_action` decides at entry, and a held refusal wins (actor-guard-review-fixes, fix 3).

Requirement "Server writes check the actor at write time" of
`specs/access-policy/spec.md`, scenarios "A refusal wins over a fault of the
lease exit", "A refused actor gets no action outcome", "A refused actor on a
stopped child gets the refusal", "A refused actor on a child without actions
gets the refusal", and "A current admin runs an action as before". The
expectations come from the spec scenarios and the frozen `run_action` interface
of `design.md` (D6, D7), not from the code.

Frozen refusal texts: `the admin role is required` and `the acting user is
unknown`. The schema values of the `store` action `add_store` are `git`,
`directory`, and `s3`: no refusal text may hold one.
"""

from __future__ import annotations

import ast
import contextlib
import inspect
import textwrap

import pytest
from conftest import ADMIN_ACTOR, make_user
from dashboard_site import make_mu_site  # noqa: F401
from reresolve_race import demote_alice
from test_bind_actor_actions import (  # noqa: F401
    FORM,
    PASSWORD,
    STORE,
    action_world,
    supervisors,
)
from test_bind_actor_race import add_store, alice_admin
from test_child_actions import store_spec

from mcpflow.identity import ADMINS_GROUP, User
from mcpflow.policy import ADMIN_REQUIRED, UNKNOWN_ACTOR
from mcpflow.supervisor import LeaseRefused, Supervisor

SCHEMA_VALUES = ("git", "directory", "s3")


def exit_fault(sup, fault: BaseException) -> None:
    """Make every lease of `sup` raise `fault` when it exits, after its body ran."""
    orig = sup._lease

    @contextlib.asynccontextmanager
    async def lease(child):
        async with orig(child) as client:
            yield client
        raise fault

    sup._lease = lease


def demote_during_listing(sup, client, user_id: str = "carol") -> list[int]:
    """Demote `user_id` the first time `client.list_tools` runs. Return the fired list."""
    orig = client.list_tools
    fired: list[int] = []

    async def listing(*a, **k):
        if not fired:
            fired.append(1)
            sup.policy.set_admin(ADMIN_ACTOR, user_id, False)
        return await orig(*a, **k)

    client.list_tools = listing
    return fired


FAULTS = [
    pytest.param(RuntimeError("exit pw-123"), id="runtime"),
    pytest.param(LeaseRefused("store", 1, "closing"), id="lease-refused"),
]


# --- T-13 to T-15: the held refusal ------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", FAULTS)
async def test_a_refusal_wins_over_a_lease_exit_fault(supervisors, fault):  # noqa: F811
    """Scenario "A refusal wins over a fault of the lease exit"."""
    sup, child, carol, calls = await action_world(supervisors)
    fired = demote_during_listing(sup, child.session.client)  # entry passes, the second check refuses
    exit_fault(sup, fault)

    with pytest.raises(PermissionError) as exc:
        await sup.run_action(STORE, "add_store", FORM, carol)

    assert fired, "the demote never ran: the window was not exercised"
    assert str(exc.value) == ADMIN_REQUIRED == "the admin role is required"
    assert calls == []
    assert exc.value.__context__ is None and exc.value.__cause__ is None
    assert "pw-123" not in repr(exc.value) and "pw-123" not in str(exc.value.args)


@pytest.mark.asyncio
async def test_a_lease_exit_fault_after_a_ran_call_is_still_a_transport_outcome(supervisors):  # noqa: F811
    """Control for the held refusal: with no refusal, an exit fault is `transport`."""
    sup, _child, carol, calls = await action_world(supervisors)
    exit_fault(sup, RuntimeError("exit boom"))

    run = await sup.run_action(STORE, "add_store", FORM, carol)

    assert (run.kind, run.detail) == ("transport", "exit boom")
    assert len(calls) == 1


@pytest.mark.parametrize("fault", FAULTS)
def test_a_refused_action_over_http_answers_403(make_mu_site, fault):  # noqa: F811
    """The same scenario at the web route `POST /servers/{ref}/actions/{action}`."""
    site = make_mu_site(add_store)
    alice_admin(site)
    site.wait_running(STORE)
    sup = site.app.state.supervisor
    client = sup.get(STORE).session.client
    demote = demote_alice(site)
    orig_run, orig_list, orig_lease = sup.run_action, client.list_tools, sup._lease
    fired: list[int] = []
    entered: list[int] = []

    async def listing(*a, **k):
        if not fired:
            fired.append(1)
            demote()
        return await orig_list(*a, **k)

    # The route lists the actions first, with a lease of its own. Arm the demote
    # and the exit fault only for the lease of `run_action`.
    async def armed(*a, **k):
        entered.append(1)
        client.list_tools = listing
        exit_fault(sup, fault)
        try:
            return await orig_run(*a, **k)
        finally:
            client.list_tools, sup._lease = orig_list, orig_lease

    sup.run_action = armed
    resp = site.request("alice", "POST", "/servers/store/actions/set_writable",
                        data={"name": "s3main"})

    assert entered and fired, "the window was not exercised"
    assert (resp.status_code, resp.text) == (403, "the admin role is required")
    calls = site.data / "calls.log"
    assert not calls.exists() or calls.read_text() == "", "the child received a call"


def test_run_action_has_no_assert():
    """Requirement text: "`run_action` SHALL hold no `assert` statement"."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(Supervisor.run_action)))
    assert not [n for n in ast.walk(tree) if isinstance(n, ast.Assert)]


# --- T-16 and T-17: the entry decision ---------------------------------------

CASES = ["actions off", "child stopped", "unknown action", "muted action",
         "bad kind", "valid form"]


async def case_world(supervisors, case):  # noqa: F811
    """A `store` child set up for `case`, with spies on lease, listing, and call."""
    sup = supervisors()
    if case == "actions off":
        spec = store_spec(actions=False)
    elif case == "child stopped":
        spec = store_spec(enabled=False)
    else:
        spec = store_spec()
    child = await sup.add(spec, ADMIN_ACTOR)
    if child.task is not None:
        await child.task
    if case == "child stopped":
        assert child.status != "running"
    elif case != "actions off":
        assert child.status == "running"
    if case == "muted action":
        sup.set_tool_muted(STORE, "add_store", True, ADMIN_ACTOR)
    spies = {"leases": 0, "listings": 0, "calls": 0}
    orig_lease = sup._lease

    def lease(c):
        spies["leases"] += 1
        return orig_lease(c)

    sup._lease = lease
    client = child.session.client if child.session is not None else None
    if client is not None:
        orig_list, orig_call = client.list_tools, client.call_tool_mcp

        async def listing(*a, **k):
            spies["listings"] += 1
            return await orig_list(*a, **k)

        async def call(*a, **k):
            spies["calls"] += 1
            return await orig_call(*a, **k)

        client.list_tools, client.call_tool_mcp = listing, call
    name = "nope" if case == "unknown action" else "add_store"
    form = {**FORM, "kind": "zzz"} if case == "bad kind" else dict(FORM)
    return sup, spies, name, form


def make_actor(sup, who: str) -> tuple[User, str]:
    """An actor of the kind `who`, and the frozen text its refusal carries."""
    local = sup.policy.local_identity()
    if who == "plain user":
        return make_user(local, "bob"), ADMIN_REQUIRED
    if who == "ghost":
        return User(id="ghost", name="ghost", groups=frozenset({ADMINS_GROUP}),
                    provider="local"), UNKNOWN_ACTOR
    carol = make_user(local, "carol", admin=True)
    if who == "deleted admin":
        sup.policy.delete_user(ADMIN_ACTOR, "carol")
        return carol, UNKNOWN_ACTOR
    assert who == "demoted admin"
    sup.policy.set_admin(ADMIN_ACTOR, "carol", False)
    return carol, ADMIN_REQUIRED


@pytest.mark.asyncio
@pytest.mark.parametrize("who", ["plain user", "deleted admin", "demoted admin", "ghost"])
@pytest.mark.parametrize("case", CASES)
async def test_a_refused_actor_gets_no_outcome(supervisors, who, case):  # noqa: F811
    """Scenarios "A refused actor gets no action outcome", "... on a stopped child
    gets the refusal", and "... on a child without actions gets the refusal"."""
    sup, spies, name, form = await case_world(supervisors, case)
    actor, text = make_actor(sup, who)

    with pytest.raises(PermissionError) as exc:
        await sup.run_action(STORE, name, form, actor)

    assert str(exc.value) == text
    assert spies == {"leases": 0, "listings": 0, "calls": 0}
    assert not any(v in str(exc.value) for v in SCHEMA_VALUES)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES)
async def test_an_authorized_admin_is_unchanged(supervisors, case):  # noqa: F811
    """Scenario "A current admin runs an action as before"."""
    sup, spies, name, form = await case_world(supervisors, case)
    carol = make_user(sup.policy.local_identity(), "carol", admin=True)

    run = await sup.run_action(STORE, name, form, carol)

    if case == "actions off":
        assert (run.kind, run.detail, run.password_keys) == ("unknown", "", frozenset())
        assert spies["leases"] == 0
    elif case == "child stopped":
        assert (run.kind, run.detail, run.password_keys) == (
            "transport", "store is not running", frozenset())
        assert spies["leases"] == 0
    elif case == "unknown action":
        assert (run.kind, run.detail) == ("unknown", "")
        assert spies["listings"] == 1 and spies["calls"] == 0
    elif case == "muted action":
        assert (run.kind, run.detail) == ("muted", "")
        assert run.password_keys == frozenset({"secret_key"})
        assert PASSWORD in run.secrets
        assert spies["listings"] == 1 and spies["calls"] == 0
    elif case == "bad kind":
        assert run.kind == "coerce_error"
        assert run.detail  # a coercion error names the value that failed
        assert run.password_keys == frozenset({"secret_key"})
        assert PASSWORD in run.secrets
        assert spies["listings"] == 1 and spies["calls"] == 0
    else:
        assert (run.kind, run.detail) == ("ran", "")
        assert run.password_keys == frozenset({"secret_key"})
        assert PASSWORD in run.secrets
        assert run.result is not None
        assert spies["listings"] == 1 and spies["calls"] == 1
