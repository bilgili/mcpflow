"""`finish_oauth` binds the actor of the flow (bind-actor-to-server-writes, T5, direct calls).

Requirements "Pending flows" (modified) and "The OAuth completion checks the
actor of the flow" of `specs/oauth-client/spec.md`. The HTTP side of the same
scenarios is in `test_bind_actor_race.py`. Model: `FlowOutlivesActorRefused`,
`RefusedFlowConsumed`, `FailedWriteChangesNothing`. The opener of a flow is an
admin `carol` that owns nothing, so a revoke of her changes no other record.
"""

from __future__ import annotations

import dataclasses
import inspect
from pathlib import Path

import pytest
from conftest import ADMIN_ACTOR, fake_child_spec, make_user
from keyed_stores import TOKENS, build, drain, tree
from test_oauth import _NEW, GMAIL_ALICE, _reauth_sup

from mcpflow.identity import User
from mcpflow.oauth import ClientCreds, HeaderSpec, PendingFlow, PendingFlows
from mcpflow.policy import ADMIN_REQUIRED, UNKNOWN_ACTOR
from mcpflow.registry import ServerKey, ServerSpec
from mcpflow.supervisor import Supervisor

GMAIL = ServerKey(None, "gmail")
MOO = ServerKey(None, "moomoo")
CLIENT = ClientCreds("abc", "shhh")
HEADER = HeaderSpec("Authorization", "Bearer", "https://webapi.moomoo.com/oauth2/token")
HEADER_TOKENS = {"access_token": "ACCESS1xyz", "refresh_token": "REFRESH1xyz",
                 "token_type": "Bearer", "expires_in": 7200}


def opener(sup: Supervisor) -> User:
    make_user(sup.policy.local_identity(), "carol", admin=True)
    snap = sup.policy.local_identity().get_user("carol")
    assert snap is not None and snap.is_admin
    return snap


def file_sink_world(tmp_path: Path) -> Supervisor:
    """A disabled `gmail` that awaits authorization: a client file and no token."""
    sup = build(tmp_path, fake_child_spec("gmail", "good", enabled=False, catalog="gmail"))
    sup.creds.write_client("gmail", "google-client", CLIENT)
    return sup


def header_sink_world(tmp_path: Path) -> Supervisor:
    return build(tmp_path, ServerSpec(
        namespace="moomoo", kind="remote", url="http://127.0.0.1:9/mcp", transport="http",
        catalog="moomoo", enabled=False, oauth_pending=True))


def revoke_how(sup: Supervisor, cause: str) -> str:
    """Change the store the way `cause` says. Return the expected refusal text."""
    policy = sup.policy
    if cause == "deleted":
        policy.delete_user(ADMIN_ACTOR, "carol")
        return UNKNOWN_ACTOR
    if cause == "demoted":
        policy.set_admin(ADMIN_ACTOR, "carol", False)
        return ADMIN_REQUIRED
    policy.delete_user(ADMIN_ACTOR, "carol")  # re-used
    make_user(sup.policy.local_identity(), "carol", admin=True)
    return UNKNOWN_ACTOR


CAUSES = ["deleted", "demoted", "re-used"]


# --- OC-1: the flow record -----------------------------------------------------


def test_a_flow_holds_its_opener():
    """Scenario "A flow holds its opener"."""
    carol = User(id="carol", name="carol", groups=frozenset({"admins"}), provider="local")
    flows = PendingFlows()
    flow = flows.create("gmail", "gmail", CLIENT, carol)
    assert flow.actor == carol
    assert flows.peek(flow.state).actor == carol
    reauth = flows.create("gmail@alice", "gmail", CLIENT, carol, reauth=True)
    assert reauth.actor == carol and reauth.reauth is True


def test_the_flow_interfaces_are_frozen():
    """Design D10: `actor` sits between `created` and `reauth`; `create` takes it fourth."""
    names = [f.name for f in dataclasses.fields(PendingFlow)]
    assert names.index("created") < names.index("actor") < names.index("reauth")
    params = inspect.signature(PendingFlows.create).parameters
    assert list(params) == ["self", "ref", "entry_id", "client", "actor", "reauth"]
    assert params["reauth"].kind is inspect.Parameter.KEYWORD_ONLY
    assert params["actor"].default is inspect.Parameter.empty
    with pytest.raises(TypeError):
        PendingFlows().create("gmail", "gmail", CLIENT)  # type: ignore[call-arg]


# --- OC-2: the completion ------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("cause", CAUSES)
async def test_a_completion_after_the_opener_is_refused(tmp_path, cause):
    """Scenarios "A completion after the opener is deleted / demoted / re-used writes
    nothing" (`FlowOutlivesActorRefused`), file sink connect."""
    sup = file_sink_world(tmp_path)
    try:
        carol = opener(sup)
        flow = sup.flows.create("gmail", "gmail", CLIENT, carol)
        child = sup.get(GMAIL)
        grant = child.grant
        text = revoke_how(sup, cause)
        before = tree(tmp_path)
        with pytest.raises(PermissionError) as exc:
            await sup.finish_oauth(flow, "google-auth-library", TOKENS)
        assert str(exc.value) == text
        assert tree(tmp_path) == before
        assert not sup.creds.paths("gmail").token.exists()
        assert sup.registry.get(GMAIL).enabled is False
        assert child.status == "stopped" and child.task is None
        assert child.grant == grant
        assert sup.flows.peek(flow.state) is None
    finally:
        await drain(sup)


@pytest.mark.asyncio
@pytest.mark.parametrize("cause", CAUSES)
async def test_a_refused_header_sink_completion_writes_nothing(tmp_path, cause):
    """Scenario "A completion after the opener is demoted writes nothing", header sink."""
    sup = header_sink_world(tmp_path)
    try:
        carol = opener(sup)
        flow = sup.flows.create("moomoo", "moomoo", CLIENT, carol)
        child = sup.get(MOO)
        grant = child.grant
        text = revoke_how(sup, cause)
        before = tree(tmp_path)
        with pytest.raises(PermissionError) as exc:
            await sup.finish_oauth(flow, None, HEADER_TOKENS, header=HEADER)
        assert str(exc.value) == text
        assert tree(tmp_path) == before
        spec = sup.registry.get(MOO)
        assert "Authorization" not in spec.headers
        assert spec.oauth_pending is True and spec.enabled is False
        assert not sup.creds.refresh_path("moomoo").exists()
        assert child.grant == grant
        assert child.status == "stopped"
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_a_refused_flow_is_consumed(tmp_path):
    """`RefusedFlowConsumed`: a refused flow is not open, and no callback reuses it."""
    sup = file_sink_world(tmp_path)
    try:
        carol = opener(sup)
        flow = sup.flows.create("gmail", "gmail", CLIENT, carol)
        sup.policy.set_admin(ADMIN_ACTOR, "carol", False)
        with pytest.raises(PermissionError):
            await sup.finish_oauth(flow, "google-auth-library", TOKENS)
        assert sup.flows.peek(flow.state) is None
        assert sup.flows.has_open("gmail") is False
        assert await sup.finish_oauth(flow, "google-auth-library", TOKENS) is False
        assert not sup.creds.paths("gmail").token.exists()
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_a_user_built_outside_the_store_cannot_complete_a_flow(tmp_path):
    """Fail closed: the opener of the flow is an id the store never held."""
    sup = file_sink_world(tmp_path)
    try:
        ghost = User(id="ghost", name="ghost", groups=frozenset({"admins"}), provider="local")
        flow = sup.flows.create("gmail", "gmail", CLIENT, ghost)
        with pytest.raises(PermissionError, match=UNKNOWN_ACTOR):
            await sup.finish_oauth(flow, "google-auth-library", TOKENS)
        assert not sup.creds.paths("gmail").token.exists()
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_a_non_admin_opener_cannot_complete_a_flow(tmp_path):
    """Requirement "The write-time right of a server write": `finish_oauth` needs the role."""
    sup = file_sink_world(tmp_path)
    try:
        bob = sup.policy.local_identity().get_user("bob")
        flow = sup.flows.create("gmail", "gmail", CLIENT, bob)
        with pytest.raises(PermissionError, match=ADMIN_REQUIRED):
            await sup.finish_oauth(flow, "google-auth-library", TOKENS)
        assert not sup.creds.paths("gmail").token.exists()
        assert sup.registry.get(GMAIL).enabled is False
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_a_current_opener_completes(tmp_path):
    """Scenario "A current opener completes the flow"."""
    sup = file_sink_world(tmp_path)
    try:
        carol = opener(sup)
        flow = sup.flows.create("gmail", "gmail", CLIENT, carol)
        assert await sup.finish_oauth(flow, "google-auth-library", TOKENS) is True
        assert sup.creds.paths("gmail").token.exists()
        child = sup.get(GMAIL)
        assert sup.registry.get(GMAIL).enabled is True
        assert child.task is not None
        await child.task
        assert child.status == "running"
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_a_current_header_sink_opener_completes(tmp_path):
    """The same opener, a header sink: the header is set and `oauth_pending` clears."""
    sup = header_sink_world(tmp_path)
    try:
        carol = opener(sup)
        flow = sup.flows.create("moomoo", "moomoo", CLIENT, carol)
        assert await sup.finish_oauth(flow, None, HEADER_TOKENS, header=HEADER) is True
        spec = sup.registry.get(MOO)
        assert spec.headers["Authorization"] == "Bearer ACCESS1xyz"
        assert spec.oauth_pending is False
        assert sup.creds.refresh_path("moomoo").exists()
    finally:
        await drain(sup)


# --- the second check of a file sink re-authorization (residual R-J) -----------


@pytest.mark.asyncio
async def test_a_refused_reauthorization_keeps_the_old_token(tmp_path):
    """Scenario "A refused re-authorization keeps the old token"."""
    sup, events = _reauth_sup(tmp_path, enabled=True)
    try:
        carol = opener(sup)
        flow = sup.flows.create("gmail@alice", "gmail", ClientCreds("new", "n"), carol, reauth=True)
        paths = sup.creds.paths("gmail@alice")
        token_before, client_before = paths.token.read_bytes(), paths.client.read_bytes()
        grant = sup.get(GMAIL_ALICE).grant
        inner = sup._teardown
        fired: list[int] = []

        async def teardown(child):
            await inner(child)  # the real drain first, then the revoke
            if not fired:
                fired.append(1)
                sup.policy.set_admin(ADMIN_ACTOR, "carol", False)

        sup._teardown = teardown
        with pytest.raises(PermissionError) as exc:
            await sup.finish_oauth(flow, "google-auth-library", _NEW,
                                   client_fmt="google-client", reauth=True)
        assert fired, "the revoke never ran: the drain window was not exercised"
        assert str(exc.value) == ADMIN_REQUIRED
        assert paths.token.read_bytes() == token_before
        assert paths.client.read_bytes() == client_before
        assert not [e for e in events if e.startswith("write_")]
        child = sup.get(GMAIL_ALICE)
        assert child.status == "stopped"
        assert child.grant == grant
        assert sup.flows.peek(flow.state) is None
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_a_revoke_before_the_first_check_stops_nothing(tmp_path):
    """The first check holds before the teardown: no teardown, the child keeps its status."""
    sup, events = _reauth_sup(tmp_path, enabled=True)
    try:
        carol = opener(sup)
        flow = sup.flows.create("gmail@alice", "gmail", ClientCreds("new", "n"), carol, reauth=True)
        paths = sup.creds.paths("gmail@alice")
        token_before, client_before = paths.token.read_bytes(), paths.client.read_bytes()
        sup.policy.set_admin(ADMIN_ACTOR, "carol", False)
        with pytest.raises(PermissionError, match=ADMIN_REQUIRED):
            await sup.finish_oauth(flow, "google-auth-library", _NEW,
                                   client_fmt="google-client", reauth=True)
        assert events == [], "the refusal came after a teardown or a write"
        assert sup.get(GMAIL_ALICE).status == "running"
        assert paths.token.read_bytes() == token_before
        assert paths.client.read_bytes() == client_before
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_a_current_opener_reauthorizes(tmp_path):
    """Both checks pass for a current opener: client then token are replaced."""
    sup, events = _reauth_sup(tmp_path, enabled=True)
    try:
        carol = opener(sup)
        flow = sup.flows.create("gmail@alice", "gmail", ClientCreds("new", "n"), carol, reauth=True)
        assert await sup.finish_oauth(flow, "google-auth-library", _NEW,
                                      client_fmt="google-client", reauth=True) is True
        assert events[:3] == ["teardown", "write_client:gmail@alice", "write_token:gmail@alice"]
    finally:
        await drain(sup)
