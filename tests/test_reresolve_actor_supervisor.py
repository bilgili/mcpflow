"""`Supervisor.add` checks its actor at write time (reresolve-actor-at-write, T2).

Requirement "Server add checks the actor at write time" of
`specs/access-policy/spec.md` in the change: a demoted admin's add is refused, a
deleted user's add is refused, a user add is unchanged. Design D1 (alternative
e), D2, D5, D9. Model: `ReReadNeverDowngrades`, `ReReadNeverGrants`,
`FailedWriteChangesNothing`. Specs use `enabled=False`, so no child starts.
"""

from __future__ import annotations

import pytest
from conftest import ADMIN_ACTOR, fake_child_spec
from keyed_stores import ALICE, BOB, build, drain, register_actors, tree, user_spec

from mcpflow.identity import User
from mcpflow.oauth import ClientCreds
from mcpflow.policy import ADMIN_REQUIRED, UNKNOWN_ACTOR
from mcpflow.registry import ServerKey


def admin_snapshot(sup, uid="alice"):
    """The snapshot the gate took of `uid` as an admin."""
    local = sup.policy.local_identity()
    sup.policy.set_admin(ADMIN_ACTOR, uid, True)
    snap = local.get_user(uid)
    assert snap.is_admin
    return snap


def keys(sup):
    return {k.ref for k in (s.key for s in sup.registry.list())}


@pytest.mark.asyncio
async def test_a_demoted_admins_add_is_refused_and_writes_nothing(tmp_path):
    """Scenario "A demoted admin's add is refused"."""
    sup = build(tmp_path, fake_child_spec("time", "good", enabled=False))
    try:
        snap = admin_snapshot(sup)
        sup.policy.set_admin(ADMIN_ACTOR, "alice", False)
        # A rule that an admin add of `time` would purge (`drop_server_rules`).
        sup.policy.add_rule(ADMIN_ACTOR, subject_kind="user", subject="bob",
                            level="server", server="time", tool=None, effect="allow")
        sup.registry.remove(ServerKey(None, "time"))
        (tmp_path / "logs" / "time.log").write_text("old log\n")
        before = tree(tmp_path)
        with pytest.raises(PermissionError) as exc:
            await sup.add(fake_child_spec("time", "good", enabled=False), snap)
        assert str(exc.value) == ADMIN_REQUIRED == "the admin role is required"
        assert tree(tmp_path) == before
        assert not keys(sup) & {"time", "time@alice"}
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_a_refused_oauth_add_writes_no_client_file(tmp_path):
    sup = build(tmp_path)
    try:
        snap = admin_snapshot(sup)
        sup.policy.set_admin(ADMIN_ACTOR, "alice", False)
        before = tree(tmp_path)
        with pytest.raises(PermissionError):
            await sup.add(fake_child_spec("gmail", "good", enabled=False), snap,
                          client_fmt="google-client", client=ClientCreds("abc", "xyz"))
        assert tree(tmp_path) == before
        assert not (tmp_path / "creds" / "gmail").exists()
        assert not sup.flows.has_open("gmail")
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_a_deleted_users_add_is_refused(tmp_path):
    """Scenario "A deleted user's add is refused"."""
    sup = build(tmp_path)
    try:
        snap = sup.policy.local_identity().get_user("bob")
        assert not snap.is_admin
        sup.policy.delete_user(ADMIN_ACTOR, "bob")
        before = tree(tmp_path)
        with pytest.raises(PermissionError) as exc:
            await sup.add(user_spec("github", "bob", enabled=False), snap)
        assert str(exc.value) == UNKNOWN_ACTOR == "the acting user is unknown"
        assert tree(tmp_path) == before
        assert "github@bob" not in keys(sup)
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_a_user_built_outside_the_store_cannot_add(tmp_path):
    sup = build(tmp_path)
    try:
        before = tree(tmp_path)
        ghost = User(id="ghost", name="ghost", groups=frozenset({"admins"}),
                     provider="local")
        with pytest.raises(PermissionError, match=UNKNOWN_ACTOR):
            await sup.add(fake_child_spec("time", "good", enabled=False), ghost)
        assert tree(tmp_path) == before
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_a_user_add_is_unchanged(tmp_path):
    """Scenario "A user add is unchanged"."""
    sup = build(tmp_path)
    try:
        await sup.add(user_spec("github", "alice", enabled=False), ALICE)
        stored = sup.registry.get(ServerKey("alice", "github"))
        assert stored.owner == "alice"
        assert stored.approval == "pending"
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_a_snapshot_promoted_mid_request_still_adds_a_user_owned_pending_server(tmp_path):
    """`ReReadNeverGrants` (D1 alternative e): the snapshot picks the branch."""
    sup = build(tmp_path)
    try:
        snap = sup.policy.local_identity().get_user("alice")
        assert not snap.is_admin
        sup.policy.set_admin(ADMIN_ACTOR, "alice", True)
        await sup.add(user_spec("github", "alice", enabled=False), snap)
        stored = sup.registry.get(ServerKey("alice", "github"))
        assert stored.owner == "alice" and stored.approval == "pending"
        assert stored.actions is False
        assert "github" not in keys(sup), "an admin-owned record was stored"
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_the_check_runs_before_every_write(tmp_path, monkeypatch):
    """D5, G3: the actor check is the first of the writes of `add`."""
    sup = build(tmp_path)
    calls: list[str] = []

    def record(obj, name, label):
        real = getattr(obj, name)

        def wrapper(*a, **kw):
            calls.append(label)
            return real(*a, **kw)

        monkeypatch.setattr(obj, name, wrapper)

    record(sup.policy, "require_current", "require_current")
    record(sup.policy, "drop_server_rules", "drop_server_rules")
    record(sup.registry, "add", "registry.add")
    try:
        await sup.add(fake_child_spec("time", "good", enabled=False), ADMIN_ACTOR)
        assert calls[0] == "require_current"
        assert calls == ["require_current", "drop_server_rules", "registry.add"]
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_a_still_admin_add_succeeds(tmp_path):
    sup = build(tmp_path)
    try:
        await sup.add(fake_child_spec("time", "good", enabled=False), ADMIN_ACTOR)
        assert sup.registry.get(ServerKey(None, "time")).owner is None
        snap = admin_snapshot(sup)
        await sup.add(fake_child_spec("clock", "good", enabled=False), snap)
        assert sup.registry.get(ServerKey(None, "clock")).owner is None
    finally:
        await drain(sup)


def test_the_helpers_register_the_constants(tmp_path):
    """Guard of the fixture itself: `build` registers ALICE and BOB."""
    sup = build(tmp_path)
    local = sup.policy.local_identity()
    assert local.get_user("alice").id == ALICE.id
    assert local.get_user("bob").id == BOB.id
    register_actors(sup, ALICE)  # idempotent
