"""The ten direct server writes check their actor (bind-actor-to-server-writes, T8, direct calls).

Requirements "Server writes check the actor at write time" and "The write-time
right of a server write" of `specs/access-policy/spec.md`, and the frozen
interfaces of `design.md` D10. `finish_oauth` is in `test_bind_actor_oauth.py`;
`run_action` is in `test_bind_actor_actions.py`.

The world holds an admin-owned `time` (disabled, so no child starts), a pending
`github@bob`, and the admin `carol` who owns nothing. A refused write changes
no file of the data dir, no record, no child status, and no root mute. Model:
`WriteByCurrentAdmin`, `NoWriteByDeleted`, `WriteByCurrentIncarnation`,
`WriteNeedsRight`, `OwnerKeepsOwnKey`, `BootAlwaysAdmin`, `BootNeverRefused`,
`EdgeAdmittedNeverDenied`, `LockHolderLocked`, `FailedWriteChangesNothing`,
`CommittedWriteStays`.
"""

from __future__ import annotations

import asyncio
import inspect
from pathlib import Path

import pytest
from conftest import ADMIN_ACTOR, fake_child_spec, make_user
from keyed_stores import BOB, build, drain, tree, user_spec

from mcpflow.identity import ADMINS_GROUP, User
from mcpflow.policy import ADMIN_REQUIRED, UNKNOWN_ACTOR
from mcpflow.registry import ServerKey, revision
from mcpflow.supervisor import Supervisor

TIME = ServerKey(None, "time")
PEND = ServerKey("bob", "github")  # pending after `bob` adds it
BOB_OWN = ServerKey("bob", "notes")  # approved, owned by bob
CAROL_OWN = ServerKey("carol", "github")

TEN = ["update", "approve", "remove", "enable", "disable", "restart",
       "write_source", "set_root_muted", "set_namespace_muted", "set_tool_muted"]
CAN_MANAGE = ["update", "remove", "enable", "disable", "restart"]
ADMIN_ONLY = ["approve", "write_source", "set_root_muted", "set_namespace_muted",
              "set_tool_muted"]


def new_spec(key: ServerKey, **extra):
    """A valid replacement record for `key`."""
    if key.owner is None:
        return fake_child_spec(key.namespace, "good", enabled=False, description="changed", **extra)
    return user_spec(key.namespace, key.owner, enabled=False, description="changed", **extra)


def call(sup: Supervisor, name: str, who: User, key: ServerKey | None = None):
    """Start one write. An async write returns a coroutine; a sync write raises at once."""
    key = key or (PEND if name == "approve" else TIME)
    if name == "update":
        return sup.update(key, new_spec(key), who)
    if name == "approve":
        return sup.approve(key, revision(sup.registry.get(key)), who)
    if name == "write_source":
        return sup.write_source(key, {"a.py": "x = 1\n"}, who)
    if name == "set_root_muted":
        return sup.set_root_muted(True, who)
    if name == "set_namespace_muted":
        return sup.set_namespace_muted(key, True, who)
    if name == "set_tool_muted":
        return sup.set_tool_muted(key, "get_current_time", True, who)
    return getattr(sup, name)(key, who)


async def run(sup: Supervisor, name: str, who: User, key: ServerKey | None = None):
    result = call(sup, name, who, key)
    if inspect.isawaitable(result):
        result = await result
    return result


def state(sup: Supervisor, root: Path) -> dict:
    """Everything a refused write must leave alone."""
    return {
        "tree": tree(root),
        "specs": [s.model_dump(mode="json") for s in sup.registry.list()],
        "status": {c.spec.key.ref: c.status for c in sup.children()},
        "root_muted": sup.root_muted(),
    }


async def world(tmp_path: Path, *extra, carol_admin: bool = True) -> Supervisor:
    """`time`, the pending `github@bob`, and `carol`; seeded log, credential, source."""
    sup = build(tmp_path, fake_child_spec("time", "good", enabled=False), *extra)
    local = sup.policy.local_identity()
    make_user(local, "carol", admin=carol_admin)
    await sup.add(user_spec("github", "bob", enabled=False), BOB)
    assert sup.registry.get(PEND).approval == "pending"
    (tmp_path / "logs" / "time.log").write_text("old log\n")
    (tmp_path / "creds" / "time").mkdir(parents=True)
    (tmp_path / "creds" / "time" / "token.json").write_text('{"old": true}')
    (tmp_path / "servers" / "time").mkdir(parents=True)
    (tmp_path / "servers" / "time" / "old.py").write_text("old = 1\n")
    return sup


def snapshot(sup: Supervisor, uid: str) -> User:
    user = sup.policy.local_identity().get_user(uid)
    assert user is not None
    return user


# --- WriteByCurrentAdmin, NoWriteByDeleted, WriteByCurrentIncarnation -----------


@pytest.mark.asyncio
@pytest.mark.parametrize("name", TEN)
async def test_write_by_current_admin(tmp_path, name):
    """Scenarios "A revoke before an update/approve/remove/enable/disable/restart/
    root mute/namespace mute/tool mute/source write refuses it"."""
    sup = await world(tmp_path)
    try:
        snap = snapshot(sup, "carol")
        assert snap.is_admin
        sup.policy.set_admin(ADMIN_ACTOR, "carol", False)
        before = state(sup, tmp_path)
        with pytest.raises(PermissionError) as exc:
            await run(sup, name, snap)
        assert str(exc.value) == ADMIN_REQUIRED == "the admin role is required"
        assert state(sup, tmp_path) == before
    finally:
        await drain(sup)


@pytest.mark.asyncio
@pytest.mark.parametrize("name", TEN)
@pytest.mark.parametrize("cause", ["deleted", "ghost"])
async def test_no_write_by_deleted(tmp_path, name, cause):
    """Scenario "A deleted actor's server write is refused" (`NoWriteByDeleted`):
    a deleted user, and a user the store never held."""
    sup = await world(tmp_path)
    try:
        if cause == "deleted":
            snap = snapshot(sup, "carol")
            sup.policy.delete_user(ADMIN_ACTOR, "carol")
        else:
            snap = User(id="ghost", name="ghost", groups=frozenset({ADMINS_GROUP}),
                        provider="local")
        before = state(sup, tmp_path)
        with pytest.raises(PermissionError) as exc:
            await run(sup, name, snap)
        assert str(exc.value) == UNKNOWN_ACTOR == "the acting user is unknown"
        assert state(sup, tmp_path) == before
    finally:
        await drain(sup)


@pytest.mark.asyncio
@pytest.mark.parametrize("name", TEN)
async def test_write_by_current_incarnation(tmp_path, name):
    """Delete and re-create `carol` as admin: the old snapshot acts as nobody."""
    sup = await world(tmp_path)
    try:
        old = snapshot(sup, "carol")
        sup.policy.delete_user(ADMIN_ACTOR, "carol")
        new = make_user(sup.policy.local_identity(), "carol", admin=True)
        assert new.is_admin and new.incarnation == old.incarnation + 1
        before = state(sup, tmp_path)
        with pytest.raises(PermissionError) as exc:
            await run(sup, name, old)
        assert str(exc.value) == UNKNOWN_ACTOR
        assert state(sup, tmp_path) == before
        # The new incarnation is a different, current actor.
        if name not in ("restart", "approve"):
            await run(sup, name, new)
    finally:
        await drain(sup)


# --- WriteNeedsRight ---------------------------------------------------------


@pytest.mark.asyncio
async def test_write_needs_right_a_foreign_server_reads_as_missing(tmp_path):
    """Scenario "A direct call for a server of another user is refused"."""
    sup = build(tmp_path, fake_child_spec("time", "good", enabled=False),
                user_spec("github", "carol"))
    try:
        bob = snapshot(sup, "bob")
        before = state(sup, tmp_path)
        with pytest.raises(KeyError) as exc:
            await sup.disable(CAROL_OWN, bob)
        assert exc.value.args[0] == "github@carol"
        assert sup.registry.get(CAROL_OWN).enabled is True
        for name in CAN_MANAGE:  # the admin-owned `time`, and the server of carol
            for key in (TIME, CAROL_OWN):
                with pytest.raises(KeyError) as other:
                    await run(sup, name, bob, key)
                assert other.value.args[0] == key.ref
        assert state(sup, tmp_path) == before
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_an_owner_cannot_approve_its_own_server(tmp_path):
    """Scenario "An owner cannot approve its own server"."""
    sup = await world(tmp_path)
    try:
        bob = snapshot(sup, "bob")
        before = state(sup, tmp_path)
        with pytest.raises(PermissionError) as exc:
            await sup.approve(PEND, revision(sup.registry.get(PEND)), bob)
        assert str(exc.value) == ADMIN_REQUIRED
        assert sup.registry.get(PEND).approval == "pending"
        assert state(sup, tmp_path) == before
    finally:
        await drain(sup)


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["set_root_muted", "set_namespace_muted", "set_tool_muted",
                                  "write_source"])
async def test_admin_only_writes_refuse_a_non_admin(tmp_path, name):
    """Requirement "The write-time right of a server write": admin role required."""
    sup = await world(tmp_path)
    try:
        bob = snapshot(sup, "bob")
        before = state(sup, tmp_path)
        with pytest.raises(PermissionError) as exc:
            await run(sup, name, bob)
        assert str(exc.value) == ADMIN_REQUIRED
        assert state(sup, tmp_path) == before
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_a_promotion_inside_the_request_grants_nothing(tmp_path):
    """Scenario "A promotion inside the request grants nothing"."""
    sup = await world(tmp_path)
    try:
        bob = snapshot(sup, "bob")
        assert not bob.is_admin
        sup.policy.set_admin(ADMIN_ACTOR, "bob", True)
        before = state(sup, tmp_path)
        with pytest.raises(PermissionError) as exc:
            sup.set_root_muted(True, bob)
        assert str(exc.value) == ADMIN_REQUIRED
        assert sup.root_muted() is False
        assert state(sup, tmp_path) == before
        # The next snapshot is an admin and writes.
        sup.set_root_muted(True, snapshot(sup, "bob"))
        assert sup.root_muted() is True
    finally:
        await drain(sup)


# --- OwnerKeepsOwnKey --------------------------------------------------------


@pytest.mark.asyncio
async def test_owner_keeps_own_key(tmp_path):
    """Scenarios "A demoted admin keeps the rights on an own server" and "A demoted
    admin's write in flight on an own server is refused" (`OwnerKeepsOwnKey`)."""
    sup = build(tmp_path, fake_child_spec("time", "good", enabled=False),
                user_spec("github", "carol", enabled=False))
    try:
        make_user(sup.policy.local_identity(), "carol", admin=True)
        admin_snapshot = snapshot(sup, "carol")
        assert admin_snapshot.is_admin
        sup.policy.set_admin(ADMIN_ACTOR, "carol", False)
        fresh = snapshot(sup, "carol")
        assert not fresh.is_admin
        child = sup.get(CAROL_OWN)
        child.status = "failed"
        # The request in flight carries the admin snapshot: refused (the veto rule).
        before = state(sup, tmp_path)
        with pytest.raises(PermissionError, match=ADMIN_REQUIRED):
            await sup.restart(CAROL_OWN, admin_snapshot)
        assert state(sup, tmp_path) == before
        # A retry with a fresh snapshot passes, as the owner, for every can_manage write.
        await sup.restart(CAROL_OWN, fresh)
        assert child.task is not None
        await sup.disable(CAROL_OWN, fresh)
        assert sup.registry.get(CAROL_OWN).enabled is False
        await sup.enable(CAROL_OWN, fresh)
        assert sup.registry.get(CAROL_OWN).enabled is True
        await sup.update(CAROL_OWN, new_spec(CAROL_OWN), fresh)
        assert sup.registry.get(CAROL_OWN).description == "changed"
        await sup.remove(CAROL_OWN, fresh)
        assert CAROL_OWN not in {s.key for s in sup.registry.list()}
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_an_owner_does_not_gain_an_admin_only_write(tmp_path):
    """The owner rights never reach the admin-only writes."""
    sup = build(tmp_path, user_spec("github", "carol", enabled=False))
    try:
        make_user(sup.policy.local_identity(), "carol")
        carol = snapshot(sup, "carol")
        for name in ("approve", "write_source", "set_namespace_muted", "set_tool_muted"):
            with pytest.raises(PermissionError, match=ADMIN_REQUIRED):
                await run(sup, name, carol, CAROL_OWN)
    finally:
        await drain(sup)


# --- BootAlwaysAdmin, BootNeverRefused ---------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("name", TEN)
async def test_the_bootstrap_admin_is_never_refused(tmp_path, name):
    """Scenario "The bootstrap admin passes the decision" (`BootNeverRefused`)."""
    sup = await world(tmp_path)
    try:
        if name == "restart":
            sup.get(TIME).status = "failed"
        await run(sup, name, ADMIN_ACTOR)  # no refusal, no other error
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_the_bootstrap_admin_restarts_a_running_child(tmp_path):
    """Scenario "The bootstrap admin passes the decision": a running `time` restarts."""
    sup = build(tmp_path, fake_child_spec("time", "good", enabled=False))
    try:
        await sup.enable(TIME, ADMIN_ACTOR)
        child = sup.get(TIME)
        await child.task
        assert child.status == "running"
        old_task = child.task
        await sup.restart(TIME, ADMIN_ACTOR)
        assert child.task is not old_task
        await child.task
        assert child.status == "running"
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_boot_always_admin(tmp_path):
    """`BootAlwaysAdmin`: the store refuses to demote or delete `admin`."""
    sup = await world(tmp_path)
    try:
        with pytest.raises(ValueError):
            sup.policy.set_admin(ADMIN_ACTOR, "admin", False)
        with pytest.raises(ValueError):
            sup.policy.delete_user(ADMIN_ACTOR, "admin")
        with pytest.raises(ValueError):
            sup.policy.change_groups(ADMIN_ACTOR, "admin", remove=[ADMINS_GROUP])
        assert snapshot(sup, "admin").is_admin
        sup.set_root_muted(True, snapshot(sup, "admin"))
    finally:
        await drain(sup)


# --- EdgeAdmittedNeverDenied -------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("name", CAN_MANAGE)
@pytest.mark.parametrize("who, key", [("carol", TIME), ("carol", BOB_OWN), ("bob", BOB_OWN)],
                         ids=["admin-on-admin-key", "admin-on-user-key", "owner-on-own-key"])
async def test_edge_admitted_never_denied(tmp_path, name, who, key):
    """A current admin on any key, and a current owner on its own key, pass the
    can_manage writes with no refusal (`EdgeAdmittedNeverDenied`, G6)."""
    sup = await world(tmp_path, user_spec("notes", "bob", enabled=False))
    try:
        if name == "restart":
            sup.get(key).status = "failed"
        await run(sup, name, snapshot(sup, who), key)
    finally:
        await drain(sup)


# --- LockHolderLocked --------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["update", "approve", "remove", "enable", "disable", "restart"])
async def test_a_write_waits_for_the_lock_then_checks(tmp_path, name):
    """The decision falls after the lock await (`LockHolderLocked`, G2): a revoke
    that lands while the write waits refuses it."""
    sup = await world(tmp_path)
    try:
        key = PEND if name == "approve" else TIME
        snap = snapshot(sup, "carol")
        child = sup.get(key)
        async with child.lock:
            task = asyncio.ensure_future(run(sup, name, snap, key))
            await asyncio.sleep(0.05)
            assert not task.done(), "the write did not wait for the child lock"
            sup.policy.set_admin(ADMIN_ACTOR, "carol", False)
            before = state(sup, tmp_path)
        with pytest.raises(PermissionError) as exc:
            await asyncio.wait_for(task, 5)
        assert str(exc.value) == ADMIN_REQUIRED
        assert state(sup, tmp_path) == before
    finally:
        await drain(sup)


# --- CommittedWriteStays -----------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["update", "remove", "disable"])
async def test_a_revoke_during_the_teardown_keeps_the_committed_write(tmp_path, name):
    """Scenario "A revoke after the commit does not undo the write"."""
    sup = build(tmp_path, fake_child_spec("time", "good"))  # enabled, never started
    make_user(sup.policy.local_identity(), "carol", admin=True)
    try:
        snap = snapshot(sup, "carol")
        fired: list[int] = []
        real = sup._teardown

        async def teardown(child):
            if not fired:
                fired.append(1)
                sup.policy.set_admin(ADMIN_ACTOR, "carol", False)
            await real(child)

        sup._teardown = teardown
        if name == "update":
            await sup.update(TIME, new_spec(TIME), snap)
            assert sup.registry.get(TIME).description == "changed"
            assert sup.registry.get(TIME).enabled is False
        elif name == "remove":
            await sup.remove(TIME, snap)
            assert TIME not in {s.key for s in sup.registry.list()}
        else:
            await sup.disable(TIME, snap)
            assert sup.registry.get(TIME).enabled is False
        assert fired, "the revoke never ran: the window was not exercised"
        assert snapshot(sup, "carol").is_admin is False
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_write_source_files_stay_when_the_restart_refuses(tmp_path):
    """Design D3, row `write_source`: the files of a refused restart stay."""
    sup = await world(tmp_path)
    try:
        snap = snapshot(sup, "carol")
        child = sup.get(TIME)
        child.status = "failed"
        written: list[Path] = []
        real = sup.sources.write

        def write(ref, files):
            path = real(ref, files)
            written.append(path)
            sup.policy.set_admin(ADMIN_ACTOR, "carol", False)
            return path

        sup.sources.write = write
        with pytest.raises(PermissionError, match=ADMIN_REQUIRED):
            await sup.write_source(TIME, {"a.py": "x = 1\n"}, snap)
        assert written, "the revoke never ran"
        assert (written[0] / "a.py").read_text() == "x = 1\n"
        assert child.status == "failed", "the refused restart tore the child down"
    finally:
        await drain(sup)


# --- the frozen interfaces (design D10) --------------------------------------


def _names(fn) -> list[str]:
    return list(inspect.signature(fn).parameters)


def test_the_frozen_signatures():
    S = Supervisor
    assert _names(S.update) == ["self", "key", "spec", "actor"]
    assert _names(S.approve) == ["self", "key", "revision", "actor"]
    assert _names(S.remove) == ["self", "key", "actor"]
    assert _names(S.enable) == ["self", "key", "actor"]
    assert _names(S.disable) == ["self", "key", "actor"]
    assert _names(S.restart) == ["self", "key", "actor"]
    assert _names(S.write_source) == ["self", "key", "files", "actor"]
    assert _names(S.set_root_muted) == ["self", "muted", "actor"]
    assert _names(S.set_namespace_muted) == ["self", "key", "muted", "actor"]
    assert _names(S.set_tool_muted) == ["self", "key", "tool", "muted", "actor"]
    for fn in (S.update, S.approve, S.remove, S.enable, S.disable, S.restart, S.write_source,
               S.set_root_muted, S.set_namespace_muted, S.set_tool_muted, S.run_action):
        params = inspect.signature(fn).parameters
        assert params["actor"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
        assert params["actor"].default is inspect.Parameter.empty
        positional = [p for p in params.values()
                      if p.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD,)]
        assert positional[-1].name == "actor"
    # The coroutine split: the three mutes stay synchronous, the rest await.
    for fn in (S.update, S.approve, S.remove, S.enable, S.disable, S.restart, S.write_source,
               S.run_action, S.finish_oauth, S.add):
        assert inspect.iscoroutinefunction(fn), fn.__name__
    for fn in (S.set_root_muted, S.set_namespace_muted, S.set_tool_muted):
        assert not inspect.iscoroutinefunction(fn), fn.__name__


def test_run_action_keeps_its_keyword_only_masks():
    params = inspect.signature(Supervisor.run_action).parameters
    assert list(params)[:5] == ["self", "key", "name", "form", "actor"]
    for name in ("rendered_password_keys", "rendered_secrets"):
        assert params[name].kind is inspect.Parameter.KEYWORD_ONLY
        assert params[name].default == frozenset()


def test_finish_oauth_and_add_keep_their_signatures():
    fin = inspect.signature(Supervisor.finish_oauth).parameters
    assert list(fin) == ["self", "flow", "token_fmt", "tokens", "client_fmt", "reauth", "header"]
    assert fin["client_fmt"].default is None and fin["reauth"].default is False
    assert fin["header"].default is None
    add = inspect.signature(Supervisor.add).parameters
    assert list(add) == ["self", "spec", "actor", "client_fmt", "client"]
