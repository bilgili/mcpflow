"""The write-time actor check of `AccessPolicy` (reresolve-actor-at-write, T1).

Scenarios of `specs/access-policy/spec.md` in the change: "Write-time actor
check" (a revoke between the gate and the write, a deleted actor, a still-admin
actor, a non-admin actor, an own token, a user built outside the store, the
bootstrap admin, a refused cascade) and "Reads decide on the request snapshot".
Frozen interfaces: `design.md` D1, D2, D6, D8, D9. Model properties:
`WriteByCurrentAdmin`, `NoWriteByDeleted`, `FailedWriteChangesNothing`,
`ReReadNeverGrants`, `BootNeverRefused`.
"""

from __future__ import annotations

import inspect

import pytest
from conftest import ADMIN_ACTOR
from test_admins_group_policy import sig
from test_policy import _files, allow, make_world

from mcpflow.identity import IdentityProvider, LocalIdentityProvider, User
from mcpflow.policy import ADMIN_REQUIRED, UNKNOWN_ACTOR, AccessPolicy
from mcpflow.registry import ServerKey
from mcpflow.supervisor import Supervisor

GHOST = User(id="ghost", name="ghost", groups=frozenset({"admins"}), provider="local")
STORES = ("users.json", "rules.json", "tokens.json", "user_tokens.json")


def stores(path):
    """The bytes of the four identity-side stores; a missing file reads None."""
    return {n: (path / n).read_bytes() if (path / n).exists() else None for n in STORES}


def seeded(tmp_path):
    """`make_world` plus a rule and a token of `bob`, and `alice` as admin."""
    w = make_world(tmp_path)
    rule = allow(w, "user", "bob", "server", "time")
    token, _ = w.policy.mint_token(w.root, "laptop", "mcp", "bob")
    w.policy.set_admin(w.root, "alice", True)
    w.rule_id, w.token_id = rule.id, token.id
    return w


def writes(w):
    """The 14 writes. Each reaches its first store write for an admin actor."""
    return {
        "add_rule": lambda p, a: p.add_rule(
            a, subject_kind="user", subject="carol", level="server",
            server="time", tool=None, effect="allow"),
        "remove_rule": lambda p, a: p.remove_rule(a, w.rule_id),
        "delete_user": lambda p, a: p.delete_user(a, "bob"),
        "delete_group": lambda p, a: p.delete_group(a, "ops"),
        "create_user": lambda p, a: p.create_user(a, "dave"),
        "issue_setup_code": lambda p, a: p.issue_setup_code(a, "carol"),
        "set_admin": lambda p, a: p.set_admin(a, "carol", True),
        "change_groups": lambda p, a: p.change_groups(a, "carol", add=["ops"]),
        "set_groups": lambda p, a: p.set_groups(a, "carol", ["ops"]),
        "remove_member": lambda p, a: p.remove_member(a, "eng", "alice"),
        "change_members": lambda p, a: p.change_members(a, "eng", add=["carol"]),
        "create_group": lambda p, a: p.create_group(a, "newg"),
        "mint_token": lambda p, a: p.mint_token(a, "t2", "admin", "carol"),
        "revoke_token": lambda p, a: p.revoke_token(a, w.token_id),
    }


WRITES = sorted(writes(type("S", (), {"rule_id": "x", "token_id": "y"})))
CAUSES = ("demoted", "deleted", "outside")
TEXT = {"demoted": ADMIN_REQUIRED, "deleted": UNKNOWN_ACTOR, "outside": UNKNOWN_ACTOR}


def snapshot_for(w, cause):
    """The actor snapshot the gate took, and the store change that follows it."""
    if cause == "outside":
        return GHOST
    snap = w.ident.get_user("alice")
    assert snap.is_admin
    if cause == "demoted":
        w.policy.set_admin(w.root, "alice", False)
    else:
        w.policy.delete_user(w.root, "alice")
    return snap


# --- the frozen texts and signatures (D9, G5) -------------------------------


def test_the_error_texts_are_the_frozen_ones():
    assert ADMIN_REQUIRED == "the admin role is required"
    assert UNKNOWN_ACTOR == "the acting user is unknown"


def test_the_frozen_signatures():
    assert [p[0] for p in sig(AccessPolicy.require_current)] == ["self", "actor"]
    assert inspect.signature(AccessPolicy.require_current).return_annotation in (None, "None")
    params = inspect.signature(Supervisor.add).parameters
    assert list(params) == ["self", "spec", "actor", "client_fmt", "client"]
    assert params["client_fmt"].default is None and params["client"].default is None
    assert params["actor"].default is inspect.Parameter.empty


def test_require_current_and_get_user_are_not_coroutine_functions():
    """R6: an `await` in the read would open a window between check and write."""
    assert not inspect.iscoroutinefunction(AccessPolicy.require_current)
    assert not inspect.iscoroutinefunction(LocalIdentityProvider.get_user)
    assert not inspect.iscoroutinefunction(IdentityProvider.get_user)


# --- the three refusals, over all 14 writes ----------------------------------


def test_the_write_table_names_fourteen_writes():
    assert len(WRITES) == 14


@pytest.mark.parametrize("name", WRITES)
def test_a_still_admin_actor_writes(tmp_path, name):
    """Scenario "A still-admin actor writes" (and the control of the refusals)."""
    w = seeded(tmp_path)
    alice = w.ident.get_user("alice")
    before = stores(tmp_path)
    writes(w)[name](w.policy, alice)
    assert stores(tmp_path) != before, f"{name} wrote nothing for an admin"


@pytest.mark.parametrize("name", WRITES)
def test_write_by_current_admin(tmp_path, name):
    """Scenario "A revoke between the gate and the write refuses the write"."""
    w = seeded(tmp_path)
    snap = snapshot_for(w, "demoted")
    with pytest.raises(PermissionError) as exc:
        writes(w)[name](w.policy, snap)
    assert str(exc.value) == "the admin role is required"


@pytest.mark.parametrize("cause", ("deleted", "outside"))
@pytest.mark.parametrize("name", WRITES)
def test_no_write_by_deleted(tmp_path, name, cause):
    """Scenarios "A deleted actor is refused", "A user built outside the store
    fails closed"."""
    w = seeded(tmp_path)
    snap = snapshot_for(w, cause)
    with pytest.raises(PermissionError) as exc:
        writes(w)[name](w.policy, snap)
    assert str(exc.value) == "the acting user is unknown"


@pytest.mark.parametrize("cause", CAUSES)
@pytest.mark.parametrize("name", WRITES)
def test_failed_write_changes_nothing(tmp_path, name, cause):
    w = seeded(tmp_path)
    snap = snapshot_for(w, cause)
    before = stores(tmp_path)
    all_json = _files(tmp_path)
    with pytest.raises(PermissionError, match=TEXT[cause]):
        writes(w)[name](w.policy, snap)
    assert stores(tmp_path) == before
    assert _files(tmp_path) == all_json


def test_a_refused_delete_user_keeps_the_cascade_targets(tmp_path):
    """Scenario "A refused cascade changes no store"."""
    w = seeded(tmp_path)
    snap = snapshot_for(w, "demoted")
    with pytest.raises(PermissionError):
        w.policy.delete_user(snap, "bob")
    assert w.ident.get_user("bob") is not None
    assert [t.id for t in w.tokens.list_for("bob")] == [w.token_id]
    assert [r.id for r in w.rules.list()] == [w.rule_id]


# --- what the check never does ----------------------------------------------


def test_a_non_admin_actor_is_refused_as_before(tmp_path):
    """Scenario "A non-admin actor is refused as before" (G6)."""
    w = make_world(tmp_path)
    before = stores(tmp_path)
    with pytest.raises(PermissionError) as exc:
        w.policy.add_rule(w.bob, subject_kind="user", subject="carol",
                          level="server", server="time", tool=None, effect="allow")
    assert str(exc.value) == "the admin role is required"
    assert stores(tmp_path) == before


def test_a_non_admin_mints_an_own_token_as_before(tmp_path):
    """Scenario "A non-admin actor mints an own token as before"."""
    w = make_world(tmp_path)
    held = len(w.policy.tokens_for(w.bob))
    w.policy.mint_token(w.bob, "t", "mcp")
    assert len(w.policy.tokens_for(w.bob)) == held + 1


def test_re_read_never_grants(tmp_path):
    """`ReReadNeverGrants`: a promotion inside the request does not upgrade it."""
    w = make_world(tmp_path)
    snap = w.ident.get_user("bob")
    assert not snap.is_admin
    w.policy.set_admin(w.root, "bob", True)
    before = stores(tmp_path)
    with pytest.raises(PermissionError) as exc:
        w.policy.add_rule(snap, subject_kind="user", subject="carol",
                          level="server", server="time", tool=None, effect="allow")
    assert str(exc.value) == "the admin role is required"
    with pytest.raises(PermissionError):
        w.policy.mint_token(snap, "t", "admin")
    assert stores(tmp_path) == before


def test_the_bootstrap_admin_is_never_refused(tmp_path):
    """Scenario "The bootstrap admin passes the check" (`BootNeverRefused`)."""
    w = make_world(tmp_path)
    w.policy.create_group(ADMIN_ACTOR, "newg")
    assert "newg" in w.ident.list_groups()
    w.policy.set_admin(ADMIN_ACTOR, "alice", True)
    assert w.ident.get_user("alice").is_admin


def test_a_demoted_admins_own_mint_is_refused_and_a_retry_succeeds(tmp_path):
    """R4 and Q3: the veto rule; the retry takes the user branch."""
    w = seeded(tmp_path)
    snap = snapshot_for(w, "demoted")
    with pytest.raises(PermissionError) as exc:
        w.policy.mint_token(snap, "t", "mcp")
    assert str(exc.value) == "the admin role is required"
    held = len(w.policy.tokens_for(w.ident.get_user("alice")))
    w.policy.mint_token(w.ident.get_user("alice"), "t", "mcp")
    assert len(w.policy.tokens_for(w.ident.get_user("alice"))) == held + 1


# --- the provider contract (D8, D9) -----------------------------------------


class Delegate:
    """An identity provider that counts or breaks `get_user`."""

    def __init__(self, inner, fail=None):
        self.inner, self.fail, self.calls = inner, fail, 0

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def get_user(self, uid):
        self.calls += 1
        if self.fail is not None:
            raise self.fail
        return self.inner.get_user(uid)


def test_require_current_reads_the_provider_once(tmp_path):
    w = make_world(tmp_path)
    counting = Delegate(w.ident)
    policy = AccessPolicy(counting, w.rules, w.tokens, w.reg)
    before = _files(tmp_path)
    assert policy.require_current(w.bob) is None
    assert counting.calls == 1
    assert _files(tmp_path) == before


@pytest.mark.parametrize("name", WRITES)
def test_a_provider_error_passes_through(tmp_path, name):
    w = seeded(tmp_path)
    boom = RuntimeError("provider down")
    policy = AccessPolicy(Delegate(w.ident, fail=boom), w.rules, w.tokens, w.reg)
    before = _files(tmp_path)
    with pytest.raises(RuntimeError) as exc:
        writes(w)[name](policy, w.ident.get_user("alice"))
    assert exc.value is boom
    assert _files(tmp_path) == before


# --- reads keep the snapshot (D6) -------------------------------------------


def test_the_list_reads_keep_the_snapshot(tmp_path):
    """Requirement "Reads decide on the request snapshot"."""
    w = seeded(tmp_path)
    snap = snapshot_for(w, "demoted")
    assert w.policy.list_users(snap)
    assert w.policy.list_groups(snap)
    assert isinstance(w.policy.list_rules(snap), list)
    for read in (w.policy.list_users, w.policy.list_groups, w.policy.list_rules):
        with pytest.raises(PermissionError) as exc:
            read(w.bob)
        assert str(exc.value) == "the admin role is required"


def test_the_other_reads_accept_the_snapshot_of_a_deleted_user(tmp_path):
    w = seeded(tmp_path)
    snap = snapshot_for(w, "deleted")
    w.policy.keys_for(snap, "dashboard")
    w.policy.tokens_for(snap)
    assert w.policy.can_manage(snap, ServerKey(None, "time")) in (True, False)
