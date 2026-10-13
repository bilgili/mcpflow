"""The incarnation of a user id (bind-actor-to-server-writes, gate tasks T1 and T2).

Scenarios from `specs/identity/spec.md` (requirements "Identity provider
interface" and "Incarnation of a user id") and `specs/access-policy/spec.md`
(scenario "A re-used id does not let an old request act", requirement
"Write-time actor check"). Model: `WriteByCurrentIncarnation`. The expected
values come from the scenarios, not from the implementation.
"""

from __future__ import annotations

import dataclasses
import json

import pytest
from conftest import make_user
from test_policy import make_world

from mcpflow.auth import hash_password
from mcpflow.identity import LocalIdentityProvider, User
from mcpflow.policy import ADMIN_REQUIRED, UNKNOWN_ACTOR


def recreate(w, uid: str, **kw) -> User:
    """Delete `uid` through the policy, then create an active user of that id."""
    w.policy.delete_user(w.root, uid)
    return make_user(w.ident, uid, "pw", **kw)


# --- ID-1: the field -----------------------------------------------------------


def test_a_user_built_with_the_defaults_has_incarnation_0():
    """Scenario "A user built with the defaults has incarnation 0"."""
    user = User(id="alice", name="alice", groups=frozenset(), provider="local")
    assert user.incarnation == 0


def test_incarnation_is_the_last_keyword_only_field():
    """Requirement "Identity provider interface": the last field, an int, default 0."""
    fields = dataclasses.fields(User)
    assert [f.name for f in fields] == ["id", "name", "groups", "provider", "pending", "incarnation"]
    last = fields[-1]
    assert last.default == 0 and last.kw_only is True and last.compare is True


def test_incarnation_takes_part_in_equality():
    """Requirement "Identity provider interface": two incarnations are two users."""
    base = {"id": "alice", "name": "alice", "groups": frozenset(), "provider": "local"}
    assert User(**base, incarnation=0) != User(**base, incarnation=1)
    assert User(**base, incarnation=1) == User(**base, incarnation=1)
    assert User(**base) == User(**base, incarnation=0)


def test_a_positional_construction_is_refused():
    """Scenario "A positional construction is refused"."""
    with pytest.raises(TypeError):
        User("alice", "alice", frozenset(), False, "local")  # type: ignore[misc]


# --- ID-2: the provider --------------------------------------------------------


def test_a_re_created_id_gets_the_next_incarnation(tmp_path):
    """Scenario "A re-created id gets the next incarnation"."""
    w = make_world(tmp_path)
    assert w.ident.get_user("alice").incarnation == 0
    w.policy.delete_user(w.root, "alice")
    user, _code = w.ident._create_user("alice")
    assert user.incarnation == 1
    assert w.ident.get_user("alice").incarnation == 1


def test_every_re_creation_steps_the_incarnation_again(tmp_path):
    """Requirement "Incarnation of a user id": the next incarnation each time."""
    w = make_world(tmp_path)
    for expected in (1, 2, 3):
        assert recreate(w, "bob").incarnation == expected
        assert w.ident.get_user("bob").incarnation == expected
    # Another id is untouched.
    assert w.ident.get_user("carol").incarnation == 0


def test_a_new_id_starts_at_incarnation_0(tmp_path):
    """Requirement "Incarnation of a user id": a new id gets incarnation 0."""
    w = make_world(tmp_path)
    user, _code = w.ident._create_user("dave")
    assert user.incarnation == 0
    assert w.ident.get_user("dave").incarnation == 0


@pytest.mark.parametrize("recreated", [False, True])
def test_an_unrelated_edit_keeps_the_incarnation(tmp_path, recreated):
    """Scenario "An unrelated edit keeps the incarnation"."""
    w = make_world(tmp_path)
    if recreated:
        recreate(w, "alice")
    before = w.ident.get_user("alice").incarnation
    assert before == (1 if recreated else 0)
    w.policy.create_group(w.root, "platform")
    w.policy.change_groups(w.root, "alice", add=["ops"])
    assert w.ident.get_user("alice").incarnation == before
    code = w.policy.issue_setup_code(w.root, "alice")
    assert w.ident.get_user("alice").incarnation == before
    state = w.ident.check_setup_code("alice", code)
    assert state is not None
    assert w.ident.replace_credential("alice", state, hash_password("new-password-1", iterations=1000))
    assert w.ident.get_user("alice").incarnation == before
    w.policy.set_admin(w.root, "alice", True)
    w.policy.set_admin(w.root, "alice", False)
    w.policy.set_groups(w.root, "alice", ["eng", "platform"])
    w.policy.remove_member(w.root, "platform", "alice")
    w.policy.delete_group(w.root, "platform")
    after = w.ident.get_user("alice")
    assert after.incarnation == before
    assert [u.incarnation for u in w.ident.list_users() if u.id == "alice"] == [before]


def test_a_second_load_keeps_a_re_created_incarnation(tmp_path):
    """Scenario "A second load keeps a re-created incarnation"."""
    w = make_world(tmp_path)
    recreate(w, "alice")
    assert w.ident.get_user("alice").incarnation == 1
    w.ident.load()
    assert w.ident.get_user("alice").incarnation == 1
    w.ident.load()
    assert w.ident.get_user("alice").incarnation == 1
    assert w.ident.get_user("bob").incarnation == 0


def test_a_load_keeps_the_incarnation_of_a_deleted_id_for_its_next_creation(tmp_path):
    """Requirement "Incarnation of a user id": a deleted id keeps its incarnation."""
    w = make_world(tmp_path)
    recreate(w, "bob")  # incarnation 1
    w.policy.delete_user(w.root, "bob")
    w.ident.load()  # the file holds no bob
    user, _code = w.ident._create_user("bob")
    assert user.incarnation == 2


def test_a_load_writes_nothing_for_the_incarnation(tmp_path, users_writes):
    """Scenario "A load writes nothing for the incarnation"."""
    path = tmp_path / "users.json"
    admin_hash = hash_password("pw", iterations=1000)
    first = LocalIdentityProvider(path, admin_hash)
    first.load()  # the first start writes the bootstrap file
    make_user(first, "alice", "pw")
    on_disk = path.read_bytes()
    users_writes["n"] = 0
    for _ in range(2):  # two more starts, one fresh provider each
        again = LocalIdentityProvider(path, admin_hash)
        again.load()
        assert {u.id: u.incarnation for u in again.list_users()} == {"admin": 0, "alice": 0}
    assert users_writes["n"] == 0
    assert path.read_bytes() == on_disk
    assert b"incarnation" not in on_disk


def test_users_json_never_holds_the_incarnation(tmp_path):
    """Requirement "Incarnation of a user id": `users.json` stays version 2."""
    w = make_world(tmp_path)
    recreate(w, "alice")
    recreate(w, "alice")
    w.policy.change_groups(w.root, "alice", add=["ops"])
    raw = (tmp_path / "users.json").read_text()
    data = json.loads(raw)
    assert data["version"] == 2
    assert all("incarnation" not in rec for rec in data["users"])
    assert "incarnation" not in raw
    assert w.ident.get_user("alice").incarnation == 2


def test_the_bootstrap_user_keeps_incarnation_0(tmp_path):
    """Scenario "The bootstrap user keeps incarnation 0"."""
    w = make_world(tmp_path)
    w.policy.change_groups(w.root, "bob", add=["ops"])
    recreate(w, "carol")
    w.ident.load()
    assert w.ident.get_user("admin").incarnation == 0
    assert w.root.incarnation == 0


# --- AP-1: the write-time check reads it ---------------------------------------


def test_an_old_snapshot_cannot_mint_a_token(tmp_path):
    """Scenario "A re-used id does not let an old request act" (`WriteByCurrentIncarnation`)."""
    w = make_world(tmp_path)
    old = w.bob
    assert not old.is_admin and old.incarnation == 0
    new = recreate(w, "bob")
    assert new.incarnation == 1 and new.id == old.id
    with pytest.raises(PermissionError) as exc:
        w.policy.mint_token(old, "t", "mcp")
    assert str(exc.value) == UNKNOWN_ACTOR == "the acting user is unknown"
    assert w.policy.tokens_for(new) == []
    assert w.tokens.list() == []


def test_the_new_incarnation_mints_for_itself(tmp_path):
    """The stamp refuses only the old snapshot: the new user acts."""
    w = make_world(tmp_path)
    new = recreate(w, "bob")
    record, clear = w.policy.mint_token(new, "t", "mcp")
    assert clear and record.user_id == "bob"
    assert [r.user_id for r in w.policy.tokens_for(new)] == ["bob"]


def test_an_old_snapshot_cannot_revoke_a_token(tmp_path):
    """The same check guards `revoke_token`."""
    w = make_world(tmp_path)
    old = w.bob
    new = recreate(w, "bob")
    record, _ = w.policy.mint_token(new, "t", "mcp")
    with pytest.raises(PermissionError, match=UNKNOWN_ACTOR):
        w.policy.revoke_token(old, record.id)
    assert [r.id for r in w.policy.tokens_for(new)] == [record.id]


def test_require_current_checks_the_incarnation_before_the_role(tmp_path):
    """An old ADMIN snapshot of a re-created non-admin id is an unknown actor."""
    w = make_world(tmp_path)
    admin_dave = make_user(w.ident, "dave", "pw", admin=True)
    assert admin_dave.is_admin
    # Same incarnation, lost role: the role text.
    w.policy.set_admin(w.root, "dave", False)
    with pytest.raises(PermissionError) as lost:
        w.policy.require_current(admin_dave)
    assert str(lost.value) == ADMIN_REQUIRED
    # Another incarnation, still no role: the unknown-actor text wins.
    w.policy.set_admin(w.root, "dave", True)
    recreate(w, "dave")  # non-admin, incarnation 1
    with pytest.raises(PermissionError) as old:
        w.policy.require_current(admin_dave)
    assert str(old.value) == UNKNOWN_ACTOR


def test_a_user_built_outside_the_store_fails_closed(tmp_path):
    """Scenario "A user built outside the store fails closed"."""
    w = make_world(tmp_path)
    ghost = User(id="ghost", name="ghost", groups=frozenset({"admins"}), provider="local")
    with pytest.raises(PermissionError) as exc:
        w.policy.create_group(ghost, "release")
    assert str(exc.value) == UNKNOWN_ACTOR
    assert "release" not in w.ident.list_groups()


def test_the_bootstrap_admin_passes_the_check(tmp_path):
    """Scenario "The bootstrap admin passes the check"."""
    w = make_world(tmp_path)
    w.policy.create_group(w.root, "release")
    assert "release" in w.ident.list_groups()
