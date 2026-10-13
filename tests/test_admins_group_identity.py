"""The identity provider under the reserved group `admins` (admins-group, 8.3).

Scenarios: identity "Change memberships by delta", "Replace memberships keeps
the admin role", "Set the admin role", "Remove one membership", "Reserved
group admins", "Bootstrap admin user", "Setup code". Design D2, D4, D5, D7,
D8 (error order, "before any write"), I2 to I5, I8, `DeltaIdempotent`.

Each refusal asserts that `users.json` is byte-identical (I5, "before any
write"). The error order of the D8 tables is tested row by row.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from mcpflow.auth import hash_password
from mcpflow.identity import ADMINS_GROUP, BOOTSTRAP_ADMIN_ID, LocalIdentityProvider


@pytest.fixture
def world(tmp_path):
    """Groups `eng`, `ops`; users `alice` (eng), `bob`; the bootstrap `admin`."""
    path = tmp_path / "users.json"
    p = LocalIdentityProvider(path, hash_password("pw", iterations=1000))
    p.load()
    p._create_group("eng")
    p._create_group("ops")
    p._create_user("alice", groups=["eng"])
    p._create_user("bob")
    return p, path


def stored(path: Path) -> dict:
    return json.loads(path.read_text())


def groups_of(path: Path, uid: str) -> set[str]:
    return set(next(r for r in stored(path)["users"] if r["id"] == uid)["groups"])


def frozen(path: Path):
    return path.read_bytes()


# --- change_groups ---------------------------------------------------------


def test_add_and_remove_in_one_write(world, users_writes):
    """Scenario "Add and remove in one call"."""
    p, path = world
    users_writes["n"] = 0
    p.change_groups("alice", add=["ops"], remove=["eng"])
    assert p.get_user("alice").groups == frozenset({"ops"})
    assert groups_of(path, "alice") == {"ops"}
    assert users_writes["n"] == 1


def test_change_groups_changes_nothing_else(world):
    p, _ = world
    p.change_groups("alice", add=["ops"])
    assert p.get_user("alice").groups == frozenset({"eng", "ops"})
    assert p.get_user("bob").groups == frozenset()
    assert p.get_user("admin").groups == frozenset({ADMINS_GROUP})
    assert set(p.list_groups()) == {"admins", "eng", "ops"}


def test_an_untouched_group_keeps_its_current_state(world):
    """Scenario "An untouched group keeps its current state"."""
    p, _ = world
    p.change_groups("alice", add=["admins"])  # another admin's concurrent grant
    p.change_groups("alice", add=["ops"])  # the stale picker's delta
    assert p.get_user("alice").groups == frozenset({"admins", "eng", "ops"})


def test_change_groups_accepts_any_iterable(world):
    p, _ = world
    p.change_groups("alice", add=(g for g in ["ops"]), remove={"eng"})
    assert p.get_user("alice").groups == frozenset({"ops"})
    p.change_groups("alice")  # both default to empty
    assert p.get_user("alice").groups == frozenset({"ops"})


def test_the_bootstrap_user_keeps_the_role(world):
    """Scenario "The bootstrap user keeps the role" (I5, I8): the add does not
    land when the remove is refused."""
    p, path = world
    before = frozen(path)
    with pytest.raises(ValueError):
        p.change_groups("admin", add=["eng"], remove=["admins"])
    assert p.get_user("admin").groups == frozenset({"admins"})
    assert groups_of(path, "admin") == {"admins"}
    assert frozen(path) == before


def test_the_bootstrap_user_can_gain_and_lose_other_groups(world):
    p, _ = world
    p.change_groups("admin", add=["eng"])
    assert p.get_user("admin").groups == frozenset({"admins", "eng"})
    p.change_groups("admin", remove=["eng"])
    assert p.get_user("admin").groups == frozenset({"admins"})
    p.change_groups("admin", add=["admins"])  # already a member: a no-op
    assert p.get_user("admin").groups == frozenset({"admins"})


def test_a_name_in_both_sets_is_refused(world, users_writes):
    """Scenario "A name in both sets"."""
    p, path = world
    before = frozen(path)
    users_writes["n"] = 0
    with pytest.raises(ValueError) as exc:
        p.change_groups("alice", add=["eng"], remove=["eng"])
    assert str(exc.value) == "groups: eng is both added and removed"
    assert frozen(path) == before and users_writes["n"] == 0


def test_an_unknown_group_is_a_value_error(world, users_writes):
    p, path = world
    before = frozen(path)
    users_writes["n"] = 0
    with pytest.raises(ValueError) as exc:
        p.change_groups("alice", add=["ops", "nope"])
    assert str(exc.value) == "groups: unknown group nope"
    assert p.get_user("alice").groups == frozenset({"eng"})  # the valid add did not land
    with pytest.raises(ValueError) as exc:
        p.change_groups("alice", remove=["nope"])
    assert str(exc.value) == "groups: unknown group nope"
    assert frozen(path) == before and users_writes["n"] == 0


def test_the_first_unknown_name_in_sorted_order_is_named(world):
    p, _ = world
    with pytest.raises(ValueError) as exc:
        p.change_groups("alice", add=["zz", "mm"], remove=["aa"])
    assert str(exc.value) == "groups: unknown group aa"  # add and remove are pooled, then sorted
    with pytest.raises(ValueError) as exc:
        p.change_groups("alice", add=["zz", "mm"])
    assert str(exc.value) == "groups: unknown group mm"


def test_an_unknown_user_is_a_key_error(world):
    p, path = world
    before = frozen(path)
    with pytest.raises(KeyError) as exc:
        p.change_groups("ghost", add=["eng"])
    assert exc.value.args == ("ghost",)
    assert frozen(path) == before


def test_the_error_order(world):
    """D8: unknown user, then unknown group, then both-sets, then bootstrap."""
    p, path = world
    before = frozen(path)
    # user before group
    with pytest.raises(KeyError) as exc:
        p.change_groups("ghost", add=["nope"])
    assert exc.value.args == ("ghost",)
    # group before both-sets
    with pytest.raises(ValueError) as exc:
        p.change_groups("alice", add=["nope", "eng"], remove=["eng"])
    assert str(exc.value) == "groups: unknown group nope"
    # both-sets before bootstrap
    with pytest.raises(ValueError) as exc:
        p.change_groups("admin", add=["eng"], remove=["eng", "admins"])
    assert "both added and removed" in str(exc.value)
    # bootstrap last
    with pytest.raises(ValueError) as exc:
        p.change_groups("admin", remove=["admins"])
    assert "bootstrap" in str(exc.value)
    assert frozen(path) == before


def test_the_same_delta_twice_writes_once(world, users_writes):
    """`DeltaIdempotent`: the second call changes nothing and writes nothing."""
    p, path = world
    users_writes["n"] = 0
    p.change_groups("alice", add=["ops"], remove=["eng"])
    once = frozen(path)
    p.change_groups("alice", add=["ops"], remove=["eng"])
    assert users_writes["n"] == 1
    assert frozen(path) == once


def test_a_delta_that_changes_nothing_writes_nothing(world, users_writes):
    p, path = world
    before = frozen(path)
    users_writes["n"] = 0
    p.change_groups("alice", add=["eng"])  # already a member
    p.change_groups("alice", remove=["ops"])  # not a member
    p.change_groups("alice")
    assert users_writes["n"] == 0 and frozen(path) == before


def test_two_deltas_on_different_groups_commute(world):
    p, _ = world
    p.change_groups("alice", add=["ops"])
    p.change_groups("alice", remove=["eng"])
    a = p.get_user("alice").groups
    p.change_groups("alice", add=["eng"])
    p.change_groups("alice", remove=["ops"])
    p.change_groups("alice", remove=["eng"])
    p.change_groups("alice", add=["ops"])
    assert a == p.get_user("alice").groups == frozenset({"ops"})


def test_change_groups_can_grant_and_revoke_the_role(world):
    p, _ = world
    p.change_groups("bob", add=["admins"])
    assert p.get_user("bob").is_admin is True
    p.change_groups("bob", remove=["admins"])
    assert p.get_user("bob").is_admin is False


# --- set_groups: one test per row of the D8 table --------------------------


def test_set_groups_unknown_user(world):
    p, path = world
    before = frozen(path)
    with pytest.raises(KeyError) as exc:
        p.set_groups("ghost", ["eng"])
    assert exc.value.args == ("ghost",)
    assert frozen(path) == before


def test_set_groups_unknown_group(world):
    p, path = world
    before = frozen(path)
    with pytest.raises(ValueError) as exc:
        p.set_groups("alice", ["eng", "nope"])
    assert str(exc.value) == "groups: unknown group nope"
    assert frozen(path) == before
    assert p.get_user("alice").groups == frozenset({"eng"})


def test_set_groups_false_with_admins_disagree(world):
    p, path = world
    before = frozen(path)
    with pytest.raises(ValueError) as exc:
        p.set_groups("alice", ["admins"], admin=False)
    assert str(exc.value) == "admin and groups disagree on admins"
    assert frozen(path) == before


def test_set_groups_none_that_adds_admins_is_refused(world):
    p, path = world
    before = frozen(path)
    with pytest.raises(ValueError) as exc:
        p.set_groups("alice", ["admins", "eng"])
    assert "admin" in str(exc.value)
    assert frozen(path) == before
    assert p.get_user("alice").is_admin is False


def test_set_groups_none_that_drops_admins_is_refused(world):
    """Scenario "An omitted admins is refused"."""
    p, path = world
    p.change_groups("alice", add=["admins"])
    before = frozen(path)
    with pytest.raises(ValueError) as exc:
        p.set_groups("alice", ["ops"])
    assert "admin" in str(exc.value)
    assert frozen(path) == before
    assert p.get_user("alice").is_admin is True


def test_set_groups_bootstrap_with_false_is_refused(world):
    p, path = world
    before = frozen(path)
    with pytest.raises(ValueError):
        p.set_groups("admin", ["eng"], admin=False)
    with pytest.raises(ValueError):
        p.set_groups("admin", ["eng"])  # None, and the result drops admins
    assert frozen(path) == before
    assert p.get_user("admin").groups == frozenset({"admins"})


def test_set_groups_error_order(world):
    """D8: user, group, disagree, none-differs, bootstrap."""
    p, _ = world
    with pytest.raises(KeyError) as exc:
        p.set_groups("ghost", ["nope", "admins"], admin=False)
    assert exc.value.args == ("ghost",)
    with pytest.raises(ValueError) as exc:
        p.set_groups("alice", ["nope", "admins"], admin=False)
    assert str(exc.value) == "groups: unknown group nope"
    with pytest.raises(ValueError) as exc:
        p.set_groups("admin", ["admins"], admin=False)
    assert "disagree" in str(exc.value)  # before the bootstrap refusal
    with pytest.raises(ValueError) as exc:
        p.set_groups("admin", ["eng"])
    assert str(exc.value) == "groups: set admin to change the membership of admins"
    with pytest.raises(ValueError) as exc:
        p.set_groups("admin", ["eng"], admin=False)
    assert str(exc.value) == "cannot remove the bootstrap user admin from admins"


def test_a_round_trip_keeps_the_role(world, users_writes):
    """Scenario "A round trip keeps the role"."""
    p, path = world
    p.change_groups("alice", add=["admins", "eng"])
    users_writes["n"] = 0
    p.set_groups("alice", ["admins", "ops"])
    assert p.get_user("alice").groups == frozenset({"admins", "ops"})
    assert groups_of(path, "alice") == {"admins", "ops"}
    assert users_writes["n"] == 1


def test_an_explicit_revoke(world, users_writes):
    """Scenario "An explicit revoke"."""
    p, path = world
    p.change_groups("alice", add=["admins"])
    users_writes["n"] = 0
    p.set_groups("alice", ["ops"], admin=False)
    assert p.get_user("alice").groups == frozenset({"ops"})
    assert groups_of(path, "alice") == {"ops"}
    assert users_writes["n"] == 1


def test_an_explicit_grant(world, users_writes):
    p, path = world
    users_writes["n"] = 0
    p.set_groups("alice", ["ops"], admin=True)
    assert p.get_user("alice").groups == frozenset({"admins", "ops"})
    assert groups_of(path, "alice") == {"admins", "ops"}
    assert users_writes["n"] == 1


def test_set_groups_without_the_role_for_a_non_admin_replaces(world, users_writes):
    p, _ = world
    users_writes["n"] = 0
    p.set_groups("alice", ["ops"])
    assert p.get_user("alice").groups == frozenset({"ops"})
    assert users_writes["n"] == 1


def test_set_groups_for_the_bootstrap_user_keeps_the_role(world):
    p, _ = world
    p.set_groups("admin", ["admins", "eng"])
    assert p.get_user("admin").groups == frozenset({"admins", "eng"})
    p.set_groups("admin", ["eng"], admin=True)
    assert p.get_user("admin").groups == frozenset({"admins", "eng"})


# --- create_user -----------------------------------------------------------


def test_create_an_admin_through_the_flag(world):
    """Scenario "Create an admin through the flag"."""
    p, path = world
    user, code = p._create_user("carol", admin=True, groups=["eng"])
    assert user.groups == frozenset({"admins", "eng"})
    assert user.is_admin and user.pending and code
    assert groups_of(path, "carol") == {"admins", "eng"}


def test_create_an_admin_through_the_groups(world):
    """Scenario "Create an admin through the groups"."""
    p, _ = world
    user, _code = p._create_user("carol", groups=["admins"])
    assert user.is_admin is True
    assert p.get_user("carol").groups == frozenset({"admins"})


def test_create_user_without_the_flag_is_not_an_admin(world):
    p, _ = world
    user, _code = p._create_user("carol", admin=False, groups=["eng"])
    assert user.is_admin is False
    user, _code = p._create_user("dave", admin=None)
    assert user.is_admin is False


def test_a_contradiction_is_refused_and_the_user_does_not_exist(world, users_writes):
    """Scenario "A contradiction is refused"."""
    p, path = world
    before = frozen(path)
    users_writes["n"] = 0
    with pytest.raises(ValueError) as exc:
        p._create_user("carol", admin=False, groups=["admins"])
    assert str(exc.value) == "admin and groups disagree on admins"
    assert p.get_user("carol") is None
    assert frozen(path) == before and users_writes["n"] == 0


def test_create_user_writes_record_and_code_once(world, users_writes):
    p, path = world
    users_writes["n"] = 0
    p._create_user("carol", admin=True)
    assert users_writes["n"] == 1
    rec = next(r for r in stored(path)["users"] if r["id"] == "carol")
    assert "admin" not in rec and rec["password_hash"] == "" and "setup" in rec


def test_create_user_error_order(world):
    """D8: bad id, duplicate, bad name, unknown group, contradiction."""
    p, path = world
    before = frozen(path)
    with pytest.raises(ValueError):  # bad id, with every later error present too
        p._create_user("Alice@home", name=7, admin=False, groups=["admins", "nope"])  # type: ignore[arg-type]
    with pytest.raises(ValueError) as exc:  # duplicate before name/group
        p._create_user("alice", name=7, groups=["nope"])  # type: ignore[arg-type]
    assert "pattern" not in str(exc.value)
    with pytest.raises(ValueError):  # name before group
        p._create_user("carol", name=7, groups=["nope"])  # type: ignore[arg-type]
    with pytest.raises(ValueError) as exc:  # group before contradiction
        p._create_user("carol", admin=False, groups=["admins", "nope"])
    assert str(exc.value) == "groups: unknown group nope"
    with pytest.raises(ValueError):
        p._create_user("carol", admin=False, groups=["admins"])
    assert frozen(path) == before
    assert p.get_user("carol") is None


# --- the wrappers and the refusals (T5) ------------------------------------


def test_set_admin_grants_and_revokes(world):
    """Scenario "Grant through the wrapper"."""
    p, _ = world
    p.set_admin("alice", True)
    assert p.get_user("alice").groups == frozenset({"admins", "eng"})
    p.set_admin("alice", False)
    assert p.get_user("alice").groups == frozenset({"eng"})


def test_set_admin_refuses_the_bootstrap_user(world):
    """Scenario "The bootstrap user refuses the wrapper"."""
    p, path = world
    before = frozen(path)
    for value in (True, False):
        with pytest.raises(ValueError):
            p.set_admin("admin", value)
    assert frozen(path) == before


def test_set_admin_unknown_user_is_a_key_error(world):
    p, _ = world
    with pytest.raises(KeyError) as exc:
        p.set_admin("ghost", True)
    assert exc.value.args == ("ghost",)


def test_remove_member_refuses_admins_for_admin(world):
    """Scenario "The bootstrap membership"."""
    p, path = world
    before = frozen(path)
    with pytest.raises(ValueError):
        p.remove_member("admins", "admin")
    assert frozen(path) == before
    assert p.get_user("admin").is_admin is True


def test_remove_member_of_admins_for_another_user(world):
    p, path = world
    p.change_groups("alice", add=["admins"])
    p.remove_member("admins", "alice")
    assert p.get_user("alice").is_admin is False
    assert groups_of(path, "alice") == {"eng"}


def test_remove_member_keeps_its_contract(world, users_writes):
    p, path = world
    with pytest.raises(KeyError) as exc:
        p.remove_member("nope", "ghost")  # group first
    assert exc.value.args == ("nope",)
    with pytest.raises(KeyError) as exc:
        p.remove_member("eng", "ghost")
    assert exc.value.args == ("ghost",)
    before = frozen(path)
    users_writes["n"] = 0
    p.remove_member("ops", "alice")  # a non-member is a no-op
    assert users_writes["n"] == 0 and frozen(path) == before
    p.remove_member("eng", "alice")
    assert p.get_user("alice").groups == frozenset()


def test_delete_group_admins_is_refused_before_any_write(world, users_writes):
    """Scenario "The reserved group cannot be deleted"."""
    p, path = world
    before = frozen(path)
    users_writes["n"] = 0
    with pytest.raises(ValueError) as exc:
        p._delete_group("admins")
    assert str(exc.value) == "cannot delete the reserved group admins"
    assert frozen(path) == before and users_writes["n"] == 0
    assert "admins" in p.list_groups()
    assert p.get_user("admin").is_admin is True


def test_delete_group_unknown_comes_first(world):
    p, _ = world
    with pytest.raises(KeyError) as exc:
        p._delete_group("nope")
    assert exc.value.args == ("nope",)


def test_delete_another_group_still_works(world):
    p, _ = world
    p._delete_group("eng")
    assert "eng" not in p.list_groups()
    assert p.get_user("alice").groups == frozenset()


def test_create_group_admins_is_refused(world):
    """Scenario "The reserved group cannot be created twice"."""
    p, path = world
    before = frozen(path)
    with pytest.raises(ValueError):
        p._create_group("admins")
    assert frozen(path) == before


def test_the_reserved_group_is_listed(world):
    p, _ = world
    assert ADMINS_GROUP in p.list_groups()


def test_delete_user_admin_is_refused(world):
    p, path = world
    before = frozen(path)
    with pytest.raises(ValueError):
        p._delete_user(BOOTSTRAP_ADMIN_ID)
    assert frozen(path) == before
    assert p.get_user("admin") is not None


def test_with_every_other_admin_removed_admin_is_still_admin(world):
    """I4: at least one admin; I3: the bootstrap user is always one."""
    p, _ = world
    p.change_groups("alice", add=["admins"])
    p.change_groups("bob", add=["admins"])
    for uid in ("alice", "bob"):
        p.remove_member("admins", uid)
    assert {u.id for u in p.list_users() if u.is_admin} == {"admin"}
    # Nothing of the interface removes the last admin.
    refusals = [
        lambda: p.remove_member("admins", "admin"),
        lambda: p.change_groups("admin", remove=["admins"]),
        lambda: p.set_groups("admin", [], admin=False),
        lambda: p.set_admin("admin", False),
        lambda: p._delete_group("admins"),
        lambda: p._delete_user("admin"),
    ]
    for op in refusals:
        with pytest.raises(ValueError):
            op()
    assert {u.id for u in p.list_users() if u.is_admin} == {"admin"}


# --- the saved file (definition of done) -----------------------------------


def test_every_saved_file_is_version_2_and_holds_no_admin_key(world):
    """After every kind of write: version 2, no `admin` key, `admins` listed,
    the bootstrap user in it."""
    p, path = world

    def check():
        data = stored(path)
        assert data["version"] == 2
        assert ADMINS_GROUP in data["groups"]
        assert all("admin" not in r for r in data["users"]), data
        assert ADMINS_GROUP in groups_of(path, "admin")

    check()
    ops = [
        lambda: p.change_groups("alice", add=["ops", "admins"]),
        lambda: p.set_groups("alice", ["eng"], admin=True),
        lambda: p.set_admin("alice", False),
        lambda: p.set_admin("bob", True),
        lambda: p.remove_member("admins", "bob"),
        lambda: p._create_user("carol", admin=True, groups=["eng"]),
        lambda: p._create_user("dave", groups=["admins"]),
        lambda: p._issue_setup_code("carol"),
        lambda: p._create_group("qa"),
        lambda: p._delete_group("qa"),
        lambda: p._delete_user("dave"),
        lambda: p._delete_group("ops"),
    ]
    for op in ops:
        op()
        check()
    fresh = LocalIdentityProvider(path, hash_password("pw", iterations=1000))
    fresh.load()
    check()


# --- the frozen signatures of D8 (identity.py) -----------------------------

P = inspect.Parameter


def sig(fn) -> list[tuple[str, object, object]]:
    return [(n, p.kind, p.default) for n, p in inspect.signature(fn).parameters.items()]


def test_the_identity_signatures_are_the_frozen_ones():
    L = LocalIdentityProvider
    E = P.empty
    assert sig(L._create_user) == [
        ("self", P.POSITIONAL_OR_KEYWORD, E), ("user_id", P.POSITIONAL_OR_KEYWORD, E),
        ("name", P.KEYWORD_ONLY, ""), ("admin", P.KEYWORD_ONLY, None),
        ("groups", P.KEYWORD_ONLY, ()),
    ]
    assert sig(L.change_groups) == [
        ("self", P.POSITIONAL_OR_KEYWORD, E), ("user_id", P.POSITIONAL_OR_KEYWORD, E),
        ("add", P.POSITIONAL_OR_KEYWORD, ()), ("remove", P.POSITIONAL_OR_KEYWORD, ()),
    ]
    assert sig(L.set_groups) == [
        ("self", P.POSITIONAL_OR_KEYWORD, E), ("user_id", P.POSITIONAL_OR_KEYWORD, E),
        ("groups", P.POSITIONAL_OR_KEYWORD, E), ("admin", P.KEYWORD_ONLY, None),
    ]
    assert sig(L.set_admin) == [
        ("self", P.POSITIONAL_OR_KEYWORD, E), ("user_id", P.POSITIONAL_OR_KEYWORD, E),
        ("admin", P.POSITIONAL_OR_KEYWORD, E),
    ]
    assert sig(L.remove_member) == [
        ("self", P.POSITIONAL_OR_KEYWORD, E), ("group", P.POSITIONAL_OR_KEYWORD, E),
        ("user_id", P.POSITIONAL_OR_KEYWORD, E),
    ]
    assert sig(L._delete_group) == [
        ("self", P.POSITIONAL_OR_KEYWORD, E), ("name", P.POSITIONAL_OR_KEYWORD, E),
    ]


def test_change_groups_is_synchronous():
    """D5: one synchronous read and write, no `await`."""
    assert not inspect.iscoroutinefunction(LocalIdentityProvider.change_groups)
    assert not inspect.iscoroutinefunction(LocalIdentityProvider.remove_member)


# --- change_members: the delta over one group, many users --------------------


def test_change_members_applies_the_delta_in_one_write(world):
    p, path = world
    p.change_members("eng", add=["bob"], remove=["alice"])
    assert groups_of(path, "bob") == {"eng"} and groups_of(path, "alice") == set()


@pytest.mark.parametrize("group, add, remove, exc", [
    ("nope", ["bob"], [], KeyError),
    (ADMINS_GROUP, ["bob"], [], ValueError),
    ("eng", ["bob"], ["bob"], ValueError),
    ("eng", ["bob", "ghost"], [], ValueError),
])
def test_change_members_refusals_leave_the_file_unchanged(world, group, add, remove, exc):
    p, path = world
    before = path.read_bytes()
    with pytest.raises(exc):
        p.change_members(group, add=add, remove=remove)
    assert path.read_bytes() == before
    assert groups_of(path, "bob") == set()


def test_change_members_that_changes_nothing_writes_nothing(world, monkeypatch):
    p, _ = world

    def boom(*a, **k):
        raise AssertionError("a no-op must not write")

    monkeypatch.setattr(p, "_save", boom)
    p.change_members("eng", add=["alice"], remove=["bob"])


def test_change_members_skips_a_removal_of_a_user_that_is_gone(world):
    """A user deleted since the picker rendered must not block the rest."""
    p, path = world
    p.change_members("eng", add=["bob"], remove=["ghost"])
    assert groups_of(path, "bob") == {"eng"}


# --- identity-error-ownership: the provider owns the kind of an unknown name --
# Spec identity "Refusal of an unknown listed name". The target is the user (or
# the group of change_members); a listed name is a name in a list argument.


def test_an_unknown_listed_group_is_a_value_error(world, users_writes):
    """V1: exact type (not a subclass, not KeyError) and exact text; no write."""
    p, path = world
    before = frozen(path)
    users_writes["n"] = 0
    with pytest.raises(Exception) as exc:
        p.change_groups("alice", add=["ops", "nope"])
    assert type(exc.value) is ValueError
    assert str(exc.value) == "groups: unknown group nope"
    with pytest.raises(Exception) as exc:
        p.change_groups("alice", remove=["nope"])
    assert type(exc.value) is ValueError
    assert str(exc.value) == "groups: unknown group nope"
    assert frozen(path) == before and users_writes["n"] == 0
    assert p.get_user("alice").groups == frozenset({"eng"})  # `ops` did not land


def test_set_groups_and_create_user_refuse_an_unknown_group(world, users_writes):
    """V2: scenarios "An unknown group in the replaced set" and "...in a created user"."""
    p, path = world
    before = frozen(path)
    users_writes["n"] = 0
    with pytest.raises(Exception) as exc:
        p.set_groups("alice", ["eng", "nope"])
    assert type(exc.value) is ValueError
    assert str(exc.value) == "groups: unknown group nope"
    with pytest.raises(Exception) as exc:
        p._create_user("carol", groups=["nope"])
    assert type(exc.value) is ValueError
    assert str(exc.value) == "groups: unknown group nope"
    assert frozen(path) == before and users_writes["n"] == 0
    assert p.get_user("carol") is None
    assert p.get_user("alice").groups == frozenset({"eng"})


def test_the_target_check_comes_first(world):
    """V3: an unknown target is a KeyError even when a listed name is unknown too."""
    p, path = world
    before = frozen(path)
    with pytest.raises(KeyError) as exc:
        p.change_groups("ghost", add=["nope"])
    assert exc.value.args == ("ghost",)
    with pytest.raises(KeyError) as exc:
        p.set_groups("ghost", ["nope"])
    assert exc.value.args == ("ghost",)
    with pytest.raises(KeyError) as exc:
        p.change_members("nope", add=["ghost"])
    assert exc.value.args == ("nope",)
    assert frozen(path) == before


def test_change_members_refuses_an_unknown_user(world, users_writes):
    """V4: an unknown user in `add` is a ValueError; one in `remove` is skipped."""
    p, path = world
    before = frozen(path)
    users_writes["n"] = 0
    with pytest.raises(Exception) as exc:
        p.change_members("eng", add=["bob", "ghost"])
    assert type(exc.value) is ValueError
    assert str(exc.value) == "members: unknown user ghost"
    assert frozen(path) == before and users_writes["n"] == 0
    assert p.get_user("bob").groups == frozenset()  # `bob` did not join
    p.change_members("eng", add=["bob"], remove=["ghost"])  # raises nothing
    assert p.get_user("bob").groups == frozenset({"eng"})
    assert users_writes["n"] == 1  # one write


def test_a_listed_name_equal_to_the_target_is_a_value_error(world):
    """V5: a listed name equal to the target name is a listed name, not a target."""
    p, path = world
    p._create_group("dev")  # group `dev`, no user `dev`
    with pytest.raises(Exception) as exc:
        p.change_members("dev", add=["dev"])
    assert type(exc.value) is ValueError
    assert str(exc.value) == "members: unknown user dev"
    p._delete_group("ops")
    p._create_user("ops")  # user `ops`, no group `ops`
    before = frozen(path)
    with pytest.raises(Exception) as exc:
        p.change_groups("ops", add=["ops"])
    assert type(exc.value) is ValueError
    assert str(exc.value) == "groups: unknown group ops"
    assert frozen(path) == before
