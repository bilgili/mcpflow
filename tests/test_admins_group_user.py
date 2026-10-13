"""`User` and the derived admin role (admins-group, task 8.1, design D1, I1).

Scenarios: identity "Reserved group admins" and "Identity provider interface"
(A positional construction is refused). The expectations come from the spec
and `design.md` D1, not from the implementation.
"""

from __future__ import annotations

import dataclasses

import pytest

from mcpflow.identity import ADMINS_GROUP, User


def _user(*groups: str) -> User:
    return User(id="a", name="a", groups=frozenset(groups), provider="local")


def test_the_reserved_group_is_named_admins():
    assert ADMINS_GROUP == "admins"


def test_is_admin_is_not_a_dataclass_field():
    assert "is_admin" not in {f.name for f in dataclasses.fields(User)}


def test_the_fields_are_the_keyword_only_six():
    fields = dataclasses.fields(User)
    assert [f.name for f in fields] == [
        "id", "name", "groups", "provider", "pending", "incarnation"]
    assert all(f.kw_only for f in fields)
    assert fields[-2].default is False  # `pending` default False
    assert fields[-1].default == 0  # `incarnation` is last, default 0


def test_a_member_of_admins_is_admin():
    assert _user("admins").is_admin is True
    assert _user("eng", "admins").is_admin is True


def test_empty_groups_is_not_admin():
    assert _user().is_admin is False
    assert _user("eng").is_admin is False


def test_positional_construction_raises_type_error():
    """Scenario "A positional construction is refused"."""
    with pytest.raises(TypeError):
        User("alice", "alice", frozenset(), False, "local")  # type: ignore[misc]


def test_is_admin_keyword_raises_type_error():
    with pytest.raises(TypeError):
        User(id="a", name="a", groups=frozenset(), provider="local",
             is_admin=True)  # type: ignore[call-arg]


def test_assigning_is_admin_raises():
    u = _user()
    with pytest.raises(AttributeError):
        u.is_admin = True  # type: ignore[misc]


def test_the_user_is_frozen():
    with pytest.raises(dataclasses.FrozenInstanceError):
        _user().groups = frozenset({"admins"})  # type: ignore[misc]


def test_replace_groups_updates_is_admin():
    u = _user()
    assert dataclasses.replace(u, groups=frozenset({"admins"})).is_admin is True
    assert dataclasses.replace(_user("admins"), groups=frozenset()).is_admin is False
