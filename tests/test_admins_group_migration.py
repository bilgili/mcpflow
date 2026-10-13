"""The `users.json` version 1 to version 2 migration (admins-group, task 8.2).

Scenarios: identity "Version 1 migration", "Local user store", "Bootstrap
admin user". Properties: `MigrationSafe`, `LoadIdempotent`, I2, I3 of
`specs/tla/admins_group.tla`. Design D3, D4, R3, and decision E2: every test
builds the provider with ONE fixed `admin_password_hash` string, because a
clear `ADMIN_PASSWORD` is re-hashed with a new salt at each start (a write at
every start, pre-existing, out of scope).
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from mcpflow.auth import hash_password
from mcpflow.identity import LocalIdentityProvider

ADMIN_HASH = hash_password("adm1n-pw-for-tests", iterations=1000)
USER_HASH = hash_password("user-pw-for-tests", iterations=1000)


def rec(uid: str, *, admin: bool | None = None, groups=(), pw: str = USER_HASH) -> dict:
    out = {"id": uid, "name": "", "password_hash": pw, "groups": list(groups)}
    if admin is not None:
        out["admin"] = admin
    return out


def write(path: Path, version: int, groups: list[str], users: list[dict]) -> bytes:
    path.write_text(json.dumps({"version": version, "groups": groups, "users": users}))
    return path.read_bytes()


def provider(path: Path) -> LocalIdentityProvider:
    return LocalIdentityProvider(path, ADMIN_HASH)


@pytest.fixture
def writes(monkeypatch):
    """Count the writes of `users.json`: every `os.replace` onto it, and every
    call of `LocalIdentityProvider._save`."""
    log: dict[str, int] = {"replace": 0, "save": 0}
    real_replace = os.replace
    real_save = LocalIdentityProvider._save

    def replace(src, dst, *a, **k):
        if Path(dst).name == "users.json":
            log["replace"] += 1
        return real_replace(src, dst, *a, **k)

    def save(self, *a, **k):
        log["save"] += 1
        return real_save(self, *a, **k)

    monkeypatch.setattr(os, "replace", replace)
    monkeypatch.setattr(LocalIdentityProvider, "_save", save)
    return log


def saved(path: Path) -> dict:
    return json.loads(path.read_text())


def records(path: Path) -> dict[str, dict]:
    return {r["id"]: r for r in saved(path)["users"]}


# --- the migration --------------------------------------------------------


def test_an_admin_flag_becomes_membership(tmp_path):
    """Scenario "An admin flag becomes membership"."""
    path = tmp_path / "users.json"
    write(path, 1, ["eng"], [rec("alice", admin=True, groups=["eng"])])
    p = provider(path)
    p.load()
    assert p.get_user("alice").groups == frozenset({"admins", "eng"})
    data = saved(path)
    assert data["version"] == 2
    assert "admins" in data["groups"] and "eng" in data["groups"]
    assert all("admin" not in r for r in data["users"])
    assert set(records(path)["alice"]["groups"]) == {"admins", "eng"}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_a_non_admin_stays_a_non_admin(tmp_path):
    """Scenario "A non-admin stays a non-admin"."""
    path = tmp_path / "users.json"
    write(path, 1, ["eng"], [rec("bob", admin=False, groups=["eng"])])
    p = provider(path)
    p.load()
    assert p.get_user("bob").is_admin is False
    assert p.get_user("bob").groups == frozenset({"eng"})


def test_a_conflicting_legacy_group_stops_the_start(tmp_path, writes):
    """Scenario "A conflicting legacy group stops the start". Decision E4: the
    message is the text of design D3, ids sorted and joined by ", "."""
    path = tmp_path / "users.json"
    before = write(path, 1, ["admins"], [
        rec("zed", admin=False, groups=["admins"]),
        rec("bob", admin=False, groups=["admins"]),
        rec("alice", admin=True, groups=["admins"]),
    ])
    with pytest.raises(ValueError) as exc:
        provider(path).load()
    assert str(exc.value) == (
        "users.json: version 1 group admins holds non-admin users bob, zed; "
        "rename that group before the upgrade")
    assert path.read_bytes() == before
    assert not (tmp_path / "users.json.tmp").exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["users.json"]
    # The check runs before the bootstrap rule and before any write.
    assert writes == {"replace": 0, "save": 0}


def test_a_conflict_names_a_single_user(tmp_path):
    path = tmp_path / "users.json"
    write(path, 1, ["admins"], [rec("bob", admin=False, groups=["admins"])])
    with pytest.raises(ValueError, match=r"non-admin users bob;"):
        provider(path).load()


def test_the_conflict_check_ignores_the_bootstrap_user(tmp_path):
    """The user `admin` with `admin: false` in a legacy `admins` is no
    conflict: it is an admin by the bootstrap rule."""
    path = tmp_path / "users.json"
    write(path, 1, ["admins"], [rec("admin", admin=False, groups=["admins"],
                                    pw=ADMIN_HASH)])
    p = provider(path)
    p.load()
    assert p.get_user("admin").is_admin is True


def test_a_legacy_group_of_admins_merges(tmp_path):
    """Scenario "A legacy group of admins merges"."""
    path = tmp_path / "users.json"
    write(path, 1, ["admins"], [rec("alice", admin=True, groups=["admins"])])
    p = provider(path)
    p.load()
    assert p.get_user("alice").groups == frozenset({"admins"})
    assert p.get_user("alice").is_admin is True
    assert p.list_groups().count("admins") == 1
    assert saved(path)["groups"].count("admins") == 1


def test_a_version_1_file_without_admins_gets_the_group(tmp_path):
    path = tmp_path / "users.json"
    write(path, 1, ["eng"], [rec("bob", admin=False)])
    p = provider(path)
    p.load()
    assert "admins" in p.list_groups()
    assert "admins" in saved(path)["groups"]


def test_the_migration_writes_once(tmp_path, writes):
    """Scenario "The migration runs once": a version 1 file gives one write."""
    path = tmp_path / "users.json"
    write(path, 1, ["eng"], [rec("alice", admin=True, groups=["eng"]),
                             rec("bob", admin=False)])
    provider(path).load()
    assert writes == {"replace": 1, "save": 1}


def test_the_second_load_writes_nothing(tmp_path, writes):
    """`LoadIdempotent`: a second `load` of the result writes nothing."""
    path = tmp_path / "users.json"
    write(path, 1, ["eng"], [rec("alice", admin=True, groups=["eng"])])
    provider(path).load()
    after_first = path.read_bytes()
    writes.update(replace=0, save=0)
    p2 = provider(path)
    p2.load()
    assert writes == {"replace": 0, "save": 0}
    assert path.read_bytes() == after_first
    assert p2.get_user("alice").groups == frozenset({"admins", "eng"})


def test_every_further_start_writes_nothing(tmp_path, writes):
    path = tmp_path / "users.json"
    provider(path).load()  # first start, no file
    stable = path.read_bytes()
    writes.update(replace=0, save=0)
    for _ in range(3):
        provider(path).load()
    assert writes == {"replace": 0, "save": 0}
    assert path.read_bytes() == stable


# --- malformed files ------------------------------------------------------


def test_a_version_2_record_with_admin_is_refused(tmp_path):
    """Scenario "A version 2 record with an admin field"."""
    path = tmp_path / "users.json"
    before = write(path, 2, ["admins"], [rec("alice", admin=False, groups=[])])
    with pytest.raises(ValueError):
        provider(path).load()
    assert path.read_bytes() == before


@pytest.mark.parametrize("version", [0, 3, 99, "2", None, True])
def test_any_other_version_is_refused(tmp_path, version):
    path = tmp_path / "users.json"
    path.write_text(json.dumps({"version": version, "groups": [], "users": []}))
    before = path.read_bytes()
    with pytest.raises(ValueError):
        provider(path).load()
    assert path.read_bytes() == before


def test_version_3_is_refused(tmp_path):
    path = tmp_path / "users.json"
    write(path, 3, ["admins"], [rec("alice", groups=["admins"])])
    with pytest.raises(ValueError):
        provider(path).load()


def test_a_version_1_record_with_a_non_boolean_admin_is_malformed(tmp_path):
    """A version 1 record holds `admin` as a boolean; a non-boolean is malformed."""
    path = tmp_path / "users.json"
    write(path, 1, [], [rec("alice", admin="yes")])  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        provider(path).load()


# --- bootstrap rules at load (I2, I3) -------------------------------------


def test_a_version_2_file_without_admins_gets_it(tmp_path):
    """Scenario "A missing reserved group is created" (I2)."""
    path = tmp_path / "users.json"
    write(path, 2, ["eng"], [rec("admin", groups=["eng"], pw=ADMIN_HASH)])
    p = provider(path)
    p.load()
    assert "admins" in p.list_groups()
    assert "admins" in saved(path)["groups"]
    assert "admins" in records(path)["admin"]["groups"]
    assert p.get_user("admin").groups == frozenset({"admins", "eng"})


def test_a_hand_edit_cannot_demote_the_bootstrap_user(tmp_path):
    """Scenario "A hand edit cannot demote the bootstrap user" (I3)."""
    path = tmp_path / "users.json"
    write(path, 2, ["admins"], [rec("admin", groups=[], pw=ADMIN_HASH)])
    p = provider(path)
    p.load()
    assert p.get_user("admin").is_admin is True
    assert "admins" in records(path)["admin"]["groups"]


def test_the_bootstrap_user_is_created_when_absent(tmp_path):
    path = tmp_path / "users.json"
    write(path, 2, ["admins"], [rec("alice", groups=["admins"])])
    p = provider(path)
    p.load()
    assert p.get_user("admin").is_admin is True
    assert p.get_user("alice").is_admin is True


def test_first_start_without_a_file(tmp_path, writes):
    """Scenario "First start of an existing install (AC-8b)" at the provider."""
    path = tmp_path / "users.json"
    p = provider(path)
    p.load()
    data = saved(path)
    assert data["version"] == 2
    assert "admins" in data["groups"]
    (admin,) = [r for r in data["users"] if r["id"] == "admin"]
    assert "admins" in admin["groups"] and "admin" not in admin
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert writes == {"replace": 1, "save": 1}
    assert p.authenticate("admin", "adm1n-pw-for-tests") is not None


def test_the_environment_hash_wins_at_every_start(tmp_path):
    """Scenario "The environment owns the admin password"."""
    path = tmp_path / "users.json"
    provider(path).load()
    new_hash = hash_password("another-pw-for-tests", iterations=1000)
    p = LocalIdentityProvider(path, new_hash)
    p.load()
    assert p.authenticate("admin", "another-pw-for-tests") is not None
    assert p.authenticate("admin", "adm1n-pw-for-tests") is None


# --- MigrationSafe --------------------------------------------------------


def test_migration_keeps_every_other_privilege(tmp_path):
    """`MigrationSafe`: after the migration a user is an admin if and only if
    it had `admin: true`, or it is the bootstrap user."""
    path = tmp_path / "users.json"
    users = [
        rec("admin", admin=False, groups=[], pw=ADMIN_HASH),
        rec("alice", admin=True, groups=["eng"]),
        rec("bob", admin=False, groups=["eng"]),
        rec("carol", admin=True, groups=[]),
        rec("dave", admin=False, groups=[]),
    ]
    write(path, 1, ["eng", "ops"], users)
    p = provider(path)
    p.load()
    had = {u["id"] for u in users if u["admin"]} | {"admin"}
    assert {u.id for u in p.list_users() if u.is_admin} == had
    # Nothing else changes: every other group of every user survives.
    assert p.get_user("alice").groups == frozenset({"admins", "eng"})
    assert p.get_user("bob").groups == frozenset({"eng"})
    assert p.get_user("dave").groups == frozenset()
    assert set(p.list_groups()) == {"admins", "eng", "ops"}


def test_the_migration_survives_a_reload_with_the_same_roles(tmp_path):
    path = tmp_path / "users.json"
    write(path, 1, ["eng"], [rec("alice", admin=True, groups=["eng"]),
                             rec("bob", admin=False, groups=["eng"])])
    provider(path).load()
    again = provider(path)
    again.load()
    assert {u.id for u in again.list_users() if u.is_admin} == {"admin", "alice"}


def test_a_crash_before_the_write_leaves_version_1_and_repeats_the_migration(
        tmp_path, monkeypatch):
    """Atomic and idempotent: if `os.replace` never runs, the version 1 file
    stays; the next start gives the same migration."""
    path = tmp_path / "users.json"
    before = write(path, 1, ["eng"], [rec("alice", admin=True, groups=["eng"])])

    def boom(*a, **k):
        raise OSError("disk gone")

    with monkeypatch.context() as m:
        m.setattr(os, "replace", boom)
        with pytest.raises(OSError):
            provider(path).load()
    assert path.read_bytes() == before
    p = provider(path)
    p.load()
    assert p.get_user("alice").groups == frozenset({"admins", "eng"})
    assert saved(path)["version"] == 2
