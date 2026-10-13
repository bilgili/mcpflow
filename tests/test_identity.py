"""The local identity provider.

Every test is one scenario of `specs/identity/spec.md` (requirements Local
user store, Bootstrap admin user, Sign-in through the provider) or of
`specs/auth/spec.md` ("Sign-in time does not reveal a user name"). The
expectations come from the spec and the frozen interface in `design.md`
("Public interfaces"), not from the implementation. The file shape of
`users.json` is not frozen, so a test reads it as generic JSON.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from pathlib import Path

import pytest
from conftest import make_user

from mcpflow.auth import hash_password
from mcpflow.identity import (
    BOOTSTRAP_ADMIN_ID,
    USER_ID_RE,
    LocalIdentityProvider,
    User,
)

ADMIN_PW = "admin-secret"


def _provider(tmp_path: Path, pw: str = ADMIN_PW) -> LocalIdentityProvider:
    p = LocalIdentityProvider(
        tmp_path / "users.json", hash_password(pw, iterations=1000)
    )
    p.load()
    return p


def _records(node, key="id"):
    """Every dict in a JSON tree that has the key `id`."""
    if isinstance(node, dict):
        if key in node:
            yield node
        for v in node.values():
            yield from _records(v, key)
    elif isinstance(node, list):
        for v in node:
            yield from _records(v, key)


def _record(path: Path, user_id: str) -> dict | None:
    data = json.loads(path.read_text())
    for rec in _records(data):
        if rec["id"] == user_id:
            return rec
    return None


# --- Local user store --------------------------------------------------------


def test_create_a_user(tmp_path):
    p = _provider(tmp_path)
    user = make_user(p, "alice", "alice-clear-text-pw")
    assert isinstance(user, User)
    assert user.id == "alice"
    path = tmp_path / "users.json"
    rec = _record(path, "alice")
    assert rec is not None
    assert rec["password_hash"].startswith("pbkdf2_sha256$")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert "alice-clear-text-pw" not in path.read_text()


def test_a_bad_user_id_is_refused(tmp_path):
    p = _provider(tmp_path)
    path = tmp_path / "users.json"
    before = path.read_bytes()
    with pytest.raises(ValueError) as exc:
        p._create_user("Alice@home")
    assert USER_ID_RE.pattern in str(exc.value)
    assert path.read_bytes() == before
    assert p.get_user("Alice@home") is None


def test_a_user_names_only_listed_groups(tmp_path):
    p = _provider(tmp_path)
    p._create_group("eng")
    make_user(p, "alice", "pw", groups=["eng"])
    path = tmp_path / "users.json"
    before = path.read_bytes()
    with pytest.raises(ValueError) as exc:
        p.set_groups("alice", ["eng", "nope"])
    assert "nope" in str(exc.value)
    assert p.get_user("alice").groups == frozenset({"eng"})
    assert path.read_bytes() == before


def test_the_write_fails(tmp_path, monkeypatch):
    p = _provider(tmp_path)

    def boom(*_a, **_k):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(Exception):
        p._create_user("bob")
    assert p.get_user("bob") is None
    assert "bob" not in [u.id for u in p.list_users()]


def test_a_malformed_file_stops_the_start(tmp_path):
    # Take a file the provider wrote, then drop `id` from one user record.
    p = _provider(tmp_path)
    make_user(p, "alice", "pw")
    path = tmp_path / "users.json"
    data = json.loads(path.read_text())
    for rec in _records(data):
        if rec["id"] == "alice":
            del rec["id"]
    path.write_text(json.dumps(data))
    fresh = LocalIdentityProvider(path, hash_password(ADMIN_PW, iterations=1000))
    with pytest.raises(ValueError):
        fresh.load()


# --- Bootstrap admin user ----------------------------------------------------


def test_first_start_of_an_existing_install(tmp_path):
    path = tmp_path / "users.json"
    assert not path.exists()
    p = LocalIdentityProvider(path, hash_password(ADMIN_PW, iterations=1000))
    p.load()
    rec = _record(path, BOOTSTRAP_ADMIN_ID)
    assert rec is not None and "admins" in rec["groups"] and "admin" not in rec
    user = p.authenticate(BOOTSTRAP_ADMIN_ID, ADMIN_PW)
    assert user is not None
    assert user.id == "admin" and user.is_admin is True


def test_the_environment_owns_the_admin_password(tmp_path):
    path = tmp_path / "users.json"
    old = LocalIdentityProvider(path, hash_password("old-pw", iterations=1000))
    old.load()
    assert old.authenticate("admin", "old-pw") is not None
    new = LocalIdentityProvider(path, hash_password("new-pw", iterations=1000))
    new.load()
    assert new.authenticate("admin", "new-pw") is not None
    assert new.authenticate("admin", "old-pw") is None


def test_the_admin_user_cannot_be_removed(tmp_path):
    p = _provider(tmp_path)
    path = tmp_path / "users.json"
    before = path.read_bytes()
    with pytest.raises(ValueError):
        p._delete_user("admin")
    with pytest.raises(ValueError):
        p.set_admin("admin", False)
    with pytest.raises(ValueError):
        p.replace_credential("admin", None, "other-hash")
    assert path.read_bytes() == before
    assert p.get_user("admin").is_admin is True


# --- Sign-in through the provider --------------------------------------------


def test_correct_password(tmp_path):
    p = _provider(tmp_path)
    make_user(p, "alice", "alice-pw")
    user = p.authenticate("alice", "alice-pw")
    assert user is not None and user.id == "alice"
    assert p.authenticate("alice", "wrong") is None


def test_unknown_user(tmp_path, monkeypatch):
    p = _provider(tmp_path)
    calls = []
    real = hashlib.pbkdf2_hmac

    def counting(*args, **kwargs):
        calls.append(args)
        return real(*args, **kwargs)

    monkeypatch.setattr(hashlib, "pbkdf2_hmac", counting)
    assert p.authenticate("nobody", "x") is None
    assert len(calls) == 1


def test_sign_in_time_does_not_reveal_a_user_name(tmp_path, monkeypatch):
    p = _provider(tmp_path)
    make_user(p, "alice", "alice-pw", iterations=600_000)  # same cost as the dummy hash
    calls: list[tuple] = []
    real = hashlib.pbkdf2_hmac

    def counting(*args, **kwargs):
        calls.append(args)
        return real(*args, **kwargs)

    monkeypatch.setattr(hashlib, "pbkdf2_hmac", counting)
    assert p.authenticate("alice", "wrong-pw") is None
    known = list(calls)
    calls.clear()
    assert p.authenticate("nobody", "wrong-pw") is None
    unknown = list(calls)
    # One verification each, with the same iteration count (4th argument).
    assert len(known) == 1 and len(unknown) == 1
    assert known[0][3] == unknown[0][3]


# --- Setup codes and pending users (user-self-service-password, 7.2) --------
#
# Scenarios of the identity delta: Local user store (pending record, `_parse`),
# Sign-in through the provider (pending user), Setup code, Setup code check,
# Credential compare-and-swap, No admin-chosen password. The one-line
# `Interface` checks sit in `tests/test_interfaces.py`.

SEVEN_DAYS = 7 * 24 * 3600
NEW_PW = "new-password-1"


class Clock:
    """An injected clock: the provider reads time only through it."""

    def __init__(self, now: int = 1_700_000_000) -> None:
        self.now = now

    def __call__(self) -> int:
        return self.now


def _clocked(tmp_path: Path, clock: Clock) -> LocalIdentityProvider:
    p = LocalIdentityProvider(
        tmp_path / "users.json", hash_password(ADMIN_PW, iterations=1000), clock=clock
    )
    p.load()
    return p


def _new_hash(pw: str = NEW_PW) -> str:
    return hash_password(pw, iterations=1000)


def _counting(monkeypatch, name: str, module=hashlib) -> list[tuple]:
    """Replace `module.<name>` by a recording wrapper; return the call list."""
    calls: list[tuple] = []
    real = getattr(module, name)

    def counting(*args, **kwargs):
        calls.append(args)
        return real(*args, **kwargs)

    monkeypatch.setattr(module, name, counting)
    return calls


def _write_users(path: Path, mutate) -> None:
    data = json.loads(path.read_text())
    mutate(data)
    path.write_text(json.dumps(data))


def _reload(tmp_path: Path) -> LocalIdentityProvider:
    fresh = LocalIdentityProvider(
        tmp_path / "users.json", hash_password(ADMIN_PW, iterations=1000)
    )
    fresh.load()
    return fresh


def test_create_a_user_stores_a_pending_record(tmp_path):
    """Local user store / Create a user."""
    clock = Clock()
    p = _clocked(tmp_path, clock)
    user, code = p._create_user("alice")
    assert isinstance(user, User) and user.id == "alice"
    assert user.pending is True
    assert isinstance(code, str) and re.fullmatch(r"[A-Za-z0-9_-]{16}", code)  # token_urlsafe(12)
    path = tmp_path / "users.json"
    rec = _record(path, "alice")
    assert rec["password_hash"] == ""
    assert rec["setup"] == {
        "sha256": hashlib.sha256(code.encode()).hexdigest(),
        "expires_at": clock.now + SEVEN_DAYS,
    }
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert code not in path.read_text()  # the digest only, never the clear code
    assert p.get_user("alice").pending is True


def test_a_pending_user_carries_the_status(tmp_path):
    """Identity provider interface / A pending user carries the status."""
    p = _provider(tmp_path)
    p._create_user("alice")
    make_user(p, "bob", "pw")
    assert p.get_user("alice") == User(id="alice", name="alice", groups=frozenset(), provider="local", pending=True)
    assert p.get_user("bob").pending is False
    assert p.get_user("admin").pending is False
    assert {u.id: u.pending for u in p.list_users()} == {
        "admin": False, "alice": True, "bob": False}


def test_a_pending_record_survives_a_restart(tmp_path):
    p = _provider(tmp_path)
    _user, code = p._create_user("alice")
    fresh = _reload(tmp_path)
    assert fresh.get_user("alice").pending is True
    assert fresh.check_setup_code("alice", code) is not None


def test_create_and_reset_each_write_the_file_once(tmp_path, monkeypatch):
    """Setup code: the record and the code reach the file in one write."""
    p = _provider(tmp_path)
    writes = _counting(monkeypatch, "replace", os)
    _user, code = p._create_user("alice")
    assert len(writes) == 1
    state = p.check_setup_code("alice", code)
    writes.clear()
    assert p.replace_credential("alice", state, _new_hash()) is True
    assert len(writes) == 1
    writes.clear()
    p._issue_setup_code("alice")
    assert len(writes) == 1


@pytest.mark.parametrize("name, mutate", [
    ("active record with setup",
     lambda rec: rec.update(password_hash=_new_hash())),
    ("sha256 too short", lambda rec: rec["setup"].update(sha256="abc123")),
    ("sha256 not hex", lambda rec: rec["setup"].update(sha256="z" * 64)),
    ("sha256 not a string", lambda rec: rec["setup"].update(sha256=12345)),
    ("expires_at a string", lambda rec: rec["setup"].update(expires_at="tomorrow")),
    ("expires_at null", lambda rec: rec["setup"].update(expires_at=None)),
    ("expires_at missing", lambda rec: rec["setup"].pop("expires_at")),
    ("sha256 missing", lambda rec: rec["setup"].pop("sha256")),
    ("setup not an object", lambda rec: rec.update(setup=["x"])),
])
def test_parse_refuses_a_bad_setup_record(tmp_path, name, mutate):
    """Local user store / An active record with a setup object stops the start
    (and a setup object with a bad digest or expiry)."""
    p = _provider(tmp_path)
    p._create_user("alice")
    path = tmp_path / "users.json"

    def edit(data):
        mutate(_records_by_id(data)["alice"])

    _write_users(path, edit)
    with pytest.raises(ValueError):
        _reload(tmp_path)


def _records_by_id(data) -> dict[str, dict]:
    return {rec["id"]: rec for rec in _records(data)}


def test_parse_loads_a_pending_record_without_setup(tmp_path):
    p = _provider(tmp_path)
    _user, code = p._create_user("alice")
    _write_users(tmp_path / "users.json",
                 lambda data: _records_by_id(data)["alice"].pop("setup"))
    fresh = _reload(tmp_path)  # does not raise
    assert fresh.get_user("alice").pending is True
    # No setup object means no code can pass.
    assert fresh.check_setup_code("alice", code) is None
    assert fresh.authenticate("alice", "") is None
    assert fresh.session_binding("alice") is None


def test_a_reset_ends_the_old_password(tmp_path):
    """Setup code / A reset ends the old password."""
    p = _provider(tmp_path)
    make_user(p, "alice", "old-password-1")
    assert p.authenticate("alice", "old-password-1") is not None
    assert p.session_binding("alice") is not None
    code = p._issue_setup_code("alice")
    assert isinstance(code, str)
    assert p.get_user("alice").pending is True
    assert p.authenticate("alice", "old-password-1") is None
    assert p.session_binding("alice") is None
    rec = _record(tmp_path / "users.json", "alice")
    assert rec["password_hash"] == "" and "setup" in rec
    assert code not in (tmp_path / "users.json").read_text()
    assert p.check_setup_code("alice", code) is not None


def test_a_new_code_replaces_the_old_code(tmp_path):
    """Setup code / A new code replaces the old code."""
    p = _provider(tmp_path)
    _user, first = p._create_user("alice")
    second = p._issue_setup_code("alice")
    assert second != first
    assert p.check_setup_code("alice", first) is None
    assert p.check_setup_code("alice", second) is not None


def test_the_bootstrap_user_has_no_setup_code(tmp_path):
    """Setup code / The bootstrap user has no setup code."""
    p = _provider(tmp_path)
    path = tmp_path / "users.json"
    before = path.read_bytes()
    with pytest.raises(ValueError):
        p._issue_setup_code("admin")
    assert path.read_bytes() == before
    assert p.get_user("admin").pending is False
    assert p.authenticate("admin", ADMIN_PW) is not None


def test_a_setup_code_for_an_unknown_user_raises_key_error(tmp_path):
    p = _provider(tmp_path)
    path = tmp_path / "users.json"
    before = path.read_bytes()
    with pytest.raises(KeyError):
        p._issue_setup_code("nobody")
    assert path.read_bytes() == before


def test_a_failed_reset_write_changes_nothing(tmp_path, monkeypatch):
    p = _provider(tmp_path)
    make_user(p, "alice", "old-password-1")

    def boom(*_a, **_k):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        p._issue_setup_code("alice")
    monkeypatch.undo()
    assert p.get_user("alice").pending is False
    assert p.authenticate("alice", "old-password-1") is not None


def test_a_valid_code(tmp_path):
    """Setup code check / A valid code."""
    p = _provider(tmp_path)
    _user, code = p._create_user("alice")
    state = p.check_setup_code("alice", code)
    assert isinstance(state, str) and state


def test_an_expired_code_with_a_fake_clock(tmp_path):
    """Setup code check / An expired code: valid before 7 days, `None` at expiry."""
    clock = Clock()
    p = _clocked(tmp_path, clock)
    _user, code = p._create_user("alice")
    clock.now += SEVEN_DAYS - 1
    assert p.check_setup_code("alice", code) is not None
    clock.now += 1  # exactly 7 days after creation: expires_at is not later than the clock
    assert p.check_setup_code("alice", code) is None
    clock.now += 3600
    assert p.check_setup_code("alice", code) is None
    # An expired code is only refused, never used up: a reset issues a fresh one.
    assert p.check_setup_code("alice", p._issue_setup_code("alice")) is not None


def test_a_reset_restarts_the_lifetime(tmp_path):
    clock = Clock()
    p = _clocked(tmp_path, clock)
    p._create_user("alice")
    clock.now += SEVEN_DAYS - 10
    code = p._issue_setup_code("alice")
    clock.now += SEVEN_DAYS - 10  # past the first expiry, inside the second
    assert p.check_setup_code("alice", code) is not None
    assert _record(tmp_path / "users.json", "alice")["setup"]["expires_at"] == (
        clock.now - (SEVEN_DAYS - 10) + SEVEN_DAYS)


def test_a_code_check_of_an_active_user(tmp_path):
    """Setup code check / An active user."""
    p = _provider(tmp_path)
    make_user(p, "alice", "alice-pw-1")
    for guess in ("anything", "", "alice-pw-1"):
        assert p.check_setup_code("alice", guess) is None


def test_a_code_check_refuses_every_other_case(tmp_path):
    p = _provider(tmp_path)
    _user, code = p._create_user("alice")
    assert p.check_setup_code("alice", "not-the-code") is None
    assert p.check_setup_code("alice", "") is None
    assert p.check_setup_code("nobody", code) is None
    assert p.check_setup_code("admin", code) is None
    assert p.check_setup_code("alice", code.upper()) is None


def test_a_code_check_costs_one_sha256_on_every_path(tmp_path, monkeypatch):
    """Setup code check: every case computes one SHA-256 digest."""
    clock = Clock()
    p = _clocked(tmp_path, clock)
    _user, code = p._create_user("alice")
    _user, expired_code = p._create_user("old")
    clock.now += SEVEN_DAYS + 1
    fresh_code = p._issue_setup_code("alice")
    make_user(p, "active", "active-pw-1")
    p._create_user("bare")
    _write_users(tmp_path / "users.json",
                 lambda data: _records_by_id(data)["bare"].pop("setup"))
    p = _clocked(tmp_path, clock)  # reload: "bare" is a pending record with no setup
    calls = _counting(monkeypatch, "sha256")
    cases = {
        "valid": ("alice", fresh_code),
        "wrong code": ("alice", "wrong"),
        "old code": ("alice", code),
        "expired": ("old", expired_code),
        "active user": ("active", "anything"),
        "unknown user": ("nobody", "anything"),
        "bootstrap": ("admin", "anything"),
        "pending without setup": ("bare", "anything"),
    }
    for label, (uid, guess) in cases.items():
        calls.clear()
        p.check_setup_code(uid, guess)
        assert len(calls) == 1, label


def test_a_code_check_compares_in_constant_time(tmp_path, monkeypatch):
    p = _provider(tmp_path)
    _user, code = p._create_user("alice")
    calls = _counting(monkeypatch, "compare_digest", hmac)
    assert p.check_setup_code("alice", code) is not None
    assert len(calls) >= 1
    calls.clear()
    assert p.check_setup_code("alice", "wrong") is None
    assert len(calls) >= 1


def test_a_code_check_never_changes_state(tmp_path):
    """Setup code check: the check changes no state, so it is repeatable."""
    p = _provider(tmp_path)
    _user, code = p._create_user("alice")
    path = tmp_path / "users.json"
    before = path.read_bytes()
    first = p.check_setup_code("alice", code)
    p.check_setup_code("alice", "wrong")
    p.check_setup_code("nobody", "wrong")
    assert p.check_setup_code("alice", code) == first
    assert path.read_bytes() == before
    assert p.get_user("alice").pending is True


def test_a_pending_user_cannot_sign_in(tmp_path):
    """Sign-in / Pending user and A pending user has no binding."""
    p = _provider(tmp_path)
    _user, code = p._create_user("alice")
    assert p.authenticate("alice", "") is None
    assert p.authenticate("alice", code) is None
    assert p.authenticate("alice", "anything") is None
    assert p.session_binding("alice") is None


@pytest.mark.parametrize("password", ["", "SETUP-CODE", "wrong-pw"])
def test_a_pending_user_costs_one_verification_like_an_unknown_user(
        tmp_path, monkeypatch, password):
    """Sign-in / Pending user: one verification against the dummy hash."""
    p = _provider(tmp_path)
    _user, code = p._create_user("alice")
    make_user(p, "bob", "bob-pw-123", iterations=600_000)  # same cost as the dummy hash
    password = code if password == "SETUP-CODE" else password
    calls = _counting(monkeypatch, "pbkdf2_hmac")
    assert p.authenticate("alice", password) is None
    pending = list(calls)
    calls.clear()
    assert p.authenticate("nobody", password) is None
    unknown = list(calls)
    calls.clear()
    assert p.authenticate("bob", "wrong-pw") is None
    known = list(calls)
    assert len(pending) == len(unknown) == len(known) == 1
    assert pending[0][3] == unknown[0][3] == known[0][3]  # the iteration count


def test_a_redeem_completes(tmp_path):
    """Compare-and-swap / A redeem completes."""
    p = _provider(tmp_path)
    _user, code = p._create_user("alice")
    state = p.check_setup_code("alice", code)
    assert state == "setup:" + hashlib.sha256(code.encode()).hexdigest()
    assert p.replace_credential("alice", state, _new_hash()) is True
    assert p.get_user("alice").pending is False
    assert p.authenticate("alice", NEW_PW).id == "alice"
    rec = _record(tmp_path / "users.json", "alice")
    assert rec["password_hash"].startswith("pbkdf2_sha256$")
    assert "setup" not in rec
    assert NEW_PW not in (tmp_path / "users.json").read_text()
    assert stat.S_IMODE(os.stat(tmp_path / "users.json").st_mode) == 0o600
    # The code worked once: neither check nor a second swap accepts it again.
    assert p.check_setup_code("alice", code) is None
    assert p.replace_credential("alice", state, _new_hash("other-pw-9")) is False
    assert p.authenticate("alice", NEW_PW) is not None


def test_the_binding_of_an_active_user_is_the_credential_state(tmp_path):
    """Compare-and-swap: for an active user the binding equals the state, which
    is `password_hash`; a change swaps on the binding."""
    p = _provider(tmp_path)
    make_user(p, "alice", "old-password-1")
    binding = p.session_binding("alice")
    assert binding == _record(tmp_path / "users.json", "alice")["password_hash"]
    # A wrong state never swaps; the right one does, once.
    assert p.replace_credential("alice", "not-the-state", _new_hash()) is False
    assert p.authenticate("alice", "old-password-1") is not None
    assert p.replace_credential("alice", binding, _new_hash()) is True
    assert p.authenticate("alice", NEW_PW) is not None
    assert p.authenticate("alice", "old-password-1") is None
    assert p.session_binding("alice") != binding  # an old session ends
    assert p.replace_credential("alice", binding, _new_hash("third-pw-99")) is False
    assert p.authenticate("alice", NEW_PW) is not None


def test_a_reset_between_check_and_swap(tmp_path):
    """Compare-and-swap / A reset between check and swap."""
    p = _provider(tmp_path)
    _user, code = p._create_user("alice")
    state = p.check_setup_code("alice", code)
    new_code = p._issue_setup_code("alice")
    assert p.replace_credential("alice", state, _new_hash()) is False
    assert p.get_user("alice").pending is True
    assert p.authenticate("alice", NEW_PW) is None
    assert _record(tmp_path / "users.json", "alice")["password_hash"] == ""
    assert p.check_setup_code("alice", new_code) is not None


def test_a_reset_of_an_active_user_between_binding_and_swap(tmp_path):
    p = _provider(tmp_path)
    make_user(p, "alice", "old-password-1")
    binding = p.session_binding("alice")
    p._issue_setup_code("alice")
    assert p.replace_credential("alice", binding, _new_hash()) is False
    assert p.get_user("alice").pending is True


def test_two_redeems_of_one_code(tmp_path):
    """Compare-and-swap / Two redeems of one code: exactly one wins."""
    p = _provider(tmp_path)
    _user, code = p._create_user("alice")
    state_a = p.check_setup_code("alice", code)
    state_b = p.check_setup_code("alice", code)
    results = [p.replace_credential("alice", state_a, _new_hash("first-pass-1")),
               p.replace_credential("alice", state_b, _new_hash("second-pass-2"))]
    assert sorted(results) == [False, True]
    assert p.authenticate("alice", "first-pass-1") is not None
    assert p.authenticate("alice", "second-pass-2") is None


def test_a_change_with_the_binding_of_a_pending_user(tmp_path):
    """Compare-and-swap / A change with the binding of a pending user."""
    p = _provider(tmp_path)
    p._create_user("alice")
    assert p.session_binding("alice") is None
    assert p.replace_credential("alice", p.session_binding("alice"), _new_hash()) is False
    assert p.get_user("alice").pending is True
    assert _record(tmp_path / "users.json", "alice")["password_hash"] == ""


def test_a_swap_for_an_unknown_user_is_false(tmp_path):
    p = _provider(tmp_path)
    path = tmp_path / "users.json"
    before = path.read_bytes()
    assert p.replace_credential("nobody", "x", _new_hash()) is False
    assert p.replace_credential("nobody", None, _new_hash()) is False
    assert path.read_bytes() == before


def test_the_bootstrap_user_refuses_a_swap(tmp_path):
    """Compare-and-swap / The bootstrap user refuses a swap."""
    p = _provider(tmp_path)
    path = tmp_path / "users.json"
    before = path.read_bytes()
    with pytest.raises(ValueError):
        p.replace_credential("admin", p.session_binding("admin"), _new_hash())
    with pytest.raises(ValueError):
        p.replace_credential("admin", "some-state", _new_hash())
    assert path.read_bytes() == before
    assert p.authenticate("admin", ADMIN_PW) is not None
    assert p.authenticate("admin", NEW_PW) is None


def test_a_failed_swap_write_changes_nothing(tmp_path, monkeypatch):
    """Local user store: write the file before memory, also for a swap."""
    p = _provider(tmp_path)
    _user, code = p._create_user("alice")
    state = p.check_setup_code("alice", code)

    def boom(*_a, **_k):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        p.replace_credential("alice", state, _new_hash())
    monkeypatch.undo()
    assert p.get_user("alice").pending is True
    assert p.check_setup_code("alice", code) == state
    assert p.replace_credential("alice", state, _new_hash()) is True


def test_a_short_password(tmp_path):
    """Compare-and-swap / A short password."""
    p = _provider(tmp_path)
    with pytest.raises(ValueError) as exc:
        p.check_new_password("short")
    assert "8" in str(exc.value)  # names the minimum length
    with pytest.raises(ValueError):
        p.check_new_password("1234567")
    with pytest.raises(ValueError):
        p.check_new_password("")
    p.check_new_password("12345678")  # exactly the minimum passes


def test_no_set_password(tmp_path):
    """No admin-chosen password / No set_password (provider; the policy is in
    `tests/test_policy.py`)."""
    p = _provider(tmp_path)
    assert not hasattr(LocalIdentityProvider, "set_password")
    assert not hasattr(p, "set_password")


# --- Remove one membership (security-page) ----------------------------------


def _two_group_world(tmp_path):
    """`alice` in `eng` and `ops`; `bob` in `eng`; the file path."""
    p = _provider(tmp_path)
    p._create_group("eng")
    p._create_group("ops")
    make_user(p, "alice", "pw", groups=["eng", "ops"])
    make_user(p, "bob", "pw", groups=["eng"])
    return p, tmp_path / "users.json"


def test_remove_a_member(tmp_path):
    """Remove one membership / Remove a member."""
    p, path = _two_group_world(tmp_path)
    p.remove_member("eng", "alice")
    assert p.get_user("alice").groups == frozenset({"ops"})
    assert sorted(_record(path, "alice")["groups"]) == ["ops"]
    # Nothing else changes: the other user keeps the group, both groups exist.
    assert p.get_user("bob").groups == frozenset({"eng"})
    assert sorted(_record(path, "bob")["groups"]) == ["eng"]
    assert set(p.list_groups()) == {"admins", "eng", "ops"}
    # A new provider over the same file reads the same state.
    fresh = LocalIdentityProvider(path, hash_password(ADMIN_PW, iterations=1000))
    fresh.load()
    assert fresh.get_user("alice").groups == frozenset({"ops"})


def test_two_removals_do_not_lose_each_other(tmp_path):
    """Remove one membership / Two removals do not lose each other."""
    p, path = _two_group_world(tmp_path)
    p.remove_member("eng", "alice")
    p.remove_member("ops", "alice")
    assert p.get_user("alice").groups == frozenset()
    assert _record(path, "alice")["groups"] == []


def test_remove_a_user_who_is_not_a_member(tmp_path):
    """Remove one membership / A user who is not a member."""
    p, path = _two_group_world(tmp_path)
    before = path.read_bytes()
    assert p.remove_member("ops", "bob") is None  # bob is not in `ops`
    assert path.read_bytes() == before
    assert p.get_user("bob").groups == frozenset({"eng"})


@pytest.mark.parametrize("group,user", [("eng", "nobody"), ("nope", "alice")])
def test_remove_an_unknown_name_raises_key_error(tmp_path, group, user):
    """Remove one membership / An unknown name."""
    p, path = _two_group_world(tmp_path)
    before = path.read_bytes()
    with pytest.raises(KeyError):
        p.remove_member(group, user)
    assert path.read_bytes() == before


def test_remove_member_is_a_synchronous_call():
    """Remove one membership: one synchronous call, no `await`."""
    import inspect

    assert not inspect.iscoroutinefunction(LocalIdentityProvider.remove_member)


# --- private-cascade-halves: the create pre-checks and the private creates ----

_BAD_GROUP_NAME = ("invalid group name: use 1 to 32 lowercase letters, digits, - or _, "
                   "starting with a letter")


def _precheck_world(tmp_path: Path):
    """`eng` and `ops` exist; `alice` is active in `eng`; the file path."""
    p = _provider(tmp_path)
    p._create_group("eng")
    p._create_group("ops")
    make_user(p, "alice", "pw", groups=["eng"])
    return p, tmp_path / "users.json"


def test_check_create_user_contract(tmp_path):
    """Requirement "Create pre-check": scenarios "The pre-check refuses in the
    order of the create" and "The pre-check passes a valid create"."""
    import inspect

    p, path = _precheck_world(tmp_path)
    before = path.read_bytes()
    pattern = r"^[a-z0-9][a-z0-9_-]{0,63}$"
    assert USER_ID_RE.pattern == pattern
    # Each call also holds an unknown group: the earlier refusal must win.
    cases = (
        (("Bad@id",), {"groups": ["nope"]}, f"user id must match {pattern}"),
        (("alice",), {"groups": ["nope"]}, "user alice already exists"),
        (("carol",), {"name": 5, "groups": ["nope"]}, "name must be a string"),
        (("carol",), {"admin": False, "groups": ["admins", "nope"]},
         "groups: unknown group nope"),
    )
    for args, kw, text in cases:
        with pytest.raises(ValueError) as exc:
            p.check_create_user(*args, **kw)
        assert type(exc.value) is ValueError
        assert str(exc.value) == text
    # The contradiction alone.
    with pytest.raises(ValueError) as exc:
        p.check_create_user("carol", admin=False, groups=["admins"])
    assert str(exc.value) == "admin and groups disagree on admins"
    # A valid create: the sorted group names, no write, no user.
    assert p.check_create_user("carol", admin=True, groups=["eng"]) == ["admins", "eng"]
    assert p.check_create_user("carol", groups=["ops", "eng"]) == ["eng", "ops"]
    assert p.get_user("carol") is None
    assert path.read_bytes() == before
    assert not inspect.iscoroutinefunction(LocalIdentityProvider.check_create_user)


def test_check_create_group_contract(tmp_path):
    """Requirement "Create pre-check": the group pre-check refuses a bad name,
    then a duplicate, and returns `None` for a new name."""
    p, path = _precheck_world(tmp_path)
    before = path.read_bytes()
    for bad in ("Bad Name", 5):
        with pytest.raises(ValueError) as exc:
            p.check_create_group(bad)
        assert type(exc.value) is ValueError
        assert str(exc.value) == _BAD_GROUP_NAME
    with pytest.raises(ValueError) as exc:
        p.check_create_group("admins")
    assert str(exc.value) == "group admins already exists"
    assert p.check_create_group("newgroup") is None
    assert "newgroup" not in p.list_groups()
    assert path.read_bytes() == before


def test_the_private_creates_validate_by_themselves(tmp_path):
    """Requirement "Create pre-check": `_create_user` and `_create_group`
    raise the refusals of the pre-checks and write nothing, so a direct
    caller gets the same validation as `AccessPolicy`."""
    p, path = _precheck_world(tmp_path)
    before = path.read_bytes()
    user_cases = (
        (("Bad@id",), {"groups": ["nope"]}, f"user id must match {USER_ID_RE.pattern}"),
        (("alice",), {"groups": ["nope"]}, "user alice already exists"),
        (("carol",), {"name": 5, "groups": ["nope"]}, "name must be a string"),
        (("carol",), {"admin": False, "groups": ["admins", "nope"]},
         "groups: unknown group nope"),
        (("carol",), {"admin": False, "groups": ["admins"]},
         "admin and groups disagree on admins"),
    )
    for args, kw, text in user_cases:
        with pytest.raises(ValueError) as exc:
            p._create_user(*args, **kw)
        assert str(exc.value) == text
        assert path.read_bytes() == before
    for bad in ("Bad Name", 5):
        with pytest.raises(ValueError) as exc:
            p._create_group(bad)
        assert str(exc.value) == _BAD_GROUP_NAME
        assert path.read_bytes() == before
    with pytest.raises(ValueError) as exc:
        p._create_group("admins")
    assert str(exc.value) == "group admins already exists"
    assert path.read_bytes() == before
    assert p.get_user("carol") is None
