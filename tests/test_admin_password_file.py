"""The admin password file and the bootstrap rules of the provider.

Each test is one scenario of the delta `specs/identity/spec.md` of the
change `admin-password-file` (requirements Bootstrap admin user, Credential
compare-and-swap, No admin-chosen password, Admin password file, Admin
password file writer), or one frozen interface of its `design.md`
("Proposed interfaces", steps S1 to S8 of `load`). The expectations come
from the spec, not from the implementation. The shape of `users.json` is
not frozen, so a test reads it as generic JSON.

Faults: `os.replace` and `pathlib.Path.unlink` are filtered by file name
(tasks.md, Interface note N10), so `_save` still works. A crash is a
test-only `BaseException`, so no handler in `load` catches it. Each test
names the mutation that must make it fail (group 11 runs them).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
import time
from pathlib import Path

import pytest

from mcpflow.auth import hash_password
from mcpflow.identity import (
    ADMIN_PASSWORD_CLAIM,
    ADMIN_PASSWORD_FILE,
    ADMIN_PENDING_NOTE,
    LocalIdentityProvider,
    write_admin_password_file,
)

LOGGER = "mcpflow.identity"
PENDING_NOTE = (
    "No admin password yet. Run `mcpflow set-admin-password` on the server, then restart."
)
INFO_LINE = (
    "admin password set from admin-password.hash; every admin browser session has "
    "ended; bearer tokens stay valid, revoke them on the tokens page"
)

_real_replace = os.replace
_real_unlink = Path.unlink


class _Crash(BaseException):
    """A process end. No `except Exception` in `load` catches it."""


def _h(pw: str) -> str:
    return hash_password(pw, iterations=1000)


def _start(d: Path) -> LocalIdentityProvider:
    p = LocalIdentityProvider(d / "users.json")
    p.load()
    return p


def _apply(d: Path, pw: str) -> LocalIdentityProvider:
    """A start that applies a file with the hash of `pw`."""
    write_admin_password_file(d, _h(pw))
    return _start(d)


def _admin_record(d: Path) -> dict:
    data = json.loads((d / "users.json").read_text())

    def walk(node):
        if isinstance(node, dict):
            if node.get("id") == "admin":
                yield node
            for v in node.values():
                yield from walk(v)
        elif isinstance(node, list):
            for v in node:
                yield from walk(v)

    recs = list(walk(data))
    assert len(recs) == 1
    return recs[0]


def _edit_admin(d: Path, mutate) -> None:
    path = d / "users.json"
    data = json.loads(path.read_text())

    def walk(node):
        if isinstance(node, dict):
            if node.get("id") == "admin":
                mutate(node)
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(data)
    path.write_text(json.dumps(data))


def _records(caplog, level: int) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == LOGGER and r.levelno == level]


def _fail_replace(monkeypatch, src_name: str, exc: BaseException) -> None:
    def fake(src, dst, *a, **kw):
        if Path(src).name == src_name:
            raise exc
        return _real_replace(src, dst, *a, **kw)

    monkeypatch.setattr(os, "replace", fake)


def _fail_unlink(monkeypatch, name: str, exc: BaseException) -> None:
    def fake(self, missing_ok=False):
        if self.name == name:
            raise exc
        return _real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", fake)


def _names_path(msg: str, d: Path, *names: str) -> bool:
    return any(str(d / n) in msg for n in names)


# --- Bootstrap admin user ------------------------------------------------------


def test_first_start_of_a_fresh_install(tmp_path, caplog):
    """Bootstrap admin user / First start of a fresh install; Admin password
    file / A pending admin at start. Design D5, S8."""
    caplog.set_level(logging.INFO, logger=LOGGER)
    caplog.clear()  # the setup apply logs a WARNING too
    p = _start(tmp_path)
    rec = _admin_record(tmp_path)
    assert rec["password_hash"] == ""
    assert "admins" in rec["groups"]
    user = p.get_user("admin")
    assert user.pending is True and user.is_admin
    # A pending admin cannot sign in and binds no cookie (PendingNoSignIn).
    assert p.authenticate("admin", "") is None
    assert p.authenticate("admin", "anything") is None
    assert p.session_binding("admin") is None
    assert ADMIN_PENDING_NOTE == PENDING_NOTE
    warnings = _records(caplog, logging.WARNING)
    assert [r.getMessage() for r in warnings] == [PENDING_NOTE]


def test_an_active_admin_logs_no_pending_note(tmp_path, caplog):
    """Admin password file: the WARNING only "when admin is pending"."""
    _apply(tmp_path, "old-password")
    caplog.set_level(logging.INFO, logger=LOGGER)
    caplog.clear()  # the setup apply logs a WARNING too
    _start(tmp_path)
    assert not any(PENDING_NOTE in r.getMessage() for r in caplog.records)


def test_an_existing_hash_stays(tmp_path):
    """Bootstrap admin user / An existing hash stays. Design S2."""
    _start(tmp_path)
    h = _h("kept-password")
    _edit_admin(tmp_path, lambda rec: rec.update(password_hash=h))
    p = _start(tmp_path)
    assert _admin_record(tmp_path)["password_hash"] == h
    assert p.authenticate("admin", "kept-password") is not None
    assert p.get_user("admin").pending is False


def test_a_hand_edit_cannot_give_admin_a_setup_code(tmp_path):
    """Bootstrap admin user / A hand edit cannot give admin a setup code.
    Design D6, S2."""
    _start(tmp_path)
    code = "A1b2C3d4E5f6G7h8"
    setup = {"sha256": hashlib.sha256(code.encode()).hexdigest(),
             "expires_at": int(time.time()) + 3600}
    _edit_admin(tmp_path, lambda rec: rec.update(setup=setup))
    p = _start(tmp_path)
    assert "setup" not in _admin_record(tmp_path)
    assert p.check_setup_code("admin", code) is None
    assert p.get_user("admin").pending is True


def test_no_setup_code_for_admin(tmp_path):
    """Bootstrap admin user (no setup code for admin, ValueError before any
    write); No admin-chosen password / No set_password. Design D6."""
    pending = tmp_path / "pending"
    active = tmp_path / "active"
    pending.mkdir()
    providers = [_start(pending), _apply(active, "old-password")]
    for d, p in zip((pending, active), providers):
        before = (d / "users.json").read_bytes()
        with pytest.raises(ValueError):
            p.check_reset("admin")
        with pytest.raises(ValueError):
            p._issue_setup_code("admin")
        assert (d / "users.json").read_bytes() == before
        assert p.check_setup_code("admin", "A1b2C3d4E5f6G7h8") is None
    assert not hasattr(LocalIdentityProvider, "set_password")
    assert not hasattr(providers[0], "set_password")


# --- Admin password file -------------------------------------------------------


def test_the_file_applies_at_start(tmp_path, caplog):
    """Admin password file / The file applies at start. Design D2, F4, S6."""
    old = _apply(tmp_path, "old-password")
    old_binding = old.session_binding("admin")
    assert old_binding is not None
    h = _h("new-password-1")
    write_admin_password_file(tmp_path, h)
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    caplog.clear()  # the setup apply logs a WARNING too
    p = _start(tmp_path)
    assert p.authenticate("admin", "new-password-1") is not None
    assert p.authenticate("admin", "old-password") is None
    assert not (tmp_path / ADMIN_PASSWORD_FILE).exists()
    assert not (tmp_path / ADMIN_PASSWORD_CLAIM).exists()
    assert _admin_record(tmp_path)["password_hash"] == h
    infos = [r.getMessage() for r in _records(caplog, logging.WARNING)]
    assert infos.count(INFO_LINE) == 1
    # No log record holds the hash, its salt, or its digest field.
    _, _, salt, digest = h.split("$")
    assert h not in caplog.text
    assert digest not in caplog.text
    assert salt not in caplog.text
    # Every admin browser session ends through the binding.
    new_binding = p.session_binding("admin")
    assert new_binding is not None and new_binding != old_binding


def test_a_crash_after_the_write_of_users_json(tmp_path, monkeypatch):
    """Admin password file / A crash after the write of users.json. Design D2."""
    _apply(tmp_path, "old-password")
    h = _h("new-password-1")
    write_admin_password_file(tmp_path, h)
    with monkeypatch.context() as m:
        _fail_unlink(m, ADMIN_PASSWORD_CLAIM, _Crash())
        with pytest.raises(_Crash):
            _start(tmp_path)
    assert _admin_record(tmp_path)["password_hash"] == h
    assert (tmp_path / ADMIN_PASSWORD_CLAIM).exists()
    p = _start(tmp_path)
    assert not (tmp_path / ADMIN_PASSWORD_CLAIM).exists()
    assert not (tmp_path / ADMIN_PASSWORD_FILE).exists()
    assert p.authenticate("admin", "new-password-1") is not None
    assert _admin_record(tmp_path)["password_hash"] == h


def test_a_failed_delete_stops_the_start(tmp_path, monkeypatch, caplog):
    """Admin password file / A failed delete stops the start (design-review
    section 9). Design R2, S6. Model: admin_password_file_gate_unlinkcontinues.

    Mutation: catch the OSError of the unlink and continue. This test fails.
    """
    _apply(tmp_path, "old-password")
    h = _h("new-password-1")
    write_admin_password_file(tmp_path, h)
    caplog.set_level(logging.INFO, logger=LOGGER)
    caplog.clear()  # the setup apply logs a WARNING too
    _fail_unlink(monkeypatch, ADMIN_PASSWORD_CLAIM, OSError(5, "I/O error"))
    with pytest.raises(OSError):
        _start(tmp_path)
    errors = _records(caplog, logging.ERROR)
    assert len(errors) == 1
    assert _names_path(errors[0].getMessage(), tmp_path, ADMIN_PASSWORD_CLAIM)
    assert _admin_record(tmp_path)["password_hash"] == h
    assert h not in caplog.text
    assert INFO_LINE not in caplog.text  # the INFO line comes after the unlink


def test_a_failed_rename_stops_the_start(tmp_path, monkeypatch, caplog):
    """Admin password file / A failed rename stops the start (design-review
    section 9). Design R1, S3. Model: admin_password_file_gate_keepmain.

    Mutation: catch the OSError of the rename and continue with S4. This
    test fails.
    """
    _apply(tmp_path, "current-password")
    write_admin_password_file(tmp_path, _h("newer-password"))
    (tmp_path / ADMIN_PASSWORD_CLAIM).write_text(_h("older-password") + "\n")
    before = (tmp_path / "users.json").read_bytes()
    caplog.set_level(logging.INFO, logger=LOGGER)
    caplog.clear()  # the setup apply logs a WARNING too
    _fail_replace(monkeypatch, ADMIN_PASSWORD_FILE, PermissionError(13, "Permission denied"))
    with pytest.raises(OSError):
        _start(tmp_path)
    errors = _records(caplog, logging.ERROR)
    assert len(errors) == 1
    assert _names_path(errors[0].getMessage(), tmp_path,
                       ADMIN_PASSWORD_FILE, ADMIN_PASSWORD_CLAIM)
    assert (tmp_path / "users.json").read_bytes() == before
    # No write came before the rename: both files stay.
    assert (tmp_path / ADMIN_PASSWORD_FILE).exists()
    assert (tmp_path / ADMIN_PASSWORD_CLAIM).exists()


def test_a_file_not_found_of_the_rename_does_not_stop_the_start(tmp_path, monkeypatch, caplog):
    """Admin password file: "A FileNotFoundError of the rename SHALL mean that
    no file exists." Design S3."""
    _apply(tmp_path, "current-password")
    write_admin_password_file(tmp_path, _h("newer-password"))
    caplog.set_level(logging.INFO, logger=LOGGER)
    caplog.clear()  # the setup apply logs a WARNING too
    _fail_replace(monkeypatch, ADMIN_PASSWORD_FILE, FileNotFoundError(2, "No such file"))
    p = _start(tmp_path)
    assert _records(caplog, logging.ERROR) == []
    assert p.authenticate("admin", "current-password") is not None
    # Also with no file at all.
    monkeypatch.undo()
    (tmp_path / ADMIN_PASSWORD_FILE).unlink()
    p = _start(tmp_path)
    assert p.authenticate("admin", "current-password") is not None


def test_a_second_apply_writes_nothing(tmp_path, caplog):
    """Admin password file / A second apply writes nothing (design-review
    section 9). Design D2, F3, S5.

    Mutation: call `_save` at every `load` that has a candidate. This test
    fails.
    """
    first = _apply(tmp_path, "new-password-1")
    binding = first.session_binding("admin")
    h = _admin_record(tmp_path)["password_hash"]
    (tmp_path / ADMIN_PASSWORD_CLAIM).write_text(h + "\n")
    users = tmp_path / "users.json"
    before = users.read_bytes()
    st = users.stat()
    caplog.set_level(logging.INFO, logger=LOGGER)
    caplog.clear()  # the setup apply logs a WARNING too
    p = _start(tmp_path)
    after = users.stat()
    assert users.read_bytes() == before
    assert (after.st_ino, after.st_mtime_ns) == (st.st_ino, st.st_mtime_ns)
    assert not (tmp_path / ADMIN_PASSWORD_CLAIM).exists()
    assert p.session_binding("admin") == binding
    assert p.authenticate("admin", "new-password-1") is not None
    assert _records(caplog, logging.ERROR) == []


def test_a_crash_before_the_write_of_users_json(tmp_path, monkeypatch):
    """Admin password file / A crash before the write of users.json. Design D2.
    Model: admin_password_file_deletefirst.

    Mutation: unlink the claimed file before `_save`. This test fails.
    """
    _apply(tmp_path, "old-password")
    h = _h("new-password-1")
    write_admin_password_file(tmp_path, h)

    def crash(self, *a, **kw):
        raise _Crash()

    with monkeypatch.context() as m:
        m.setattr(LocalIdentityProvider, "_save", crash)
        with pytest.raises(_Crash):
            _start(tmp_path)
    assert _admin_record(tmp_path)["password_hash"] != h
    p = _start(tmp_path)
    assert p.authenticate("admin", "new-password-1") is not None
    assert _admin_record(tmp_path)["password_hash"] == h
    assert not (tmp_path / ADMIN_PASSWORD_CLAIM).exists()
    assert not (tmp_path / ADMIN_PASSWORD_FILE).exists()


def test_a_write_during_a_start(tmp_path, monkeypatch):
    """Admin password file / A write during a start (a CLI write is not lost).
    Design D3. Model: admin_password_file_noclaim.

    Mutation: read and delete `admin-password.hash` by its path, with no
    claim. This test fails.
    """
    _apply(tmp_path, "old-password")
    write_admin_password_file(tmp_path, _h("first-password"))
    h2 = _h("second-password")
    real_save = LocalIdentityProvider._save
    written = []

    def save(self, *a, **kw):
        # The persist step: after the claim and before the end of `load`.
        if not written:
            write_admin_password_file(tmp_path, h2)
            written.append(True)
        return real_save(self, *a, **kw)

    with monkeypatch.context() as m:
        m.setattr(LocalIdentityProvider, "_save", save)
        p = _start(tmp_path)
    assert written
    assert p.authenticate("admin", "first-password") is not None
    assert (tmp_path / ADMIN_PASSWORD_FILE).read_text().strip() == h2
    p = _start(tmp_path)
    assert p.authenticate("admin", "second-password") is not None
    assert not (tmp_path / ADMIN_PASSWORD_FILE).exists()
    assert not (tmp_path / ADMIN_PASSWORD_CLAIM).exists()


def test_an_invalid_file(tmp_path, caplog):
    """Admin password file / An invalid file. Design D4, N3.
    Model: admin_password_file_badclears.

    Mutations: clear the admin hash for an invalid file; delete the invalid
    file; log `str(exc)`. Each fails this test.
    """
    _apply(tmp_path, "old-password")
    h = _admin_record(tmp_path)["password_hash"]
    (tmp_path / ADMIN_PASSWORD_FILE).write_text("not-a-hash\n")
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    caplog.clear()  # the setup apply logs a WARNING too
    p = _start(tmp_path)  # returns: the start continues
    assert _admin_record(tmp_path)["password_hash"] == h
    assert p.authenticate("admin", "old-password") is not None
    errors = _records(caplog, logging.ERROR)
    assert len(errors) == 1
    msg = errors[0].getMessage()
    assert _names_path(msg, tmp_path, ADMIN_PASSWORD_CLAIM)
    assert "not a pbkdf2_sha256 hash" in msg
    assert "not-a-hash" not in caplog.text
    assert (tmp_path / ADMIN_PASSWORD_CLAIM).read_text().strip() == "not-a-hash"
    assert INFO_LINE not in caplog.text
    # Each later start logs the error again and keeps the file.
    caplog.clear()
    _start(tmp_path)
    assert len(_records(caplog, logging.ERROR)) == 1
    assert (tmp_path / ADMIN_PASSWORD_CLAIM).exists()


def test_an_undecodable_file_cannot_be_read(tmp_path, caplog):
    """Admin password file / An invalid file: a file that `load` cannot read
    as UTF-8. The ERROR never holds a byte of it (N3)."""
    _apply(tmp_path, "old-password")
    h = _admin_record(tmp_path)["password_hash"]
    (tmp_path / ADMIN_PASSWORD_FILE).write_bytes(b"\xff\xfe")
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    caplog.clear()  # the setup apply logs a WARNING too
    p = _start(tmp_path)
    assert _admin_record(tmp_path)["password_hash"] == h
    assert p.authenticate("admin", "old-password") is not None
    errors = _records(caplog, logging.ERROR)
    assert len(errors) == 1
    msg = errors[0].getMessage()
    assert "cannot read" in msg
    assert _names_path(msg, tmp_path, ADMIN_PASSWORD_CLAIM)
    text = caplog.text.lower()
    assert "0xff" not in text and "\\xff" not in text and "0xfe" not in text
    assert (tmp_path / ADMIN_PASSWORD_CLAIM).read_bytes() == b"\xff\xfe"


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0,
                    reason="root reads a mode 000 file")
def test_an_unreadable_file_cannot_be_read(tmp_path, caplog):
    """Admin password file / An invalid file: a file that `load` cannot read
    (mode 000) does not stop the start. Design D4."""
    _apply(tmp_path, "old-password")
    h = _admin_record(tmp_path)["password_hash"]
    f = tmp_path / ADMIN_PASSWORD_FILE
    f.write_text(_h("unread-password") + "\n")
    f.chmod(0)
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    caplog.clear()  # the setup apply logs a WARNING too
    try:
        p = _start(tmp_path)
        assert _admin_record(tmp_path)["password_hash"] == h
        assert p.authenticate("admin", "old-password") is not None
        errors = _records(caplog, logging.ERROR)
        assert len(errors) == 1
        assert "cannot read" in errors[0].getMessage()
        assert (tmp_path / ADMIN_PASSWORD_CLAIM).exists()
    finally:
        for n in (ADMIN_PASSWORD_FILE, ADMIN_PASSWORD_CLAIM):
            if (tmp_path / n).exists():
                (tmp_path / n).chmod(0o600)


def test_a_newer_file_replaces_an_invalid_claimed_file(tmp_path):
    """Admin password file / A newer file replaces an invalid claimed file.
    Design D3."""
    _apply(tmp_path, "old-password")
    (tmp_path / ADMIN_PASSWORD_CLAIM).write_text("garbage\n")
    h = _h("new-password-1")
    write_admin_password_file(tmp_path, h)
    p = _start(tmp_path)
    assert p.authenticate("admin", "new-password-1") is not None
    assert _admin_record(tmp_path)["password_hash"] == h
    assert not (tmp_path / ADMIN_PASSWORD_FILE).exists()
    assert not (tmp_path / ADMIN_PASSWORD_CLAIM).exists()


def test_no_reload_while_running(tmp_path):
    """Admin password file / No reload while running. Design D8."""
    p = _apply(tmp_path, "old-password")
    write_admin_password_file(tmp_path, _h("new-password-1"))
    assert p.authenticate("admin", "old-password") is not None
    assert p.authenticate("admin", "new-password-1") is None
    p._create_group("eng")  # a mutation of the running server
    assert p.authenticate("admin", "old-password") is not None
    assert (tmp_path / ADMIN_PASSWORD_FILE).exists()
    assert not (tmp_path / ADMIN_PASSWORD_CLAIM).exists()


def test_memory_holds_the_applied_hash(tmp_path):
    """Admin password file: "The memory of the provider SHALL hold the applied
    hash after load." Design S7. Model: admin_password_file_gate_noadopt.

    Mutation: adopt the parsed state in S7. This test fails.
    """
    _apply(tmp_path, "old-password")
    h = _h("new-password-1")
    write_admin_password_file(tmp_path, h)
    p = _start(tmp_path)
    assert p.session_binding("admin") == h
    p._create_group("eng")
    assert _admin_record(tmp_path)["password_hash"] == h
    assert _start(tmp_path).authenticate("admin", "new-password-1") is not None


def test_the_pending_admin_is_activated_only_by_the_file(tmp_path):
    """Admin password file / A pending admin at start; NoSetupForAdmin: admin
    leaves pending only through the file at start."""
    _start(tmp_path)
    p = _apply(tmp_path, "new-password-1")
    assert p.get_user("admin").pending is False
    assert p.authenticate("admin", "new-password-1") is not None


# --- Credential compare-and-swap ------------------------------------------------


def test_a_pending_bootstrap_user_refuses_every_swap(tmp_path):
    """Credential compare-and-swap / A pending bootstrap user refuses every
    swap (design-review section 9). Design D6, N4.

    Mutation: return "setup:" for a pending user without a setup object.
    This test fails.
    """
    p = _start(tmp_path)
    before = (tmp_path / "users.json").read_bytes()
    for s in (None, "", "setup:"):
        assert p.replace_credential("admin", s, _h("new-password-1")) is False
    assert (tmp_path / "users.json").read_bytes() == before
    assert p._credential_state("admin") is None
    assert p.get_user("admin").pending is True
    assert p.authenticate("admin", "new-password-1") is None


def test_the_active_bootstrap_user_swaps(tmp_path):
    """Credential compare-and-swap / The active bootstrap user swaps. Design D7.

    Mutation: put back the refusal of admin in `replace_credential`. This
    test fails.
    """
    p = _apply(tmp_path, "old-password")
    old = p.session_binding("admin")
    h = _h("new-password-1")
    assert p.replace_credential("admin", old, h) is True
    assert p.session_binding("admin") == h
    assert _admin_record(tmp_path)["password_hash"] == h
    # The old binding no longer matches: a cookie bound to it fails.
    assert p.replace_credential("admin", old, _h("third-password")) is False


# --- Admin password file writer ---------------------------------------------------


def test_the_writer_leaves_users_json_alone(tmp_path):
    """Admin password file writer / The writer leaves users.json alone."""
    _apply(tmp_path, "old-password")
    before = (tmp_path / "users.json").read_bytes()
    h = _h("new-password-1")
    out = write_admin_password_file(tmp_path, h)
    assert out == tmp_path / ADMIN_PASSWORD_FILE
    assert (tmp_path / "users.json").read_bytes() == before
    assert out.read_text() == h + "\n"
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_the_writer_writes_no_users_json(tmp_path):
    """Admin password file writer: it SHALL NOT read or write users.json."""
    write_admin_password_file(tmp_path, _h("new-password-1"))
    assert sorted(p.name for p in tmp_path.iterdir()) == [ADMIN_PASSWORD_FILE]


@pytest.mark.parametrize("value", [
    "pbkdf2_sha256$0$00$00",
    "hunter2-secret-value",
    "pbkdf2_sha256$1000$" + "ab" * 8 + "$" + "C" * 64,  # uppercase hex
])
def test_the_writer_refuses_a_bad_hash(tmp_path, value):
    """Admin password file writer / The writer refuses a bad hash."""
    d = tmp_path / "d"
    d.mkdir()
    (d / "keep").write_text("x")
    with pytest.raises(ValueError) as info:
        write_admin_password_file(d, value)
    assert sorted(p.name for p in d.iterdir()) == ["keep"]
    msg = str(info.value)
    assert value not in msg
    for part in value.split("$")[1:]:
        assert part not in msg


def test_the_writer_refuses_before_it_creates_the_directory(tmp_path):
    """Admin password file writer: ValueError "before any write"."""
    d = tmp_path / "missing"
    with pytest.raises(ValueError):
        write_admin_password_file(d, "not-a-hash")
    assert not d.exists()


@pytest.mark.parametrize("exc", [OSError(28, "No space left"), KeyboardInterrupt()])
def test_the_writer_removes_its_temporary_file(tmp_path, monkeypatch, exc):
    """Admin password file writer: on an error it removes the temporary file
    and raises the error again (N7: also a KeyboardInterrupt)."""
    seen = []

    def fake(src, dst, *a, **kw):
        if Path(dst).name == ADMIN_PASSWORD_FILE:
            seen.append(Path(src))
            raise exc
        return _real_replace(src, dst, *a, **kw)

    monkeypatch.setattr(os, "replace", fake)
    with pytest.raises(type(exc)):
        write_admin_password_file(tmp_path, _h("new-password-1"))
    assert len(seen) == 1
    assert seen[0].parent == tmp_path
    assert seen[0].name.startswith(".admin-password.hash.")
    assert list(tmp_path.glob(".admin-password.hash.*")) == []
    assert not (tmp_path / ADMIN_PASSWORD_FILE).exists()


def test_the_writer_creates_the_directory(tmp_path):
    """Admin password file writer: it creates `data_dir` (parents too)."""
    d = tmp_path / "a" / "b"
    h = _h("new-password-1")
    out = write_admin_password_file(d, h)
    assert out == d / ADMIN_PASSWORD_FILE
    assert out.read_text() == h + "\n"
    assert list(d.glob(".admin-password.hash.*")) == []
