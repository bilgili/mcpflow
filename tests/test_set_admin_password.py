"""Group 9: `mcpflow set-admin-password`, the settings change flow, the WARNING.

Derived from `specs/packaging`, `specs/auth`, and `design.md` of
`admin-password-file`.
"""

from __future__ import annotations

import getpass
import logging
import stat

import httpx
import pytest
from conftest import make_settings

from mcpflow import cli
from mcpflow.auth import hash_password, verify_password

NEW = "new-password-1"


def _feed(monkeypatch, *answers):
    it = iter(answers)

    def fake(prompt=""):
        v = next(it)
        if isinstance(v, BaseException):
            raise v
        return v

    monkeypatch.setattr(getpass, "getpass", fake)


def _run(monkeypatch, d, *answers):
    _feed(monkeypatch, *answers)
    return cli.main(["set-admin-password", "--data-dir", str(d)])


def test_set_the_admin_password(tmp_path, monkeypatch, capsys):
    assert _run(monkeypatch, tmp_path, NEW, NEW) == 0
    out, err = capsys.readouterr()
    f = tmp_path / "admin-password.hash"
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    lines = f.read_text().splitlines()
    assert len(lines) == 1 and verify_password(NEW, lines[0])
    assert "browser session" in out and "bearer tokens stay valid" in out
    assert str(f) in out
    for text in (out, err):
        assert NEW not in text and lines[0] not in text
    assert not (tmp_path / "users.json").exists()


def test_two_different_values(tmp_path, monkeypatch, capsys):
    assert _run(monkeypatch, tmp_path, NEW, "other-password-2") == 2
    assert "The two passwords differ." in capsys.readouterr().err
    assert not (tmp_path / "admin-password.hash").exists()


def test_a_short_password(tmp_path, monkeypatch, capsys):
    assert _run(monkeypatch, tmp_path, "short", "short") == 2
    assert "8" in capsys.readouterr().err
    assert not (tmp_path / "admin-password.hash").exists()


@pytest.mark.parametrize("exc", [EOFError(), KeyboardInterrupt()])
def test_end_of_input_and_interrupt(tmp_path, monkeypatch, exc):
    assert _run(monkeypatch, tmp_path, exc) == 1
    assert not (tmp_path / "admin-password.hash").exists()


def test_a_write_error(tmp_path, monkeypatch):
    # A directory in place of the data dir makes the write fail with OSError.
    blocker = tmp_path / "file"
    blocker.write_text("x")
    assert _run(monkeypatch, blocker / "sub", NEW, NEW) == 1
    assert not (blocker / "sub").exists()


def test_the_default_data_directory(tmp_path, monkeypatch):
    for k in ("ADMIN_PASSWORD", "ADMIN_PASSWORD_HASH", "SECRET_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    _feed(monkeypatch, NEW, NEW)
    assert cli.main(["set-admin-password"]) == 0
    assert (tmp_path / "admin-password.hash").is_file()
    assert not (tmp_path / "secret_key").exists()


# --- the settings change flow ------------------------------------------------


def _login(server, password):
    c = httpx.Client(base_url=server.base_url, follow_redirects=False)
    r = c.post("/login", data={"user": "admin", "password": password, "next": "/"})
    assert r.status_code == 303, r.text
    return c


def test_admin_changes_its_password_and_other_sessions_end(server_factory):
    srv = server_factory(password="old-password-1")
    first, second = _login(srv, "old-password-1"), _login(srv, "old-password-1")
    assert second.get("/settings").status_code == 200
    r = first.post(
        "/settings/password",
        data={"current": "old-password-1", "password": NEW, "confirm": NEW},
    )
    assert r.status_code == 303 and r.headers["location"] == "/settings?changed=1"
    # the changing session stays signed in (new cookie), the other one ends
    assert first.get("/settings").status_code == 200
    old = second.get("/settings")
    assert old.status_code in (303, 401) and "/login" in old.headers.get("location", "/login")
    # the new password signs in, the old one does not
    assert _login(srv, NEW)
    bad = httpx.post(
        srv.base_url + "/login",
        data={"user": "admin", "password": "old-password-1", "next": "/"},
    )
    assert bad.status_code != 303


# --- the gateway WARNING -----------------------------------------------------


def test_a_variable_is_ignored_and_named_in_a_warning(tmp_path, caplog):
    from mcpflow.gateway import build_app

    (tmp_path / "logs").mkdir()
    s = make_settings(tmp_path, password="old-password-1", ADMIN_PASSWORD="other-password")
    with caplog.at_level(logging.WARNING, logger="mcpflow.gateway"):
        build_app(s)
    warns = [r for r in caplog.records if r.levelno == logging.WARNING and "ignored" in r.getMessage()]
    assert len(warns) == 1
    msg = warns[0].getMessage()
    assert "ADMIN_PASSWORD" in msg and "other-password" not in msg
    assert "ADMIN_PASSWORD_HASH" not in msg


def test_both_variables_named_values_never(tmp_path, caplog):
    from mcpflow.gateway import build_app

    (tmp_path / "logs").mkdir()
    h = hash_password("zzz-password-9")
    s = make_settings(
        tmp_path, password="old-password-1", ADMIN_PASSWORD="other-password", ADMIN_PASSWORD_HASH=h
    )
    with caplog.at_level(logging.WARNING, logger="mcpflow.gateway"):
        build_app(s)
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "ADMIN_PASSWORD" in text and "ADMIN_PASSWORD_HASH" in text
    assert "other-password" not in text and h not in text


def test_no_warning_when_no_variable_is_set(tmp_path, caplog):
    from mcpflow.gateway import build_app

    (tmp_path / "logs").mkdir()
    with caplog.at_level(logging.WARNING, logger="mcpflow.gateway"):
        build_app(make_settings(tmp_path, password="old-password-1"))
    assert not [r for r in caplog.records if "ignored" in r.getMessage()]


# --- group 9.5 to 9.10 -------------------------------------------------------


def test_data_dir_path(tmp_path, monkeypatch):
    from mcpflow.config import data_dir_path

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DATA_DIR", raising=False)
    assert str(data_dir_path()) == "data"
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "env"))
    assert data_dir_path() == tmp_path / "env"
    assert data_dir_path({"DATA_DIR": str(tmp_path / "ov")}) == tmp_path / "ov"
    assert list(tmp_path.iterdir()) == []  # creates nothing


def test_is_password_hash():
    from mcpflow.auth import is_password_hash

    good = hash_password("x")
    assert is_password_hash(good) is True
    bad = [
        "totally-invalid",
        good.upper(),
        None,
        good.encode(),
        123,
        "pbkdf2_sha256$0$" + "a" * 16 + "$" + "b" * 64,
        "pbkdf2_sha256$1$short$" + "b" * 64,
        "",
    ]
    for v in bad:
        assert is_password_hash(v) is False, v


def test_no_variable_set(tmp_path, monkeypatch):
    from starlette.testclient import TestClient

    from mcpflow.config import load_settings
    from mcpflow.gateway import build_app

    for k in ("ADMIN_PASSWORD", "ADMIN_PASSWORD_HASH"):
        monkeypatch.delenv(k, raising=False)
    (tmp_path / "logs").mkdir()
    s = load_settings({"DATA_DIR": str(tmp_path)})
    assert s.ignored_admin_env == ()
    assert not hasattr(s, "admin_password_hash")
    with TestClient(build_app(s)) as c:
        assert c.get("/login").status_code == 200


def test_a_variable_is_ignored(tmp_path, monkeypatch):
    from mcpflow.config import load_settings

    monkeypatch.setenv("ADMIN_PASSWORD", "other-password")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    s = load_settings({"DATA_DIR": str(tmp_path)})
    assert s.ignored_admin_env == ("ADMIN_PASSWORD",)
    assert "other-password" not in repr(s) and "pbkdf2" not in repr(s)


def test_an_ignored_variable_does_not_sign_in(server_factory):
    srv = server_factory(password="old-password-1", ADMIN_PASSWORD="other-password")
    assert _login(srv, "old-password-1")
    r = httpx.post(
        srv.base_url + "/login",
        data={"user": "admin", "password": "other-password", "next": "/"},
    )
    assert r.status_code != 303


def test_an_upgrade_keeps_the_admin_hash(tmp_path):
    from starlette.testclient import TestClient

    from mcpflow.config import load_settings
    from mcpflow.gateway import build_app

    (tmp_path / "logs").mkdir()
    build_app(make_settings(tmp_path, password="old-password-1"))  # users.json holds the hash
    (tmp_path / "admin-password.hash").unlink(missing_ok=True)  # an upgrade has no file
    with TestClient(build_app(load_settings({"DATA_DIR": str(tmp_path)})), follow_redirects=False) as c:
        r = c.post("/login", data={"user": "admin", "password": "old-password-1", "next": "/"})
        assert r.status_code == 303


def test_the_file_keeps_the_bearer_tokens(server_factory):
    from starlette.testclient import TestClient

    from mcpflow.auth import TokenStore
    from mcpflow.config import load_settings
    from mcpflow.gateway import build_app
    from mcpflow.identity import write_admin_password_file

    holder: dict = {}

    def seed(d):
        store = TokenStore(d / "tokens.json", d / "user_tokens.json")
        store.load()
        _, holder["tok"] = store.create("adm", "admin", "admin")

    srv = server_factory(seed, password="old-password-1")
    auth = {"Authorization": f"Bearer {holder['tok']}"}
    old = _login(srv, "old-password-1")
    assert httpx.get(srv.base_url + "/api/servers", headers=auth).status_code == 200

    # a password-file apply at the next start
    write_admin_password_file(srv.data_dir, hash_password(NEW))
    app = build_app(load_settings({"DATA_DIR": str(srv.data_dir)}))
    with TestClient(app, follow_redirects=False) as c:
        assert c.get("/api/servers", headers=auth).status_code == 200
        cookie = {"Cookie": "mcpflow_session=" + old.cookies.get("mcpflow_session")}
        assert c.get("/settings", headers=cookie).status_code != 200  # old cookie rejected

    # a change through the settings page
    srv2 = server_factory(seed, password="old-password-1")
    auth2 = {"Authorization": f"Bearer {holder['tok']}"}
    cl = _login(srv2, "old-password-1")
    r = cl.post(
        "/settings/password",
        data={"current": "old-password-1", "password": NEW, "confirm": NEW},
    )
    assert r.status_code == 303
    assert httpx.get(srv2.base_url + "/api/servers", headers=auth2).status_code == 200
