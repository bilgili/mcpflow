"""Web pages and deploy files of admin-password-file (tasks group 10).

Each test is a scenario of `specs/auth/spec.md`, `specs/web-ui/spec.md`, or
`specs/docker-deploy/spec.md`. One real `build_app` behind `TestClient`.
"""

from __future__ import annotations

import asyncio
import html as htmllib
import json
import re
from pathlib import Path

import pytest
from conftest import make_settings
from starlette.testclient import TestClient

from mcpflow import cli
from mcpflow.gateway import build_app
from mcpflow.identity import ADMIN_PENDING_NOTE
from mcpflow.web import _LOGIN_ERROR, _SETUP_ERROR

ROOT = Path(__file__).resolve().parent.parent
CMD = "mcpflow set-admin-password"
NEW = "new-password-1"


def _plain(html: str) -> str:
    """Page text without tags, so `<code>` around the command does not matter."""
    return htmllib.unescape(re.sub(r"<[^>]+>", "", html))


def has_note(html: str) -> bool:
    return _plain(ADMIN_PENDING_NOTE).replace("`", "") in _plain(html).replace("`", "")


@pytest.fixture
def sleeps(monkeypatch):
    recorded: list[float] = []
    real = asyncio.sleep

    async def fake(delay, *a, **k):
        if delay >= 1:
            recorded.append(delay)
            return await real(0)
        return await real(delay, *a, **k)

    monkeypatch.setattr(asyncio, "sleep", fake)
    return recorded


def client_for(d, **kw):
    (d / "logs").mkdir(exist_ok=True)
    return TestClient(build_app(make_settings(d, **kw)), follow_redirects=False)


def cookie_of(resp) -> str:
    return resp.cookies["mcpflow_session"]


def get(c, path, cookie=None):
    r = c.get(path, headers={"Cookie": f"mcpflow_session={cookie}"} if cookie else {})
    c.cookies.clear()
    return r


def post(c, path, data, cookie=None):
    r = c.post(path, data=data, headers={"Cookie": f"mcpflow_session={cookie}"} if cookie else {})
    c.cookies.clear()
    return r


def sign_in(c, password):
    r = post(c, "/login", {"user": "admin", "password": password, "next": "/"})
    assert r.status_code == 303, r.text
    return cookie_of(r)


def admin_hash(d) -> str:
    users = json.loads((d / "users.json").read_text())["users"]
    return next(u for u in users if u["id"] == "admin")["password_hash"]


def test_a_pending_admin_shows_the_note(tmp_path, sleeps):
    with client_for(tmp_path, password=None) as c:
        page = get(c, "/login")
        assert page.status_code == 200
        assert has_note(page.text)
        assert f"<code>{CMD}</code>" in page.text
        refused = post(c, "/login", {"user": "admin", "password": "x", "next": "/"})
        assert refused.status_code != 303 and has_note(refused.text)


def test_an_active_admin_hides_the_note(tmp_path):
    with client_for(tmp_path) as c:
        page = get(c, "/login")
        assert "No admin password yet" not in page.text
        assert 'name="user"' in page.text and 'name="password"' in page.text
        assert 'href="/login/setup"' in page.text


def test_a_fresh_install_cannot_sign_in_as_admin(tmp_path, sleeps):
    with client_for(tmp_path, password=None) as c:
        for user in ("admin", ""):
            for pw in ("", "anything-at-all"):
                before = len(sleeps)
                r = post(c, "/login", {"user": user, "password": pw, "next": "/"})
                assert r.status_code != 303
                assert "set-cookie" not in r.headers
                assert _plain(_LOGIN_ERROR) in _plain(r.text)
                assert len(sleeps) == before + 1 and sleeps[-1] >= 1


def test_no_setup_code_for_a_pending_admin(tmp_path, sleeps):
    with client_for(tmp_path, password=None) as c:
        r = post(c, "/login/setup",
                 {"user": "admin", "code": "any-code", "password": NEW, "confirm": NEW})
        assert r.status_code == 400
        assert _plain(_SETUP_ERROR) in _plain(r.text)
        assert sleeps and sleeps[0] >= 1
        assert "set-cookie" not in r.headers
        assert not admin_hash(tmp_path)


def test_the_admin_sees_the_form(tmp_path):
    with client_for(tmp_path) as c:
        page = get(c, "/settings", sign_in(c, "secret"))
        assert page.status_code == 200
        assert 'action="/settings/password"' in page.text
        for name in ("current", "password", "confirm"):
            tag = re.search(rf'<input[^>]*name="{name}"[^>]*>', page.text)
            assert tag and 'type="password"' in tag.group(0), name
        assert "ADMIN_PASSWORD" not in page.text  # also covers ADMIN_PASSWORD_HASH


def test_the_bootstrap_user_changes_the_password_here(tmp_path):
    with client_for(tmp_path) as c:
        old_a, old_b = sign_in(c, "secret"), sign_in(c, "secret")
        old_hash = admin_hash(tmp_path)
        r = post(c, "/settings/password",
                 {"current": "secret", "password": NEW, "confirm": NEW}, old_a)
        assert r.status_code == 303
        assert r.headers["location"] == "/settings?changed=1"
        new = cookie_of(r)
        assert admin_hash(tmp_path) not in ("", old_hash)
        for old in (old_a, old_b):
            r2 = get(c, "/", old)
            assert r2.status_code == 303 and r2.headers["location"].startswith("/login")
        assert get(c, "/", new).status_code == 200


def test_the_file_ends_the_pending_state(tmp_path, monkeypatch):
    with client_for(tmp_path, password=None) as c:
        assert has_note(get(c, "/login").text)
    answers = iter([NEW, NEW])
    monkeypatch.setattr("getpass.getpass", lambda *a, **k: next(answers))
    assert cli.main(["set-admin-password", "--data-dir", str(tmp_path)]) == 0
    with client_for(tmp_path, password=None) as c:  # password=None writes no file
        assert sign_in(c, NEW)
        assert "No admin password yet" not in get(c, "/login").text


def test_the_env_example_names_the_command():
    env = (ROOT / ".env.example").read_text()
    for line in env.splitlines():
        assert not re.match(r"\s*(export\s+)?ADMIN_PASSWORD(_HASH)?\s*=", line), line
    assert CMD in env
    assert re.search(r"^SECRET_KEY=", env, re.MULTILINE)
    assert re.search(r"^COOKIE_SECURE=", env, re.MULTILINE)
    compose = (ROOT / "docker-compose.yml").read_text()
    assert "ADMIN_PASSWORD" not in compose
    assert re.search(r"env_file:\s*(\n\s*-\s*)?\.env\b", compose)
