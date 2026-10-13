"""A sign-in binds the record the password was checked against (Codex finding 1).

`login_post` reads the session binding before and after the slow verify and
signs the one read before; a change in between answers as a wrong password.
A password reset, or a delete and re-create of the id, during the verify
therefore never yields a cookie.
"""

from __future__ import annotations

import pytest
from conftest import ADMIN_ACTOR, make_settings, make_user
from starlette.testclient import TestClient

from mcpflow.auth import hash_password
from mcpflow.gateway import build_app
from mcpflow.identity import LocalIdentityProvider
from mcpflow.web import _LOGIN_ERROR

PW = "pw-alice-0123456789"


@pytest.fixture
def site(tmp_path):
    (tmp_path / "logs").mkdir()
    ident = LocalIdentityProvider(tmp_path / "users.json",
                                  hash_password("secret", iterations=1000))
    ident.load()
    make_user(ident, "alice", PW)
    app = build_app(make_settings(tmp_path))
    with TestClient(app, follow_redirects=False) as client:
        yield app.state.policy, client


def login(client, password: str = PW):
    resp = client.post("/login", data={"user": "alice", "password": password, "next": "/"})
    client.cookies.clear()
    return resp


def during_verify(monkeypatch, identity, change) -> None:
    """Run `change` inside `authenticate`, after the password check."""
    original = identity.authenticate

    def authenticate(user_id, password):
        user = original(user_id, password)
        change()
        return user

    monkeypatch.setattr(identity, "authenticate", authenticate)


def refused_like_a_wrong_password(resp, wrong) -> None:
    assert resp.status_code == wrong.status_code == 200
    assert "set-cookie" not in resp.headers
    assert _LOGIN_ERROR in resp.text and _LOGIN_ERROR in wrong.text


def test_a_normal_login_gets_a_cookie(site):
    _policy, client = site
    resp = login(client)
    assert resp.status_code == 303
    assert "mcpflow_session=" in resp.headers["set-cookie"]


def test_a_reset_during_the_verify_gets_no_cookie(site, monkeypatch):
    policy, client = site
    identity = policy._identity
    wrong = login(client, "not-the-password")
    during_verify(monkeypatch, identity,
                  lambda: identity._issue_setup_code("alice"))
    refused_like_a_wrong_password(login(client), wrong)


def test_a_delete_and_recreate_during_the_verify_gets_no_cookie(site, monkeypatch):
    policy, client = site
    identity = policy._identity
    wrong = login(client, "not-the-password")

    def replace() -> None:
        policy.delete_user(ADMIN_ACTOR, "alice")
        # The replacement even shares the password: the record still differs.
        make_user(policy, "alice", PW)

    during_verify(monkeypatch, identity, replace)
    refused_like_a_wrong_password(login(client), wrong)
    # Control: once the race is over, the replacement signs in normally.
    monkeypatch.undo()
    assert login(client).status_code == 303
