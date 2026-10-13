"""An interrupted delete only removes access (Codex finding 2, design D8b).

`delete_user` deletes the identity first, then revokes tokens, then drops
rules; `delete_group` deletes the group, then drops rules. Each test injects a
crash at one step and checks the state it leaves, then that a recreated id or
name inherits nothing.
"""

from __future__ import annotations

import sys

import pytest
from conftest import ADMIN_ACTOR, make_settings, make_user
from starlette.testclient import TestClient

from mcpflow.auth import hash_password
from mcpflow.gateway import build_app
from mcpflow.identity import LocalIdentityProvider
from mcpflow.registry import Registry, ServerKey, ServerSpec

PW = "pw-alice-0123456789"
TIME = ServerKey.parse("time")
STEPS = {"identity": "_delete_user", "tokens": "revoke_user", "rules": "drop_subject"}


@pytest.fixture
def site(tmp_path):
    """alice in group `staff`; staff may use `time`, alice is denied `convert`."""
    (tmp_path / "logs").mkdir()
    ident = LocalIdentityProvider(tmp_path / "users.json",
                                  hash_password("secret", iterations=1000))
    ident.load()
    ident._create_group("staff")
    make_user(ident, "alice", PW, groups=["staff"])
    reg = Registry(tmp_path / "servers.json", tmp_path / "user_servers.json")
    reg.load()
    # Disabled: the policy reads the spec, no child starts.
    reg.add(ServerSpec(namespace="time", kind="custom", command=sys.executable,
                       enabled=False))
    app = build_app(make_settings(tmp_path))
    with TestClient(app, follow_redirects=False) as client:
        policy = app.state.policy
        for kind, subject, level, tool, effect in (
            ("group", "staff", "server", None, "allow"),
            ("user", "alice", "tool", "convert", "deny"),
        ):
            policy.add_rule(ADMIN_ACTOR, subject_kind=kind, subject=subject,
                            level=level, server="time", tool=tool, effect=effect)
        yield policy, client


def owner(policy, step: str):
    return {"identity": policy._identity, "tokens": policy._tokens,
            "rules": policy._rules}[step]


def crash_at(monkeypatch, policy, step: str) -> None:
    def boom(*_a, **_k):
        raise OSError(f"crash at {step}")
    monkeypatch.setattr(owner(policy, step), STEPS[step], boom)


def signs_in(client) -> bool:
    resp = client.post("/login", data={"user": "alice", "password": PW, "next": "/"})
    client.cookies.clear()
    return resp.status_code == 303


def session_ok(client, cookie: str) -> bool:
    resp = client.get("/", headers={"Cookie": f"mcpflow_session={cookie}"})
    client.cookies.clear()
    return resp.status_code == 200


def token_ok(client, token: str) -> bool:
    resp = client.post("/mcp", headers={"Authorization": f"Bearer {token}"}, json={})
    return resp.status_code != 401


def allows(policy, tool: str) -> bool:
    user = policy._identity.get_user("alice")
    return user is not None and policy.keys_for(user, "mcp").allows_tool(TIME, tool)


@pytest.mark.parametrize("step", ["identity", "tokens", "rules"])
def test_an_interrupted_user_delete_never_widens_access(site, monkeypatch, step):
    policy, _client = site
    assert allows(policy, "now") and not allows(policy, "convert")
    crash_at(monkeypatch, policy, step)
    with pytest.raises(OSError):
        policy.delete_user(ADMIN_ACTOR, "alice")
    assert not allows(policy, "convert")


@pytest.mark.parametrize("step", ["tokens", "rules"])
def test_a_user_delete_interrupted_after_the_identity_leaves_no_access(
    site, monkeypatch, step
):
    policy, client = site
    assert signs_in(client)
    cookie = client.post("/login", data={"user": "alice", "password": PW}).cookies[
        "mcpflow_session"]
    client.cookies.clear()
    _rec, token = policy.mint_token(ADMIN_ACTOR, "laptop", "mcp", "alice")
    assert session_ok(client, cookie) and token_ok(client, token)

    crash_at(monkeypatch, policy, step)
    with pytest.raises(OSError):
        policy.delete_user(ADMIN_ACTOR, "alice")
    monkeypatch.undo()
    assert policy._identity.get_user("alice") is None
    assert not signs_in(client)
    assert not session_ok(client, cookie) and not token_ok(client, token)

    # The recreated id inherits no token and no rule.
    user = make_user(policy, "alice", PW, groups=["staff"])
    assert policy._tokens.list_for("alice") == []
    assert [r for r in policy._rules.list() if r.subject == "alice"] == []
    assert not token_ok(client, token) and not session_ok(client, cookie)
    assert policy.keys_for(user, "mcp").allows_tool(TIME, "convert")  # the deny is gone


def test_create_user_never_clears_an_existing_user(site):
    policy, _client = site
    policy.mint_token(ADMIN_ACTOR, "laptop", "mcp", "alice")
    with pytest.raises(ValueError, match="already exists"):
        make_user(policy, "alice", PW)
    assert len(policy._tokens.list_for("alice")) == 1
    assert not allows(policy, "convert")


def test_a_group_delete_interrupted_before_the_rules_leaves_no_grant(site, monkeypatch):
    policy, _client = site
    crash_at(monkeypatch, policy, "rules")
    with pytest.raises(OSError):
        policy.delete_group(ADMIN_ACTOR, "staff")
    monkeypatch.undo()
    assert "staff" not in policy.list_groups(ADMIN_ACTOR)
    assert not allows(policy, "now")
    # The recreated group starts with no rule; a member gains nothing.
    policy.create_group(ADMIN_ACTOR, "staff")
    assert [r for r in policy._rules.list() if r.subject == "staff"] == []
    policy.set_groups(ADMIN_ACTOR, "alice", ["staff"])
    assert not allows(policy, "now")


def test_create_group_never_clears_an_existing_group(site):
    policy, _client = site
    with pytest.raises(ValueError, match="already exists"):
        policy.create_group(ADMIN_ACTOR, "staff")
    assert allows(policy, "now")
