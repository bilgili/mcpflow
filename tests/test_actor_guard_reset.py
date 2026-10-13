"""The reset revokes the tokens of the user (actor-guard-review-fixes, fix 1).

Scenarios of `specs/identity/spec.md`: requirement "Reset pre-check" (three
scenarios) and requirement "A reset revokes the tokens of the user". The
expectations come from the spec and from the frozen interfaces of `design.md`
(D1 to D4), not from the code. Model: `specs/tla/actor_guard_fixes.tla`
(`NoCondemnedAdmitted`, `NoStaleTokenAfterReset`, `RefusalChangesNothing`,
`CrashLeavesNoGain`).

The store files are read as bytes. `tokens.json` does not exist in a fresh
world until something writes it, so a missing file reads as `None`.
"""

from __future__ import annotations

import inspect
import json
import re
from types import SimpleNamespace

import pytest
from conftest import ADMIN_ACTOR, make_user
from dashboard_site import api_headers, bearer, make_mu_site, mcp_tools  # noqa: F401
from reresolve_race import make_admin_user, make_second_admin
from test_policy import make_world

from mcpflow.auth import TokenStore, hash_password
from mcpflow.identity import LocalIdentityProvider
from mcpflow.policy import AccessPolicy

STORES = ("users.json", "tokens.json", "user_tokens.json")
BOOTSTRAP_TEXT = "cannot issue a setup code for the bootstrap user admin"


def snap(path) -> dict[str, bytes | None]:
    """The bytes of the three store files; a missing file reads `None`."""
    return {n: (path / n).read_bytes() if (path / n).exists() else None for n in STORES}


def users_of(path, user_id: str) -> list[dict]:
    """The records of `user_tokens.json` that belong to `user_id`."""
    f = path / "user_tokens.json"
    if not f.exists():
        return []
    return [r for r in json.loads(f.read_text())["tokens"] if r["user_id"] == user_id]


def _mcp_status(site, token: str) -> int:
    """The raw status of `initialize` on `/mcp` with one bearer token."""
    resp = site.client.post(
        "/mcp",
        headers={**bearer(token), "Accept": "application/json, text/event-stream",
                 "Content-Type": "application/json"},
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "t", "version": "1"}}})
    return resp.status_code


def _api_status(site, token: str) -> int:
    return site.client.get("/api/users", headers=bearer(token)).status_code


def _redeem(site, user: str, code: str, password: str = "redeemed-pw-123"):
    resp = site.client.post("/login/setup", data={
        "user": user, "code": code, "password": password, "confirm": password})
    site.client.cookies.clear()
    return resp


# --- Requirement "Reset pre-check" ------------------------------------------


def test_check_reset_contract(tmp_path):
    """Scenarios "The pre-check refuses the bootstrap user", "... an unknown id",
    and "... passes an existing user"."""
    w = make_world(tmp_path)
    _, _code = w.ident._create_user("zed")  # a pending user
    assert w.ident.get_user("zed").pending is True
    assert w.ident.get_user("alice").pending is False
    before = snap(tmp_path)

    with pytest.raises(ValueError) as exc:
        w.ident.check_reset("admin")
    assert str(exc.value) == BOOTSTRAP_TEXT
    with pytest.raises(KeyError) as key:
        w.ident.check_reset("nobody")
    assert key.value.args == ("nobody",)
    assert w.ident.check_reset("alice") is None
    assert w.ident.check_reset("zed") is None

    assert snap(tmp_path) == before
    assert not inspect.iscoroutinefunction(LocalIdentityProvider.check_reset)


def test_issue_setup_code_keeps_the_refusals_of_the_pre_check(tmp_path):
    """The provider reset has the same refusals as the pre-check (one owner)."""
    w = make_world(tmp_path)
    before = snap(tmp_path)
    with pytest.raises(ValueError) as exc:
        w.ident._issue_setup_code("admin")
    assert str(exc.value) == BOOTSTRAP_TEXT
    with pytest.raises(KeyError) as key:
        w.ident._issue_setup_code("nobody")
    assert key.value.args == ("nobody",)
    assert snap(tmp_path) == before


# --- Requirement "A reset revokes the tokens of the user" -------------------


def test_a_reset_revokes_every_token_of_the_user(tmp_path):
    """Scenario "A reset revokes every token of the user"."""
    w = make_world(tmp_path)
    w.policy.set_admin(w.root, "bob", True)
    w.policy.mint_token(w.root, "m", "mcp", "bob")
    w.policy.mint_token(w.root, "a", "admin", "bob")
    w.policy.mint_token(w.root, "x", "mcp", "alice")
    w.policy.mint_token(w.root, "r", "mcp", "admin")
    assert len(users_of(tmp_path, "bob")) == 2
    tokens_before = snap(tmp_path)["tokens.json"]
    assert tokens_before is not None  # the bootstrap token is stored there
    alice_before = users_of(tmp_path, "alice")

    code = w.policy.issue_setup_code(w.root, "bob")

    assert isinstance(code, str) and code
    assert users_of(tmp_path, "bob") == []
    assert users_of(tmp_path, "alice") == alice_before and len(alice_before) == 1
    assert snap(tmp_path)["tokens.json"] == tokens_before
    assert w.ident.get_user("bob").pending is True


@pytest.mark.parametrize("route", ["api", "web"])
def test_the_old_tokens_are_refused_by_both_gates(make_mu_site, route):  # noqa: F811
    """Scenarios "The old tokens are refused after a reset", "A reset from the web
    revokes the tokens", and "A redeem does not revive an old token"."""
    site = make_mu_site()
    policy = site.app.state.supervisor.policy
    admin_token = make_second_admin(site)  # alice is an admin now
    _rec, mcp_token = policy.mint_token(ADMIN_ACTOR, "m", "mcp", "alice")
    # Both tokens work before the reset.
    assert _api_status(site, admin_token) == 200
    assert mcp_tools(site, mcp_token) is not None
    assert _mcp_status(site, mcp_token) == 200

    if route == "api":
        resp = site.client.post("/api/users/alice/setup-code", headers=api_headers(site))
        assert resp.status_code == 200, resp.text
        code = resp.json()["setup_code"]
    else:
        resp = site.request("admin", "POST", "/users/alice/setup-code")
        assert resp.status_code == 200, resp.text
        code = re.search(r'id="setup-code">([^<]+)<', resp.text).group(1)
    assert code

    assert _api_status(site, admin_token) == 401
    assert _mcp_status(site, mcp_token) == 401

    # The redeem makes alice active again; it does not revive an old token.
    assert _redeem(site, "alice", code).status_code == 303
    assert policy.local_identity().get_user("alice").pending is False
    assert _api_status(site, admin_token) == 401
    assert _mcp_status(site, mcp_token) == 401


def _refused_reset_case(w, case):
    """Return `(policy, actor, target, error type)` for one refusal."""
    policy, actor, target, exc = w.policy, w.root, "bob", PermissionError
    if case == "bootstrap":
        w.policy.mint_token(w.root, "r", "admin", "admin")
        target, exc = "admin", ValueError
    elif case == "unknown":
        make_user(w.ident, "ghost")
        w.policy.mint_token(w.root, "g", "mcp", "ghost")
        w.ident._delete_user("ghost")  # the token record of `ghost` stays (residue)
        assert users_of(w.path, "ghost"), "the residue record must exist"
        target, exc = "ghost", KeyError
    elif case == "non-admin":
        actor = w.bob
    elif case == "demoted":
        w.policy.set_admin(w.root, "carol", True)
        actor = w.ident.get_user("carol")
        w.policy.set_admin(w.root, "carol", False)
    elif case == "deleted":
        w.policy.set_admin(w.root, "carol", True)
        actor = w.ident.get_user("carol")
        w.policy.delete_user(w.root, "carol")
    else:
        assert case == "non-local"
        policy = AccessPolicy(SimpleNamespace(kind="keycloak", get_user=w.ident.get_user),
                              w.rules, w.tokens, w.reg)
        exc = ValueError
    return policy, actor, target, exc


@pytest.mark.parametrize(
    "case", ["bootstrap", "unknown", "non-admin", "demoted", "deleted", "non-local"])
def test_a_refused_reset_revokes_nothing(tmp_path, case):
    """Scenarios "A refused reset of the bootstrap user revokes nothing", "... of an
    unknown id ...", and "A refused actor revokes nothing"; D2 steps 1 to 3."""
    w = make_world(tmp_path)
    w.policy.mint_token(w.root, "b", "mcp", "bob")  # a token that must stay
    policy, actor, target, exc = _refused_reset_case(w, case)
    before = snap(tmp_path)
    assert users_of(tmp_path, "bob")

    with pytest.raises(exc) as raised:
        policy.issue_setup_code(actor, target)

    if case == "non-local":
        assert "manages its own users" in str(raised.value)
    assert snap(tmp_path) == before
    assert users_of(tmp_path, "bob") and not w.ident.get_user("bob").pending


def test_a_failed_identity_write_leaves_an_active_user_with_no_token(tmp_path, monkeypatch):
    """Scenario "A failed identity write leaves an active user with no token"."""
    w = make_world(tmp_path)
    w.policy.mint_token(w.root, "b", "mcp", "bob")
    assert users_of(tmp_path, "bob")

    def boom(self, *a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(LocalIdentityProvider, "_save", boom)
    with pytest.raises(OSError):
        w.policy.issue_setup_code(w.root, "bob")

    monkeypatch.undo()
    # The write to users.json failed, so bob is active, in memory and on disk.
    assert w.ident.get_user("bob").pending is False
    assert w.ident.authenticate("bob", "pw") is not None  # the old password still works
    fresh = LocalIdentityProvider(tmp_path / "users.json", hash_password("pw", iterations=1000))
    fresh.load()
    assert fresh.get_user("bob").pending is False
    assert fresh.authenticate("bob", "pw") is not None
    assert users_of(tmp_path, "bob") == []


def test_a_failed_revoke_changes_nothing(tmp_path, monkeypatch):
    """Scenario "A failed revoke changes nothing"."""
    w = make_world(tmp_path)
    w.policy.mint_token(w.root, "b", "mcp", "bob")
    before = snap(tmp_path)
    assert users_of(tmp_path, "bob")

    def boom(self, *a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(TokenStore, "_commit", boom)
    with pytest.raises(OSError):
        w.policy.issue_setup_code(w.root, "bob")

    monkeypatch.undo()
    assert w.ident.get_user("bob").pending is False
    after = snap(tmp_path)
    assert after["users.json"] == before["users.json"]
    assert after["user_tokens.json"] == before["user_tokens.json"]
    assert users_of(tmp_path, "bob")


def test_a_self_reset_ends_the_callers_own_token(make_mu_site):  # noqa: F811
    """Scenario "A self-reset ends the token of the caller"."""
    site = make_mu_site()
    token = make_admin_user(site, "carol")
    assert _api_status(site, token) == 200

    resp = site.client.post("/api/users/carol/setup-code", headers=bearer(token))

    assert resp.status_code == 200, resp.text
    assert resp.json()["setup_code"]
    assert _api_status(site, token) == 401


def test_a_token_minted_after_the_reset_works(make_mu_site):  # noqa: F811
    """Scenario "A token minted for a pending user works": the gates have no
    `pending` check (D1)."""
    site = make_mu_site()
    policy = site.app.state.supervisor.policy
    policy.mint_token(ADMIN_ACTOR, "old", "mcp", "bob")
    resp = site.client.post("/api/users/bob/setup-code", headers=api_headers(site))
    assert resp.status_code == 200, resp.text
    assert policy.local_identity().get_user("bob").pending is True

    _rec, token = policy.mint_token(ADMIN_ACTOR, "new", "mcp", "bob")

    assert _mcp_status(site, token) == 200
    assert isinstance(mcp_tools(site, token), set)


def test_check_reset_runs_before_the_revoke(tmp_path, monkeypatch):
    """D2: the pre-check comes first, the revoke second, the identity write third."""
    w = make_world(tmp_path)
    log: list[str] = []
    for cls, name in ((LocalIdentityProvider, "check_reset"), (TokenStore, "revoke_user"),
                      (LocalIdentityProvider, "_issue_setup_code")):
        orig = getattr(cls, name)

        def spy(self, *a, _orig=orig, _name=name, **k):
            log.append(_name)
            return _orig(self, *a, **k)

        monkeypatch.setattr(cls, name, spy)

    w.policy.issue_setup_code(w.root, "bob")

    # The provider reset calls `check_reset` again, so only the first three count.
    assert log[:3] == ["check_reset", "revoke_user", "_issue_setup_code"]
