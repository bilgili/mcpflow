"""Auth primitives: password hash, session cookie, token store.

Scenarios from `specs/auth/spec.md`:
  Login and session cookie, Token storage, Bearer tokens for /mcp.
"""

from __future__ import annotations

import hashlib
import json
import time

import pytest

from mcpflow.auth import (
    HashedTokenVerifier,
    TokenStore,
    hash_password,
    sign_session,
    verify_password,
    verify_session,
)
from mcpflow.identity import LocalIdentityProvider

SECRET = b"unit-test-secret-key"


# --- Login and session cookie (12.1) -----------------------------------------


def test_hash_round_trip():
    encoded = hash_password("hunter2")
    assert encoded.startswith("pbkdf2_sha256$")
    assert verify_password("hunter2", encoded) is True
    assert verify_password("wrong", encoded) is False


def test_bad_format():
    assert verify_password("hunter2", "not-a-valid-hash") is False
    assert verify_password("hunter2", "") is False


def _binding(ph: str):
    return lambda user_id: ph if user_id == "alice" else None


def test_sign_and_verify():
    ph = hash_password("pw")
    expires_at = int(time.time()) + 3600
    value = sign_session(SECRET, "alice", ph, expires_at)
    assert value.startswith(f"alice.{expires_at}.")
    assert verify_session(SECRET, value, _binding(ph), now=int(time.time())) == "alice"


def test_tampered_cookie():
    ph = hash_password("pw")
    expires_at = int(time.time()) + 3600
    value = sign_session(SECRET, "alice", ph, expires_at)
    tampered = value[:-1] + ("0" if value[-1] != "0" else "1")
    assert verify_session(SECRET, tampered, _binding(ph), now=int(time.time())) is None


def test_expired_cookie():
    ph = hash_password("pw")
    expires_at = int(time.time()) - 10
    value = sign_session(SECRET, "alice", ph, expires_at)
    assert verify_session(SECRET, value, _binding(ph), now=int(time.time())) is None


def test_password_change_invalidates_sessions():
    old_hash = hash_password("old")
    new_hash = hash_password("new")
    expires_at = int(time.time()) + 3600
    value = sign_session(SECRET, "alice", old_hash, expires_at)
    # A cookie signed under the old hash is invalid under the new hash.
    assert verify_session(SECRET, value, _binding(new_hash), now=int(time.time())) is None


def test_session_refuses_a_cookie_of_the_earlier_build_and_odd_shapes():
    ph = hash_password("pw")
    now = int(time.time())
    expires_at = now + 3600
    good = sign_session(SECRET, "alice", ph, expires_at)
    mac = good.rsplit(".", 1)[1]
    for value in (
        f"{expires_at}.{mac}",  # the two-part cookie of the earlier build
        f"alice.+{expires_at}.{mac}",  # a non-canonical expiry
        f"alice.{expires_at}.{mac}.x",
        f"bob.{expires_at}.{mac}",  # a user without a binding
        "alice.é.x",  # a non-ASCII value must not raise
        "",
    ):
        assert verify_session(SECRET, value, _binding(ph), now=now) is None, value


# --- Token storage (12.2) ----------------------------------------------------


def test_digest_only_on_disk(tmp_path):
    store = TokenStore(tmp_path / "tokens.json", tmp_path / "user_tokens.json")
    store.load()
    _record, clear = store.create("laptop", "mcp", "admin")
    raw = (tmp_path / "tokens.json").read_text()
    assert clear not in raw
    import hashlib

    digest = hashlib.sha256(clear.encode()).hexdigest()
    assert digest in raw


def test_create_returns_clear_text_once(tmp_path):
    store = TokenStore(tmp_path / "tokens.json", tmp_path / "user_tokens.json")
    store.load()
    record, clear = store.create("laptop", "mcp", "admin")
    assert clear.startswith("mcpflow_")
    # The clear text is not recoverable from the stored record.
    assert clear not in json.dumps(
        {"id": record.id, "name": record.name, "sha256": record.sha256}
    )


def test_revoke_persists(tmp_path):
    path = tmp_path / "tokens.json"
    store = TokenStore(path, path.with_name("user_tokens.json"))
    store.load()
    record, _clear = store.create("laptop", "mcp", "admin")
    store.revoke(record.id)
    # A fresh load reflects the revoke.
    reloaded = TokenStore(path, path.with_name("user_tokens.json"))
    reloaded.load()
    assert all(r.id != record.id for r in reloaded.list())
    with pytest.raises(KeyError):
        store.revoke(record.id)


def test_lookup(tmp_path):
    store = TokenStore(tmp_path / "tokens.json", tmp_path / "user_tokens.json")
    store.load()
    record, clear = store.create("laptop", "mcp", "admin")
    found = store.lookup(clear, "mcp")
    assert found is not None
    assert found.id == record.id
    assert store.lookup("mcpflow_nope", "mcp") is None


# --- token scope (5.2) -------------------------------------------------------


def test_old_file_loads_as_mcp(tmp_path):
    path = tmp_path / "tokens.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "tokens": [
                    {
                        "id": "tok_old",
                        "name": "legacy",
                        "sha256": hashlib.sha256(b"hmcp_legacy").hexdigest(),
                        "created_at": "2026-01-01T00:00:00+00:00",
                        "last_used_at": None,
                    }
                ],
            }
        )
    )
    store = TokenStore(path, path.with_name("user_tokens.json"))
    store.load()
    (record,) = store.list()
    assert record.scope == "mcp"
    # A missing-scope record authenticates /mcp.
    assert store.lookup("hmcp_legacy", "mcp") is not None


def test_load_refuses_bad_scope(tmp_path):
    path = tmp_path / "tokens.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "tokens": [
                    {
                        "id": "tok_x",
                        "name": "x",
                        "sha256": "deadbeef",
                        "created_at": "2026-01-01T00:00:00+00:00",
                        "last_used_at": None,
                        "scope": "root",
                    }
                ],
            }
        )
    )
    store = TokenStore(path, path.with_name("user_tokens.json"))
    with pytest.raises(ValueError):
        store.load()


def test_lookup_wrong_scope_returns_none_and_keeps_last_used(tmp_path):
    store = TokenStore(tmp_path / "tokens.json", tmp_path / "user_tokens.json")
    store.load()
    _record, clear = store.create("ci", "admin", "admin")
    # A wrong-scope lookup is a failed authentication.
    assert store.lookup(clear, "mcp") is None
    (stored,) = store.list()
    assert stored.last_used_at is None


def test_lookup_two_scopes_match_either_record(tmp_path):
    # The verifier calls lookup(token, "mcp", "admin"); both scopes resolve.
    store = TokenStore(tmp_path / "tokens.json", tmp_path / "user_tokens.json")
    store.load()
    _m, mcp_clear = store.create("m", "mcp", "admin")
    _a, admin_clear = store.create("a", "admin", "admin")
    mcp_found = store.lookup(mcp_clear, "mcp", "admin")
    admin_found = store.lookup(admin_clear, "mcp", "admin")
    assert mcp_found is not None and mcp_found.scope == "mcp"
    assert admin_found is not None and admin_found.scope == "admin"


def test_lookup_no_scope_returns_none_and_keeps_last_used(tmp_path):
    # An empty scope set matches nothing, so a caller that forgets the scope
    # fails closed rather than authenticating every token.
    store = TokenStore(tmp_path / "tokens.json", tmp_path / "user_tokens.json")
    store.load()
    _record, clear = store.create("laptop", "mcp", "admin")
    assert store.lookup(clear) is None
    (stored,) = store.list()
    assert stored.last_used_at is None


def test_scope_persists(tmp_path):
    path = tmp_path / "tokens.json"
    store = TokenStore(path, path.with_name("user_tokens.json"))
    store.load()
    store.create("ci", "admin", "admin")
    reloaded = TokenStore(path, path.with_name("user_tokens.json"))
    reloaded.load()
    (record,) = reloaded.list()
    assert record.scope == "admin"


def test_create_refuses_bad_scope(tmp_path):
    path = tmp_path / "tokens.json"
    store = TokenStore(path, path.with_name("user_tokens.json"))
    store.load()
    with pytest.raises(ValueError):
        store.create("x", "root", "admin")
    assert not path.exists()


@pytest.mark.asyncio
async def test_verifier_valid_and_revoked(tmp_path):
    store = TokenStore(tmp_path / "tokens.json", tmp_path / "user_tokens.json")
    store.load()
    record, clear = store.create("laptop", "mcp", "admin")
    identity = LocalIdentityProvider(
        tmp_path / "users.json", hash_password("pw", iterations=1000)
    )
    identity.load()
    verifier = HashedTokenVerifier(store, identity)
    access = await verifier.verify_token(clear)
    assert access is not None
    assert access.client_id == record.id
    assert access.scopes == ["mcp"]
    assert access.subject == "admin"
    store.revoke(record.id)
    assert await verifier.verify_token(clear) is None


# =============================================================================
# 10B (tasks 10.3-10.5): written from specs/auth/spec.md, not from the code.
# =============================================================================

import hmac
import re
from pathlib import Path

import httpx
from conftest import fake_child_spec, make_user, seed_registry
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from mcpflow.auth import SessionGate


def _tokens(tmp_path: Path) -> TokenStore:
    store = TokenStore(tmp_path / "tokens.json", tmp_path / "user_tokens.json")
    store.load()
    return store


def _identity(tmp_path: Path) -> LocalIdentityProvider:
    ident = LocalIdentityProvider(
        tmp_path / "users.json", hash_password("admin-pw", iterations=1000)
    )
    ident.load()
    return ident


def _all_text(tmp_path: Path) -> str:
    return "".join(p.read_text() for p in tmp_path.glob("*.json"))


# --- Token storage (10.3) ----------------------------------------------------


def test_digest_only_on_disk_for_a_user_token(tmp_path):
    store = _tokens(tmp_path)
    record, clear = store.create("laptop", "mcp", "alice")
    digest = hashlib.sha256(clear.encode()).hexdigest()
    user_file = (tmp_path / "user_tokens.json").read_text()
    assert digest in user_file
    assert '"alice"' in user_file
    tokens_file = tmp_path / "tokens.json"
    assert not tokens_file.exists() or digest not in tokens_file.read_text()
    assert clear not in _all_text(tmp_path)
    assert record.user_id == "alice"


def test_admin_token_digest_goes_to_tokens_json(tmp_path):
    store = _tokens(tmp_path)
    _record, clear = store.create("laptop", "mcp", "admin")
    digest = hashlib.sha256(clear.encode()).hexdigest()
    assert digest in (tmp_path / "tokens.json").read_text()
    assert clear not in _all_text(tmp_path)


def test_old_file_loads_as_mcp_and_mcp_accepts_it(tmp_path):
    path = tmp_path / "tokens.json"
    path.write_text(json.dumps({"version": 1, "tokens": [{
        "id": "tok_old", "name": "legacy",
        "sha256": hashlib.sha256(b"old-token").hexdigest(),
        "created_at": "2026-01-01T00:00:00+00:00", "last_used_at": None}]}))
    store = _tokens(tmp_path)
    (record,) = store.list()
    assert record.scope == "mcp"
    assert store.lookup("old-token", "mcp") is not None


@pytest.mark.asyncio
async def test_old_file_record_reaches_mcp_as_the_admin_user(tmp_path):
    # AC-8b: a record of the earlier build has no user_id and no scope.
    path = tmp_path / "tokens.json"
    path.write_text(json.dumps({"version": 1, "tokens": [{
        "id": "tok_old", "name": "legacy",
        "sha256": hashlib.sha256(b"old-token").hexdigest(),
        "created_at": "2026-01-01T00:00:00+00:00", "last_used_at": None}]}))
    store = _tokens(tmp_path)
    (record,) = store.list()
    assert record.user_id == "admin"
    access = await HashedTokenVerifier(store, _identity(tmp_path)).verify_token("old-token")
    assert access is not None and access.subject == "admin"


def test_old_file_loads_as_the_admin_user_ac_8b(tmp_path):
    path = tmp_path / "tokens.json"
    path.write_text(json.dumps({"version": 1, "tokens": [{
        "id": "tok_old", "name": "legacy", "sha256": "ab" * 32,
        "created_at": "2026-01-01T00:00:00+00:00", "last_used_at": None,
        "scope": "admin"}]}))
    (record,) = _tokens(tmp_path).list()
    assert record.user_id == "admin"


def test_tokens_json_with_another_user_id_raises(tmp_path):
    (tmp_path / "tokens.json").write_text(json.dumps({"version": 1, "tokens": [{
        "id": "tok_x", "name": "x", "sha256": "ab" * 32,
        "created_at": "2026-01-01T00:00:00+00:00", "last_used_at": None,
        "scope": "mcp", "user_id": "alice"}]}))
    store = TokenStore(tmp_path / "tokens.json", tmp_path / "user_tokens.json")
    with pytest.raises(ValueError):
        store.load()


def test_lookup_checks_the_scope(tmp_path):
    store = _tokens(tmp_path)
    _r, clear = store.create("ci", "admin", "admin")
    assert store.lookup(clear, "mcp") is None
    assert store.list()[0].last_used_at is None
    # A fresh load agrees: the failed lookup wrote nothing.
    assert _tokens(tmp_path).list()[0].last_used_at is None


def test_lookup_with_two_scopes_returns_admin_and_updates_last_used(tmp_path):
    store = _tokens(tmp_path)
    _r, clear = store.create("ci", "admin", "admin")
    found = store.lookup(clear, "mcp", "admin")
    assert found is not None and found.scope == "admin"
    assert store.list()[0].last_used_at is not None


def test_lookup_with_no_scope_returns_none_and_keeps_last_used(tmp_path):
    store = _tokens(tmp_path)
    _r, clear = store.create("ci", "mcp", "admin")
    assert store.lookup(clear) is None
    assert store.list()[0].last_used_at is None


def test_lookup_finds_a_user_token_with_its_user_id(tmp_path):
    store = _tokens(tmp_path)
    _r, clear = store.create("laptop", "mcp", "alice")
    found = store.lookup(clear, "mcp", "admin")
    assert found is not None and found.user_id == "alice"


def test_load_refuses_a_bad_scope_in_the_user_file(tmp_path):
    (tmp_path / "user_tokens.json").write_text(json.dumps({"version": 1, "tokens": [{
        "id": "tok_x", "name": "x", "sha256": "ab" * 32,
        "created_at": "2026-01-01T00:00:00+00:00", "last_used_at": None,
        "scope": "root", "user_id": "alice"}]}))
    store = TokenStore(tmp_path / "tokens.json", tmp_path / "user_tokens.json")
    with pytest.raises(ValueError):
        store.load()


def test_create_refuses_a_bad_scope_and_no_file_changes(tmp_path):
    store = _tokens(tmp_path)
    store.create("keep", "mcp", "admin")
    before = {p.name: p.read_text() for p in tmp_path.glob("*.json")}
    for owner in ("admin", "alice"):
        with pytest.raises(ValueError):
            store.create("x", "root", owner)
    assert {p.name: p.read_text() for p in tmp_path.glob("*.json")} == before
    assert len(store.list()) == 1


def test_list_for_and_revoke_user(tmp_path):
    store = _tokens(tmp_path)
    a1, _ = store.create("a1", "mcp", "alice")
    store.create("a2", "mcp", "alice")
    b1, _ = store.create("b1", "mcp", "bob")
    assert len(store.list_for("alice")) == 2
    assert a1.id in {r.id for r in store.list_for("alice")}
    assert [r.id for r in store.list_for("bob")] == [b1.id]
    store.revoke_user("alice")
    assert store.list_for("alice") == []
    assert [r.id for r in _tokens(tmp_path).list_for("bob")] == [b1.id]


# --- Login and session cookie (10.4) -----------------------------------------
# HTTP scenarios run against the real app; cookie scenarios run against the
# real SessionGate in front of a one-route app.

ALICE_PW = "alice-pw"


def _seed_users(data_dir: Path) -> None:
    ident = LocalIdentityProvider(
        data_dir / "users.json", hash_password("secret", iterations=1000)
    )
    ident.load()
    make_user(ident, "alice", ALICE_PW)
    make_user(ident, "bob", "bob-pw")


def _post_login(server, user, password, nxt="/"):
    data = {"password": password, "next": nxt}
    if user is not None:
        data["user"] = user
    return httpx.post(server.base_url + "/login", data=data, follow_redirects=False)


def test_correct_password(server_factory):
    server = server_factory(_seed_users)
    resp = _post_login(server, "alice", ALICE_PW, "/servers")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/servers"
    assert "mcpflow_session=alice." in resp.headers["set-cookie"]


def test_empty_user_name_signs_in_as_admin_ac_8b(server_factory):
    server = server_factory(_seed_users)
    for user in ("", None):
        resp = _post_login(server, user, "secret")
        assert resp.status_code == 303
        assert "mcpflow_session=admin." in resp.headers["set-cookie"]
    # The session names the user admin: it passes the dashboard.
    cookie = resp.headers["set-cookie"].split(";")[0]
    page = httpx.get(server.base_url + "/", headers={"cookie": cookie},
                     follow_redirects=False)
    assert page.status_code == 200


def test_open_redirect_refused(server_factory):
    server = server_factory(_seed_users)
    for evil in ("https://evil.test", "//evil.test", "/\\evil.test"):
        resp = _post_login(server, "alice", ALICE_PW, evil)
        assert resp.status_code == 303
        assert resp.headers["location"] == "/"


def test_wrong_password_waits_and_sets_no_cookie(server_factory):
    server = server_factory(_seed_users)
    start = time.perf_counter()
    resp = _post_login(server, "alice", "nope")
    assert time.perf_counter() - start >= 1.0
    assert resp.status_code == 200
    assert "set-cookie" not in resp.headers
    assert "error" in resp.text.lower()


def test_unknown_user_gets_the_same_page_as_a_wrong_password(server_factory):
    server = server_factory(_seed_users)
    wrong = _post_login(server, "alice", "nope")
    start = time.perf_counter()
    unknown = _post_login(server, "nobody", "nope")
    assert time.perf_counter() - start >= 1.0
    assert unknown.status_code == wrong.status_code == 200
    assert "set-cookie" not in unknown.headers
    assert unknown.text == wrong.text  # no user name is revealed


def _gate(tmp_path, ident, calls):
    async def handler(request):
        calls.append(request.state.user.id)
        return JSONResponse({"user": request.state.user.id})

    app = Starlette(routes=[Route("/", handler)])
    routes = ((frozenset({"GET"}), re.compile(r"^/$")),)
    gate = SessionGate(app, secret=SECRET, identity=ident,
                       public_prefixes=("/login",), user_routes=routes)
    return TestClient(gate, follow_redirects=False)


def _cookie(ident, user_id, *, expires_in=3600):
    value = sign_session(SECRET, user_id, ident.session_binding(user_id),
                         int(time.time()) + expires_in)
    return {"cookie": f"mcpflow_session={value}"}


def test_the_gate_names_the_user(tmp_path):
    ident = _identity(tmp_path)
    make_user(ident, "alice", ALICE_PW)
    calls: list[str] = []
    resp = _gate(tmp_path, ident, calls).get("/", headers=_cookie(ident, "alice"))
    assert resp.status_code == 200
    assert resp.json() == {"user": "alice"}
    assert calls == ["alice"]


def _assert_unauthenticated(client, headers, calls):
    resp = client.get("/", headers=headers)
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/login")
    assert calls == []


def test_tampered_cookie_at_the_gate(tmp_path):
    ident = _identity(tmp_path)
    make_user(ident, "alice", ALICE_PW)
    calls: list[str] = []
    good = _cookie(ident, "alice")["cookie"]
    bad = good[:-1] + ("0" if good[-1] != "0" else "1")
    _assert_unauthenticated(_gate(tmp_path, ident, calls), {"cookie": bad}, calls)


def test_expired_cookie_at_the_gate(tmp_path):
    ident = _identity(tmp_path)
    make_user(ident, "alice", ALICE_PW)
    calls: list[str] = []
    _assert_unauthenticated(_gate(tmp_path, ident, calls),
                            _cookie(ident, "alice", expires_in=-10), calls)


def test_cookie_of_a_removed_user(tmp_path):
    ident = _identity(tmp_path)
    make_user(ident, "bob", "bob-pw")
    calls: list[str] = []
    client = _gate(tmp_path, ident, calls)
    headers = _cookie(ident, "bob")
    assert client.get("/", headers=headers).status_code == 200  # valid first
    calls.clear()
    ident._delete_user("bob")
    _assert_unauthenticated(client, headers, calls)


def test_cookie_from_an_earlier_build(tmp_path):
    ident = _identity(tmp_path)
    expires = int(time.time()) + 3600
    mac = hmac.new(SECRET, f"{expires}".encode(), "sha256").hexdigest()
    calls: list[str] = []
    _assert_unauthenticated(
        _gate(tmp_path, ident, calls),
        {"cookie": f"mcpflow_session={expires}.{mac}"}, calls)


def test_password_change_invalidates_sessions_through_the_dashboard(tmp_path):
    ident = _identity(tmp_path)
    make_user(ident, "alice", ALICE_PW)
    calls: list[str] = []
    client = _gate(tmp_path, ident, calls)
    headers = _cookie(ident, "alice")
    assert client.get("/", headers=headers).status_code == 200
    calls.clear()
    ident._issue_setup_code("alice")  # the admin reset: the password and the sessions end
    _assert_unauthenticated(client, headers, calls)


def test_password_change_invalidates_sessions_through_the_environment(tmp_path):
    ident = _identity(tmp_path)
    headers = _cookie(ident, "admin")  # signed under the old ADMIN_PASSWORD
    calls: list[str] = []
    # A restart with a new ADMIN_PASSWORD builds a new provider on the same file.
    restarted = LocalIdentityProvider(
        tmp_path / "users.json", hash_password("changed-admin-pw", iterations=1000)
    )
    restarted.load()
    _assert_unauthenticated(_gate(tmp_path, restarted, calls), headers, calls)


# --- htmx request without a session (htmx-session-redirect) ------------------
# The gate answers 401 + HX-Redirect, so htmx loads the login page instead of
# swapping it into the target; `next` is the page that sent the request.


def _htmx_gate(tmp_path, calls):
    async def handler(request):
        calls.append(request.url.path)
        return JSONResponse({})

    app = Starlette(routes=[Route("/login", handler),
                            Route("/tools/tree", handler),
                            Route("/visibility/root", handler, methods=["POST"])])
    gate = SessionGate(app, secret=SECRET, identity=_identity(tmp_path),
                       public_prefixes=("/login",), user_routes=())
    return TestClient(gate, base_url="http://gateway.lan", follow_redirects=False)


def _htmx(current_url=None):
    headers = {"HX-Request": "true"}
    if current_url is not None:
        headers["HX-Current-URL"] = current_url
    return headers


def _assert_htmx_redirect(resp, nxt):
    assert resp.status_code == 401
    assert resp.headers["hx-redirect"] == f"/login?next={nxt}"
    assert "location" not in resp.headers


def test_unauthenticated_htmx_partial(tmp_path):
    calls: list[str] = []
    resp = _htmx_gate(tmp_path, calls).get(
        "/tools/tree", headers=_htmx("http://gateway.lan/servers"))
    _assert_htmx_redirect(resp, "/servers")
    assert calls == []


def test_unauthenticated_htmx_post(tmp_path):
    calls: list[str] = []
    resp = _htmx_gate(tmp_path, calls).post(
        "/visibility/root", headers=_htmx("http://gateway.lan/"))
    _assert_htmx_redirect(resp, "/")
    assert calls == []


@pytest.mark.parametrize("current_url", [
    None,                                # absent
    "http://[",                          # does not parse
    "https://evil.test/servers",         # another host
    "http://gateway.lan:8443/servers",   # same host, other port
    "http://gateway.lan//evil.test",
    "http://gateway.lan/\\evil.test",
    "http://gateway.lan/\t/evil.test",   # urlsplit drops the tab: `//evil.test`
])
def test_foreign_or_malformed_current_url(tmp_path, current_url):
    resp = _htmx_gate(tmp_path, []).get("/tools/tree", headers=_htmx(current_url))
    _assert_htmx_redirect(resp, "/")


@pytest.mark.parametrize(("current_url", "nxt"), [
    ("http://gateway.lan/a&next=//x", "/a%26next%3D//x"),
    ("http://gateway.lan/a%20b", "/a%2520b"),  # login_get decodes it once
])
def test_the_gate_encodes_next(tmp_path, current_url, nxt):
    resp = _htmx_gate(tmp_path, []).get("/tools/tree", headers=_htmx(current_url))
    _assert_htmx_redirect(resp, nxt)


def test_a_request_without_htmx_keeps_the_303(tmp_path):
    for value in (None, "false"):
        headers = {} if value is None else {"HX-Request": value}
        resp = _htmx_gate(tmp_path, []).get("/tools/tree", headers=headers)
        assert resp.status_code == 303
        assert resp.headers["location"] == "/login?next=/tools/tree"
        assert "hx-redirect" not in resp.headers


def test_an_htmx_request_to_a_public_path_passes(tmp_path):
    calls: list[str] = []
    resp = _htmx_gate(tmp_path, calls).get(
        "/login", headers=_htmx("http://gateway.lan/servers"))
    assert resp.status_code == 200
    assert calls == ["/login"]


def test_an_empty_host_never_matches_a_relative_current_url(tmp_path):
    headers = {**_htmx("/servers"), "Host": ""}
    resp = _htmx_gate(tmp_path, []).get("/tools/tree", headers=headers)
    _assert_htmx_redirect(resp, "/")


def test_a_cross_origin_htmx_post_is_still_refused(tmp_path):
    headers = {**_htmx("http://gateway.lan/"), "Origin": "https://evil.test"}
    resp = _htmx_gate(tmp_path, []).post("/visibility/root", headers=headers)
    assert resp.status_code == 403
    assert resp.text == "cross-origin request rejected"
    assert "hx-redirect" not in resp.headers


# --- Bearer tokens for /mcp and the admin gate (10.5) ------------------------


async def _verify(tmp_path, clear):
    store = _tokens(tmp_path)
    return await HashedTokenVerifier(store, _identity(tmp_path)).verify_token(clear)


@pytest.mark.asyncio
async def test_valid_token_names_the_user(tmp_path):
    ident = _identity(tmp_path)
    make_user(ident, "alice", ALICE_PW)
    store = _tokens(tmp_path)
    _r, clear = store.create("laptop", "mcp", "alice")
    access = await HashedTokenVerifier(store, ident).verify_token(clear)
    assert access is not None
    assert access.subject == "alice"
    assert access.scopes == ["mcp"]


@pytest.mark.asyncio
async def test_admin_token_accepted_on_mcp(tmp_path):
    ident = _identity(tmp_path)
    make_user(ident, "root2", "pw", admin=True)
    store = _tokens(tmp_path)
    for uid in ("admin", "root2"):
        _r, clear = store.create("ci", "admin", uid)
        access = await HashedTokenVerifier(store, ident).verify_token(clear)
        assert access is not None and access.subject == uid
        assert access.scopes == ["admin"]


@pytest.mark.asyncio
async def test_admin_scope_token_of_a_demoted_user_acts_as_mcp(tmp_path):
    ident = _identity(tmp_path)
    make_user(ident, "dave", "pw", admin=True)
    store = _tokens(tmp_path)
    _r, clear = store.create("ci", "admin", "dave")
    ident.set_admin("dave", False)
    access = await HashedTokenVerifier(store, ident).verify_token(clear)
    assert access is not None
    assert access.subject == "dave"
    assert access.scopes == ["mcp"]


@pytest.mark.asyncio
async def test_verifier_refuses_unknown_and_empty_tokens(tmp_path):
    assert await _verify(tmp_path, "mcpflow_nope") is None
    assert await _verify(tmp_path, "") is None


@pytest.mark.asyncio
async def test_token_of_a_removed_user_is_refused(tmp_path):
    ident = _identity(tmp_path)
    make_user(ident, "bob", "pw")
    store = _tokens(tmp_path)
    _r, clear = store.create("laptop", "mcp", "bob")
    verifier = HashedTokenVerifier(store, ident)
    assert await verifier.verify_token(clear) is not None
    ident._delete_user("bob")  # the record stays; the provider no longer knows bob
    assert await verifier.verify_token(clear) is None
    # A record whose user never existed is refused the same way.
    _r2, ghost = store.create("ghost", "mcp", "ghost")
    assert await verifier.verify_token(ghost) is None


def _seed_tokens(holder: dict):
    def seed(data_dir: Path) -> None:
        ident = LocalIdentityProvider(
            data_dir / "users.json", hash_password("secret", iterations=1000)
        )
        ident.load()
        make_user(ident, "alice", ALICE_PW)
        make_user(ident, "dave", "pw", admin=True)
        store = TokenStore(data_dir / "tokens.json", data_dir / "user_tokens.json")
        store.load()
        for label, scope, uid in (
            ("admin_admin", "admin", "admin"),
            ("admin_mcp", "mcp", "admin"),
            ("alice_mcp", "mcp", "alice"),
            ("dave_admin", "admin", "dave"),
            ("ghost", "mcp", "ghost"),
        ):
            record, clear = store.create(label, scope, uid)
            holder[label] = clear
            holder[label + "_id"] = record.id
        ident.set_admin("dave", False)  # dave keeps an admin-scope token

    return seed


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_missing_token_on_mcp_is_401_with_challenge(server_factory):
    server = server_factory(_seed_tokens({}))
    resp = httpx.post(server.base_url + "/mcp", json={})
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == "Bearer"


def test_revoked_token_is_401_on_mcp(server_factory):
    holder: dict = {}
    server = server_factory(_seed_tokens(holder))
    probe = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    headers = {**_bearer(holder["alice_mcp"]),
               "Accept": "application/json, text/event-stream"}
    assert httpx.post(server.base_url + "/mcp", json=probe,
                      headers=headers).status_code != 401
    client = server.login()
    assert client.post(f"/tokens/{holder['alice_mcp_id']}/delete").status_code == 303
    client.close()
    assert httpx.post(server.base_url + "/mcp", json=probe,
                      headers=headers).status_code == 401


def test_token_of_a_removed_user_is_401_on_mcp(server_factory):
    holder: dict = {}
    server = server_factory(_seed_tokens(holder))
    resp = httpx.post(server.base_url + "/mcp", json={},
                      headers=_bearer(holder["ghost"]))
    assert resp.status_code == 401


def test_mcp_token_still_refused_on_api(server_factory):
    holder: dict = {}
    server = server_factory(_seed_tokens(holder))
    resp = httpx.get(server.base_url + "/api/servers",
                     headers=_bearer(holder["admin_mcp"]))
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == "Bearer"


def test_admin_token_of_an_admin_user_opens_api(server_factory):
    holder: dict = {}
    server = server_factory(_seed_tokens(holder))
    resp = httpx.get(server.base_url + "/api/servers",
                     headers=_bearer(holder["admin_admin"]))
    assert resp.status_code == 200


def test_admin_token_of_a_non_admin_user_is_refused_on_api(server_factory):
    holder: dict = {}
    server = server_factory(_seed_tokens(holder))
    resp = httpx.get(server.base_url + "/api/servers",
                     headers=_bearer(holder["dave_admin"]))
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == "Bearer"


def test_demoted_admin_token_lists_no_mcpflow_tool(server_factory):
    from test_gateway import mcp_session

    holder: dict = {}

    def seed(data_dir: Path) -> None:
        seed_registry(fake_child_spec("time", "good"))(data_dir)
        _seed_tokens(holder)(data_dir)

    server = server_factory(seed)
    server.wait(running=1)
    # Guard against a vacuous pass: an admin session does see mcpflow_* tools.
    _n, admin_tools = mcp_session(server.base_url, holder["admin_admin"])
    assert any(t.startswith("mcpflow_") for t in admin_tools)
    _n, dave_tools = mcp_session(server.base_url, holder["dave_admin"])
    assert not any(t.startswith("mcpflow_") for t in dave_tools)


# --- Cross-site request protection on public paths (login-origin-check) ------
# From `specs/auth/spec.md` (Cross-site request protection, Bearer prefixes are
# public prefixes) and `design.md` D1, D1b, D2: not from the code.

EVIL = "https://evil.test"
REFUSED = "cross-origin request rejected"


def _host(server) -> str:
    return server.base_url.removeprefix("http://")


def _login_with(server, headers, user="alice", password=ALICE_PW):
    return httpx.post(
        server.base_url + "/login",
        data={"user": user, "password": password, "next": "/"},
        headers=headers,
        follow_redirects=False,
    )


def _assert_refused(resp):
    assert resp.status_code == 403
    assert resp.text == REFUSED
    assert "set-cookie" not in resp.headers


def test_t1_cross_origin_login_is_refused(server_factory):
    server = server_factory(_seed_users)
    _assert_refused(_login_with(server, {"Origin": EVIL}))


def test_t2_same_origin_login_signs_in(server_factory):
    server = server_factory(_seed_users)
    resp = _login_with(server, {"Origin": f"http://{_host(server)}"})
    assert resp.status_code == 303
    assert "mcpflow_session=alice." in resp.headers["set-cookie"]


def test_t3_login_without_origin_signs_in(server_factory):
    server = server_factory(_seed_users)
    resp = _login_with(server, {})
    assert "origin" not in resp.request.headers
    assert resp.status_code == 303
    assert "mcpflow_session=alice." in resp.headers["set-cookie"]


def test_t4_opaque_origin_login_is_refused(server_factory):
    server = server_factory(_seed_users)
    _assert_refused(_login_with(server, {"Origin": "null"}))


def test_t13_malformed_origin_is_refused_not_an_error(server_factory):
    server = server_factory(_seed_users)
    _assert_refused(_login_with(server, {"Origin": "http://["}))


def test_t6b_cross_origin_mcp_post_without_a_token_is_401(server_factory):
    server = server_factory()
    resp = httpx.post(
        server.base_url + "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        headers={"Origin": EVIL},
    )
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == "Bearer"


def test_t7_cross_origin_api_post_without_a_token_is_401(server_factory):
    server = server_factory()
    resp = httpx.post(
        server.base_url + "/api/tokens",
        json={"name": "x", "scope": "mcp"},
        headers={"Origin": EVIL},
    )
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == "Bearer"
    assert resp.json() == {"error": "unauthorized"}  # AdminTokenGate, not SessionGate


# --- SessionGate unit tests (raw ASGI, a stub app) ---------------------------


def _run_gate(gate, method, path, headers):
    """Drive the gate with a raw scope. Return (reached the app, statuses sent)."""
    import asyncio

    reached: list[str] = []
    sent: list[dict] = []

    async def stub(scope, receive, send):
        reached.append(scope["path"])
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    gate.app = stub

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers,
        "state": {},
    }
    asyncio.run(gate(scope, receive, send))
    statuses = [m["status"] for m in sent if m["type"] == "http.response.start"]
    return bool(reached), statuses


def _unit_gate(tmp_path, public, **kw):
    return SessionGate(
        None,
        secret=SECRET,
        identity=_identity(tmp_path),
        public_prefixes=public,
        user_routes=(),
        **kw,
    )


def test_t6_cross_origin_post_on_a_bearer_prefix_reaches_the_app(tmp_path):
    gate = _unit_gate(tmp_path, ("/login", "/mcp"), bearer_prefixes=("/mcp",))
    reached, statuses = _run_gate(
        gate, "POST", "/mcp",
        [(b"host", b"gateway.lan"), (b"origin", EVIL.encode())],
    )
    assert reached
    assert statuses == [204]  # only the stub answered: the gate sent no response


def test_t8_a_public_path_is_checked_by_default(tmp_path):
    gate = _unit_gate(tmp_path, ("/login", "/hook"))
    reached, statuses = _run_gate(
        gate, "POST", "/hook",
        [(b"host", b"gateway.lan"), (b"origin", EVIL.encode())],
    )
    assert not reached
    assert statuses == [403]


def test_t9_a_bearer_prefix_outside_the_public_prefixes_is_refused(tmp_path):
    with pytest.raises(ValueError, match="/mcp"):
        _unit_gate(tmp_path, ("/login",), bearer_prefixes=("/mcp",))


def test_t12_a_non_utf8_header_byte_is_not_a_500(tmp_path):
    gate = _unit_gate(tmp_path, ("/login", "/mcp"), bearer_prefixes=("/mcp",))
    for method, path in (("POST", "/mcp"), ("GET", "/login")):
        reached, statuses = _run_gate(
            gate, method, path,
            [(b"host", b"gateway.lan"), (b"x-odd", b"caf\xff")],
        )
        assert reached, (method, path)
        assert 500 not in statuses


def test_t12b_a_non_utf8_origin_on_a_checked_post_is_a_403(tmp_path):
    # Scenario: the check itself reads Origin and Host as Latin-1 (review M3).
    gate = _unit_gate(tmp_path, ("/login",))
    reached, statuses = _run_gate(
        gate, "POST", "/login",
        [(b"host", b"gateway.lan"), (b"origin", b"http://caf\xff")],
    )
    assert not reached
    assert statuses == [403]


def test_t14_a_bearer_prefix_matches_on_a_segment_boundary(tmp_path):
    # Scenario: a bearer prefix exempts its own path segment only (review M1).
    gate = _unit_gate(tmp_path, ("/login", "/mcp"), bearer_prefixes=("/mcp",))
    headers = [(b"host", b"gateway.lan"), (b"origin", EVIL.encode())]
    for path in ("/mcp", "/mcp/", "/mcp/x"):
        reached, _ = _run_gate(gate, "POST", path, headers)
        assert reached, path
    for path in ("/mcpfoo", "/mcp-settings"):
        reached, statuses = _run_gate(gate, "POST", path, headers)
        assert not reached and statuses == [403], path


def test_t10_the_gateway_wires_the_bearer_prefixes(tmp_path):
    from conftest import make_settings

    from mcpflow.gateway import build_app

    (tmp_path / "logs").mkdir()
    app = build_app(make_settings(tmp_path))
    (kw,) = [m.kwargs for m in app.user_middleware if m.cls is SessionGate]
    assert kw["bearer_prefixes"] == ("/mcp", "/api/")
    assert all(p in kw["public_prefixes"] for p in kw["bearer_prefixes"])
    assert kw["bearer_prefixes"] != tuple(kw["public_prefixes"])
