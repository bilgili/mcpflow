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


def test_sign_and_verify():
    ph = hash_password("pw")
    expires_at = int(time.time()) + 3600
    value = sign_session(SECRET, ph, expires_at)
    assert value.startswith(f"{expires_at}.")
    assert verify_session(SECRET, ph, value, now=int(time.time())) is True


def test_tampered_cookie():
    ph = hash_password("pw")
    expires_at = int(time.time()) + 3600
    value = sign_session(SECRET, ph, expires_at)
    tampered = value[:-1] + ("0" if value[-1] != "0" else "1")
    assert verify_session(SECRET, ph, tampered, now=int(time.time())) is False


def test_expired_cookie():
    ph = hash_password("pw")
    expires_at = int(time.time()) - 10
    value = sign_session(SECRET, ph, expires_at)
    assert verify_session(SECRET, ph, value, now=int(time.time())) is False


def test_password_change_invalidates_sessions():
    old_hash = hash_password("old")
    new_hash = hash_password("new")
    expires_at = int(time.time()) + 3600
    value = sign_session(SECRET, old_hash, expires_at)
    # A cookie signed under the old hash is invalid under the new hash.
    assert verify_session(SECRET, new_hash, value, now=int(time.time())) is False


# --- Token storage (12.2) ----------------------------------------------------


def test_digest_only_on_disk(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    store.load()
    _record, clear = store.create("laptop")
    raw = (tmp_path / "tokens.json").read_text()
    assert clear not in raw
    import hashlib

    digest = hashlib.sha256(clear.encode()).hexdigest()
    assert digest in raw


def test_create_returns_clear_text_once(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    store.load()
    record, clear = store.create("laptop")
    assert clear.startswith("mcpflow_")
    # The clear text is not recoverable from the stored record.
    assert clear not in json.dumps(
        {"id": record.id, "name": record.name, "sha256": record.sha256}
    )


def test_revoke_persists(tmp_path):
    path = tmp_path / "tokens.json"
    store = TokenStore(path)
    store.load()
    record, _clear = store.create("laptop")
    store.revoke(record.id)
    # A fresh load reflects the revoke.
    reloaded = TokenStore(path)
    reloaded.load()
    assert all(r.id != record.id for r in reloaded.list())
    with pytest.raises(KeyError):
        store.revoke(record.id)


def test_lookup(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    store.load()
    record, clear = store.create("laptop")
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
    store = TokenStore(path)
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
    store = TokenStore(path)
    with pytest.raises(ValueError):
        store.load()


def test_lookup_wrong_scope_returns_none_and_keeps_last_used(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    store.load()
    _record, clear = store.create("ci", "admin")
    # A wrong-scope lookup is a failed authentication.
    assert store.lookup(clear, "mcp") is None
    (stored,) = store.list()
    assert stored.last_used_at is None


def test_lookup_two_scopes_match_either_record(tmp_path):
    # The verifier calls lookup(token, "mcp", "admin"); both scopes resolve.
    store = TokenStore(tmp_path / "tokens.json")
    store.load()
    _m, mcp_clear = store.create("m", "mcp")
    _a, admin_clear = store.create("a", "admin")
    mcp_found = store.lookup(mcp_clear, "mcp", "admin")
    admin_found = store.lookup(admin_clear, "mcp", "admin")
    assert mcp_found is not None and mcp_found.scope == "mcp"
    assert admin_found is not None and admin_found.scope == "admin"


def test_lookup_no_scope_returns_none_and_keeps_last_used(tmp_path):
    # An empty scope set matches nothing, so a caller that forgets the scope
    # fails closed rather than authenticating every token.
    store = TokenStore(tmp_path / "tokens.json")
    store.load()
    _record, clear = store.create("laptop")
    assert store.lookup(clear) is None
    (stored,) = store.list()
    assert stored.last_used_at is None


def test_scope_persists(tmp_path):
    path = tmp_path / "tokens.json"
    store = TokenStore(path)
    store.load()
    store.create("ci", "admin")
    reloaded = TokenStore(path)
    reloaded.load()
    (record,) = reloaded.list()
    assert record.scope == "admin"


def test_create_refuses_bad_scope(tmp_path):
    path = tmp_path / "tokens.json"
    store = TokenStore(path)
    store.load()
    with pytest.raises(ValueError):
        store.create("x", "root")
    assert not path.exists()


@pytest.mark.asyncio
async def test_verifier_valid_and_revoked(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    store.load()
    record, clear = store.create("laptop")
    verifier = HashedTokenVerifier(store)
    access = await verifier.verify_token(clear)
    assert access is not None
    assert access.client_id == record.id
    assert access.scopes == ["mcp"]
    store.revoke(record.id)
    assert await verifier.verify_token(clear) is None
