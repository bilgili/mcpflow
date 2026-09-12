"""Password hashing, session cookies, the session gate, and bearer tokens.

This module depends only on the standard library and `fastmcp.server.auth`.
It takes no `Settings`, so `config.py` may import `hash_password` from here.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from fastmcp.server.auth import TokenVerifier
from fastmcp.server.auth.auth import AccessToken
from starlette.responses import JSONResponse, PlainTextResponse, RedirectResponse
from starlette.types import ASGIApp, Receive, Scope, Send

COOKIE_NAME = "mcpflow_session"

# A token grants exactly one privilege. `mcp` authenticates `/mcp`; `admin`
# authenticates `/api`. The annotation documents the set; `TokenStore` enforces
# it, so `_TOKEN_SCOPES` is the runtime owner of the membership check.
TokenScope = Literal["mcp", "admin"]
_TOKEN_SCOPES: frozenset[str] = frozenset(("mcp", "admin"))


def _require_scope(scope: object) -> None:
    """Raise `ValueError` unless `scope` is a known scope string.

    The one owner of the membership check, called by both `create` and `load`.
    Rejects a non-string first: a JSON body can carry an unhashable `scope`
    (a list, an object), and `x in frozenset` would raise `TypeError`, which
    the API's `ValueError -> 400` mapping does not catch. Keep every bad scope
    a `ValueError`, so a malformed body answers 400, never a re-raised 500.
    """
    if not isinstance(scope, str) or scope not in _TOKEN_SCOPES:
        raise ValueError(f"unknown token scope {scope!r}")

# --- password hashing --------------------------------------------------------


def hash_password(password: str, *, iterations: int = 600_000) -> str:
    """Return `pbkdf2_sha256$<iterations>$<salt hex>$<digest hex>`."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    """Constant-time password check. Return False on a bad format."""
    try:
        scheme, iters, salt_hex, digest_hex = encoded.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(iters)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, AttributeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return hmac.compare_digest(actual, expected)


# --- session cookie ----------------------------------------------------------


def sign_session(secret: bytes, password_hash: str, expires_at: int) -> str:
    """Return `<expires_at>.<hmac hex>` over `f"{expires_at}.{password_hash}"`."""
    msg = f"{expires_at}.{password_hash}".encode()
    mac = hmac.new(secret, msg, hashlib.sha256).hexdigest()
    return f"{expires_at}.{mac}"


def verify_session(secret: bytes, password_hash: str, value: str, now: int) -> bool:
    """Reject a bad signature, a bad format, and `expires_at <= now`."""
    try:
        exp_str, _mac = value.split(".", 1)
        expires_at = int(exp_str)
    except (ValueError, AttributeError):
        return False
    if expires_at <= now:
        return False
    expected = sign_session(secret, password_hash, expires_at)
    return hmac.compare_digest(value, expected)


# --- session gate ------------------------------------------------------------


class SessionGate:
    """Starlette pure-ASGI middleware that guards the UI routes."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        secret: bytes,
        password_hash: str,
        public_prefixes: tuple[str, ...],
    ) -> None:
        self.app = app
        self.secret = secret
        self.password_hash = password_hash
        self.public_prefixes = public_prefixes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope["path"]
        if any(path.startswith(p) for p in self.public_prefixes):
            await self.app(scope, receive, send)
            return

        method = scope["method"]
        headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}

        # Cross-site request protection: reject a cross-origin POST.
        if method == "POST":
            origin = headers.get("origin")
            host = headers.get("host")
            if origin and urlsplit(origin).netloc != host:
                await PlainTextResponse(
                    "cross-origin request rejected", status_code=403
                )(scope, receive, send)
                return

        if not self._authenticated(headers):
            if method == "GET":
                target = f"/login?next={path}"
                await RedirectResponse(target, status_code=303)(scope, receive, send)
            else:
                await PlainTextResponse("unauthorized", status_code=401)(
                    scope, receive, send
                )
            return

        await self.app(scope, receive, send)

    def _authenticated(self, headers: dict[str, str]) -> bool:
        raw = headers.get("cookie")
        if not raw:
            return False
        jar = SimpleCookie()
        jar.load(raw)
        morsel = jar.get(COOKIE_NAME)
        if morsel is None:
            return False
        now = int(datetime.now(UTC).timestamp())
        return verify_session(self.secret, self.password_hash, morsel.value, now)


# --- token storage -----------------------------------------------------------


@dataclass(frozen=True)
class TokenRecord:
    id: str
    name: str
    sha256: str
    created_at: datetime
    last_used_at: datetime | None
    scope: TokenScope = "mcp"  # a missing key in the file loads as "mcp"


def _sha256_hex(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class TokenStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._records: list[TokenRecord] = []

    def load(self) -> None:
        if not self._path.exists():
            self._records = []
            return
        data = json.loads(self._path.read_text())
        records: list[TokenRecord] = []
        for t in data.get("tokens", []):
            scope = t.get("scope", "mcp")
            # Refuse an off-table scope at load, the same way `Registry.load`
            # refuses a duplicate namespace. The store then never holds a scope
            # the gates cannot ask for; a hand-edited file fails at start.
            _require_scope(scope)
            records.append(
                TokenRecord(
                    id=t["id"],
                    name=t["name"],
                    sha256=t["sha256"],
                    created_at=datetime.fromisoformat(t["created_at"]),
                    last_used_at=(
                        datetime.fromisoformat(t["last_used_at"])
                        if t.get("last_used_at")
                        else None
                    ),
                    scope=scope,
                )
            )
        self._records = records

    def list(self) -> list[TokenRecord]:
        return list(self._records)

    def create(self, name: str, scope: TokenScope = "mcp") -> tuple[TokenRecord, str]:
        _require_scope(scope)
        token = "mcpflow_" + secrets.token_urlsafe(32)
        record = TokenRecord(
            id="tok_" + secrets.token_hex(4),
            name=name,
            sha256=_sha256_hex(token),
            created_at=datetime.now(UTC),
            last_used_at=None,
            scope=scope,
        )
        self._records.append(record)
        self._save()
        return record, token

    def revoke(self, token_id: str) -> None:
        for i, record in enumerate(self._records):
            if record.id == token_id:
                del self._records[i]
                self._save()
                return
        raise KeyError(token_id)

    def lookup(self, token: str, *scopes: TokenScope) -> TokenRecord | None:
        # One or more required scopes; the record matches when its scope is in
        # the set. An empty set matches nothing, so a caller that forgets the
        # scope fails closed rather than authenticating every token.
        digest = _sha256_hex(token)
        for i, record in enumerate(self._records):
            if hmac.compare_digest(record.sha256, digest):
                # A scope mismatch is a failed authentication: return None and
                # leave `last_used_at` untouched, so a wrong-scope probe cannot
                # be told apart from an unknown token by the timestamp.
                if record.scope not in scopes:
                    return None
                # Update last_used_at in memory only; not persisted.
                self._records[i] = TokenRecord(
                    id=record.id,
                    name=record.name,
                    sha256=record.sha256,
                    created_at=record.created_at,
                    last_used_at=datetime.now(UTC),
                    scope=record.scope,
                )
                return self._records[i]
        return None

    def _save(self) -> None:
        payload = {
            "version": 1,
            "tokens": [
                {
                    "id": r.id,
                    "name": r.name,
                    "sha256": r.sha256,
                    "created_at": r.created_at.isoformat(),
                    "last_used_at": r.last_used_at.isoformat()
                    if r.last_used_at
                    else None,
                    "scope": r.scope,
                }
                for r in self._records
            ],
        }
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        # Create the file already-private (0600); child secrets never sit at
        # 0644 in the write window.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(payload, indent=2))
        os.replace(tmp, self._path)


class HashedTokenVerifier(TokenVerifier):
    """Bearer verifier that matches a SHA-256 digest against `TokenStore`."""

    def __init__(self, store: TokenStore) -> None:
        super().__init__()
        self.store = store

    async def verify_token(self, token: str) -> AccessToken | None:
        # `/mcp` accepts both scopes; the recorded scope rides on the
        # `AccessToken` so a transform (the admin scope filter) can tell an
        # `admin` session from an `mcp` session. `/api` keeps its own gate on
        # scope `admin` only.
        record = self.store.lookup(token, "mcp", "admin")
        if record is None:
            return None
        return AccessToken(token=token, client_id=record.id, scopes=[record.scope])


# --- admin bearer gate -------------------------------------------------------


class AdminTokenGate:
    """Pure-ASGI middleware that guards the `/api` sub-app.

    It owns one credential type and one path set, the mirror of `SessionGate`.
    The session cookie never reaches here, and a bearer token never reaches
    the session gate: `/api/` is a public prefix there. A request passes only
    when its bearer token resolves in `TokenStore` with scope `admin`.
    """

    def __init__(self, app: ASGIApp, *, store: TokenStore) -> None:
        self.app = app
        self.store = store

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
        token = self._bearer(headers.get("authorization"))
        if token is None or self.store.lookup(token, "admin") is None:
            await JSONResponse(
                {"error": "unauthorized"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )(scope, receive, send)
            return
        await self.app(scope, receive, send)

    @staticmethod
    def _bearer(value: str | None) -> str | None:
        if not value:
            return None
        parts = value.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
            return None
        return parts[1].strip()
