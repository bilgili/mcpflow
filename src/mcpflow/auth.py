"""Password hashing, session cookies, the session gate, and bearer tokens.

This module depends only on the standard library and `fastmcp.server.auth`.
It takes no `Settings`, so `config.py` may import `hash_password` from here.
`identity.py` imports `hash_password` too, so this module names its
`IdentityProvider` and `User` types under `TYPE_CHECKING` only.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from http.cookies import SimpleCookie
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal
from urllib.parse import quote, urlsplit

from fastmcp.server.auth import TokenVerifier
from fastmcp.server.auth.auth import AccessToken
from starlette.responses import JSONResponse, PlainTextResponse, RedirectResponse
from starlette.types import ASGIApp, Receive, Scope, Send

if TYPE_CHECKING:
    from .identity import IdentityProvider, User

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


def sign_session(secret: bytes, user_id: str, binding: str, expires_at: int) -> str:
    """Return `<user_id>.<expires_at>.<hmac hex>`.

    The HMAC covers `f"{user_id}.{expires_at}.{binding}"`. The binding is the
    provider's `session_binding(user_id)` (the password hash for the Local
    provider), so a password change or a removal invalidates every session.
    """
    msg = f"{user_id}.{expires_at}.{binding}".encode()
    mac = hmac.new(secret, msg, hashlib.sha256).hexdigest()
    return f"{user_id}.{expires_at}.{mac}"


def verify_session(
    secret: bytes, value: str, binding_of: Callable[[str], str | None], now: int
) -> str | None:
    """Return the user id of a valid cookie, else `None`.

    Rejects a bad format (the two-part cookie of the earlier build included),
    `expires_at <= now`, a user without a binding, and a bad signature.
    """
    if not isinstance(value, str):
        return None
    parts = value.split(".")
    if len(parts) != 3:
        return None
    user_id, exp_str, _mac = parts
    try:
        expires_at = int(exp_str)
    except ValueError:
        return None
    if expires_at <= now:
        return None
    binding = binding_of(user_id)
    if binding is None:
        return None
    expected = sign_session(secret, user_id, binding, expires_at)
    # Compare bytes: `compare_digest` raises TypeError on a non-ASCII str, and
    # a cookie is client input. The full-string compare also refuses a
    # non-canonical `expires_at` such as `+5` or `05`.
    if not hmac.compare_digest(value.encode(), expected.encode()):
        return None
    return user_id


def _under_prefix(path: str, prefix: str) -> bool:
    """`path` is below `prefix` on a segment boundary: `/mcp` covers `/mcp`
    and `/mcp/x`, never `/mcpfoo` or `/mcp-settings`; `/api/` covers only
    paths below `/api/`."""
    if prefix.endswith("/"):
        return path.startswith(prefix)
    return path == prefix or path.startswith(prefix + "/")


def _origin_netloc(origin: str) -> str | None:
    """The host of an `Origin` header, or None when it does not parse: a
    malformed Origin (`http://[`) then counts as cross-site, never as a 500."""
    try:
        return urlsplit(origin).netloc
    except ValueError:
        return None


def local_path(p: str) -> bool:
    """`p` stays on this origin: it starts with `/`, and not with `//` or
    `/\\`, which a browser reads as `//`. The sign-in and the session gate
    share this rule."""
    return p.startswith("/") and not p.startswith(("//", "/\\"))


def _htmx_next(current_url: str | None, host: str | None) -> str:
    """The `next` value for an htmx request: the path of the page that sent
    it (`HX-Current-URL`), when that page is on this host and the path is
    local; `/` otherwise. Encoded, because it goes into a raw header."""
    try:
        url = urlsplit(current_url or "")
    except ValueError:
        return "/"
    if not host or url.netloc != host or not local_path(url.path):
        return "/"
    return quote(url.path, safe="/")


def _set_user(scope: Scope, user: User) -> None:
    # Copy the state dict, never mutate it: a server shares the lifespan state
    # between requests, so an in-place write could leak one request's user.
    scope["state"] = {**scope.get("state", {}), "user": user}


# --- session gate ------------------------------------------------------------


class SessionGate:
    """Starlette pure-ASGI middleware that guards the UI routes.

    It owns two checks at one seam, before the router: the cookie to a user
    (resolved on every request, into `request.state.user`), and the role
    check. An admin passes to every route. A non-admin user passes only on a
    method and path that `user_routes` lists; every other route answers 403,
    so a route nobody listed fails closed.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        secret: bytes,
        identity: IdentityProvider,
        public_prefixes: tuple[str, ...],
        user_routes: tuple[tuple[frozenset[str], re.Pattern[str]], ...],
        bearer_prefixes: tuple[str, ...] = (),
    ) -> None:
        # A bearer prefix outside the public prefixes would take a cookie
        # with no cross-site check: refuse that wiring at build time.
        for p in bearer_prefixes:
            if p not in public_prefixes:
                raise ValueError(f"bearer prefix {p!r} is not a public prefix")
        self.app = app
        self.secret = secret
        self.identity = identity
        self.public_prefixes = public_prefixes
        self.user_routes = user_routes
        self.bearer_prefixes = bearer_prefixes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope["path"]
        method = scope["method"]

        # Cross-site request protection: reject a cross-origin POST. It runs
        # before the public skip, so `/login` gets it too; only a bearer
        # prefix (no ambient credential) is exempt. It reads only Origin and
        # Host, as Latin-1, which never raises on an obs-text byte.
        if method == "POST" and not any(
            _under_prefix(path, p) for p in self.bearer_prefixes
        ):
            origin = host = None
            for k, v in scope["headers"]:
                name = k.decode("latin-1").lower()
                if name == "origin":
                    origin = v.decode("latin-1")
                elif name == "host":
                    host = v.decode("latin-1")
            if origin and _origin_netloc(origin) != host:
                await PlainTextResponse(
                    "cross-origin request rejected", status_code=403
                )(scope, receive, send)
                return

        if any(path.startswith(p) for p in self.public_prefixes):
            await self.app(scope, receive, send)
            return

        headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}

        user = self._user(headers)
        if user is None:
            if headers.get("hx-request") == "true":
                # htmx would follow a 303 inside the XHR and swap the login
                # page into the target; HX-Redirect makes it load the page.
                # Same rule as `is_htmx` in web.py, which reads a Request.
                nxt = _htmx_next(headers.get("hx-current-url"), headers.get("host"))
                await PlainTextResponse(
                    "unauthorized",
                    status_code=401,
                    headers={"HX-Redirect": f"/login?next={nxt}"},
                )(scope, receive, send)
            elif method == "GET":
                target = f"/login?next={path}"
                await RedirectResponse(target, status_code=303)(scope, receive, send)
            else:
                await PlainTextResponse("unauthorized", status_code=401)(
                    scope, receive, send
                )
            return

        if not user.is_admin and not any(
            method in methods and pattern.fullmatch(path)
            for methods, pattern in self.user_routes
        ):
            await PlainTextResponse("forbidden", status_code=403)(scope, receive, send)
            return

        _set_user(scope, user)
        await self.app(scope, receive, send)

    def _user(self, headers: dict[str, str]) -> User | None:
        raw = headers.get("cookie")
        if not raw:
            return None
        jar = SimpleCookie()
        jar.load(raw)
        morsel = jar.get(COOKIE_NAME)
        if morsel is None:
            return None
        now = int(datetime.now(UTC).timestamp())
        user_id = verify_session(
            self.secret, morsel.value, self.identity.session_binding, now
        )
        # Resolve again after the signature check: the binding proves the
        # cookie, the lookup gives the current role and groups.
        return None if user_id is None else self.identity.get_user(user_id)


# --- token storage -----------------------------------------------------------


@dataclass(frozen=True)
class TokenRecord:
    id: str
    name: str
    sha256: str
    created_at: datetime
    last_used_at: datetime | None
    scope: TokenScope = "mcp"  # a missing key in the file loads as "mcp"
    # A missing key in `tokens.json` loads as the bootstrap user (AC-8b).
    user_id: str = "admin"


def _sha256_hex(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# The bootstrap user id. `identity.BOOTSTRAP_ADMIN_ID` owns the name; this
# module cannot import it at run time, because `identity` imports
# `hash_password` from here.
_ADMIN_ID = "admin"


def _is_admin_file(user_id: str) -> bool:
    return user_id == _ADMIN_ID


# The default count of tokens one user may hold. `config.py` imports it for
# the `MAX_USER_TOKENS` default, so a store built without the setting is
# capped too (D3).
DEFAULT_MAX_USER_TOKENS: Final = 10


class TokenStore:
    """Token records in two files; the `user_id` of a record selects the file.

    `tokens.json` holds the tokens of `admin` only, because an earlier build
    reads that file and must accept no token of another user (D10).
    `user_tokens.json` holds every other user's tokens. A record never moves,
    because its `user_id` never changes. Every mutator writes one file and
    adopts the candidate in memory only after the write.
    """

    def __init__(
        self,
        path: Path,
        user_path: Path,
        *,
        max_user_tokens: int = DEFAULT_MAX_USER_TOKENS,
    ) -> None:
        self._path = path
        self._user_path = user_path
        self._max_user_tokens = max_user_tokens
        self._records: list[TokenRecord] = []

    @staticmethod
    def _read(path: Path, admin_file: bool) -> list[TokenRecord]:
        if not path.exists():
            return []
        data = json.loads(path.read_text())
        records: list[TokenRecord] = []
        for t in data.get("tokens", []):
            scope = t.get("scope", "mcp")
            # Refuse an off-table scope at load, the same way `Registry.load`
            # refuses a duplicate namespace. The store then never holds a scope
            # the gates cannot ask for; a hand-edited file fails at start.
            _require_scope(scope)
            user_id = t.get("user_id", _ADMIN_ID) if admin_file else t.get("user_id")
            if not isinstance(user_id, str) or _is_admin_file(user_id) != admin_file:
                raise ValueError(
                    f"{path.name}: token {t.get('id')!r} has user_id {user_id!r}, "
                    "which belongs in the other token file"
                )
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
                    user_id=user_id,
                )
            )
        return records

    def load(self) -> None:
        # Reads only; an old file keeps its shape until the next mutator.
        self._records = self._read(self._path, True) + self._read(self._user_path, False)

    def list(self) -> list[TokenRecord]:
        return list(self._records)

    def list_for(self, user_id: str) -> list[TokenRecord]:
        return [r for r in self._records if r.user_id == user_id]

    def create(
        self, name: str, scope: TokenScope, user_id: str, *, exempt: bool = False
    ) -> tuple[TokenRecord, str]:
        """`exempt` skips the cap. Only `AccessPolicy.mint_token`, the owner of
        the admin decision, passes it; the default caps (fail closed, D2)."""
        _require_scope(scope)
        if not isinstance(user_id, str) or not user_id:
            raise ValueError(f"bad user_id {user_id!r}")
        # No `await` before `_commit`, so two concurrent mints cannot both
        # pass the count (D1). `load` never refuses a file above it (D4).
        if not exempt:
            held = sum(1 for r in self._records if r.user_id == user_id)
            if held >= self._max_user_tokens:
                raise ValueError(
                    f"limit: {user_id} holds {held} tokens; "
                    f"MAX_USER_TOKENS is {self._max_user_tokens}"
                )
        token = "mcpflow_" + secrets.token_urlsafe(32)
        record = TokenRecord(
            id="tok_" + secrets.token_hex(4),
            name=name,
            sha256=_sha256_hex(token),
            created_at=datetime.now(UTC),
            last_used_at=None,
            scope=scope,
            user_id=user_id,
        )
        self._commit([*self._records, record], user_id)
        return record, token

    def revoke(self, token_id: str) -> None:
        for record in self._records:
            if record.id == token_id:
                self._commit(
                    [r for r in self._records if r.id != token_id], record.user_id
                )
                return
        raise KeyError(token_id)

    def revoke_user(self, user_id: str) -> None:
        """Remove every record of one user in one write of that user's file."""
        kept = [r for r in self._records if r.user_id != user_id]
        if len(kept) != len(self._records):
            self._commit(kept, user_id)

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
                self._records[i] = replace(record, last_used_at=datetime.now(UTC))
                return self._records[i]
        return None

    def _commit(self, candidate: list[TokenRecord], user_id: str) -> None:
        """Write the file of `user_id` from `candidate`, then adopt it."""
        admin_file = _is_admin_file(user_id)
        path = self._path if admin_file else self._user_path
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
                    "user_id": r.user_id,
                }
                for r in candidate
                if _is_admin_file(r.user_id) == admin_file
            ],
        }
        tmp = path.with_suffix(path.suffix + ".tmp")
        # Create the file already-private (0600); child secrets never sit at
        # 0644 in the write window.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(payload, indent=2))
        os.replace(tmp, path)
        self._records = candidate


class HashedTokenVerifier(TokenVerifier):
    """Bearer verifier that matches a SHA-256 digest against `TokenStore`."""

    def __init__(self, store: TokenStore, identity: IdentityProvider) -> None:
        super().__init__()
        self.store = store
        self.identity = identity

    async def verify_token(self, token: str) -> AccessToken | None:
        # `/mcp` accepts both scopes. The user is resolved on every request,
        # so a removed user's token stops at once. The effective scope rides on
        # the `AccessToken`, so the admin scope filter sees `admin` only for an
        # admin user with an admin token; a demoted user's admin token acts as
        # `mcp`. `/api` keeps its own gate.
        record = self.store.lookup(token, "mcp", "admin")
        if record is None:
            return None
        user = self.identity.get_user(record.user_id)
        if user is None:
            return None
        scope = "admin" if record.scope == "admin" and user.is_admin else "mcp"
        return AccessToken(
            token=token, client_id=record.id, scopes=[scope], subject=user.id
        )


# --- admin bearer gate -------------------------------------------------------


class AdminTokenGate:
    """Pure-ASGI middleware that guards the `/api` sub-app.

    It owns one credential type and one path set, the mirror of `SessionGate`.
    The session cookie never reaches here, and a bearer token never reaches
    the session gate: `/api/` is a public prefix there. A request passes only
    when its bearer token resolves in `TokenStore` with scope `admin` and its
    user, resolved on every request, holds the admin role.
    """

    def __init__(
        self, app: ASGIApp, *, store: TokenStore, identity: IdentityProvider
    ) -> None:
        self.app = app
        self.store = store
        self.identity = identity

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
        user = self._user(headers.get("authorization"))
        if user is None:
            await JSONResponse(
                {"error": "unauthorized"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )(scope, receive, send)
            return
        _set_user(scope, user)
        await self.app(scope, receive, send)

    def _user(self, authorization: str | None) -> User | None:
        token = self._bearer(authorization)
        record = None if token is None else self.store.lookup(token, "admin")
        user = None if record is None else self.identity.get_user(record.user_id)
        return user if user is not None and user.is_admin else None

    @staticmethod
    def _bearer(value: str | None) -> str | None:
        if not value:
            return None
        parts = value.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
            return None
        return parts[1].strip()
