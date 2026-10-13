"""OAuth 2.0 authorization-code sign-in for marketplace entries.

One generic flow serves every vendor. Vendor differences live in data files
under `mcpflow/catalog/providers/` (and admin overrides under
`DATA_DIR/catalog/providers/`), loaded by `ProviderRegistry`. A child's token
file shape lives in one small function in `TOKEN_FORMATS`. The module depends
on `catalog.py` for the `OAuthBlock` type and on `registry.py` for the
`ServerKey` reference shape, and on `identity.py` for the `User` type only
(the opener of a flow); none of these modules imports this one.

Ownership (see `design.md`):

- `ProviderRegistry` owns the provider schema, the two directories, and the
  local-wins-on-id merge.
- `CredStore` is, inside MCP Flow, the only writer and the only deleter of
  `DATA_DIR/creds/<ref>/client.json`, `token.json`, and `refresh.json`,
  where `<ref>` is the server reference (`<ns>` admin-owned, `<ns>@<owner>`
  user-owned). Every method validates the reference with `ServerKey.parse`
  before it builds a path, so no call names a path outside `DATA_DIR/creds/`
  or the directory of another reference. No child is given the path of
  `refresh.json`. It is not the only
  writer on the host: a file sink child that refreshes its own access token
  rewrites the `token.json` MCP Flow gave it, so the store never assumes the
  file is unchanged since it wrote it. The supervisor owns the ordering that
  keeps the file coherent against that second writer. Every write and the
  delete of `refresh.json` (`remove_refresh`) sync the directory, so the
  supervisor's order of the file before the registry header survives a power
  loss.
- `PendingFlows` owns open flows, keyed by a one-shot, short-lived `state`;
  each flow names one server reference.
- `authorize_url` and `token_request` build the two OAuth messages.

The supervisor is the only caller of `write_client`, `write_token`,
`write_refresh`, `remove_refresh`, `CredStore.remove`, and
`PendingFlows.discard`. The web layer calls `create`,
`pop`, `paths`, the read-only `has_token` and `awaiting`, and the URL builders.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import secrets
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlencode

import httpx
from pydantic import (
    BaseModel,
    ConfigDict,
    ValidationError,
    field_validator,
    model_validator,
)

from .catalog import OAuthBlock
from .registry import ServerKey

if TYPE_CHECKING:
    from .identity import User

# Shared with the catalog reason formatter in spirit: one line per fault.
_HTTPS = "https://"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Provider(_Strict):
    id: str
    name: str
    authorize_url: str  # https only
    token_url: str  # https only
    authorize_params: dict[str, str] = {}
    pkce: bool = True
    # A public client has no secret (RFC 8252). The connect and re-authorize
    # forms then ask for no secret, and PKCE is what binds the code instead.
    public_client: bool = False
    scope_separator: str = " "  # how the scopes join in the authorize query
    help: str = ""
    help_url: str = ""

    @field_validator("authorize_url", "token_url")
    @classmethod
    def _check_https(cls, value: str) -> str:
        if not value.startswith(_HTTPS):
            raise ValueError("must use the https scheme")
        return value

    @model_validator(mode="after")
    def _check_public_client(self) -> Provider:
        if self.public_client and not self.pkce:
            raise ValueError("public_client requires pkce true")
        return self


def _reason(exc: BaseException) -> str:
    """One line per fault, with the field name, so a skipped provider file
    reads `token_url: must use the https scheme`."""
    if isinstance(exc, ValidationError):
        parts = []
        for err in exc.errors():
            loc = ".".join(str(p) for p in err.get("loc", ()))
            msg = err.get("msg", "invalid")
            parts.append(f"{loc}: {msg}" if loc else msg)
        return "; ".join(parts)
    return str(exc)


class ProviderRegistry:
    """A loaded snapshot of the two provider directories. Build one with
    `load`. Local wins on id; a bad file is skipped with a reason."""

    def __init__(
        self, providers: dict[str, Provider], skipped: list[tuple[Path, str]]
    ) -> None:
        self._providers = providers
        self.skipped = skipped

    @classmethod
    def load(cls, builtin_dir: Path, local_dir: Path | None) -> ProviderRegistry:
        providers: dict[str, Provider] = {}
        skipped: list[tuple[Path, str]] = []
        for directory in (builtin_dir, local_dir):
            if directory is None or not directory.is_dir():
                continue
            for path in sorted(directory.glob("*.json")):
                try:
                    raw = json.loads(path.read_text(encoding="utf-8"))
                    if not isinstance(raw, dict):
                        raise ValueError("top level must be an object")
                    provider = Provider.model_validate(raw)
                except (OSError, ValueError, ValidationError) as exc:
                    skipped.append((path, _reason(exc)))
                    continue
                providers[provider.id] = provider
        return cls(providers, skipped)

    def get(self, provider_id: str) -> Provider | None:
        return self._providers.get(provider_id)

    def ids(self) -> frozenset[str]:
        return frozenset(self._providers)


@dataclass(frozen=True)
class ClientCreds:
    client_id: str
    client_secret: str


@dataclass(frozen=True)
class CredPaths:
    client: Path
    token: Path


@dataclass(frozen=True)
class HeaderSpec:
    """How a header sink delivers the token: the header name and the scheme.
    `finish_oauth` writes `{name: f"{scheme} {access_token}"}` into the child's
    registry spec."""

    name: str
    scheme: str
    # The provider's token URL for a public client, which `finish_oauth` keeps
    # in `refresh.json` so the supervisor refreshes with no catalog lookup.
    # None for a confidential client: its header sink is never refreshed.
    refresh_token_url: str | None = None


def _write_private(path: Path, text: str) -> None:
    """Write `text` to `path` with mode 0600, replacing it atomically.

    The temporary file is created already-private (0600) in the same
    directory, so no 0644 window ever exposes a secret, and `os.replace` is
    atomic within one directory.
    """
    tmp = path.with_name(path.name + ".tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        # A failed write leaves no stray `.tmp` holding a secret.
        tmp.unlink(missing_ok=True)
        raise
    # Sync the directory too, so the rename itself survives a power loss. The
    # supervisor orders `refresh.json` before the registry header (design D4);
    # without this the order would hold only while the host stays up.
    dfd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


class CredStore:
    """The one owner of `DATA_DIR/creds/<ref>/`.

    Every method takes the server reference, never the namespace alone, so an
    operation on `github@alice` never touches admin-owned `github`.
    """

    def __init__(self, data_dir: Path) -> None:
        self.root = data_dir / "creds"

    def _dir(self, ref: str) -> Path:
        # The shape check runs before any path is built: `ServerKey.parse`
        # admits no `/`, no `.`, and no second `@`, so a traversal in the
        # owner id raises `ValueError` here and touches nothing.
        ServerKey.parse(ref)
        return self.root / ref

    def paths(self, ref: str) -> CredPaths:
        base = self._dir(ref)
        return CredPaths(client=base / "client.json", token=base / "token.json")

    def _ensure_dir(self, ref: str) -> None:
        self._dir(ref).mkdir(parents=True, exist_ok=True, mode=0o700)

    def write_client(self, ref: str, fmt: str, creds: ClientCreds) -> None:
        self._ensure_dir(ref)
        _write_private(self.paths(ref).client, CLIENT_FORMATS[fmt](creds))

    def write_token(self, ref: str, fmt: str, tokens: dict) -> None:
        self._ensure_dir(ref)
        _write_private(self.paths(ref).token, TOKEN_FORMATS[fmt](tokens))

    def has_client(self, ref: str) -> bool:
        return self.paths(ref).client.exists()

    def refresh_path(self, ref: str) -> Path:
        return self._dir(ref) / "refresh.json"

    def write_refresh(self, ref: str, state: dict) -> None:
        """Write `refresh.json`, the grant of a public client header sink.
        `state` is built by `refresh_state`."""
        self._ensure_dir(ref)
        _write_private(self.refresh_path(ref), json.dumps(state))

    def read_refresh(self, ref: str) -> dict | None:
        """The refresh state, or None when the file is absent. Raises
        `ValueError` for a file that is not a JSON object with the refresh
        fields, whose `token_url` is not https (the supervisor would POST a
        refresh token there), or whose `expires_at` is present but not a
        finite number (a `bool` included): a `NaN` would schedule a refresh at
        the 30 s floor forever. Any other `OSError` of the read propagates."""
        try:
            text = self.refresh_path(ref).read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        state = json.loads(text)
        if not isinstance(state, dict) or not all(
            isinstance(state.get(k), str) for k in _REFRESH_KEYS
        ):
            raise ValueError("refresh.json lacks a refresh field")
        if not state["token_url"].startswith(_HTTPS):
            raise ValueError("refresh.json token_url must use the https scheme")
        if "expires_at" in state:
            expires_at = state["expires_at"]
            try:
                # float() raises OverflowError for an int past the float range.
                finite = (
                    not isinstance(expires_at, bool)
                    and isinstance(expires_at, (int, float))
                    and math.isfinite(float(expires_at))
                )
            except OverflowError:
                finite = False
            if not finite:
                raise ValueError("refresh.json expires_at must be a finite number")
        return state

    def remove_refresh(self, ref: str) -> None:
        """Delete `refresh.json`, then sync its directory (design D13), so a
        power loss cannot bring back an old grant's file that the startup
        reconcile would then write into the header."""
        path = self.refresh_path(ref)
        path.unlink(missing_ok=True)
        if path.parent.is_dir():
            dfd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)

    def refs(self) -> list[str]:
        """The server references that hold a credential directory. A
        directory whose name is not a reference is skipped: no method of this
        store may build a path from it."""
        if not self.root.is_dir():
            return []
        out = []
        for p in self.root.iterdir():
            if not p.is_dir():
                continue
            try:
                ServerKey.parse(p.name)
            except ValueError:
                continue
            out.append(p.name)
        return out

    def has_token(self, ref: str) -> bool:
        return self.paths(ref).token.exists()

    def awaiting(self, ref: str) -> bool:
        return self.has_client(ref) and not self.has_token(ref)

    def remove(self, ref: str) -> None:
        """Delete the directory of `ref` only. No-op when it is absent."""
        shutil.rmtree(self._dir(ref), ignore_errors=True)


# The account id the Calendar child reads its token map by. `getAccountMode`
# returns this literal with `GOOGLE_ACCOUNT_MODE` unset and `NODE_ENV` not
# `test`, and the child's read path is `multiAccountTokens[this.accountMode]`.
# It is a fact about one child, so it lives beside the format that needs it.
GCAL_ACCOUNT_MODE = "normal"


def _google_client(creds: ClientCreds) -> str:
    # The Gmail child accepts `web` or `installed`; `web` is the correct type
    # for a redirect to a public URL.
    return json.dumps(
        {"web": {"client_id": creds.client_id, "client_secret": creds.client_secret}}
    )


def _google_client_flat(creds: ClientCreds) -> str:
    # The Calendar child's loader tests `keys.installed`, then the two fields
    # at the top level, and has no `web` branch at all, so `_google_client`
    # fails it at start. The `installed` branch returns `redirect_uris`
    # unchanged and its caller reads `redirect_uris[0]`, so an `installed`
    # object without that key is a TypeError; the top-level branch defaults
    # the value itself, which is the one shape needing no field MCP Flow
    # cannot honestly supply.
    return json.dumps(
        {"client_id": creds.client_id, "client_secret": creds.client_secret}
    )


class OAuthTokenError(ValueError):
    """A token response that cannot become a child's credential file. Raised by
    a `TOKEN_FORMATS` builder, caught in the OAuth callback before any
    credential is written, and shown to the admin. A `ValueError` subclass, so
    a caller that already catches `ValueError` still catches it, while the
    callback catches the specific type."""


def _expires_in_seconds(tokens: dict) -> int | None:
    """The one conversion of a token response's `expires_in`.

    Two faults, not one. `expires_in` absent or JSON null means the provider
    gave no expiry: a non-expiring token is a valid response, so the caller
    omits its expiry field rather than guess one. A present-but-unparseable
    value is malformed, so refuse it. The absent test is `is None`, not
    truthiness, so an integer `0` is a valid zero-second expiry, not an
    omission. `int` keeps a numeric string like "3600", which some providers
    send and the child accepts.
    """
    raw = tokens.get("expires_in")
    if raw is None:
        return None
    try:
        return int(raw)
    except (ValueError, TypeError, OverflowError):
        # OverflowError: JSON `1e400` parses to float inf, and int(inf)
        # overflows. A non-integer, an infinity, and a mangled string are
        # all one fault here: a value MCP Flow cannot turn into an expiry.
        raise OAuthTokenError(
            "the token response has a non-numeric expires_in"
        ) from None


def _google_credentials(tokens: dict) -> dict:
    # The `google-auth-library` credentials object: `expires_in` becomes
    # `expiry_date`, the epoch time in milliseconds the access token expires.
    # A response without `refresh_token` is written as is.
    #
    # Two formats below lay this object out two ways. Neither repeats the
    # conversion: it reads the clock, so a second copy drifts invisibly.
    out = {
        k: tokens[k]
        for k in ("access_token", "refresh_token", "scope", "token_type")
        if k in tokens
    }
    seconds = _expires_in_seconds(tokens)
    if seconds is not None:
        out["expiry_date"] = int(time.time() * 1000) + seconds * 1000
    return out


def check_token_response(
    token_fmt: str | None, tokens: dict, *, refresh: bool = False
) -> None:
    """Raise `OAuthTokenError` when `tokens` cannot become the child's token
    file. A file sink builds the file in `token_fmt` and discards it; a raise
    means the response is unusable. A header sink (`token_fmt` None) builds no
    file and passes, unless `refresh` is true (a public client header sink):
    then `finish_oauth` writes `refresh.json`, so its `expires_in` is checked
    the same way, and a `refresh_token` that is present must be a non-empty
    string. The callback calls this before it dispatches to
    `finish_oauth`, so a malformed response is refused before any credential is
    written or any child is torn down."""
    if token_fmt is not None:
        TOKEN_FORMATS[token_fmt](tokens)
    if refresh:
        _expires_in_seconds(tokens)
        rt = tokens.get("refresh_token")
        if rt is not None and (not isinstance(rt, str) or not rt):
            raise OAuthTokenError("the token response has a malformed refresh_token")


# The fields `refresh.json` must hold as strings. `expires_at` is optional: a
# response without `expires_in` schedules no refresh. `header_name` and
# `header_scheme` let `startup` and the refresh task rebuild the header with no
# catalog lookup.
_REFRESH_KEYS = (
    "client_id",
    "token_url",
    "access_token",
    "refresh_token",
    "header_name",
    "header_scheme",
)


def refresh_state(
    client_id: str,
    token_url: str,
    header: HeaderSpec,
    tokens: dict,
    prior_refresh_token: str | None = None,
) -> dict:
    """The serializer of `refresh.json`. Not a `TOKEN_FORMATS` entry: no
    child reads this file. A response without `refresh_token` keeps
    `prior_refresh_token`. `expires_at` (epoch seconds) comes from the shared
    `expires_in` conversion and is absent when the response has no expiry."""
    refresh_token = tokens.get("refresh_token") or prior_refresh_token
    if not isinstance(refresh_token, str) or not refresh_token:
        raise OAuthTokenError("the token response has a malformed refresh_token")
    state = {
        "client_id": client_id,
        "token_url": token_url,
        "access_token": tokens["access_token"],
        "refresh_token": refresh_token,
        "header_name": header.name,
        "header_scheme": header.scheme,
    }
    seconds = _expires_in_seconds(tokens)
    if seconds is not None:
        state["expires_at"] = int(time.time()) + seconds
    return state


def _google_auth_library(tokens: dict) -> str:
    return json.dumps(_google_credentials(tokens))


def _google_calendar(tokens: dict) -> str:
    # The same object as one entry of the child's account map. The child also
    # accepts the flat shape, but only through a migration branch that rewrites
    # the file at the first read; this shape is what its steady-state read path
    # wants, and it leaves the file untouched.
    return json.dumps({GCAL_ACCOUNT_MODE: _google_credentials(tokens)})


CLIENT_FORMATS: dict[str, Callable[[ClientCreds], str]] = {
    "google-client": _google_client,
    "google-client-flat": _google_client_flat,
}
TOKEN_FORMATS: dict[str, Callable[[dict], str]] = {
    "google-auth-library": _google_auth_library,
    "google-calendar": _google_calendar,
}


@dataclass(frozen=True)
class PendingFlow:
    state: str
    ref: str  # the server reference, `<ns>` or `<ns>@<owner>`
    entry_id: str
    client: ClientCreds  # in memory only, for the token exchange
    code_verifier: str
    created: float
    # The snapshot of the admin who opened the flow. `finish_oauth` checks
    # it at the write, so a flow never outlives its opener's right.
    actor: User
    reauth: bool = False  # a re-authorization of an existing child


class PendingFlows:
    """Open flows in memory, keyed by a random `state`. A restart drops them."""

    def __init__(self, ttl: float = 600.0) -> None:
        self.ttl = ttl
        self._flows: dict[str, PendingFlow] = {}
        # States whose token exchange is in flight. A concurrent duplicate
        # callback for the same state is rejected before it POSTs a second
        # time, so one `state` drives at most one token exchange (the model's
        # `exchanging` guard). Marks are set and cleared with no await between,
        # so they are atomic on the event loop.
        self._exchanging: set[str] = set()

    def _sweep(self) -> None:
        # Evict every expired flow, so an abandoned flow's ClientCreds leave
        # memory at the next flow operation, not only on its own pop. A flow
        # the admin never returns to would otherwise hold the secret until a
        # process restart.
        cutoff = time.time() - self.ttl
        for state in [s for s, f in self._flows.items() if f.created <= cutoff]:
            del self._flows[state]

    def create(
        self,
        ref: str,
        entry_id: str,
        client: ClientCreds,
        actor: User,
        *,
        reauth: bool = False,
    ) -> PendingFlow:
        self._sweep()
        flow = PendingFlow(
            state=secrets.token_urlsafe(32),
            ref=ref,
            entry_id=entry_id,
            client=client,
            code_verifier=secrets.token_urlsafe(64),
            created=time.time(),
            actor=actor,
            reauth=reauth,
        )
        self._flows[flow.state] = flow
        return flow

    def has_open(self, ref: str) -> bool:
        # True when a non-expired flow of the reference exists. The re-auth
        # route uses it to refuse a second re-authorization while one is open,
        # so one reference has at most one flow in flight. An exact match: the
        # flow of `github` is not a flow of `github@alice`.
        self._sweep()
        return any(f.ref == ref for f in self._flows.values())

    def peek(self, state: str) -> PendingFlow | None:
        # Non-consuming: the callback validates the state before the token
        # exchange await without spending the one-shot. `finish_oauth` does
        # the consuming `pop` under the child lock.
        self._sweep()
        return self._flows.get(state)

    def pop(self, state: str) -> PendingFlow | None:
        # One-shot: the entry is removed on the first read, so a replayed
        # callback gets nothing. An expired flow is removed and treated as
        # absent.
        self._sweep()
        return self._flows.pop(state, None)

    def begin_exchange(self, state: str) -> bool:
        # True when this call marks the exchange in flight; False when another
        # callback already did. The caller ends it on every exit path.
        if state in self._exchanging:
            return False
        self._exchanging.add(state)
        return True

    def end_exchange(self, state: str) -> None:
        self._exchanging.discard(state)

    def discard(self, ref: str) -> None:
        # The flows of this reference only; the same namespace under another
        # owner keeps its flow.
        for state in [s for s, f in self._flows.items() if f.ref == ref]:
            del self._flows[state]
            self._exchanging.discard(state)


def _pkce_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# The callback query parameters that carry a credential: the one-shot
# authorization code, and the `state` that names the open flow. The gateway's
# access-log filter masks their values (`gateway._AccessQueryMask`).
CALLBACK_SECRET_PARAMS = frozenset({"code", "state"})


def authorize_url(
    provider: Provider, block: OAuthBlock, redirect_uri: str, flow: PendingFlow
) -> str:
    """The provider's authorize URL with the consent query. `client_id` comes
    from the flow; `scope` is the entry's scopes joined by the provider's scope
    separator (a space by default; a comma for vendors like Linear)."""
    params: dict[str, str] = {
        "response_type": "code",
        "client_id": flow.client.client_id,
        "redirect_uri": redirect_uri,
        "scope": provider.scope_separator.join(block.scopes),
        "state": flow.state,
        **provider.authorize_params,
    }
    if provider.pkce:
        params["code_challenge"] = _pkce_challenge(flow.code_verifier)
        params["code_challenge_method"] = "S256"
    return f"{provider.authorize_url}?{urlencode(params)}"


def token_request(
    provider: Provider, redirect_uri: str, code: str, flow: PendingFlow
) -> tuple[str, dict[str, str]]:
    """The token endpoint URL and the form body. The client secret comes from
    the flow, never from disk."""
    body: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": flow.client.client_id,
    }
    # A public client has no secret; an empty field would read as a wrong one.
    if flow.client.client_secret:
        body["client_secret"] = flow.client.client_secret
    if provider.pkce:
        body["code_verifier"] = flow.code_verifier
    return provider.token_url, body


def refresh_request(state: dict) -> tuple[str, dict[str, str]]:
    """The refresh POST of a public client, from `refresh.json` alone. No
    `client_secret`: only a public client has a refresh file."""
    return state["token_url"], {
        "grant_type": "refresh_token",
        "refresh_token": state["refresh_token"],
        "client_id": state["client_id"],
    }


def http_client() -> httpx.AsyncClient:
    """The HTTP client the callback uses for the token exchange. A module-level
    factory so a test can `monkeypatch` it. Not a frozen name."""
    return httpx.AsyncClient(timeout=15.0)
