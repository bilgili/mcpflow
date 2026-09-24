"""The persisted list of child MCP servers.

`Registry` owns `DATA_DIR/servers.json`. Every mutator validates, builds a
candidate state, writes the file atomically, and only then adopts the
candidate in memory. A failed write therefore leaves the file and the memory
equal, so no caller can act on a state that was never persisted.
"""

from __future__ import annotations

import json
import math
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from urllib.parse import unquote, unquote_plus, urlsplit, urlunsplit

import httpx
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

Kind = Literal["python", "npm", "remote", "custom"]

_NAMESPACE_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")

# The built-in admin server mounts under `mcpflow`, publishing its tools as
# `mcpflow_<tool>`. Reserve the namespace and the `mcpflow_` prefix so no child tool
# name `<namespace>_<tool>` can collide with, and shadow, an admin tool name.
RESERVED_NAMESPACE = "mcpflow"

# The two admin tools that visibility never hides. A mute of the `mcpflow`
# namespace hides every other `mcpflow_*` tool, so without these two an `admin`
# session could not reverse its own mute over MCP. The names are bare admin
# tool names; the gateway publishes them as `mcpflow_set_namespace_muted` and
# `mcpflow_set_tool_muted`.
PINNED_ADMIN_TOOLS: tuple[str, ...] = ("set_namespace_muted", "set_tool_muted")

# Redact the user information in a source URL for every admin-facing view. The
# raw value stays in `servers.json` (mode 0600), the only store of the
# credential.
_USERINFO_RE = re.compile(r"^([a-z0-9+.-]+://)[^/]*@")


def redact_source(source: str | None) -> str | None:
    """Replace the user information of a source URL with `***`.

    `git+https://oauth2:TOKEN@host/o/r` becomes `git+https://***@host/o/r`. A
    `@ref` after the path is not user information and stays. A `github:` or an
    absolute-path source has no scheme and is unchanged.
    """
    if source is None:
        return None
    return _USERINFO_RE.sub(r"\1***@", source, count=1)


def _with_decoded(values: list[str], *decoders) -> list[str]:
    """Each value, followed by every decoded form of it that differs."""
    out: list[str] = []
    for value in values:
        out.append(value)
        for decode in decoders:
            decoded = decode(value)
            if decoded not in out:
                out.append(decoded)
    return out


def _unparsed_secrets(url: str) -> list[str]:
    """The secrets of a URL that `urlsplit` rejects, cut by hand.

    Best effort, for a legacy record only: `_refuse_unparseable` keeps a new
    one out of the registry, since no hand cut tracks every shape `urlsplit`
    normalizes (a scheme-relative URL, a deleted newline).

    `urlsplit` raises on some netlocs (NFKC normalization) and its error text
    echoes the netloc, not the whole URL, so the whole string alone does not
    mask it. Register the whole string, the authority (scheme to the first
    `/`, `?`, or `#`), and its user information and password.
    """
    authority = re.split(r"[/?#]", url.partition("://")[2] or url, maxsplit=1)[0]
    out = [url, authority]
    if "@" in authority:
        userinfo = authority.rsplit("@", 1)[0]
        out.append(userinfo)
        if ":" in userinfo:
            out.append(userinfo.split(":", 1)[1])
    return [v for v in out if v]


def source_secrets(source: str | None) -> list[str]:
    """The credential strings to mask from diagnostics for a source URL.

    A source `scheme://user:pass@host/path` carries a credential in its
    user-information substring. Returns that substring and its password
    component (the part after the first `:`), so a diagnostic that echoes the
    whole source or the bare password is masked. The user information only,
    never the whole source, so a failed source stays readable as
    `scheme://•••@host/path` rather than masking the host and path too.

    Returns `[]` for `None`, a source with no scheme (`github:o/r`, an absolute
    path), or one with no user information. The single owner of extracting a
    source credential; `Supervisor._secrets_of` feeds the result to
    `scrub_secrets`, which drops any substring under its length floor.

    `urlsplit` bounds the user information to the URL authority, so a `@` later
    in a query or fragment does not stretch the extracted credential past the
    host. It also covers only the documented credential form — the user
    information before the `@` — not a credential smuggled into a path segment
    or a query parameter, the same boundary `redact_source` draws.
    """
    if source is None:
        return []
    try:
        netloc = urlsplit(source).netloc
    except ValueError:
        return _unparsed_secrets(source)
    if "@" not in netloc:
        return []
    userinfo = netloc.rsplit("@", 1)[0]
    if not userinfo:
        return []
    secrets = [userinfo]
    if ":" in userinfo:
        secrets.append(userinfo.split(":", 1)[1])
    # A diagnostic can echo the credential percent-decoded
    # (`pass%40word` -> `pass@word`); register that form too.
    return _with_decoded(secrets, unquote)


# The mask every admin-facing view shows in place of a secret value. `catalog`
# (the marketplace preview) and `supervisor` (the diagnostic scrub) import it,
# so one string means "hidden" on every surface and `Registry.update` can
# recognise an echo of it.
SECRET_MASK = "•••"


def redact_secrets(mapping: dict[str, str]) -> dict[str, str]:
    """Hide every non-empty value of an `env`/`headers` map behind the mask.

    Every value, not only keys that look secret: a name heuristic misses a real
    credential name, and a miss is a leak. An empty value holds nothing and
    stays, so a reader can still tell "set" from "unset".
    """
    return {k: (SECRET_MASK if v else v) for k, v in mapping.items()}


def _query_values(query: str) -> list[str]:
    """Every non-empty query value, under both parsings a server may use.

    `&` separates pairs, and a value runs to the next `&` (so
    `api_key=;tok` has the value `;tok`, which `redact_url` masks whole). A
    legacy parser also splits on `;`, so each `;` piece of a value is
    registered too: `region=eu;api_key=tok` yields `eu;api_key=tok`, `eu`, and
    `tok`.
    """
    values = []
    for pair in query.split("&"):
        _, sep, value = pair.partition("=")
        if not (sep and value):
            continue
        values.append(value)
        if ";" in value:
            # The first piece is already a value (it can end in `=` base64
            # padding); each later piece is a `key=value` pair of its own.
            first, *rest = value.split(";")
            pieces = [first] + [p.partition("=")[2] if "=" in p else p for p in rest]
            values.extend(p for p in pieces if p)
    return values


def _mask_query_pair(pair: str) -> str:
    key, sep, value = pair.partition("=")
    return f"{key}={SECRET_MASK}" if sep and value else pair


def redact_url(url: str | None) -> str | None:
    """Mask the user information and every non-empty query value of a URL.

    `https://u:pw@host/mcp?api_key=k&flag` becomes
    `https://•••@host/mcp?api_key=•••&flag`. Scheme, host, path, query keys,
    and fragment stay, so the endpoint is readable. The query is rebuilt by
    hand, not with `urlencode`, so the mask stays literal and `_refuse_mask`
    finds it in an echo. A URL with nothing to mask comes back unchanged. The
    path is not masked (a known limit, see the redact-registry-secrets design).

    A URL `urlsplit` rejects comes back as the bare mask. An outward view must
    never raise: the `urlsplit` error echoes the netloc, credential included,
    and an error page that renders a refused URL would log it (codex round 4).
    """
    if url is None:
        return None
    if not _parses(url):
        return SECRET_MASK
    parts = urlsplit(url)
    netloc = parts.netloc
    if "@" in netloc:
        netloc = f"{SECRET_MASK}@{netloc.rsplit('@', 1)[1]}"
    # Split on `&` only and mask each whole value, `;` tail included: the
    # conservative reading, so no parser sees an unmasked credential.
    query = "&".join(_mask_query_pair(p) for p in parts.query.split("&"))
    if netloc == parts.netloc and query == parts.query:
        return url
    return urlunsplit(parts._replace(netloc=netloc, query=query))


def url_secrets(url: str | None) -> list[str]:
    """The credential strings of a URL, for the diagnostic scrub.

    The user information via `source_secrets` (which owns that shape and its
    decoded forms) plus each non-empty query value raw, percent-decoded, and
    form-decoded (`+` as a space), because an HTTP error can echo any of them.
    The same parts `redact_url` masks. Both again from the URL as `httpx`
    normalizes it (a space is `%20`, `ä` is `%C3%A4`), because `httpx` and the
    SDK transports log that form. A URL `urlsplit` rejects goes through
    `_unparsed_secrets`, and still gets its `httpx` form, which can parse.
    """
    if url is None:
        return []
    try:
        values = _query_values(urlsplit(url).query)
        out = [*source_secrets(url), *_with_decoded(values, unquote, unquote_plus)]
    except ValueError:
        out = _unparsed_secrets(url)
    try:
        sent = str(httpx.URL(url))
    except httpx.InvalidURL:
        # httpx cannot send to this URL, so it never logs it.
        return out
    if sent != url:
        out += [*source_secrets(sent), *_query_values(urlsplit(sent).query)]
    return out


def redact_spec(spec: ServerSpec) -> ServerSpec:
    """The outward view of a stored record: a copy with every credential masked.

    The single owner of what an admin-facing surface may show. `api.child_json`
    (REST and every admin MCP tool) and the web server window build from it;
    only `Registry.get` hands the raw record to the supervisor, which launches
    the child. `Registry.update` reverses the mask on an echo.
    """
    return spec.model_copy(
        update={
            "source": redact_source(spec.source),
            "url": redact_url(spec.url),
            "env": redact_secrets(spec.env),
            "headers": redact_secrets(spec.headers),
        }
    )


def _keep_echoed(incoming: dict[str, str], stored: dict[str, str]) -> dict[str, str]:
    """Merge one secret map for `update`: an incoming mask for a stored key keeps
    the stored value; anything else is adopted. A key absent from `incoming` is
    dropped, the full-replacement rule `update` uses for every field.
    """
    return {
        k: (stored[k] if v == SECRET_MASK and k in stored else v)
        for k, v in incoming.items()
    }


def _parses(url: str) -> bool:
    """`urlsplit` takes it whole: no control character (which `urlsplit`
    silently deletes, so the parsed form no longer matches the raw one) and no
    netloc it rejects (NFKC normalization)."""
    if any(ord(c) < 32 or ord(c) == 127 for c in url):
        return False
    try:
        urlsplit(url)
    except ValueError:
        return False
    return True


def _refuse_unparseable(spec: ServerSpec) -> None:
    """Refuse a `url` or `source` the secret extractors cannot cut.

    `url_secrets` and `source_secrets` find a credential by parsing. A URL that
    `urlsplit` rejects raises an error that echoes the netloc, and a hand-cut
    fallback cannot track every shape `urlsplit` normalizes (codex rounds 2 and
    3). Refusing at the write boundary keeps such a record out of the registry,
    so it never starts and never logs. The message names the field only, never
    the value. `load` does not call this, so a legacy record still loads.
    """
    if spec.url is not None:
        parts = urlsplit(spec.url) if _parses(spec.url) else None
        # `hostname`, not `netloc`: user information alone makes the netloc
        # of `https://u:pw@/mcp` non-empty.
        ok = parts is not None and parts.scheme in ("http", "https") and parts.hostname
        if ok:
            try:
                httpx.URL(spec.url)
            except httpx.InvalidURL:
                ok = False
        if not ok:
            raise RegistryError("url: not a valid http(s) URL")
    if spec.source is not None and not _parses(spec.source):
        raise RegistryError("source: not a valid URL")


def _refuse_mask(spec: ServerSpec) -> None:
    """Refuse a record that still holds a mask after the merge.

    An echo the merge could not resolve (a masked value under a new key, a
    clone of a read record, `Bearer •••`, a URL edit that kept a masked query)
    would persist the mask as the credential and lose the real one. "Contains",
    not "equals", so a prefixed mask is caught too. The message names the field
    and key, never a value. An unparseable `url` or `source` is refused first:
    the `urlsplit` below would otherwise raise with the netloc in its text.
    """
    _refuse_unparseable(spec)
    for field in ("env", "headers"):
        for key, value in getattr(spec, field).items():
            if SECRET_MASK in value:
                raise RegistryError(
                    f"{field}: {key} holds the mask {SECRET_MASK}; "
                    "send the real value"
                )
    # Decode first: a client may percent-encode the mask in any letter case.
    if spec.url is not None and SECRET_MASK in unquote(spec.url):
        raise RegistryError(
            f"url: holds the mask {SECRET_MASK}; send the full url"
        )
    if spec.source is not None:
        netloc = urlsplit(spec.source).netloc
        if "@" in netloc and unquote(netloc.rsplit("@", 1)[0]) == "***":
            raise RegistryError(
                "source: holds the redacted credential ***; send the full source"
            )


_SOURCE_PREFIXES = ("git+https://", "https://", "github:", "/")


def validate_source(kind: str, source: str | None) -> str | None:
    """The one source rule: the kind restriction, the prefix, the empty case.

    A free function so every module that accepts a source calls the same rule
    instead of holding a copy, the way `validate_namespace` already works for
    a namespace. `ServerSpec` calls it; the catalog's `SpecTemplate` calls it
    at load time, so a bad file is a skipped entry with a reason rather than a
    connect that fails later.

    Returns the stripped source, or `None` for absent. A shape check only: it
    never contacts the source, because `uvx` and `npx` report a bad one at the
    child's first start.
    """
    if source is None:
        return None
    source = source.strip()
    if not source:
        # The form posts an empty field for a blank input; store one value for
        # "no source" so the registry never holds "". An empty source on any
        # kind is absent, not a fault, so the kind check comes after this.
        return None
    if kind not in ("python", "npm"):
        raise ValueError("source is allowed only for kind python or npm")
    if not source.startswith(_SOURCE_PREFIXES):
        raise ValueError(
            "source must start with git+https://, https://, github:, or /"
        )
    return source


def build_command(
    kind: str,
    package: str | None,
    args: list[str],
    command: str | None,
    source: str | None,
) -> tuple[str, list[str]]:
    """The one answer to "what does this spec run as".

    The supervisor starts a child with it and the marketplace detail shows it,
    so the two can never disagree. `--from` and `--package=` come before the
    package so `uvx` and `npx` read them as their own flags.

    Callers pass keyword arguments: `package`, `command`, and `source` are all
    `str | None`, so a positional swap would be silent.

    `remote` is not a kind here. A remote child has a URL and a transport, not
    an argument list, and both callers branch on it before they arrive. The
    raise is a programmer guard, not an admin-facing fault, so it is a plain
    `ValueError` and no caller maps it.
    """
    if kind == "python":
        if source:
            return "uvx", ["--from", source, package, *args]
        return "uvx", [package, *args]
    if kind == "npm":
        if source:
            return "npx", ["-y", f"--package={source}", package, *args]
        return "npx", ["-y", package, *args]
    if kind == "custom":
        return command, list(args)
    raise ValueError(f"build_command does not build a command for kind {kind}")


def spec_command(spec, args: list[str] | None = None) -> str:
    """The one-line command a spec runs as, with the source redacted.

    The view adapter over `build_command`: that function owns the rule, this
    joins the result for a page and hides the credential a source may carry.
    A `remote` spec has no argument list, so it never reaches `build_command`.

    `spec` is duck-typed over the command fields `kind`, `package`, `args`,
    `command`, `source`, `url`, and `transport`: a `ServerSpec` or the
    catalog's `SpecTemplate`. The registry cannot import the catalog, so the
    parameter carries no annotation.

    `args` overrides `spec.args` when given, so the marketplace preview and the
    command line show the same arguments.
    """
    shown = list(spec.args) if args is None else list(args)
    if spec.kind == "remote":
        return f"{spec.transport.upper()} {redact_url(spec.url)}"
    command, argv = build_command(
        kind=spec.kind,
        package=spec.package or "",
        args=shown,
        command=spec.command or "",
        source=redact_source(spec.source),
    )
    return " ".join([command, *argv]).strip()


class RegistryError(ValueError):
    """Raised on a duplicate namespace or an invalid spec. Names the field."""


def validate_namespace(value: str) -> str:
    """The one namespace rule: the shape and the reserved prefix.

    `ServerSpec` and the marketplace catalog (an entry id is the default
    namespace) both call this, so the rule that keeps a child tool from
    shadowing an admin tool has one owner. Raises `ValueError`.
    """
    if not _NAMESPACE_RE.match(value):
        raise ValueError("namespace must match ^[a-z][a-z0-9_]{0,31}$")
    if value == RESERVED_NAMESPACE or value.startswith(RESERVED_NAMESPACE + "_"):
        raise ValueError(
            f"namespace {value} is reserved: mcpflow and mcpflow_* are reserved"
        )
    return value


class ServerSpec(BaseModel):
    namespace: str
    kind: Kind
    package: str | None = None
    args: list[str] = Field(default_factory=list)
    url: str | None = None
    transport: Literal["http", "sse"] = "http"
    headers: dict[str, str] = Field(default_factory=dict)
    command: str | None = None
    env: dict[str, str] = Field(default_factory=dict)
    enabled: bool = True
    muted: bool = False
    disabled_tools: list[str] = Field(default_factory=list)
    description: str = ""
    # Seconds the proxy serves lookups by name from its cached component
    # lists. `None` inherits `Settings.child_cache_ttl`. `0` disables the
    # cache. Caller-owned: `Registry.update` does not re-merge it.
    cache_ttl: float | None = None
    # True marks this child action-capable: mcpflow honors its
    # `_meta["mcpflow"]["action"]` tags. Default False, so actions are opt-in
    # per child. Registry-owned, NOT caller-owned: `Registry.update` re-merges
    # it, so an edit save that omits it keeps the grant and a caller partial
    # dict cannot self-grant capability (child-actions-page F2 revised).
    actions: bool = False
    source: str | None = None
    # The marketplace entry id this child came from. Free text: the registry
    # never checks it against the catalog, so a deleted local entry leaves a
    # harmless tag. `None` for a child added by hand.
    catalog: str | None = None
    # A header-sink oauth child that is registered but not yet signed in: the
    # callback has not set its Authorization header. It is cleared only by
    # `set_oauth_header`, which writes the header and clears this flag in one
    # atomic write; plain `update` preserves it (remote-oauth).
    oauth_pending: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("namespace")
    @classmethod
    def _check_namespace(cls, value: str) -> str:
        return validate_namespace(value)

    @field_validator("cache_ttl")
    @classmethod
    def _check_cache_ttl(cls, value: float | None) -> float | None:
        if value is not None and not (math.isfinite(value) and value >= 0):
            raise ValueError("cache_ttl must be a finite number >= 0")
        return value

    @model_validator(mode="after")
    def _check_kind_fields(self) -> ServerSpec:
        if self.kind in ("python", "npm") and not self.package:
            raise ValueError(f"package is required for kind {self.kind}")
        if self.kind == "remote" and not self.url:
            raise ValueError("url is required for kind remote")
        if self.kind == "custom" and not self.command:
            raise ValueError("command is required for kind custom")
        self.source = validate_source(self.kind, self.source)
        return self


class Registry:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._specs: list[ServerSpec] = []
        # Set before any load: a mutator can run before `load` on a fresh dir.
        self._root_muted = False
        # The visibility state of the built-in admin server. It has no
        # `ServerSpec`, so it cannot live in `_specs`.
        self._admin_muted = False
        self._admin_disabled_tools: list[str] = []

    def load(self) -> None:
        if not self._path.exists():
            self._specs = []
            self._root_muted = False
            self._admin_muted = False
            self._admin_disabled_tools = []
            return
        data = json.loads(self._path.read_text())
        self._root_muted = bool(data.get("muted", False))
        # A file written before the admin object existed loads as "nothing
        # muted", which is the behaviour that file had.
        admin = data.get("admin") or {}
        self._admin_muted = bool(admin.get("muted", False))
        self._admin_disabled_tools = [str(t) for t in admin.get("disabled_tools", [])]
        specs = [ServerSpec(**s) for s in data.get("servers", [])]
        seen: set[str] = set()
        for spec in specs:
            if spec.namespace in seen:
                raise RegistryError(f"namespace {spec.namespace} already exists")
            seen.add(spec.namespace)
        self._specs = specs

    def list(self) -> list[ServerSpec]:
        return list(self._specs)

    def get(self, namespace: str) -> ServerSpec:
        for spec in self._specs:
            if spec.namespace == namespace:
                return spec
        raise KeyError(namespace)

    def _commit(
        self,
        specs: list[ServerSpec],
        root_muted: bool | None = None,
        admin: tuple[bool, list[str]] | None = None,
    ) -> None:
        """Persist a candidate state, then adopt it in memory.

        Every mutator goes through here. Persist-then-adopt, never the other
        way round: if the write raises, memory still equals the file, and the
        caller's own exception stops the supervisor before it applies the
        change to a live transform. Adopting first would leave three views of
        the policy - file, memory, live transform - disagreeing.

        The admin state travels as a third candidate field. Every mutator
        rewrites the whole file, so a mutator that dropped it here would erase
        the built-in policy from disk on the next unrelated child change.
        """
        root = self._root_muted if root_muted is None else root_muted
        admin_muted, admin_tools = (
            (self._admin_muted, self._admin_disabled_tools) if admin is None else admin
        )
        self._write(specs, root, admin_muted, admin_tools)
        self._specs = specs
        self._root_muted = root
        self._admin_muted = admin_muted
        self._admin_disabled_tools = admin_tools

    def add(self, spec: ServerSpec) -> None:
        if any(s.namespace == spec.namespace for s in self._specs):
            raise RegistryError(f"namespace {spec.namespace} already exists")
        # A new record has no stored value to echo against, so any mask here
        # is a clone of a read record and would persist as the credential.
        _refuse_mask(spec)
        self._commit([*self._specs, spec])

    def update(self, spec: ServerSpec) -> None:
        merged = self.merge(spec)
        i = self._index(spec.namespace)
        self._commit([*self._specs[:i], merged, *self._specs[i + 1 :]])

    def merge(self, spec: ServerSpec) -> ServerSpec:
        """The record `update(spec)` would store, validated, without storing it.

        Pure: raises exactly what `update` raises before its write, and writes
        nothing. The supervisor reads the merged secret set here, so it can
        discard derived state that the new record cannot scrub (the child log)
        BEFORE the record is persisted.
        """
        existing = self._specs[self._index(spec.namespace)]
        # The web form builds a fresh spec and carries neither the visibility
        # state nor the creation time. Merge here, in the one owner, so no
        # caller has to remember to preserve them.
        # An API client cannot see the raw source: GET returns the redacted
        # form. When the incoming source equals the redacted stored value, the
        # client is echoing GET back to PUT, so keep the stored credential. A
        # new credential differs from the redacted form and is adopted. A
        # source with no user information is its own redacted form, so the rule
        # is a no-op for it.
        source = spec.source
        if source is not None and source == redact_source(existing.source):
            source = existing.source
        # `env`, `headers`, and `url` follow the same echo rule: a read returns
        # `redact_spec`, so an incoming mask means the client never saw the
        # secret and the stored value is kept. `env`/`headers` merge per key.
        url = spec.url
        if url is not None and url == redact_url(existing.url):
            url = existing.url
        # `catalog` is provenance, the same as `created_at`: the marketplace
        # sets it once at connect and no caller may change or drop it.
        # `oauth_pending` is registry-owned, the same as visibility: a form or
        # API edit that omits it must not clear it and bypass the enable guard.
        # `set_oauth_header` is the one path that clears it (at OAuth completion).
        merged = spec.model_copy(
            update={
                "muted": existing.muted,
                "disabled_tools": list(existing.disabled_tools),
                "created_at": existing.created_at,
                "source": source,
                "catalog": existing.catalog,
                "oauth_pending": existing.oauth_pending,
                # `actions` is a trust grant, registry-owned like `catalog` and
                # `oauth_pending`. An edit save that omits it keeps the grant,
                # and a caller partial dict cannot self-grant it. Only a
                # create-time write or a catalog connect sets it (F2 revised).
                "actions": existing.actions,
                "url": url,
                "env": _keep_echoed(spec.env, existing.env),
                "headers": _keep_echoed(spec.headers, existing.headers),
            }
        )
        # After the merge, no mask may remain: it would persist as the
        # credential and lose the real one.
        _refuse_mask(merged)
        return merged

    def set_oauth_header(self, namespace: str, name: str, value: str) -> None:
        """Set the child's `name` header to `value` and clear `oauth_pending`
        in one atomic write.

        The one path that writes a header sink's token: the OAuth callback via
        `finish_oauth`. It flips the token and the awaiting flag together in one
        `servers.json` write, so they are never inconsistent. `update` preserves
        `oauth_pending` for every other edit; only this method clears it.
        """
        i = self._index(namespace)
        existing = self._specs[i]
        headers = dict(existing.headers)
        headers[name] = value
        updated = existing.model_copy(
            update={"headers": headers, "oauth_pending": False}
        )
        # A token response that carries the mask would persist it as the
        # credential; the no-mask rule holds for this writer too.
        _refuse_mask(updated)
        self._commit([*self._specs[:i], updated, *self._specs[i + 1 :]])

    def remove(self, namespace: str) -> None:
        i = self._index(namespace)
        self._commit([*self._specs[:i], *self._specs[i + 1 :]])

    def set_enabled(self, namespace: str, enabled: bool) -> None:
        self._replace(namespace, {"enabled": enabled})

    # --- visibility ------------------------------------------------------

    def root_muted(self) -> bool:
        return self._root_muted

    def set_root_muted(self, muted: bool) -> None:
        self._commit(list(self._specs), root_muted=muted)

    def set_muted(self, namespace: str, muted: bool) -> None:
        self._replace(namespace, {"muted": muted})

    def set_tool_muted(self, namespace: str, tool: str, muted: bool) -> None:
        """Mute or unmute one tool.

        `tool` is the bare child tool name, taken verbatim. The child owns
        that string and visibility matching is exact, so the registry must
        not trim or normalise it.
        """
        i = self._index(namespace)
        names = list(self._specs[i].disabled_tools)
        if muted and tool not in names:
            names.append(tool)
        elif not muted and tool in names:
            names.remove(tool)
        else:
            return
        self._replace(namespace, {"disabled_tools": names})

    # --- built-in admin visibility ---------------------------------------

    def admin_muted(self) -> bool:
        return self._admin_muted

    def set_admin_muted(self, muted: bool) -> None:
        self._commit(
            list(self._specs), admin=(muted, list(self._admin_disabled_tools))
        )

    def set_admin_tool_muted(self, tool: str, muted: bool) -> None:
        """Mute or unmute one admin tool. `tool` is the bare admin tool name.

        The name is taken verbatim, for the same reason as `set_tool_muted`.
        A pinned name is stored like any other: the resolution ignores it, so
        the name applies again if the tool ever leaves the pinned set.
        """
        names = list(self._admin_disabled_tools)
        if muted and tool not in names:
            names.append(tool)
        elif not muted and tool in names:
            names.remove(tool)
        else:
            return
        self._commit(list(self._specs), admin=(self._admin_muted, names))

    def admin_visibility(self) -> tuple[bool, set[str]]:
        """The resolution rule for the built-in admin server.

        Returns the same `(hide_all, hidden)` shape as `visibility`, so the
        supervisor pushes it onto a `Visibility` transform the same way. It
        reads the `admin` object only. The root level does not cover a
        `mcpflow_*` tool: a muted root must never remove the tool that unmutes
        the root. The pin is a second, constant transform, not a subtraction
        here, so this stays one shape for both callers.
        """
        if self._admin_muted:
            return True, set()
        return False, set(self._admin_disabled_tools)

    def _replace(self, namespace: str, update: dict) -> None:
        i = self._index(namespace)
        changed = self._specs[i].model_copy(update=update)
        self._commit([*self._specs[:i], changed, *self._specs[i + 1 :]])

    def visibility(self, spec: ServerSpec) -> tuple[bool, set[str]]:
        """The resolution rule. The only place that reads the levels together.

        Returns `(hide_all, hidden)`. A tool of this child is visible when
        `hide_all` is false and its bare name is not in `hidden`.
        """
        if self._root_muted or spec.muted:
            return True, set()
        return False, set(spec.disabled_tools)

    def _index(self, namespace: str) -> int:
        for i, spec in enumerate(self._specs):
            if spec.namespace == namespace:
                return i
        raise KeyError(namespace)

    def _write(
        self,
        specs: list[ServerSpec],
        root_muted: bool,
        admin_muted: bool,
        admin_disabled_tools: list[str],
    ) -> None:
        payload = {
            "version": 1,
            "muted": root_muted,
            "admin": {
                "muted": admin_muted,
                "disabled_tools": list(admin_disabled_tools),
            },
            "servers": [json.loads(s.model_dump_json()) for s in specs],
        }
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        # Create the file already-private (0600); child secrets in `env` never
        # sit at 0644 in the write window.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(payload, indent=2))
        os.replace(tmp, self._path)


def spec_from_dict(data: dict) -> ServerSpec:
    """Build a `ServerSpec`, translating validation errors to `RegistryError`."""
    try:
        return ServerSpec(**data)
    except ValidationError as exc:
        field = exc.errors()[0]["loc"]
        name = field[0] if field else "spec"
        raise RegistryError(f"{name}: {exc.errors()[0]['msg']}") from exc
