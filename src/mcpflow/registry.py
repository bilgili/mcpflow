"""The persisted list of child MCP servers.

`Registry` owns `DATA_DIR/servers.json` (admin-owned servers) and
`DATA_DIR/user_servers.json` (user-owned servers). The class of a key selects
the file: a mutator writes the one file of the key it changes. Every mutator
validates, builds a candidate state, writes the file atomically, and only then
adopts the candidate in memory. A failed write therefore leaves the file and
the memory equal, so no caller can act on a state that was never persisted.

An earlier build reads only `servers.json`, whose shape is unchanged, so a
downgrade starts no user-owned server.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import math
import operator
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal
from urllib.parse import unquote, unquote_plus, urlsplit, urlunsplit

import httpx
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from .identity import USER_ID_RE

logger = logging.getLogger(__name__)

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


@dataclass(frozen=True, order=True)
class ServerKey:
    """The registry key of a child. `owner` is `None` for an admin-owned child.

    The reference is `<namespace>` for an admin-owned child and
    `<namespace>@<owner>` for a user-owned one. `@` is outside both patterns,
    so the key and the reference map one to one, and every per-server store
    keys by the reference. For an admin-owned child the reference is the
    namespace, so no existing path moves.
    """

    owner: str | None
    namespace: str

    def __post_init__(self) -> None:
        # The one-to-one map is the type's invariant, not `parse`'s: without
        # it `ServerKey(None, "github@alice")` would share alice's reference,
        # and so her credential, source, and log paths. A shape check only;
        # the reserved-namespace rule belongs to `validate_namespace`.
        if not isinstance(self.namespace, str) or not _NAMESPACE_RE.fullmatch(
            self.namespace
        ):
            raise ValueError(f"bad server namespace {self.namespace!r}")
        if self.owner is not None and (
            not isinstance(self.owner, str) or not USER_ID_RE.fullmatch(self.owner)
        ):
            raise ValueError(f"bad server owner {self.owner!r}")

    @property
    def ref(self) -> str:
        if self.owner is None:
            return self.namespace
        return f"{self.namespace}@{self.owner}"

    @classmethod
    def parse(cls, ref: str) -> ServerKey:
        """The key a reference names. `ValueError` for any other shape.

        A shape check only: the reserved-namespace rule belongs to
        `validate_namespace`, and the built-in `mcpflow` reference must parse.
        """
        if not isinstance(ref, str):
            raise ValueError(f"bad server reference {ref!r}")  # noqa: TRY004 -- one error type for every bad shape
        namespace, sep, owner = ref.partition("@")
        if not _NAMESPACE_RE.fullmatch(namespace) or (
            sep and not USER_ID_RE.fullmatch(owner)
        ):
            raise ValueError(
                f"bad server reference {ref!r}: expected <namespace> or "
                "<namespace>@<owner>"
            )
        return cls(owner if sep else None, namespace)


# The fields that decide what code runs and where it connects. An edit of one
# of them changes `revision`, so it un-approves a user-owned server by
# construction. `description`, `enabled`, `cache_ttl`, and the mute state are
# not here: an edit of them keeps the approval.
REVISION_FIELDS: Final = (
    "kind",
    "package",
    "args",
    "url",
    "transport",
    "headers",
    "command",
    "env",
    "source",
)

# The declared shape of each `REVISION_FIELDS` value, for the type guard of
# the approval memo (D6, gate R3-A). A field missing here keeps no memo, so a
# new revision field fails closed until it is added.
_REVISION_SHAPES: Final = {
    "kind": str,
    "package": str,
    "args": list,
    "url": str,
    "transport": str,
    "headers": dict,
    "command": str,
    "env": dict,
    "source": str,
}
_revision_values: Final = operator.attrgetter(*REVISION_FIELDS)


def _typed_revision_value(name: str, value: object) -> bool:
    """True when `value` has the exact declared type of revision field `name`."""
    shape = _REVISION_SHAPES.get(name)
    if shape is str:
        return type(value) is str or value is None
    if shape is list:
        return type(value) is list and all(type(x) is str for x in value)
    if shape is dict:
        return type(value) is dict and all(
            type(k) is str and type(x) is str for k, x in value.items()
        )
    return False


def revision(spec: ServerSpec) -> str:
    """SHA-256 hex digest of the canonical JSON of `REVISION_FIELDS`."""
    fields = spec.model_dump(mode="json", include=set(REVISION_FIELDS))
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


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
    # Registry-owned, never read from a caller body: `Supervisor.add` stamps
    # `owner` from the actor and `Registry.update` keeps both stored values.
    # `None` owner is admin-owned. No field stores an approval flag; the state
    # is derived in `approval` (F7a).
    owner: str | None = None
    approved_revision: str | None = None

    @property
    def key(self) -> ServerKey:
        return ServerKey(self.owner, self.namespace)

    @property
    def approval(self) -> Literal["pending", "approved"]:
        """Derived: admin-owned is always approved; a user-owned spec is
        approved only while its stored approval covers its current revision."""
        if self.owner is None or self.approved_revision == self._current_revision():
            return "approved"
        return "pending"

    def _current_revision(self) -> str:
        """`revision(self)`, reused while the `REVISION_FIELDS` values equal
        the kept snapshot, so `keys_for` hashes each stored record once, not
        once per request (D6).

        The only reader and writer of `__dict__["_revision_memo"]`, a
        `(snapshot, digest)` pair. Dumps and `==` ignore a non-field
        `__dict__` key, and a copy that carries the pair either equals it or
        misses, so no hook has to drop it. The snapshot is a `copy.copy` of
        each value, so an in-place change through a shared container cannot
        reach it.
        """
        try:
            current = _revision_values(self)
        except AttributeError:  # a deleted field: keep no pair
            return revision(self)
        pair = self.__dict__.get("_revision_memo")
        if pair is not None and pair[0] == current:
            return pair[1]
        digest = revision(self)
        snapshot = tuple(copy.copy(v) for v in current)
        # An out-of-type value can equal one with another digest (`1 == True`),
        # so keep a pair only for the declared exact types (gate R3-A).
        if all(map(_typed_revision_value, REVISION_FIELDS, snapshot)):
            self.__dict__["_revision_memo"] = (snapshot, digest)
        return digest

    @field_validator("namespace")
    @classmethod
    def _check_namespace(cls, value: str) -> str:
        return validate_namespace(value)

    @field_validator("owner")
    @classmethod
    def _check_owner(cls, value: str | None) -> str | None:
        if value is not None and not USER_ID_RE.fullmatch(value):
            raise ValueError(f"owner must match {USER_ID_RE.pattern}")
        return value

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


# The two fields that only `user_servers.json` carries. `servers.json` keeps
# the shape an earlier build reads.
_USER_FIELDS = frozenset(("owner", "approved_revision"))

# --- pinning of a user-owned server (D7b, gate condition C4) ----------------
#
# The revision binds the spec text, so an approval is only as strong as the
# code that text names. A user-owned spec must therefore name immutable code.
# `Registry.add` and `Registry.update` are the single owner of the rule; no
# route holds a copy.

_SHA = r"[0-9a-fA-F]{40}"
_NPM_PINNED_RE = re.compile(
    r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*"
    r"@\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_PYTHON_PINNED_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*"
    r"==\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?$"
)
# `git+https://[userinfo@]host/o/r`: no `@`, `#`, or `?` in the path, so the
# ref after it is the whole tail.
_GIT_URL = r"git\+https://(?:[^/@\s]+@)?[^/@\s]+(?:/[^/@#?\s]+)+"
_PYTHON_SOURCE_RE = re.compile(rf"^{_GIT_URL}@{_SHA}$")
_NPM_SOURCE_RE = re.compile(
    rf"^(?:github:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+|{_GIT_URL})#{_SHA}$"
)
_PINNED_FORMS = {
    "npm": (
        "name@X.Y.Z or @scope/name@X.Y.Z",
        "github:o/r#<sha> or git+https://host/o/r#<sha>",
    ),
    "python": ("name==X.Y.Z", "git+https://host/o/r@<sha>"),
}
# With a pinned `source`, `package` is the entry point inside that source. It
# sits in the launcher's own argv (`uvx --from <source> <package> ...`), so it
# must be a bare name: a leading `-` would be read as a launcher option such as
# `--with <unpinned>` or npx `-c <shell>`.
_PYTHON_ENTRY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_NPM_ENTRY_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
# `env` keys that change which code a child loads or where it fetches it. The
# launcher (`uvx`, `npx`) runs with this env, so a proxy plus a trusted CA could
# serve other bytes for a pinned version. Compared upper-cased, so
# `npm_config_registry` and `https_proxy` are refused as well.
_CODE_ENV_NAMES = frozenset((
    "PATH", "HOME", "NPX",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
))
_CODE_ENV_PREFIXES = (
    "LD_", "DYLD_", "PYTHON", "NODE_", "NPM_CONFIG_", "UV_", "PIP_", "GIT_",
    "XDG_", "BUN_",
)


def _check_pinned(spec: ServerSpec) -> None:
    """Refuse an unpinned user-owned spec with `RegistryError` naming the field.

    Admin-owned specs and kind `remote` pass: mcpflow runs no host code for a
    remote child, and the approval binds its URL and headers. The error never
    echoes the source, which may carry a credential.
    """
    if spec.owner is None or spec.kind == "remote":
        return
    if spec.kind == "custom":
        # No digest of the spec covers the content of a host executable, so
        # no approval can bind it (D7b, "The `custom` decision").
        raise RegistryError("kind: a user-owned server cannot be kind custom")
    for name in spec.env:
        upper = name.upper()
        if upper in _CODE_ENV_NAMES or upper.startswith(_CODE_ENV_PREFIXES):
            raise RegistryError(
                f"env: {name} changes which code the child loads; a user-owned "
                "server cannot set it"
            )
    package_form, source_form = _PINNED_FORMS[spec.kind]
    if spec.source is not None:
        # A branch, a tag, a short SHA, an https archive, and a local path all
        # fail here: only a full commit SHA names immutable code.
        pattern = _PYTHON_SOURCE_RE if spec.kind == "python" else _NPM_SOURCE_RE
        if not pattern.fullmatch(spec.source):
            raise RegistryError(
                f"source: a user-owned {spec.kind} server needs a git source "
                f"pinned to a full commit SHA: {source_form}"
            )
        entry = _PYTHON_ENTRY_RE if spec.kind == "python" else _NPM_ENTRY_RE
        if not entry.fullmatch(spec.package or ""):
            raise RegistryError(
                f"package: with a source, a user-owned {spec.kind} server names "
                "its entry point as a bare name, not an option"
            )
        return
    pattern = _PYTHON_PINNED_RE if spec.kind == "python" else _NPM_PINNED_RE
    if not pattern.fullmatch(spec.package or ""):
        raise RegistryError(
            f"package: a user-owned {spec.kind} server needs an exact version: "
            f"{package_form}"
        )


def _prefix_conflict(a: str, b: str) -> bool:
    """D5b: `github` and `github_create` can publish one tool name."""
    return a.startswith(b + "_") or b.startswith(a + "_")


# The default count of servers one user may own. `config.py` imports it for
# the `MAX_USER_SERVERS` default, so a registry built without the setting is
# capped too (D3).
DEFAULT_MAX_USER_SERVERS: Final = 20


class Registry:
    def __init__(
        self,
        path: Path,
        user_path: Path,
        *,
        max_user_servers: int = DEFAULT_MAX_USER_SERVERS,
    ) -> None:
        self._path = path
        self._user_path = user_path
        self._max_user_servers = max_user_servers
        # Both classes in one list, in insertion order. `ServerSpec.owner`
        # names the class, and so the file a record lives in.
        self._specs: list[ServerSpec] = []
        # Set before any load: a mutator can run before `load` on a fresh dir.
        self._root_muted = False
        # The visibility state of the built-in admin server. It has no
        # `ServerSpec`, so it cannot live in `_specs`.
        self._admin_muted = False
        self._admin_disabled_tools: list[str] = []

    def load(self) -> None:
        """Read both files. Writes nothing, so an old file keeps version 1."""
        root_muted = admin_muted = False
        admin_tools: list[str] = []
        specs: list[ServerSpec] = []
        if self._path.exists():
            data = json.loads(self._path.read_text())
            root_muted = bool(data.get("muted", False))
            # A file written before the admin object existed loads as "nothing
            # muted", which is the behaviour that file had.
            admin = data.get("admin") or {}
            admin_muted = bool(admin.get("muted", False))
            admin_tools = [str(t) for t in admin.get("disabled_tools", [])]
            for raw in data.get("servers", []):
                spec = ServerSpec(**raw)
                if spec.owner is not None:
                    raise ValueError(
                        f"servers.json: {spec.namespace} carries an owner; "
                        "user-owned servers live in user_servers.json"
                    )
                specs.append(spec.model_copy(update={"approved_revision": None}))
        if self._user_path.exists():
            data = json.loads(self._user_path.read_text())
            for raw in data.get("servers", []):
                if not raw.get("owner"):
                    raise ValueError(
                        f"user_servers.json: {raw.get('namespace')!r} has no owner"
                    )
                specs.append(ServerSpec(**raw))
        seen: set[ServerKey] = set()
        for spec in specs:
            if spec.key in seen:
                raise RegistryError(f"namespace {spec.key.ref} already exists")
            seen.add(spec.key)
        # An existing install can hold a colliding pair from before the
        # write-time check. Refusing it would stop the start; the router's
        # backstop refuses the shared names at request time instead (D5b).
        names = sorted({s.namespace for s in specs})
        for i, a in enumerate(names):
            for b in names[i + 1 :]:
                if _prefix_conflict(a, b):
                    logger.warning(
                        "namespace %s conflicts with %s: a tool name could "
                        "resolve to both",
                        b,
                        a,
                    )
        self._specs = specs
        self._root_muted = root_muted
        self._admin_muted = admin_muted
        self._admin_disabled_tools = admin_tools

    def list(self) -> list[ServerSpec]:
        return list(self._specs)

    def get(self, key: ServerKey) -> ServerSpec:
        return self._specs[self._index(key)]

    def _commit(
        self,
        specs: list[ServerSpec],
        root_muted: bool | None = None,
        admin: tuple[bool, list[str]] | None = None,
        *,
        user: bool = False,
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

        `user` selects the file: the mutator of a user-owned key writes
        `user_servers.json` only, every other mutator `servers.json` only.
        """
        root = self._root_muted if root_muted is None else root_muted
        admin_muted, admin_tools = (
            (self._admin_muted, self._admin_disabled_tools) if admin is None else admin
        )
        if user:
            self._write_user(specs)
        else:
            self._write(specs, root, admin_muted, admin_tools)
        self._specs = specs
        self._root_muted = root
        self._admin_muted = admin_muted
        self._admin_disabled_tools = admin_tools

    def add(self, spec: ServerSpec) -> None:
        if any(s.key == spec.key for s in self._specs):
            raise RegistryError(f"namespace {spec.key.ref} already exists")
        # The cap: an admin-owned record is exempt, and `load` never refuses
        # a file above it (D2, D4). No `await` before `_commit`, so two
        # concurrent adds cannot both pass the count (D1).
        if spec.owner is not None:
            owned = sum(1 for s in self._specs if s.owner == spec.owner)
            if owned >= self._max_user_servers:
                raise RegistryError(
                    f"limit: {spec.owner} owns {owned} servers; "
                    f"MAX_USER_SERVERS is {self._max_user_servers}"
                )
        # A new record has no stored value to echo against, so any mask here
        # is a clone of a read record and would persist as the credential.
        _refuse_mask(spec)
        _check_pinned(spec)
        self._check_prefix(spec)
        self._commit([*self._specs, spec], user=spec.owner is not None)

    def _check_prefix(self, spec: ServerSpec) -> None:
        """Refuse a namespace that can publish a tool name another can (D5b).

        A user write only: it compares with the admin-owned namespaces and the
        user's own, never a foreign one, so the error never reveals a private
        namespace. An admin write is exempt, so the marketplace can connect a
        second account under `<ns>_<suffix>` (D5b, user decision 2026-10-02).
        The router's request-time backstop refuses a name two tools really
        share, for every caller.
        """
        if spec.owner is None:
            return
        for other in self._specs:
            if other.owner not in (None, spec.owner):
                continue
            if _prefix_conflict(spec.namespace, other.namespace):
                raise RegistryError(
                    f"namespace {spec.namespace} conflicts with "
                    f"{other.namespace}: a tool name could resolve to both"
                )

    def update(self, spec: ServerSpec) -> None:
        """Replace the caller-owned fields of the record that `spec.key` names.

        The caller states the key through `spec.owner`; `Supervisor.update`
        stamps it from the key it was given, so no body chooses it.
        """
        merged = self.merge(spec)
        i = self._index(spec.key)
        self._commit(
            [*self._specs[:i], merged, *self._specs[i + 1 :]],
            user=merged.owner is not None,
        )

    def merge(self, spec: ServerSpec) -> ServerSpec:
        """The record `update(spec)` would store, validated, without storing it.

        Pure: raises exactly what `update` raises before its write, and writes
        nothing. The supervisor reads the merged secret set here, so it can
        discard derived state that the new record cannot scrub (the child log)
        BEFORE the record is persisted.
        """
        existing = self._specs[self._index(spec.key)]
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
                # Registry-owned. The approval is derived from the stored
                # `approved_revision`, so an edit of a revision field
                # un-approves by construction and no body can approve.
                "owner": existing.owner,
                "approved_revision": existing.approved_revision,
                "url": url,
                "env": _keep_echoed(spec.env, existing.env),
                "headers": _keep_echoed(spec.headers, existing.headers),
            }
        )
        # After the merge, no mask may remain: it would persist as the
        # credential and lose the real one.
        _refuse_mask(merged)
        # On the merged, unmasked record, before the write: an edit cannot
        # unpin an approved server, and a refusal leaves the stored spec and
        # its approval unchanged (C4). An echoed mask is restored above, so
        # `revision(merged)` equals the stored revision and keeps approval.
        _check_pinned(merged)
        return merged

    def set_approved_revision(self, key: ServerKey, revision: str) -> None:
        """Record the revision the admin approved. User-owned keys only: an
        admin-owned server is always approved and stores no revision."""
        if key.owner is None:
            raise RegistryError(f"{key.ref} is admin-owned and needs no approval")
        self._replace(key, {"approved_revision": revision})

    def set_oauth_header(self, key: ServerKey, name: str, value: str) -> None:
        """Set the child's `name` header to `value` and clear `oauth_pending`
        in one atomic write.

        The one path that writes a header sink's token. Three callers in the
        supervisor: the OAuth callback via `finish_oauth`, the header sink
        refresh apply, and the `startup` repair from `refresh.json`. It flips
        the token and the awaiting flag together in one `servers.json` write,
        so they are never inconsistent. `update` preserves
        `oauth_pending` for every other edit; only this method clears it.
        """
        existing = self.get(key)
        headers = dict(existing.headers)
        headers[name] = value
        update = {"headers": headers, "oauth_pending": False}
        # A token response that carries the mask would persist it as the
        # credential; the no-mask rule holds for this writer too.
        _refuse_mask(existing.model_copy(update=update))
        self._replace(key, update)

    def remove(self, key: ServerKey) -> None:
        i = self._index(key)
        self._commit(
            [*self._specs[:i], *self._specs[i + 1 :]], user=key.owner is not None
        )

    def set_enabled(self, key: ServerKey, enabled: bool) -> None:
        self._replace(key, {"enabled": enabled})

    # --- visibility ------------------------------------------------------

    def root_muted(self) -> bool:
        return self._root_muted

    def set_root_muted(self, muted: bool) -> None:
        self._commit(list(self._specs), root_muted=muted)

    def set_muted(self, key: ServerKey, muted: bool) -> None:
        self._replace(key, {"muted": muted})

    def set_tool_muted(self, key: ServerKey, tool: str, muted: bool) -> None:
        """Mute or unmute one tool.

        `tool` is the bare child tool name, taken verbatim. The child owns
        that string and visibility matching is exact, so the registry must
        not trim or normalise it.
        """
        names = list(self.get(key).disabled_tools)
        if muted and tool not in names:
            names.append(tool)
        elif not muted and tool in names:
            names.remove(tool)
        else:
            return
        self._replace(key, {"disabled_tools": names})

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

    def _replace(self, key: ServerKey, update: dict) -> None:
        i = self._index(key)
        changed = self._specs[i].model_copy(update=update)
        self._commit(
            [*self._specs[:i], changed, *self._specs[i + 1 :]],
            user=key.owner is not None,
        )

    def visibility(self, spec: ServerSpec) -> tuple[bool, set[str]]:
        """The resolution rule. The only place that reads the levels together.

        Returns `(hide_all, hidden)`. A tool of this child is visible when
        `hide_all` is false and its bare name is not in `hidden`.
        """
        if self._root_muted or spec.muted:
            return True, set()
        return False, set(spec.disabled_tools)

    def _index(self, key: ServerKey) -> int:
        for i, spec in enumerate(self._specs):
            if spec.key == key:
                return i
        raise KeyError(key.ref)

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
            # The admin-owned records only, in the shape an earlier build
            # reads: no `owner`, no `approved_revision`.
            "servers": [
                json.loads(s.model_dump_json(exclude=set(_USER_FIELDS)))
                for s in specs
                if s.owner is None
            ],
        }
        _atomic_write(self._path, payload)

    def _write_user(self, specs: list[ServerSpec]) -> None:
        payload = {
            "version": 1,
            "servers": [
                json.loads(s.model_dump_json()) for s in specs if s.owner is not None
            ],
        }
        _atomic_write(self._user_path, payload)


def _atomic_write(path: Path, payload: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    # Create the file already-private (0600); child secrets in `env` never
    # sit at 0644 in the write window.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(payload, indent=2))
    os.replace(tmp, path)


def spec_from_dict(data: dict) -> ServerSpec:
    """Build a `ServerSpec`, translating validation errors to `RegistryError`."""
    try:
        return ServerSpec(**data)
    except ValidationError as exc:
        field = exc.errors()[0]["loc"]
        name = field[0] if field else "spec"
        raise RegistryError(f"{name}: {exc.errors()[0]['msg']}") from exc
