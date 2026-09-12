"""The persisted list of child MCP servers.

`Registry` owns `DATA_DIR/servers.json`. Every mutator validates, builds a
candidate state, writes the file atomically, and only then adopts the
candidate in memory. A failed write therefore leaves the file and the memory
equal, so no caller can act on a state that was never persisted.
"""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

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
    netloc = urlsplit(source).netloc
    if "@" not in netloc:
        return []
    userinfo = netloc.rsplit("@", 1)[0]
    if not userinfo:
        return []
    secrets = [userinfo]
    if ":" in userinfo:
        secrets.append(userinfo.split(":", 1)[1])
    return secrets


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
        self._commit([*self._specs, spec])

    def update(self, spec: ServerSpec) -> None:
        i = self._index(spec.namespace)
        existing = self._specs[i]
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
            }
        )
        self._commit([*self._specs[:i], merged, *self._specs[i + 1 :]])

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
