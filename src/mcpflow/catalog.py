"""The marketplace catalog: known MCP servers as one JSON file per entry.

`Catalog.load` is the only reader of the two catalog directories. It merges
the built-in entries shipped in `mcpflow/catalog/` with the local entries
under `DATA_DIR/catalog/`; a local entry replaces a built-in one with the same
id. An invalid file is skipped and recorded, never fatal, so one bad local
file cannot hide the marketplace. A loaded catalog is a snapshot: the web
layer builds one per request and never mutates it.

The catalog holds no secret. `build_spec` is the single path that turns an
entry plus the admin's input into a `ServerSpec`; the web layer registers
that spec through `Supervisor.add`, the same as the add-server form.
"""

from __future__ import annotations

import json
import re
from collections.abc import Collection
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from .registry import (
    RegistryError,
    ServerSpec,
    redact_source,
    spec_command,
    validate_namespace,
    validate_source,
)

if TYPE_CHECKING:
    # Runtime import would make `catalog.py` depend on `oauth.py`. The web
    # layer passes `CredPaths` in; the type is needed only for the signature.
    from .oauth import CredPaths

BUILTIN_DIR = Path(__file__).parent / "catalog"

Category = Literal[
    "google",
    "microsoft",
    "chat",
    "projects",
    "crm",
    "dev",
    "data",
    "design",
    "finance",
    "automation",
    "research",
    "util",
]

# Rail order and display names.
CATEGORIES: dict[str, str] = {
    "google": "Google",
    "microsoft": "Microsoft",
    "chat": "Chat & meetings",
    "projects": "Projects & docs",
    "crm": "CRM & support",
    "dev": "Developer",
    "data": "Data & files",
    "design": "Design",
    "finance": "Finance",
    "automation": "Automation",
    "research": "Search & research",
    "util": "Utilities",
}

Auth = Literal["none", "env", "header", "oauth"]
Origin = Literal["builtin", "local"]

_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
SECRET_MASK = "•••"


class _Strict(BaseModel):
    # A misspelled key is a skipped file with a reason, never a silent
    # entry with a default in place of the admin's intent.
    model_config = ConfigDict(extra="forbid")


class SetupField(_Strict):
    key: str
    where: Literal["env", "header"]
    hint: str = ""
    required: bool = True


class FileSink(_Strict):
    """One file the child reads a path to from an environment variable.

    `format` names a writer in `oauth.CLIENT_FORMATS` or `oauth.TOKEN_FORMATS`.
    The catalog never imports the oauth module; `Catalog.load` is told the
    known format names and skips an entry that names an unknown one.
    """

    env: str  # the env var the child reads the path from
    format: str  # a key in oauth.CLIENT_FORMATS or oauth.TOKEN_FORMATS


class HeaderSink(_Strict):
    """The child sends the OAuth token in a request header. Used by a remote
    entry: the callback writes the token into the child's registry header, not
    a file."""

    name: str = "Authorization"  # the header the child sends
    scheme: str = "Bearer"  # the prefix before the token


class OAuthBlock(_Strict):
    provider: str  # a provider id
    scopes: list[str]
    # Exactly one sink: a file pair (client_file AND token_file) for a local
    # child, or a header sink for a remote child.
    client_file: FileSink | None = None
    token_file: FileSink | None = None
    header: HeaderSink | None = None

    @model_validator(mode="after")
    def _check_one_sink(self) -> OAuthBlock:
        if self.header is not None:
            if self.client_file is not None or self.token_file is not None:
                raise ValueError(
                    "an oauth block has one sink: a header, or client_file and "
                    "token_file, not both"
                )
        elif self.client_file is None or self.token_file is None:
            raise ValueError(
                "an oauth block needs a header sink, or both client_file and "
                "token_file"
            )
        return self


class SpecTemplate(_Strict):
    """The `ServerSpec` fields an entry fixes. Namespace, env, headers, and
    the catalog tag come from the connect form, never from the file."""

    kind: Literal["python", "npm", "remote", "custom"]
    package: str | None = None
    args: list[str] = Field(default_factory=list)
    url: str | None = None
    transport: Literal["http", "sse"] = "http"
    command: str | None = None
    source: str | None = None  # validated by `registry.validate_source`

    @model_validator(mode="after")
    def _check_kind_fields(self) -> SpecTemplate:
        # Same rule as `ServerSpec`, checked here so a bad file is reported
        # at load time rather than at the first connect.
        if self.kind in ("python", "npm") and not self.package:
            raise ValueError(f"package is required for kind {self.kind}")
        if self.kind == "remote" and not self.url:
            raise ValueError("url is required for kind remote")
        if self.kind == "custom" and not self.command:
            raise ValueError("command is required for kind custom")
        # Call the rule, never copy it: `registry.py` owns what a source may
        # be, the same way it owns what a namespace may be.
        self.source = validate_source(self.kind, self.source)
        return self


class CatalogFile(_Strict):
    """What a catalog file may hold. No `origin`: the loader owns that."""

    id: str
    name: str
    vendor: str
    category: Category
    color: str = "#4c8bf5"
    description: str
    auth: Auth = "none"
    tools: list[str] = Field(default_factory=list)
    spec: SpecTemplate
    setup: list[SetupField] = Field(default_factory=list)
    oauth: OAuthBlock | None = None

    @field_validator("id")
    @classmethod
    def _check_id(cls, value: str) -> str:
        # The entry id is the default namespace, so it obeys the one
        # namespace rule that `registry.py` owns.
        return validate_namespace(value)

    @field_validator("color")
    @classmethod
    def _check_color(cls, value: str) -> str:
        if not _COLOR_RE.match(value):
            raise ValueError("color must match ^#[0-9a-fA-F]{6}$")
        return value

    @model_validator(mode="after")
    def _check_setup(self) -> CatalogFile:
        if self.spec.kind != "remote" and any(f.where == "header" for f in self.setup):
            raise ValueError("a header setup field is allowed only for kind remote")
        return self

    @model_validator(mode="after")
    def _check_oauth(self) -> CatalogFile:
        # One-directional: a block requires `auth: "oauth"` and forbids setup
        # fields; `auth: "oauth"` alone stays valid (a remote vendor MCP Flow
        # cannot sign in to yet, keeping its notice and optional header). The
        # web layer branches on the block, never on `auth`.
        if self.oauth is not None:
            if self.auth != "oauth":
                raise ValueError('oauth block requires auth "oauth"')
            if self.setup:
                raise ValueError("oauth block forbids setup fields")
            # The sink must match the child kind: a header sink writes an HTTP
            # header, so the child is remote; a file sink writes files a local
            # child reads.
            if self.oauth.header is not None:
                if self.spec.kind != "remote":
                    raise ValueError("an oauth header sink requires kind remote")
            elif self.spec.kind not in ("python", "npm"):
                raise ValueError("an oauth file sink requires kind python or npm")
        return self


class CatalogEntry(CatalogFile):
    origin: Origin

    @property
    def monogram(self) -> str:
        return "".join(w[0] for w in self.name.split()[:2]).upper()

    def run_command(self, args: list[str] | None = None) -> str:
        """The command line the child runs as, with the same args the
        preview shows (`None` = the entry args).

        `registry.spec_command` owns the view, `registry.build_command` owns
        the rule. The dashboard server row and the server window call the same
        adapter, so the three pages can never disagree.
        """
        return spec_command(self.spec, args)

    def preview(self, namespace: str, args: list[str] | None = None) -> dict:
        """The spec the connect action registers, every secret masked."""
        data: dict = {"namespace": namespace, "kind": self.spec.kind}
        if self.spec.package:
            data["package"] = self.spec.package
        if self.spec.source:
            # Masked like every other secret here. The registry keeps the raw
            # value; only the page sees this one.
            data["source"] = redact_source(self.spec.source)
        if self.spec.url:
            data["url"] = self.spec.url
            data["transport"] = self.spec.transport
        if self.spec.command:
            data["command"] = self.spec.command
        shown_args = list(self.spec.args) if args is None else list(args)
        if shown_args:
            data["args"] = shown_args
        env = {f.key: SECRET_MASK for f in self.setup if f.where == "env"}
        headers = {f.key: SECRET_MASK for f in self.setup if f.where == "header"}
        if env:
            data["env"] = env
        if headers:
            data["headers"] = headers
        data["catalog"] = self.id
        return data


class Catalog:
    """A loaded snapshot of the two directories. Build one with `load`."""

    def __init__(self, entries: dict[str, CatalogEntry], errors: list[tuple[Path, str]]) -> None:
        self._entries = entries
        self.errors = errors

    @classmethod
    def load(
        cls,
        builtin_dir: Path,
        local_dir: Path | None,
        *,
        providers: Collection[str] = (),
        client_formats: Collection[str] = (),
        token_formats: Collection[str] = (),
    ) -> Catalog:
        # ponytail: a full re-read on every call. Sixty small files parse in
        # milliseconds; a cache keyed on directory mtime is the upgrade path.
        #
        # `providers`, `client_formats`, and `token_formats` are the known
        # names the web layer reads from the provider registry and the format
        # tables. The catalog never imports `oauth.py`; it is told the names
        # and skips an `oauth` entry that references one it does not know, so a
        # bad name is a skipped file with a reason, not a runtime crash. The
        # glob stays `*.json` on the directory itself, so `providers/` is
        # never read as a catalog entry.
        entries: dict[str, CatalogEntry] = {}
        errors: list[tuple[Path, str]] = []
        for origin, directory in (("builtin", builtin_dir), ("local", local_dir)):
            if directory is None or not directory.is_dir():
                continue
            for path in sorted(directory.glob("*.json")):
                try:
                    raw = json.loads(path.read_text(encoding="utf-8"))
                    if not isinstance(raw, dict):
                        raise ValueError("top level must be an object")
                    # Validate the file shape first: a file cannot claim an
                    # origin. Then attach the origin the loader knows.
                    file = CatalogFile.model_validate(raw)
                    entry = CatalogEntry(**file.model_dump(), origin=origin)
                    _check_oauth_names(entry, providers, client_formats, token_formats)
                except (OSError, ValueError, ValidationError) as exc:
                    # A ValidationError is a ValueError; one clause for both.
                    errors.append((path, _reason(exc)))
                    continue
                entries[entry.id] = entry
        return cls(entries, errors)

    def entries(self) -> list[CatalogEntry]:
        return sorted(self._entries.values(), key=lambda e: e.name.lower())

    def get(self, id: str) -> CatalogEntry | None:
        return self._entries.get(id)

    def search(self, q: str, category: str | None) -> list[CatalogEntry]:
        needle = (q or "").strip().lower()
        out = []
        for e in self.entries():
            if category and e.category != category:
                continue
            if needle:
                hay = " ".join([e.name, e.vendor, e.id, *e.tools]).lower()
                if needle not in hay:
                    continue
            out.append(e)
        return out

    def counts(self) -> dict[str, int]:
        """Entries per category over the whole catalog; a search does not
        change the rail counts."""
        counts = {c: 0 for c in CATEGORIES}
        for e in self._entries.values():
            counts[e.category] += 1
        return counts


def _check_oauth_names(
    entry: CatalogEntry,
    providers: Collection[str],
    client_formats: Collection[str],
    token_formats: Collection[str],
) -> None:
    """Raise a `ValueError` naming an unknown provider or format.

    A non-`oauth` entry passes untouched. A header sink entry checks only the
    provider; it names no format. A file sink entry checks the provider and
    both formats. The reason names the offending value, so a skipped entry
    reads `provider acme is not known` rather than a generic failure.
    """
    block = entry.oauth
    if block is None:
        return
    if block.provider not in providers:
        raise ValueError(f"provider {block.provider} is not known")
    if block.header is not None:
        return
    if block.client_file.format not in client_formats:
        raise ValueError(f"client file format {block.client_file.format} is not known")
    if block.token_file.format not in token_formats:
        raise ValueError(f"token file format {block.token_file.format} is not known")


def _reason(exc: BaseException) -> str:
    """Every fault in one line, so a misspelled key shows next to the
    missing field it caused."""
    if isinstance(exc, ValidationError):
        parts = []
        for err in exc.errors():
            loc = ".".join(str(p) for p in err.get("loc", ()))
            msg = err.get("msg", "invalid")
            parts.append(f"{loc}: {msg}" if loc else msg)
        return "; ".join(parts)
    return str(exc)


def build_spec(
    entry: CatalogEntry,
    namespace: str,
    values: dict[str, str],
    args: list[str] | None,
    cred_paths: CredPaths | None = None,
) -> ServerSpec:
    """Turn an entry plus the admin's input into the spec to register.

    `args` is `None` when the form posted no args field (the entry has none);
    a posted value wins verbatim, an empty one included. Raises
    `RegistryError` naming a missing required key or an invalid namespace,
    before any registry write. An empty optional value leaves its key out.

    For an `oauth` entry the two file paths from `cred_paths` become `env`,
    `enabled` is `False`, `headers` is empty, and `values` is ignored. The
    callback enables the child once the token file exists. `cred_paths` is
    required for an `oauth` entry; its absence is a `RegistryError`.
    """
    if entry.oauth is not None:
        if entry.oauth.header is not None:
            # Header sink (a remote child): no file paths. The callback writes
            # the access token into the child's Authorization header via
            # registry.update; `oauth_pending` marks it awaiting until then.
            # `cred_paths` is ignored; there is no file.
            env: dict[str, str] = {}
            extra: dict = {"oauth_pending": True}
        else:
            # File sink (a local child): the two file paths become env.
            if cred_paths is None:
                raise RegistryError("cred_paths is required for an oauth entry")
            env = {
                entry.oauth.client_file.env: str(cred_paths.client),
                entry.oauth.token_file.env: str(cred_paths.token),
            }
            extra = {}
        data = {
            "namespace": (namespace or "").strip(),
            "kind": entry.spec.kind,
            "package": entry.spec.package,
            "args": list(entry.spec.args) if args is None else list(args),
            "url": entry.spec.url,
            "transport": entry.spec.transport,
            "command": entry.spec.command,
            "source": entry.spec.source,
            "env": env,
            "headers": {},
            "enabled": False,
            "description": entry.description,
            "catalog": entry.id,
            **extra,
        }
        try:
            return ServerSpec.model_validate(data)
        except ValidationError as exc:
            raise RegistryError(_reason(exc)) from exc
    env: dict[str, str] = {}
    headers: dict[str, str] = {}
    for field in entry.setup:
        value = (values.get(field.key) or "").strip()
        if not value:
            if field.required:
                raise RegistryError(f"{field.key} is required")
            continue
        (env if field.where == "env" else headers)[field.key] = value
    data = {
        "namespace": (namespace or "").strip(),
        "kind": entry.spec.kind,
        "package": entry.spec.package,
        "args": list(entry.spec.args) if args is None else list(args),
        "url": entry.spec.url,
        "transport": entry.spec.transport,
        "command": entry.spec.command,
        "source": entry.spec.source,
        "env": env,
        "headers": headers,
        "description": entry.description,
        "catalog": entry.id,
    }
    try:
        return ServerSpec.model_validate(data)
    except ValidationError as exc:
        raise RegistryError(_reason(exc)) from exc
