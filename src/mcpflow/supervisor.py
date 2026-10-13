"""Child lifecycle, transports, and the mount table.

The supervisor owns one `AggregateProvider` mount table. For each running
child it appends one namespaced `ProxyProvider` and removes it on stop. The
public operation owns the status transition; `_teardown` owns the mechanics.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import itertools
import logging
import os
import re
import threading
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, TextIO

import httpx
from fastmcp import Client, FastMCP
from fastmcp.client.transports import (
    ClientTransport,
    SSETransport,
    StdioTransport,
    StreamableHttpTransport,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Iterator
    from typing import Unpack

    from fastmcp.client.transports.base import SessionKwargs, TransportOptions
    from mcp import ClientSession

    from .identity import User
    from .policy import AccessPolicy, Reach
from fastmcp.server.providers import AggregateProvider, FastMCPProvider, Provider
from fastmcp.server.providers.proxy import ProxyProvider
from fastmcp.server.transforms import Namespace, Visibility
from mcp.types import CallToolResult, TextResourceContents, Tool

from . import oauth as _oauth
from .actions import (
    ActionScopeFilter,
    ActionView,
    AuthorizedHashProvider,
    _coerced_secret_literals,
    action_enabled,
    clause_violation,
    coerce_form,
    is_tagged,
    secret_keys,
    secret_literals,
)
from .config import Settings
from .oauth import (
    ClientCreds,
    CredStore,
    HeaderSpec,
    PendingFlow,
    PendingFlows,
    refresh_request,
    refresh_state,
)
from .policy import ADMIN_REQUIRED
from .registry import (
    PINNED_ADMIN_TOOLS,
    RESERVED_NAMESPACE,
    SECRET_MASK,
    Registry,
    RegistryError,
    ServerKey,
    ServerSpec,
    build_command,
    source_secrets,
    url_secrets,
)
from .registry import (
    revision as spec_revision,
)
from .sources import SourceStore, total_bytes

# The four states a child can hold. `configured` used to sit at the front of
# this list; nothing ever assigned it, so a reader had to handle a case that
# could not occur. This is an annotation, not a runtime check, and the project
# runs no type checker, so the literal documents the set rather than enforcing
# it. `test_status_holds_exactly_the_four_real_states` is what actually fails
# if a member comes back.
Status = Literal["starting", "running", "failed", "stopped"]

# Gateway secrets scrubbed from the child environment before the merge.
_SCRUB = ("ADMIN_PASSWORD", "ADMIN_PASSWORD_HASH", "SECRET_KEY")

# Diagnostic text (a child log tail, a start exception) can echo a value the
# child was configured with. `scrub_secrets` masks each configured secret
# before the text is returned or stored. `MIN_SCRUB_LEN` skips a value too
# short to be a credential (a port, a "1"/"on"/"true" flag); masking such a
# value would replace those characters everywhere in a log and shred it.
MIN_SCRUB_LEN = 4

# Header values that carry a credential behind a scheme word. The token after
# the prefix is registered as its own secret, so it masks even when a child
# error echoes it without the scheme. Compared against a lower-cased value.
_AUTH_SCHEMES = ("bearer ", "basic ", "token ")

logger = logging.getLogger(__name__)

# The key of the built-in admin server. It has no `Child`; the visibility
# mutators route it to the `admin` object of the registry.
_BUILTIN_KEY = ServerKey(None, RESERVED_NAMESPACE)

# A child that publishes a concrete resource at this URI contributes a block to
# the gateway's `instructions`. The contract is the URI only.
INSTRUCTIONS_URI: str = "instructions://self"
INSTRUCTIONS_READ_TIMEOUT: float = 2.0  # seconds, per child

# The bound `_teardown` waits for in-flight leases to drain before it exits the
# owned client and closes the transport. A healthy lease holds one `list_tools`
# or one `read_resource`; a hold past this is a hung request, so the close fails
# it and its caller runs its own failure path. Not `child_start_timeout`: the
# lifecycle mutators hold `child.lock` across `_teardown`, so a 60 s default
# would block every operation of that child behind one hung read.
LEASE_DRAIN_TIMEOUT: float = 5.0  # seconds, per teardown

# The age at which a probing render starts a background probe of a
# generation (design D3, D7). A rate limit only: a poll answer never probes.
# Read as a module global at call time, so a test can patch it.
SNAPSHOT_MAX_AGE: float = 10.0  # seconds

# The four states of one `ChildSession`. `_run_start` owns `starting -> open`;
# `_teardown` owns `open -> closing -> closed`. `acquire` and the proxy factory
# grant only while the state is `open`.
SessionState = Literal["starting", "open", "closing", "closed"]

# Header sink token refresh (design D6). The task fires `max(60 s, lifetime/10)`
# before `expires_at`; a transient failure retries from 30 s, doubling to a
# 300 s cap, and keeps retrying past the expiry.
REFRESH_MIN_MARGIN: float = 60.0
REFRESH_RETRY_START: float = 30.0
REFRESH_RETRY_CAP: float = 300.0
# The errors of `read_refresh` that do not heal by themselves (design D11): a
# corrupt file, a permission fault, a path that is not a file. They stop the
# task with `refresh.json unreadable; re-authorize`. Every other `OSError`
# (`EMFILE`, `EIO`) is a round fault the task retries.
_REFRESH_UNREADABLE = (ValueError, PermissionError, IsADirectoryError, NotADirectoryError)
_REFRESH_UNREADABLE_TEXT = "refresh.json unreadable; re-authorize"
# The characters of an OAuth error code; anything else a provider sends is
# dropped before it reaches `last_error`.
_OAUTH_ERROR_JUNK = re.compile(r"[^A-Za-z0-9_.-]")
_OAUTH_ERROR_MAX = 64
# Clock and sleep of the refresh task, module-level so a test drives them.
_now = time.time
_sleep = asyncio.sleep


def scrub_secrets(text: str, secrets: Iterable[str]) -> str:
    """Replace every occurrence of each configured secret value with the mask.

    The one owner of how a secret is masked in diagnostic text. `secrets` are
    a child's non-empty `env` and `headers` values. A value shorter than
    `MIN_SCRUB_LEN` is skipped, so a value too short to be a credential (a
    port, a `1`/`on`/`true` flag) does not mask ordinary text everywhere it
    appears. `text` with no content, or an empty secret set, returns unchanged.

    Every match is found against the original `text` and overlapping matches
    merge into one masked span. A naive replace of one value at a time mutates
    the text between passes, so two overlapping or adjacent secrets could leave
    a readable fragment of one (`replace("abcdefg", "cdefg")` first strands the
    `ab` of a second secret `abcd`) or a later value could match a mask this
    pass inserted. The span merge closes both.
    """
    if not text:
        return text
    values = {s for s in secrets if len(s) >= MIN_SCRUB_LEN}
    spans: list[tuple[int, int]] = []
    for value in values:
        start = text.find(value)
        while start != -1:
            spans.append((start, start + len(value)))
            start = text.find(value, start + 1)
    if not spans:
        return text
    spans.sort()
    merged = [spans[0]]
    for start, end in spans[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    out: list[str] = []
    prev = 0
    for start, end in merged:
        out.append(text[prev:start])
        out.append(SECRET_MASK)
        prev = end
    out.append(text[prev:])
    return "".join(out)


# The process log is process-wide, so its secret set is too. `_run_start`
# pushes each generation's secrets here before it builds the transport; a
# secret stays until the process exits, because a removed or replaced
# generation's transport can still log after it left the child table (see the
# redact-process-log design, D4). Readers take one reference read; the lock
# only serialises writers' read-then-replace.
_LOG_SECRETS: frozenset[str] = frozenset()
_LOG_SECRETS_LOCK = threading.Lock()
REDACTION_FAILED = "log record suppressed: secret redaction failed"


def remember_log_secrets(values: Iterable[str]) -> None:
    """Add secrets the process log must mask from now until exit."""
    global _LOG_SECRETS
    new = frozenset(v for v in values if len(v) >= MIN_SCRUB_LEN)
    with _LOG_SECRETS_LOCK:
        if not new <= _LOG_SECRETS:
            _LOG_SECRETS = _LOG_SECRETS | new


def _redact_record(record: logging.LogRecord, extra_keys: Iterable[str] = ()) -> None:
    """Scrub one record in place against the remembered secrets.

    Keeps `msg`/`args`/`exc_info` when nothing matches, so structured
    formatters (`uvicorn.access` reads the `args` tuple) keep working. A
    scrubbed template is applied only once it renders to the scrubbed text;
    otherwise the record flattens to that text. `extra_keys` are the fields
    `makeRecord` merged from `extra` (a child's log notification forwards its
    own `extra`); a matching value is replaced by its scrubbed text. Any failure
    fails closed, because `handleError` would print the raw message and args
    to stderr.
    """
    secrets = _LOG_SECRETS
    if not secrets:
        return
    try:
        text = record.getMessage()
        clean = scrub_secrets(text, secrets)
        if clean != text:
            msg, args = clean, None
            if isinstance(record.msg, str) and isinstance(record.args, tuple):
                cand_msg = scrub_secrets(record.msg, secrets)
                cand_args = tuple(
                    scrub_secrets(a, secrets) if isinstance(a, str) else a
                    for a in record.args
                )
                with contextlib.suppress(Exception):
                    # Render as `getMessage` does: no `%` step without args.
                    if (cand_msg % cand_args if cand_args else cand_msg) == clean:
                        msg, args = cand_msg, cand_args
            record.msg, record.args = msg, args
        # An argument the message never renders (an unused mapping key, an
        # extra tuple item) still reaches stderr through `handleError` when a
        # formatter fails; flatten when the arguments hold a secret at all.
        if record.args and scrub_secrets(repr(record.args), secrets) != repr(record.args):
            record.msg, record.args = clean, None
        if record.exc_info:
            trace = logging.Formatter().formatException(record.exc_info)
            clean_trace = scrub_secrets(trace, secrets)
            if clean_trace != trace:
                record.exc_text, record.exc_info = clean_trace, None
        if record.stack_info:
            record.stack_info = scrub_secrets(record.stack_info, secrets)
        for key in extra_keys:
            value = record.__dict__[key]
            value_text = value if isinstance(value, str) else str(value)
            clean_value = scrub_secrets(value_text, secrets)
            if clean_value != value_text:
                record.__dict__[key] = clean_value
    except Exception:  # noqa: BLE001 - fail closed on any scrub fault
        record.msg, record.args = REDACTION_FAILED, None
        record.exc_info = record.exc_text = record.stack_info = None
        for key in extra_keys:
            record.__dict__[key] = REDACTION_FAILED


def install_log_redaction() -> None:
    """Wrap `logging.Logger.makeRecord` with the redactor, once per process.

    `makeRecord` is the one seam every record of every logger crosses before
    any handler, after `extra` is merged, including handlers added later and
    loggers that do not propagate (`uvicorn`). A record factory runs before the
    `extra` merge, so it cannot see those fields. Never restored: shutdown does
    not stop every transport, so a restore would let a late record through.
    """
    make = logging.Logger.makeRecord
    if getattr(make, "_mcpflow_redactor", False):
        return

    def makeRecord(self, *args, **kwargs):
        record = make(self, *args, **kwargs)
        extra = kwargs.get("extra", args[8] if len(args) > 8 else None)
        _redact_record(record, extra or ())
        return record

    makeRecord._mcpflow_redactor = True  # type: ignore[attr-defined]
    logging.Logger.makeRecord = makeRecord  # type: ignore[method-assign]


def _set_event() -> asyncio.Event:
    """A fresh, already-set `asyncio.Event`. `ChildSession.idle` starts set,
    because a new generation holds no lease."""
    event = asyncio.Event()
    event.set()
    return event


class LeaseRefused(RuntimeError):
    """A child generation refused a lease or a connect.

    `reason` is one of "no generation", "starting", "closing", "closed",
    "second connect". `generation` is 0 for "no generation". The message is
    `f"{namespace}: generation {generation} refused: {reason}"`, and it carries
    no secret: only the namespace, the generation number, and the reason word.
    """

    def __init__(self, namespace: str, generation: int, reason: str) -> None:
        super().__init__(f"{namespace}: generation {generation} refused: {reason}")
        self.namespace = namespace
        self.generation = generation
        self.reason = reason


class RevisionConflict(Exception):
    """`approve` named a revision that is not the revision of the stored spec.

    Not a `ValueError`: the adapters map it to 409, not 400. Carries the
    stored revision so the API can answer it.
    """

    def __init__(self, ref: str, stored: str) -> None:
        super().__init__(f"{ref} changed since the approval was read")
        self.revision = stored


class ActionUnavailable(RuntimeError):
    """The leased generation cannot run the named action.

    `reason` is one of: "unknown" (no such tool, or a tagged tool that
    violates the clause), "muted" (the visibility transform hides it).
    `str(exc)` carries no secret: only the action name and the reason word.
    """

    def __init__(self, name: str, reason: str) -> None:
        super().__init__(f"action {name} is unavailable: {reason}")
        self.reason = reason


@dataclass(frozen=True)
class ActionRun:
    """Execution outcome and accumulated secrecy for one submit.

    `Supervisor.run_action` classifies, coerces, and calls under one lease and
    one execution listing. Every outcome preserves rendered secrecy metadata
    and any declarations learned during execution. The web boundary combines
    this context with the page metadata before masking presentation values.

    `kind` is one of:
      "ran"           a tool ran; `result` is its `CallToolResult` (may be
                      is_error).
      "muted"         the execution listing hides the tool; no tool ran.
      "coerce_error"  the posted form failed coercion; `detail` names the
                      property; no tool ran.
      "unknown"       no such conforming action on the execution generation.
      "lease_refused" the generation refused the lease; no tool ran.
      "transport"     a transport or validation failure; no tool ran.

    `detail` is RAW (unredacted): the coercion property message, or the
    transport/lease text; "" for "ran" and "muted". `run_action` does not scrub
    `detail` and does not log it. The web boundary scrubs it once with the
    complete page secret union.
    """

    kind: str
    secrets: frozenset[str]
    password_keys: frozenset[str]
    result: CallToolResult | None
    detail: str


async def _drop_notification(*_args: Any, **_kwargs: Any) -> None:
    """Drop a child log or progress notification (F2, codex review 3).

    A child log notification and a progress notification are payload-bearing,
    and mcpflow surfaces neither. A child can echo a submitted secret in a log
    notification, so the supervisor's child `Client` construction drops both.
    One handler serves `log_handler` and `progress_handler`, which FastMCP
    calls positionally (`fastmcp/client/client.py:430-432`).
    """
    return


# The one child-`Client` logging policy. Threaded through every child
# `Client(...)` site so the policy has one owner, not a guard per site.
_CHILD_CLIENT_KW: dict[str, Any] = {
    "log_handler": _drop_notification,
    "progress_handler": _drop_notification,
}


class SingleConnectTransport(ClientTransport):
    """A stdio transport that admits one connect per generation.

    Leases keep a caller cancel off the shared transport, but a race still
    leaves a gap: after `_teardown` exits the owned client, a proxy borrower
    that got the client earlier can exit last, drop `nesting_counter` to zero,
    and stop the session task. A later `async with client` is then a first
    enter that reaches `StdioTransport.connect` and respawns the process. This
    wrapper closes that gap. It admits the one connect of the owned enter and
    refuses every later connect, so the process count per generation is
    structural rather than a timing argument.
    """

    def __init__(
        self,
        inner: StdioTransport,
        namespace: str,
        generation: int,
        log: TextIO | None = None,
    ) -> None:
        self.inner = inner
        self.namespace = namespace
        self.generation = generation
        # The open log handle of this generation, owned here: its lifetime is
        # the transport's, and `_teardown` already closes the transport.
        self.log = log
        self._admitted = False

    @property
    def legacy_only(self) -> bool:
        return self.inner.legacy_only

    @contextlib.asynccontextmanager
    async def connect_session(
        self,
        *,
        transport_options: TransportOptions | None = None,
        **session_kwargs: Unpack[SessionKwargs],
    ) -> AsyncIterator[ClientSession]:
        # Refuse a second connect before any await, so the failure lands in the
        # caller's session task and no process starts. Set the flag before any
        # await, so a concurrent second connect cannot slip past the check.
        if self._admitted:
            raise LeaseRefused(self.namespace, self.generation, "second connect")
        self._admitted = True
        # Forward `transport_options` only when it is set: passing `None` would
        # be equivalent, but the inner transport reads its own default and the
        # invariant is that this wrapper adds no option of its own.
        if transport_options is not None:
            async with self.inner.connect_session(
                transport_options=transport_options, **session_kwargs
            ) as session:
                yield session
        else:
            async with self.inner.connect_session(**session_kwargs) as session:
                yield session

    async def close(self) -> None:
        try:
            await self.inner.close()
        finally:
            if self.log is not None:
                self.log.close()


@dataclass(eq=False)
class ChildSession:
    """One generation of a child: its transport, its owned client, and its lease
    count. `_run_start` builds it in `starting`; the commit moves it to `open`;
    `_teardown` moves it through `closing` to `closed`. `eq=False`, because the
    identity of a generation, not its field values, is what a `child.session is
    session` check compares.
    """

    namespace: str
    generation: int
    transport: ClientTransport
    client: Client | None  # stdio: the owned client; remote: None
    state: SessionState = "starting"
    leases: int = 0
    idle: asyncio.Event = field(default_factory=_set_event)  # set iff leases == 0
    # The tool snapshot of this generation (design D1). Display-only: only
    # `Supervisor.tools` reads it. `tools` is raw, pre-transform, so it keeps a
    # muted tool; `None` until `_run_start` seeds it. A probe captures its
    # session and writes only that object, so a late write lands on a dead
    # generation that no render reads.
    tools: list[Tool] | None = None  # raw, pre-transform; None until seeded
    probed_at: float | None = None  # time.monotonic() of the last finished probe
    # The last probe task; the strong reference the loop does not keep. It can
    # hold a done task: a cancel before the first step skips the `finally` that
    # clears it (design D4), so every reader treats a done task as no probe.
    probe: asyncio.Task[None] | None = None

    def acquire(self) -> None:
        """Grant one lease. Synchronous, so `_lease` reads `child.session` and
        acquires with no await between the two. Raises `LeaseRefused` unless the
        generation is `open`."""
        if self.state != "open":
            raise LeaseRefused(self.namespace, self.generation, self.state)
        self.leases += 1
        self.idle.clear()

    def release(self) -> None:
        """Drop one lease. Synchronous. Sets `idle` when the last lease goes, so
        `_teardown` wakes."""
        self.leases -= 1
        if self.leases == 0:
            self.idle.set()


@dataclass
class Child:
    spec: ServerSpec
    status: Status
    last_error: str | None
    tool_count: int
    started_at: datetime | None
    transport: ClientTransport | None
    provider: Provider | None
    visibility: Visibility | None
    lock: asyncio.Lock
    task: asyncio.Task | None
    session: ChildSession | None
    # The grant generation of a header sink (design D5). `finish_oauth` for a
    # header sink and `remove` bump it; a refresh result whose captured value
    # differs is discarded. In memory only: it restarts at 0 on a re-add, so
    # the refresh task also checks the `Child` object's identity.
    grant: int = 0
    # The message of a refresh the provider rejected (design D6). Set when the
    # refresh task stops on a rejection; cleared only by `finish_oauth`. In
    # memory only. `_run_start` restores it as `last_error` on a successful
    # start, so a restart before the expiry does not hide "re-authorize".
    refresh_rejected: str | None = None
    # The last transient text the refresh task stored as `last_error` (design
    # D12). A successful apply clears `last_error` only while it still equals
    # this text, so an error the task did not record stays. In memory only.
    refresh_transient: str | None = None


@dataclass(frozen=True)
class ToolView:
    namespace: str
    name: str
    description: str
    schema_summary: str
    status: Status
    # The bare child tool name. The visibility control posts this, so no
    # template has to strip the namespace prefix off `name`.
    tool: str = ""
    visible: bool = True
    # True for an admin tool that visibility never hides. The dashboard
    # renders such a row as a checked, disabled control.
    pinned: bool = False
    # The server reference and the owner of the child that publishes the
    # tool. `owner` is `None` for an admin-owned child and the built-in rows.
    ref: str = ""
    owner: str | None = None


@dataclass(frozen=True)
class SourceWrite:
    namespace: str
    path: Path
    files: int  # len(files)
    bytes: int  # total_bytes(files)
    restarted: bool


def _new_child(spec: ServerSpec) -> Child:
    return Child(
        spec=spec,
        status="stopped",
        last_error=None,
        tool_count=0,
        started_at=None,
        transport=None,
        provider=None,
        visibility=None,
        lock=asyncio.Lock(),
        task=None,
        session=None,
    )


def _visible(pinned: bool, hide_all: bool, hidden: set[str], tool: str) -> bool:
    """The one expression that decides whether a tool row is published.

    Every caller that renders a row uses it, so the mark the dashboard shows
    and the mark the live transforms apply cannot drift. A pinned tool is
    published whatever the stored policy says; the policy still stores the
    name, so it applies again if the tool leaves the pinned set.
    """
    return pinned or (not hide_all and tool not in hidden)


def _summarize_schema(schema: dict | None) -> str:
    """Total (design D11): a schema shape comes from the child, and one raise
    would fail the whole tree. A shape is not proof of a dead child."""
    if not schema or not isinstance(schema, dict):
        return ""
    props = schema.get("properties", {})
    if not isinstance(props, dict):
        return ""
    parts = [
        f"{name}: {spec.get('type', 'any') if isinstance(spec, dict) else 'any'}"
        for name, spec in props.items()
    ]
    return ", ".join(parts)


def _read_tail(path, lines: int) -> str:
    """Return the last `lines` lines of a file, reading only its tail.

    Child logs never rotate, so reading the whole file to show 100 lines
    scales with file growth. Seek from the end and read fixed blocks until
    the buffer holds enough newlines. Output matches the whole-file read.
    """
    if lines <= 0:
        return ""
    block = 65536
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        pos = f.tell()
        buf = b""
        while pos > 0 and buf.count(b"\n") <= lines:
            read = min(block, pos)
            pos -= read
            f.seek(pos)
            buf = f.read(read) + buf
    text = buf.decode(errors="replace")
    return "".join(text.splitlines(keepends=True)[-lines:])


class Supervisor:
    def __init__(
        self,
        registry: Registry,
        settings: Settings,
        creds: CredStore,
        flows: PendingFlows,
        policy: AccessPolicy,
    ) -> None:
        self.registry = registry
        self.settings = settings
        self.creds = creds
        self.flows = flows
        # The one owner of every access decision. The supervisor never builds
        # a `Reach`; the read methods take one from the caller, so they cannot
        # choose or widen the keys. The web and REST adapters reach the policy
        # through this attribute.
        self.policy = policy
        self.sources = SourceStore(settings.data_dir / "servers")
        self.table = AggregateProvider(provider_error_strategy="warn")
        self._children: dict[ServerKey, Child] = {
            spec.key: _new_child(spec) for spec in registry.list()
        }
        # One generation number per start, so a `ChildSession` and its refusals
        # name the generation that produced them. Starts at 1; 0 is the "no
        # generation" sentinel of `LeaseRefused`.
        self._generations = itertools.count(1)
        # Keys a `remove` holds until its teardown returns. Separate from
        # `_children`, which `remove` empties before the await so `children()`
        # never lists a half torn down child. A reclaim inside that window
        # would let the old process write a file the replacement inherits, so
        # `add` refuses a key this set holds. Keys, not namespaces: the
        # removal of one owner's server never blocks another owner's add.
        self._removing: set[ServerKey] = set()
        # The built-in admin server. It is deliberately NOT a `_children`
        # entry: `startup` starts every child, `set_root_muted` applies the
        # root to every child, `children()` publishes every child to
        # `/servers` and to `mcpflow_list_servers`, and `remove` accepts every
        # child key. None of the four may reach the built-in mount.
        self._builtin: FastMCP | None = None
        self._builtin_visibility: Visibility | None = None
        # One header sink refresh task per server key that holds a
        # `refresh.json` (design D7). A task removes only its own entry.
        self._refresh_tasks: dict[ServerKey, asyncio.Task] = {}

    # --- environment, command, transport ---------------------------------

    def _build_env(self, spec: ServerSpec) -> dict[str, str]:
        env = dict(os.environ)
        for key in _SCRUB:
            env.pop(key, None)
        for key in [k for k in env if k.startswith("UV_PUBLISH_")]:
            del env[key]
        env.update(spec.env)
        return env

    def _log_path(self, key: ServerKey):
        # Keyed by reference: an admin-owned child keeps `logs/<ns>.log`, and
        # two owners of one namespace never share a log.
        return self.settings.data_dir / "logs" / f"{key.ref}.log"

    def _build_transport(
        self, spec: ServerSpec, generation: int = 0
    ) -> ClientTransport:
        if spec.kind == "remote":
            # A copy: fastmcp keeps the dict, and `_apply_refresh_header` writes
            # into the live transport's dict. Shared with the stored record, that
            # write would change the record in place and leave its approval memo
            # stale (bound-user-writes R1).
            headers = dict(spec.headers)
            if spec.transport == "sse":
                return SSETransport(spec.url, headers=headers)
            return StreamableHttpTransport(spec.url, headers=headers)
        # The raw source, never the redacted one: the child has to install from
        # it. The marketplace detail calls the same function with the redacted
        # form, so the page and the child agree on the shape and differ only in
        # the credential.
        command, args = build_command(
            kind=spec.kind,
            package=spec.package,
            args=spec.args,
            command=spec.command,
            source=spec.source,
        )
        log_path = self._log_path(spec.key)
        log_path.write_text("")  # truncate on each start
        # Open the log here, in the same synchronous step as the truncate and
        # the `child.spec` read of `_run_start`, and hand fastmcp the handle.
        # Given a `Path`, fastmcp opens it by name later, in its connect task,
        # which `child.task.cancel()` does not cancel: after an `update`
        # unlinked the log for a secret change, that open would recreate the
        # file under the old generation's env. With the handle, nothing opens
        # the log by name after this step, so an unlink is final. Append mode,
        # so writers that share the inode never overwrite each other.
        log = log_path.open("a")
        # `SingleConnectTransport` admits the one owned enter of `_run_start`
        # and refuses every later connect, so a borrower that outlives teardown
        # cannot respawn the process (D3). It owns and closes the handle.
        return SingleConnectTransport(
            StdioTransport(
                command=command,
                args=args,
                env=self._build_env(spec),
                keep_alive=True,
                log_file=log,
            ),
            spec.key.ref,
            generation,
            log,
        )

    def _build_provider(self, child: Child) -> Provider:
        """Build the provider chain of a child and store its live transform.

        The visibility transform runs BEFORE the namespace transform, so it
        matches the bare child tool name. The reverse order would match only
        the prefixed name, and a namespace rename would then silently unmute
        every muted tool of the child.

        Reads `child.spec`, never a captured local spec: a mute that lands
        while the child is `starting` must not be lost.
        """
        hide_all, hidden = self.registry.visibility(child.spec)
        visibility = Visibility(False, match_all=hide_all, names=hidden)
        child.visibility = visibility
        spec = child.spec
        if not spec.actions:
            # F2 revised: a non-capable child has no action, so no tool of it is
            # ever hidden from an mcp session by scope. Keep the pre-amendment
            # chain (visibility, then namespace) and the
            # `child-catalog-freshness` cache_ttl, with NO ActionScopeFilter:
            # the classification path is not built, so a stale cache cannot
            # cross into an admin-only boundary.
            ttl = (
                spec.cache_ttl
                if spec.cache_ttl is not None
                else self.settings.child_cache_ttl
            )
            provider = ProxyProvider(self._make_factory(child.session), cache_ttl=ttl)
            chain = provider.wrap_transform(visibility).wrap_transform(
                Namespace(spec.namespace)
            )
            # D6: the mute is a global kill switch on every path. The app path
            # skips every transform, so wrap this chain too: the wrapper re-runs
            # the named decision there, which here is the mute alone. On the
            # hashed path the chain's own template applies the mute mark, and
            # the wrapper's `_check_hashed_target` refuses a muted tool. The
            # cache stays below it and holds raw lists, never a decision.
            return AuthorizedHashProvider(chain, spec.namespace)
        # F2 revised: an action-capable child. cache_ttl=0, so every
        # list_tools/get_tool/get_tool_by_hash re-lists the live generation. The
        # filter and the hashed-path authorizer then classify the metadata the
        # tool executes with, not a stale cache. `spec.cache_ttl` is inert here:
        # a mutable cache must not gate an admin-only boundary.
        provider = ProxyProvider(self._make_factory(child.session), cache_ttl=0)
        # Innermost, for the reason `register_builtin` gives: the filter
        # removes an action, a visibility mark must never resurrect it, and it
        # reads the bare name and the bare `_meta`. `add_transform` returns
        # None, so this is its own statement.
        provider.add_transform(ActionScopeFilter())
        chain = provider.wrap_transform(visibility).wrap_transform(
            Namespace(spec.namespace)
        )
        # F1: outermost, so the hashed and app paths resolve through it. On the
        # hashed path the chain's template applies the scope filter and the
        # mute mark, and the wrapper refuses a muted tool; on the app path,
        # which bypasses every transform, it re-applies the named decision.
        return AuthorizedHashProvider(chain, spec.namespace)

    def register_builtin(self, server: FastMCP) -> Provider:
        """Build the provider chain of the built-in admin server.

        `build_app` hands the server here and registers the returned provider
        with no `namespace` keyword, so this method owns the whole chain. The
        order below is the same rule the children follow: a visibility
        transform matches the bare tool name, so it must sit inside the
        namespace transform.

        From innermost to outermost:

        1. The scope filter. It removes a component from a non-admin session.
           It stays innermost, because a visibility transform only marks a
           component: a mark can never resurrect a component the scope filter
           removed.
        2. The policy transform. `_apply_builtin` pushes the resolved
           `(hide_all, hidden)` pair onto it, the same way `_apply` does for a
           child.
        3. The pin. One constant transform. A later mark wins over an earlier
           one, so it re-enables exactly the pinned tools after the policy
           marked them. It needs no tool inventory, so the visibility mutators
           stay synchronous, and a future admin tool still falls under a muted
           namespace.
        4. The namespace, which publishes every tool as `mcpflow_<tool>`.

        `admin_mcp` imports `api`, and `api` imports this module, so the scope
        filter is imported here and not at module level.
        """
        from .admin_mcp import ScopeFilter

        self._builtin = server
        visibility = Visibility(False)
        self._builtin_visibility = visibility
        self._apply_builtin()
        provider = FastMCPProvider(server)
        # `add_transform` returns None, so this is its own statement.
        provider.add_transform(ScopeFilter())
        return (
            provider.wrap_transform(visibility)
            .wrap_transform(Visibility(True, names=set(PINNED_ADMIN_TOOLS)))
            .wrap_transform(Namespace(RESERVED_NAMESPACE))
        )

    def _apply_builtin(self) -> None:
        """Push the resolved built-in policy onto its live transform."""
        if self._builtin_visibility is None:
            return
        hide_all, hidden = self.registry.admin_visibility()
        self._builtin_visibility.match_all = hide_all
        self._builtin_visibility.names = hidden

    @contextlib.asynccontextmanager
    async def _lease(self, child: Child) -> AsyncIterator[Client]:
        """Lease the current generation of `child` and yield a usable client.

        Reads `child.session` and calls `acquire()` with no await between, so
        no teardown can move the generation out of `open` between the two. A
        stdio generation yields the owned client and enters nothing; a remote
        generation enters a fresh client, because F7 makes each remote connect
        independent. `release()` runs in `finally`, so return, raise, and cancel
        all release the lease.

        Rule L1: a holder must never await `child.lock` while it holds the
        lease. `_teardown` holds the lock and waits for the drain, so a holder
        that waited for the lock would deadlock until the bound expires.
        """
        session = child.session
        if session is None:
            raise LeaseRefused(child.spec.key.ref, 0, "no generation")
        session.acquire()
        try:
            if session.client is not None:
                yield session.client
            else:
                async with Client(
                    session.transport,
                    timeout=self.settings.child_start_timeout,
                    **_CHILD_CLIENT_KW,
                ) as client:
                    yield client
        finally:
            session.release()

    def _make_factory(self, session: ChildSession) -> Callable[[], Client]:
        """The proxy factory of one generation. It refuses unless the generation
        is `open`, so a proxy call during or after teardown fails with a typed
        error rather than reaching a torn-down transport. It changes no lease
        count: `nesting_counter` counts proxy borrowers, and D2/D3 make that
        count safe, so teardown does not wait for proxy calls."""

        def factory() -> Client:
            if session.state != "open":
                raise LeaseRefused(
                    session.namespace, session.generation, session.state
                )
            if session.client is not None:
                return session.client
            return Client(
                session.transport,
                timeout=self.settings.child_start_timeout,
                **_CHILD_CLIENT_KW,
            )

        return factory

    # --- lifecycle -------------------------------------------------------

    async def startup(self) -> None:
        # Before any child starts (design D7). First drop the credential of
        # every reference the registry does not list: a crash between
        # `registry.remove` and `creds.remove` leaves a live refresh token on
        # disk otherwise (I2b). By reference, so the credential of `github`
        # never survives or dies by the state of `github@alice`.
        for ref in self.creds.refs():
            if ServerKey.parse(ref) not in self._children:
                self.creds.remove(ref)
        # Then make each header follow its `refresh.json` (D4, I5): a crash
        # between the file write and the header write left the old token in
        # the registry. No network call. Then one task per file, enabled or
        # not: a disabled child keeps its grant alive. A fault of one file
        # never stops the boot (D11): an unreadable file is a recorded
        # rejection with no task; any other read or repair fault starts the
        # task, whose first round reads and repairs again.
        for key, child in self._children.items():
            try:
                state = self.creds.read_refresh(key.ref)
            except _REFRESH_UNREADABLE as exc:
                logger.warning(
                    "refresh.json of %s is unreadable (%s)", key.ref, type(exc).__name__
                )
                self._record_error(
                    child, _REFRESH_UNREADABLE_TEXT, self._secrets_of(child.spec)
                )
                child.refresh_rejected = child.last_error
                continue
            except OSError as exc:
                logger.warning(
                    "cannot read refresh.json of %s (%s); the refresh task retries",
                    key.ref, type(exc).__name__,
                )
                self._start_refresh_task(key, child)
                continue
            if state is None:
                continue
            try:
                self._repair_refresh_header(child, state)
            except Exception as exc:  # noqa: BLE001 -- one bad header must not stop the boot; the task repairs again
                logger.warning(
                    "header repair of %s failed (%s); the refresh task retries",
                    key.ref, type(exc).__name__,
                )
            self._start_refresh_task(key, child)
        for child in self._children.values():
            # A pending child stays `stopped`, even with `enabled` stored true.
            if not (child.spec.enabled and self._start_unless_pending(child)):
                child.status = "stopped"

    async def shutdown(self) -> None:
        tasks = list(self._refresh_tasks.values())
        self._refresh_tasks.clear()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for child in list(self._children.values()):
            await self._teardown(child)

    # --- header sink token refresh (design D1-D8) -----------------------

    def _apply_refresh_header(self, child: Child, state: dict) -> None:
        """Derive the registry header, and the live transport header, from
        a `refresh.json` state. The caller holds the child lock, or runs in
        `startup` before any task. No teardown, no restart (D8): fastmcp reads
        `transport.headers` at each connect, and every lease and proxy call
        builds a new `Client` over `child.transport`."""
        key = child.spec.key
        name = state["header_name"]
        value = f"{state['header_scheme']} {state['access_token']}"
        remember_log_secrets(
            [state["access_token"], state["refresh_token"], value]
        )
        self.registry.set_oauth_header(key, name, value)
        child.spec = self.registry.get(key)
        if child.transport is not None:
            headers = getattr(child.transport, "headers", None)
            if isinstance(headers, dict):
                headers[name] = value
            else:
                # D13: say so. The next start reads the registry header.
                logger.warning(
                    "the transport of %s has no header map; the new header "
                    "applies at the next start",
                    key.ref,
                )

    def _repair_refresh_header(self, child: Child, state: dict) -> None:
        """Make the registry header follow `refresh.json` (design D4, D10).

        The one owner of "compare the header with the file, then repair when
        they differ": `startup` and `_refresh_sync` call it. Writes only when
        the header differs. The caller holds the child lock, or runs in
        `startup` before any task. Raises what `_apply_refresh_header` raises.

        A repair that writes heals the fault of an earlier header write, so it
        clears the task's own transient text (D12), like a successful apply.
        """
        value = f"{state['header_scheme']} {state['access_token']}"
        # The file's tokens join the log scrubber even when no write is due:
        # after a restart the set does not hold them yet.
        remember_log_secrets([state["access_token"], state["refresh_token"], value])
        current = self.registry.get(child.spec.key).headers.get(state["header_name"])
        if current != value:
            self._apply_refresh_header(child, state)
            if child.last_error == child.refresh_transient:
                child.last_error = None
            child.refresh_transient = None

    def _cancel_refresh_task(self, key: ServerKey) -> None:
        """Cancel the task of `key`, if any. No await, so it is atomic with
        the caller's lock hold."""
        old = self._refresh_tasks.pop(key, None)
        if old is not None:
            old.cancel()

    def _start_refresh_task(self, key: ServerKey, child: Child) -> None:
        """Start the task of the current grant. The caller has cancelled any
        previous task and knows `refresh.json` exists. No await."""
        self._refresh_tasks[key] = asyncio.create_task(
            self._refresh_loop(key, child, child.grant)
        )

    def _refresh_current(self, key: ServerKey, child: Child, grant: int) -> bool:
        # I1: apply only for the same grant of the same `Child` object.
        return self._children.get(key) is child and child.grant == grant

    async def _refresh_sync(
        self, key: ServerKey, child: Child, grant: int
    ) -> dict | None:
        """The start of each round (design D10). Returns the state of
        `refresh.json`, or None to stop the task. Takes `child.lock`.

        Under the lock: check the grant and identity (I1), read the file, and
        make the header follow it. None when the grant is no longer current,
        the file is gone, or the file is unreadable (D11: recorded as a
        rejection). Any other `OSError` of the read, and a fault of the header
        repair, propagate as a round fault: that round sends no request, so the
        provider does not rotate a grant whose header cannot follow the file.
        """
        async with child.lock:
            if not self._refresh_current(key, child, grant):
                return None
            try:
                state = self.creds.read_refresh(key.ref)
            except _REFRESH_UNREADABLE as exc:
                logger.warning(
                    "refresh.json of %s is unreadable (%s)", key.ref, type(exc).__name__
                )
                self._record_error(
                    child, _REFRESH_UNREADABLE_TEXT, self._secrets_of(child.spec)
                )
                child.refresh_rejected = child.last_error
                return None
            if state is None:
                return None
            self._repair_refresh_header(child, state)
            return state

    async def _refresh_loop(self, key: ServerKey, child: Child, grant: int) -> None:
        """Keep one header sink grant alive (design D5, D6, D10).

        Each round starts from `refresh.json` (D10): `_refresh_sync` checks
        the grant, reads the file, and makes the header follow it. The file is
        the only input of a round, so a header write that failed after the
        file write cannot make the retry send the old refresh token. A file
        that differs from the last read holds the task's own landed write, and
        the task adopts it.

        The round sleeps until `expires_at - max(60, lifetime / 10)`, POSTs
        the refresh without the child lock, then applies under the lock only
        when the captured grant and `Child` are still current. The lifetime is
        measured from when the task read the state, so a state read at startup
        uses the remaining lifetime (a later, still-safe margin).

        The first request may fire at once (a past expiry at startup). Every
        later one waits at least `REFRESH_RETRY_START`, so a provider that
        issues a very short `expires_in` cannot drive back-to-back refreshes.
        An unexpected exception in a round (a disk error, an unusable URL, a
        header repair that raises, a transient read error) never ends the
        task: the round records a scrubbed error with the exception class
        only, and the next round first sleeps the 30 s to 300 s backoff, then
        reads the file again (gate R1). A free lock does not yield, so without
        that sleep a sync that raises every time would spin.
        """
        state: dict | None = None
        read_at = 0.0
        floor = 0.0
        backoff: float | None = None
        try:
            while True:
                try:
                    if backoff is not None:
                        # A fault always waits before the next read (gate R1).
                        await _sleep(backoff)
                    fresh = await self._refresh_sync(key, child, grant)
                    if fresh is None or fresh.get("expires_at") is None:
                        return
                    if fresh != state:
                        # The first round, or the task's own write landed.
                        state, read_at, backoff = fresh, _now(), None
                    if backoff is None:
                        expires_at = state["expires_at"]
                        margin = max(REFRESH_MIN_MARGIN, (expires_at - read_at) / 10)
                        await _sleep(max(floor, expires_at - margin - _now()))
                    # Else: a fault with the file unchanged. The backoff
                    # already waited; send the request with no second sleep.
                    floor = REFRESH_RETRY_START
                    if not await self._refresh_once(key, child, grant, state):
                        return
                    backoff = None
                except Exception as exc:  # noqa: BLE001 -- the task must outlive any fault; CancelledError is not an Exception
                    backoff = (
                        REFRESH_RETRY_START
                        if backoff is None
                        else min(backoff * 2, REFRESH_RETRY_CAP)
                    )
                    # The class name only: the message can carry the URL or
                    # the body.
                    name = type(exc).__name__
                    logger.warning(
                        "token refresh for %s failed (%s); retrying in %.0fs",
                        key.ref, name, backoff,
                    )
                    try:
                        async with child.lock:
                            if self._refresh_current(key, child, grant):
                                self._record_error(
                                    child,
                                    f"refresh failed ({name}); retrying",
                                    self._secrets_of(child.spec),
                                )
                                child.refresh_transient = child.last_error
                    except Exception as rec:  # noqa: BLE001 -- a fault of the record must not end the task
                        logger.warning(
                            "token refresh for %s: the error record failed (%s)",
                            key.ref, type(rec).__name__,
                        )
        finally:
            if self._refresh_tasks.get(key) is asyncio.current_task():
                del self._refresh_tasks[key]

    async def _refresh_once(
        self, key: ServerKey, child: Child, grant: int, state: dict
    ) -> bool:
        """One refresh request of a round, with its transport retries (design
        D6, D10). Returns True when applied: the loop continues, and its next
        `_refresh_sync` reads the file. Returns False to stop the task: a
        rejection, or the grant is no longer current.

        The retries keep `state`: no write happens between them, so it equals
        the file. At or after `expires_at` a retry records
        `refresh failing (<cause>); retrying` (D12): the header no longer
        works. Never logs a body or a token."""
        delay = REFRESH_RETRY_START
        while True:
            if not self._refresh_current(key, child, grant):
                return False
            url, body = refresh_request(state)
            resp = None
            cause = ""
            try:
                # Through the module, so a test can `monkeypatch` the factory.
                async with _oauth.http_client() as client:
                    resp = await client.post(url, data=body)
            except httpx.HTTPError as exc:
                # A transport error or a timeout. The exception can carry the
                # URL and the body, so only its class name is kept.
                cause = type(exc).__name__
            status = resp.status_code if resp is not None else None
            if status is None or status in (408, 429) or status >= 500:
                cause = str(status) if status is not None else cause
                logger.info(
                    "token refresh for %s failed (%s); retrying in %.0fs",
                    key.ref, cause, delay,
                )
                if _now() >= state["expires_at"]:
                    async with child.lock:
                        if self._refresh_current(key, child, grant):
                            self._record_error(
                                child,
                                f"refresh failing ({cause}); retrying",
                                self._secrets_of(child.spec),
                            )
                            child.refresh_transient = child.last_error
                await _sleep(delay)
                delay = min(delay * 2, REFRESH_RETRY_CAP)
                continue
            tokens: object = None
            if status // 100 == 2:
                try:
                    tokens = resp.json()
                except ValueError:
                    tokens = None
            if (
                isinstance(tokens, dict)
                and isinstance(tokens.get("access_token"), str)
                and tokens["access_token"]
            ):
                # Mask the new tokens before anything else can log them.
                remember_log_secrets(
                    [tokens["access_token"], str(tokens.get("refresh_token") or "")]
                )
                try:
                    new_state = refresh_state(
                        state["client_id"],
                        state["token_url"],
                        HeaderSpec(state["header_name"], state["header_scheme"]),
                        tokens,
                        prior_refresh_token=state["refresh_token"],
                    )
                except _oauth.OAuthTokenError:
                    new_state = None
                if new_state is not None:
                    async with child.lock:
                        if not self._refresh_current(key, child, grant):
                            return False
                        # D4: the file first, then the header.
                        self.creds.write_refresh(key.ref, new_state)
                        self._apply_refresh_header(child, new_state)
                        # D12: clear only the transient text this task stored;
                        # a rejection or a start error is never equal to it.
                        if child.last_error == child.refresh_transient:
                            child.last_error = None
                        child.refresh_transient = None
                    logger.info("refreshed the access token of %s", key.ref)
                    return True
            # Any other status, or a 2xx this task cannot use: stop, keep the
            # file, and tell the admin to re-authorize.
            # The current tokens join the scrub set: a provider may echo the
            # refresh token in its error word.
            secrets = [
                *self._secrets_of(child.spec),
                state["access_token"],
                state["refresh_token"],
            ]
            error = ""
            if resp is not None and status // 100 != 2:
                try:
                    payload = resp.json()
                except ValueError:
                    payload = None
                if isinstance(payload, dict):
                    error = _OAUTH_ERROR_JUNK.sub("", str(payload.get("error") or ""))
                    # Scrub before the cut, or the cut leaves a token prefix
                    # that no longer matches the secret.
                    error = scrub_secrets(error, secrets)[:_OAUTH_ERROR_MAX]
            async with child.lock:
                if self._refresh_current(key, child, grant):
                    self._record_error(
                        child,
                        f"refresh rejected ({status} {error}); re-authorize",
                        secrets,
                    )
                    child.refresh_rejected = child.last_error
            return False

    def children(self) -> list[Child]:
        return list(self._children.values())

    def children_of(self, owner: str | None) -> list[Child]:
        """The children of one owner; `None` names the admin-owned ones."""
        return [c for c in self.children() if c.spec.owner == owner]

    def routed(self, reach: Reach) -> list[tuple[ServerKey, Provider]]:
        """The provider of each running child whose key `reach` holds.

        The router asks only these, so a server outside the `Reach` is never
        asked. Reads the mount table's members through `child.provider`, which
        `_run_start` and `_teardown` set and clear together with the table.
        """
        keys = set(reach.keys)
        return [
            (key, c.provider)
            for c in self.children()
            if c.status == "running"
            and c.provider is not None
            and (key := c.spec.key) in keys
        ]

    def get(self, key: ServerKey) -> Child:
        """The child of `key`. `KeyError` carries the reference, so every
        error mapper names `<ref> not found`, as it named the namespace."""
        try:
            return self._children[key]
        except KeyError:
            raise KeyError(key.ref) from None

    def _begin_start(self, child: Child) -> None:
        """The one start gate: step one of the two-step start (D7).

        Every start path calls this, and nothing else creates a start task.
        It reads the STORED record, never an incoming spec, so no caller body
        can carry an approval in. A pending child raises before any state
        changes: no task, no transport, no provider, so a pending `remote`
        child sends no request to its URL. The child then runs the record the
        gate checked, because `child.spec` is set from that same read.

        Synchronous on purpose: no await separates the check from the task
        creation, and the publish block of `_run_start` (step two) mounts the
        provider only while the status is still `starting`. An edit cancels
        the task in `_teardown`, so an un-approved revision never publishes.
        """
        key = child.spec.key
        child.spec = self._approved_record(key)
        child.status = "starting"
        child.task = asyncio.create_task(self._run_start(key))

    def _approved_record(self, key: ServerKey) -> ServerSpec:
        """The stored record of `key`, or `RegistryError` when it is pending.

        The gate's one read. `enable` also calls it before its registry
        write, so a refused enable changes nothing.
        """
        stored = self.registry.get(key)
        if stored.approval != "approved":
            raise RegistryError(f"{key.ref} awaits approval")
        return stored

    def _start_unless_pending(self, child: Child) -> bool:
        """Pass the gate, or leave the child alone when it awaits approval.

        For the paths where a pending child is a normal end state, not an
        error: `startup`, `add`, `update`, and the OAuth completion. The
        caller sets `stopped` on `False`. `enable` and `restart` call the
        gate directly, so they raise.
        """
        try:
            self._begin_start(child)
        except RegistryError:
            return False
        return True

    async def _run_start(self, key: ServerKey) -> None:
        child = self.get(key)
        spec = child.spec
        # The secret set of this generation, captured before the probe. A
        # concurrent `update` cancels this task, so its error is normally never
        # stored; the capture keeps the scrub correct even so.
        secrets = self._secrets_of(spec)
        # Before the transport exists, so it can never log an unmasked secret.
        remember_log_secrets(secrets)
        # Allocate the generation and build its session before the first await.
        # A stdio child owns one client; a remote child owns none and borrows a
        # fresh client per read (D2). The transport and the session are assigned
        # together, so `_teardown` sees a matched pair.
        generation = next(self._generations)
        transport = self._build_transport(spec, generation)
        child.transport = transport
        owned = (
            None
            if spec.kind == "remote"
            else Client(
                transport,
                timeout=self.settings.child_start_timeout,
                **_CHILD_CLIENT_KW,
            )
        )
        session = ChildSession(
            namespace=spec.key.ref,
            generation=generation,
            transport=transport,
            client=owned,
        )
        child.session = session
        try:
            try:
                async with asyncio.timeout(self.settings.child_start_timeout):
                    if owned is not None:
                        # Enter the owned client once and keep it entered: it is
                        # the one admitted connect of this generation. `_teardown`
                        # exits it. A probe failure leaves it entered and the
                        # session `starting`; the next teardown closes it.
                        await owned.__aenter__()
                        tools = await owned.list_tools()
                    else:
                        async with Client(
                            transport,
                            timeout=self.settings.child_start_timeout,
                            **_CHILD_CLIENT_KW,
                        ) as c:
                            tools = await c.list_tools()
            except asyncio.CancelledError:
                raise
            except TimeoutError:
                async with child.lock:
                    if child.status == "starting":
                        child.last_error = (
                            "probe timed out after "
                            f"{self.settings.child_start_timeout}s"
                        )
                        child.status = "failed"
                return
            except Exception as exc:  # noqa: BLE001 -- probe must never raise; any error means failed
                async with child.lock:
                    if child.status == "starting":
                        self._record_error(child, str(exc) or repr(exc), secrets)
                        child.status = "failed"
                return

            async with child.lock:
                if child.status != "starting":
                    return
                child.tool_count = len(tools)
                provider = self._build_provider(child)
                child.provider = provider
                self.table.providers.append(provider)
                child.started_at = datetime.now(UTC)
                # The one clearer of `last_error`: a rejected refresh stays
                # visible until a re-authorization clears it.
                child.last_error = child.refresh_rejected
                child.status = "running"
                # Open the generation in the same locked block that publishes
                # the provider and sets `running`, so a lease or a proxy call is
                # granted exactly when the tools become reachable.
                session.state = "open"
                # Seed the snapshot in the same block (design D2), so the first
                # render after a start lists the rows and starts no probe. A
                # probe never writes `tool_count`: it keeps the start read.
                session.tools = list(tools)
                session.probed_at = time.monotonic()
        finally:
            # Clear the in-flight task, but only when it is still this task.
            # A concurrent teardown/restart may have installed a newer task.
            if child.task is asyncio.current_task():
                child.task = None

    def _still_current(self, key: ServerKey, child: Child) -> None:
        """Fail if this child is no longer the one that owns the key.

        A mutator resolves its child before it awaits `child.lock`, so a
        queued waiter can hold a generation that a completed `remove` already
        dropped and a later `add` already replaced. The lock of a dead
        generation is uncontended, so the waiter would wake and mutate the
        registry and `_children` entries of the replacement while tearing
        down its own stale object.

        The lock cannot prevent this on its own: it belongs to the `Child`,
        so it serialises one generation, not the key. Re-check identity
        after acquiring it.
        """
        if self._children.get(key) is not child:
            raise RegistryError(
                f"{key.ref} changed while the operation waited; try again"
            )

    def _authorize(self, actor: User, key: ServerKey | None, *, admin: bool) -> None:
        """The write-time decision of a server write.

        Synchronous on purpose: the caller writes after this returns, with no
        `await` between. `require_current` first, then the right of the write
        on the snapshot. Writes nothing; never grants a right.

        The policy owns the primitives: `require_current`, the admin check,
        and `can_manage`. This method only puts them in sequence for a server
        write, so the supervisor holds the whole decision and no adapter can
        widen it. A key the actor cannot manage reads as a missing one
        (`KeyError`), the rule of the edge."""
        self.policy.require_current(actor)
        if admin and not actor.is_admin:
            raise PermissionError(ADMIN_REQUIRED)
        if key is not None and not self.policy.can_manage(actor, key):
            raise KeyError(key.ref)

    @contextlib.asynccontextmanager
    async def _locked(
        self, key: ServerKey, actor: User, *, admin: bool = False
    ) -> AsyncIterator[Child]:
        """Take the child lock, then decide, then hand the child to the write.

        The one `await` is the lock, and it comes first: the checks see the
        state at lock time. Nothing awaits between `_authorize` and the first
        statement of the caller's block."""
        child = self.get(key)
        async with child.lock:
            self._still_current(key, child)
            self._authorize(actor, key, admin=admin)
            yield child

    async def _teardown(self, child: Child) -> None:
        """Release the live resources of a child.

        Takes the child, not its namespace. `remove` drops the child from
        `_children` before it awaits here, so a lookup by name could return a
        replacement that a concurrent `add` installed under the same
        namespace.

        Raises no `Exception` and no `CancelledError`: both awaits list them
        together, because `CancelledError` derives from `BaseException` and a
        handler for `Exception` alone would let a cancellation during the
        close escape. `remove` relies on that, having already written the
        registry by the time it calls here.

        Another `BaseException` is not swallowed, but it does not skip a
        release either: each later step runs in a `finally`, so the provider
        is unpublished, the transport closed (with the log handle it owns),
        and the generation closed before the exception leaves. The one step
        it can still interrupt is the close itself: a `BaseException` from
        `transport.close()` escapes before the handle is dropped, and
        `SingleConnectTransport.close` has already closed the log handle in
        its own `finally`. The step order is the same on every path. A
        `BaseException` from the lease drain is the one path that closes the
        transport while a lease is still held, before `LEASE_DRAIN_TIMEOUT`.

        It does not promise the subprocess died. A close that raises
        `Exception` or `CancelledError` is swallowed and the transport handle
        dropped anyway, so a wedged child can outlive the gateway's record of
        it.
        """
        try:
            if child.task is not None:
                child.task.cancel()
                try:
                    await child.task
                except (asyncio.CancelledError, Exception):  # noqa: BLE001, S110 -- best-effort teardown
                    pass
                finally:
                    # The task is done either way; a kept reference would make
                    # the next teardown await it and re-raise its exception.
                    child.task = None
        finally:
            if child.provider is not None and child.provider in self.table.providers:
                self.table.providers.remove(child.provider)
            child.provider = None
            child.visibility = None
            # No await separates the provider removal from `closing`: from here
            # `acquire` and the factory refuse, so no new lease enters the drain.
            session = child.session
            try:
                if session is not None:
                    session.state = "closing"
                    # Cancel the snapshot probe in the same synchronous block
                    # (design D6): no render starts a probe of a `closing`
                    # generation, so none can start after this. Not awaited: the
                    # drain below waits for its lease. The cancel shortens the
                    # drain, it does not bound it; FastMCP can swallow it, so
                    # the probe keeps its own captured-session guards (D4).
                    if session.probe is not None:
                        session.probe.cancel()
                    # Wait for the in-flight leases to drain, but only for the
                    # bound. A hold past it is a hung request; the close below
                    # fails it.
                    try:
                        async with asyncio.timeout(LEASE_DRAIN_TIMEOUT):
                            await session.idle.wait()
                    except TimeoutError:
                        logger.warning(
                            "lease drain timed out for %s generation %d with %d "
                            "leases after %.1fs",
                            session.namespace,
                            session.generation,
                            session.leases,
                            LEASE_DRAIN_TIMEOUT,
                        )
                    except asyncio.CancelledError:
                        # Continue, as the task await and the close already do.
                        pass
                    finally:
                        # Exit the owned client, so its session task can stop.
                        # It stops now, or when the last proxy borrower exits
                        # (F3). Remote leaves it None. In a `finally`, so a
                        # `BaseException` from the drain does not skip it.
                        if session.client is not None:
                            try:
                                await session.client.__aexit__(None, None, None)
                            except (asyncio.CancelledError, Exception):  # noqa: BLE001, S110 -- see the docstring
                                pass
            finally:
                if child.transport is not None:
                    try:
                        await child.transport.close()
                    except (asyncio.CancelledError, Exception):  # noqa: BLE001, S110 -- see the docstring
                        pass
                    child.transport = None
                if session is not None:
                    session.state = "closed"
                    child.session = None

    # --- public operations ----------------------------------------------

    def _check_source(self, spec: ServerSpec) -> None:
        """Reject a source under the store root that is not this reference's.

        A source that resolves inside `DATA_DIR/servers` must resolve to
        exactly the directory of the spec's own reference. The store resolves
        symlinks and `..` before it compares, so `servers/tool@alice/../github`
        is the directory of `github`. Another namespace and the same namespace
        under another owner are both refused. One guard for every write path
        (form, REST, admin MCP), so no child runs from another child's tree
        and no `remove` deletes a directory a sibling owns. The callers run it
        before the registry write and before any teardown. `RegistryError` is
        a `ValueError`, so the REST layer answers 400 and the admin tool a
        `ToolError` with no new mapping.
        """
        owner = self.sources.owner_of(spec.source)
        ref = spec.key.ref
        if owner is not None and not self.sources.owns(spec.source, ref):
            root = self.sources.root
            if owner == "":
                raise RegistryError(
                    f"source: {spec.source} is inside DATA_DIR/servers but is "
                    f"not {root}/{ref}"
                )
            raise RegistryError(
                f"source: {spec.source} belongs to reference {owner}"
            )

    def _check_creds(
        self, key: ServerKey, enabled: bool, oauth_pending: bool = False
    ) -> None:
        """Refuse to enable a child that awaits OAuth authorization.

        A file sink child awaits while it has a client file and no token file
        (`creds.awaiting`). A header sink child awaits while its registry flag
        `oauth_pending` is true; the caller passes that flag from the spec, so
        the guard needs no catalog knowledge. One guard beside `_check_source`,
        called by `add`, `update`, and `enable`, so the web form, the REST API,
        and the admin MCP tool cannot start a child before its token exists.
        `RegistryError` is a `ValueError`, so every caller answers 400 with no
        new mapping.
        """
        # The own reference only: the credential state of the same namespace
        # under another owner never decides this guard.
        if enabled and (self.creds.awaiting(key.ref) or oauth_pending):
            raise RegistryError(
                f"{key.ref} awaits authorization; delete it and connect again"
            )

    async def add(
        self,
        spec: ServerSpec,
        actor: User,
        client_fmt: str | None = None,
        client: ClientCreds | None = None,
    ) -> Child:
        """Register a child, and for an OAuth connect write its client file.

        `client_fmt` and `client` carry the file sink's client credentials, so
        the register and the write happen here with no `await` between them.
        The web layer must not do that pair itself: `add` awaits the child lock
        after the install, and a `remove` that interleaves there would leave a
        `client.json` for a namespace the registry no longer lists.

        `actor` decides the owner; the body never does. An admin actor adds
        an admin-owned server (owner `None`). A non-admin actor adds a server
        it owns, pending approval, with no trust grant: `approved_revision`,
        `actions`, and `catalog` are reset whatever the body holds (D7). The
        registry refuses an unpinned user-owned spec at the write (D7b).

        The actor check runs first, with no `await` before the registry write:
        a demoted or deleted actor raises `PermissionError` and nothing is
        written (no record, no rule purge, no log delete, no client file). The
        check never moves an admin call to the user branch.
        """
        self.policy.require_current(actor)
        if actor.is_admin:
            spec = spec.model_copy(update={"owner": None, "approved_revision": None})
        else:
            spec = spec.model_copy(
                update={
                    "owner": actor.id,
                    "approved_revision": None,
                    "actions": False,
                    "catalog": None,
                }
            )
        key = spec.key
        if key in self._removing:
            # A `remove` holds the key until its teardown returns. Its old
            # process may still be alive and may still write its token file,
            # which a replacement registered now would inherit.
            raise RegistryError(f"{key.ref} is being removed")
        self._check_source(spec)
        self._check_creds(key, spec.enabled, spec.oauth_pending)
        # Prove the key free BEFORE the rule purge: a duplicate add must
        # keep the rules of the live server. A free key's rules are residue
        # of a removed server, so a new server inherits no grant (D8b). A
        # refusal by `registry.add` below drops only that residue.
        if any(s.key == key for s in self.registry.list()):
            raise RegistryError(f"namespace {key.ref} already exists")
        self.policy.drop_server_rules(key)
        # A log under a free key is residue (a remove that a restart
        # interrupted, or one from before the log delete) and holds an old
        # child's output, which this child cannot scrub. Discard it BEFORE the
        # registry write, for the reason `update` discards first: a crash or
        # an `OSError` after the write would leave the new record beside the
        # old log. Only after the proof above that the key is free, so a
        # duplicate `add` never deletes the log of a live child. By key, so
        # `logs/github@alice.log` never touches `logs/github.log`.
        self._log_path(key).unlink(missing_ok=True)
        self.registry.add(spec)
        # `registry.add` raises on a duplicate key, and the key and the
        # reference map one to one, so reaching here proves the REFERENCE was
        # free, and any credential directory under it is residue of a removal
        # that a restart interrupted. A free namespace proves nothing: another
        # owner may hold it, so the purge names the reference, never the
        # namespace alone. Delete it AFTER that proof, never before: before
        # it, a duplicate `add` would delete the live child's credential and
        # only then raise. No `await` from the registry write to the install
        # below, so nothing can interleave.
        self.creds.remove(key.ref)
        child = _new_child(spec)
        self._children[key] = child
        # The client file is written last, after the registry and the child
        # table already agree. It is the only fallible step here: a disk error
        # between the two stores would stand the namespace up in one and not
        # the other, and the child would then be unremovable (`remove` reads
        # `_children`) and unaddable (`registry.add` sees the duplicate).
        # Writing after the install keeps the failure recoverable by the
        # documented route, delete the child and connect again. Still no
        # `await` since `registry.add`, so the register-before-write order the
        # residue purge depends on is unchanged.
        if client_fmt is not None:
            self.creds.write_client(key.ref, client_fmt, client)
        async with child.lock:
            # A pending child stays `stopped`; the add itself succeeds.
            if not (spec.enabled and self._start_unless_pending(child)):
                child.status = "stopped"
        return child

    async def update(self, key: ServerKey, spec: ServerSpec, actor: User) -> Child:
        """Replace the caller-owned fields of the child `key` names.

        The key names the child, never the body: the owner is stamped from
        `key`, and a body that names another namespace is refused, so an edit
        can never land on a different server.

        `actor` is checked under the child lock, before the first write.
        """
        # Before the lock and the check: it writes nothing.
        if spec.namespace != key.namespace:
            raise RegistryError(
                f"namespace: {spec.namespace} does not match {key.ref}"
            )
        spec = spec.model_copy(update={"owner": key.owner})
        async with self._locked(key, actor) as child:
            self._check_source(spec)
            # oauth_pending is registry-owned and preserved by registry.update,
            # so an edit that omits it (defaulting False) must not lower the
            # guard: read the stored value, not the incoming spec's.
            self._check_creds(key, spec.enabled, child.spec.oauth_pending)
            # When the secret set changes, the retained log holds a secret that
            # `_scrub` cannot mask once `child.spec` holds the new record, so
            # discard the log BEFORE the record is persisted. `merge` validates
            # and returns the record `update` stores, writing nothing, so a
            # rejected edit keeps the log. Discard-then-persist, not the other
            # way round: a crash or an `OSError` from the unlink after the write
            # would leave the new record beside the old log, and the next
            # lock-free mute (or the restart) would copy the new record into
            # `child.spec` and `log_tail` would show the old secret. A failed
            # write after the discard costs diagnostics only: the old process
            # keeps its descriptor and writes to the unlinked inode, which no
            # reader can open. In BOTH enabled branches: a restart truncates
            # the log only for a local transport, so a child switched to
            # `remote` (or disabled) would keep the old output. No `await`
            # from here to the write, so `merge` and `update` agree.
            old_secrets = set(self._secrets_of(child.spec))
            if set(self._secrets_of(self.registry.merge(spec))) != old_secrets:
                self._log_path(key).unlink(missing_ok=True)
            self.registry.update(spec)
            await self._teardown(child)
            # `registry.update` merges the visibility state and `created_at`
            # into the stored record. Read it back: installing the incoming
            # `spec` here would drop the merge, and `_build_provider` reads
            # `child.spec`, so the restart would republish a muted tool.
            child.spec = self.registry.get(key)
            # A pending child (an edit of a revision field un-approves it) is
            # left `stopped` by the gate, the same as a disabled one.
            if not (spec.enabled and self._start_unless_pending(child)):
                child.status = "stopped"
        return child

    async def approve(self, key: ServerKey, revision: str, actor: User) -> Child:
        """Approve the revision the admin read, then start through the gate.

        `revision` is the one the approver saw. Compared with the revision of
        the STORED spec under the child lock, the same lock `update` holds
        across its write and teardown, so an edit lands either before the
        compare (a mismatch: `RevisionConflict`, nothing changes) or after
        the approval (it un-approves and cancels the start). A stale page
        never approves code its reader did not see (F1). Admin-only: an
        owner cannot approve its own server.
        """
        async with self._locked(key, actor, admin=True) as child:
            if key.owner is None:
                raise RegistryError(f"{key.ref} is admin-owned and needs no approval")
            stored = spec_revision(self.registry.get(key))
            if revision != stored:
                raise RevisionConflict(key.ref, stored)
            self.registry.set_approved_revision(key, revision)
            child.spec = self.registry.get(key)
            # `stopped` only: an approve of an already running child (a
            # repeat) must not start a second task over the live transport.
            if child.spec.enabled and child.status == "stopped":
                self._begin_start(child)
        return child

    async def remove(self, key: ServerKey, actor: User) -> None:
        async with self._locked(key, actor) as child:
            # Write first, like the other persisted lifecycle mutators here.
            # Tearing down first and then failing the write would unpublish
            # the provider and drop the transport handle while the registry still
            # listed the child and its status still read `running`, and
            # nothing could repair that. The mirror exposure is narrower, not
            # absent: `_teardown` swallows `Exception` and `CancelledError`,
            # so no ordinary failure returns control part-way, but another
            # `BaseException` still escapes. See its docstring.
            self.registry.remove(key)
            # Reserve the key for the rest of this removal. Not at the
            # entry of this method: the first `await` here is the child lock
            # above, so reserving at entry would hold the namespace while this
            # call queues behind another operation that `_still_current` may
            # then reject anyway.
            self._removing.add(key)
            try:
                # Drop the open flow and the credential files in the same
                # window, right after the registry write and before the first
                # `await`. A callback that arrives after this would otherwise
                # write a token file for a reference that no longer exists, or
                # enable a reconnected child with a token issued to the old
                # client. `discard` and `remove` are both no-ops when absent.
                # This delete runs while the process is still up: it is the one
                # stated exception to "touch a credential only while no process
                # of that reference runs", and it races only the file of the
                # child being removed. Every store call names `key.ref`, so
                # the removal of `github@alice` never touches `github`.
                self.flows.discard(key.ref)
                # Retire the grant and its refresh task before the teardown
                # (design D7, I2): a refresh response that arrives later sees
                # the bump and writes nothing.
                child.grant += 1
                self._cancel_refresh_task(key)
                self.creds.remove(key.ref)
                # Drop the child before the first await, so `children()` never
                # sees a child that is half torn down. Nothing between the
                # write and the `del` suspends.
                child.status = "stopped"
                del self._children[key]
                await self._teardown(child)
                # Delete again now the teardown has closed the transport. A
                # child that rewrites its own token file, as one that refreshes
                # its access token does, can have recreated `token.json` after
                # the first delete; `rmtree(ignore_errors=True)` reports
                # nothing. No child-table guard: the reservation admits no
                # replacement, so there is nothing here to protect.
                self.creds.remove(key.ref)
                # And the log: it holds this child's raw output, which a later
                # child under the same key could not scrub (its secret set is
                # different), so `server_log` would show the old secret.
                self._log_path(key).unlink(missing_ok=True)
                # Same for the source directory, and for the same reason it
                # waits for the teardown: no delete pulls files out from under
                # a live process. `owns` answers whether the directory is ours
                # to delete at all, since a `source` may name a foreign path.
                if self.sources.owns(child.spec.source, key.ref):
                    self.sources.remove(key.ref)
                # Hygiene (D8b): drop the grants that name the reference. After
                # the registry write and the teardown, so a failed rule write
                # can never strand a half torn down child. A rule that outlives
                # a crash here grants nothing: no server holds the reference,
                # and the next `add` of it purges the rule first.
                self.policy.drop_server_rules(key)
            finally:
                # Release whatever the teardown or the deletes did. An `OSError`
                # from the source delete propagates with the key free.
                self._removing.discard(key)

    async def finish_oauth(
        self,
        flow: PendingFlow,
        token_fmt: str | None,
        tokens: dict,
        client_fmt: str | None = None,
        reauth: bool = False,
        header: HeaderSpec | None = None,
    ) -> bool:
        """Apply a successful OAuth token exchange atomically.

        The web layer runs the HTTP token exchange and hands the parsed
        `tokens` here. This method owns the apply, because it touches the same
        child lifecycle `remove` owns: under the child lock it pops the flow,
        writes the credential, and starts the child. `remove` takes the same
        lock and calls `PendingFlows.discard`, so a delete during the token
        exchange makes the `pop` here return `None` and nothing is written; a
        delete after this returns cleans the just-written credential as normal.

        File sink (`header is None`): write the token file (connect), or the
        new client file then the new token file (re-auth), under the lock.

        Header sink (`header` set, `token_fmt` None): ONE `registry.set_oauth_header`
        sets the child's `Authorization` header AND `oauth_pending=False`, so the
        token and the awaiting flag flip in one atomic `servers.json` write.
        A public client writes `refresh.json` before that write; every other
        header sink callback deletes `refresh.json`. The grant is bumped and
        the old refresh task cancelled before any write.

        Then, for connect enable a `stopped` child; for re-auth restart only a
        child the registry still says is enabled (a disable during the flow is
        honored — never force-enable).

        Returns `True` when applied, `False` when the flow was gone (removed or
        expired during the exchange) or the child changed.

        `flow.actor`, the admin who opened the flow, is checked right after
        the pop, so the flow is spent whatever the answer. A refusal raises
        `PermissionError` or `KeyError` and writes no credential. A file sink
        re-authorization checks again after its teardown, before the client
        write; that refusal leaves the child `stopped` with its old token.
        """
        key = ServerKey.parse(flow.ref)
        child = self._children.get(key)
        if child is None:
            # The child was removed during the exchange; its flow is already
            # discarded. Consume the state in case it somehow survived.
            self.flows.pop(flow.state)
            return False
        async with child.lock:
            if self._children.get(key) is not child:
                # A remove-then-add replaced the child during the exchange.
                self.flows.pop(flow.state)
                return False
            if self.flows.pop(flow.state) is None:
                # Removed or expired during the exchange: write nothing.
                return False
            # After the pop: a refused flow is consumed. No `await` from here
            # to the first write.
            self._authorize(flow.actor, key, admin=True)
            if header is not None:
                # A new grant (D5), retired first: a refresh in flight for the
                # old grant is discarded, and the old task is cancelled before
                # any write, so a failing write cannot leave it live.
                child.grant += 1
                self._cancel_refresh_task(key)
                # The rejection and the transient error belonged to the old
                # grant (D12): clear `last_error` only when it is one of them.
                if child.last_error is not None and child.last_error in (
                    child.refresh_rejected,
                    child.refresh_transient,
                ):
                    child.last_error = None
                child.refresh_rejected = None
                child.refresh_transient = None
                # Public client (design D3, D4): `refresh.json` first, in this
                # lock hold, then the header. Every other header sink callback
                # deletes the file: no refresh token, a provider that is now
                # confidential, or a user-owned key (D13, m9: `headers` is a
                # revision field, so a refresh would drop the approval). A
                # stale file would otherwise let a later task overwrite this
                # grant's header with the old grant.
                wrote_refresh = (
                    key.owner is None
                    and header.refresh_token_url is not None
                    and bool(tokens.get("refresh_token"))
                )
                if wrote_refresh:
                    self.creds.write_refresh(
                        key.ref,
                        refresh_state(
                            flow.client.client_id,
                            header.refresh_token_url,
                            header,
                            tokens,
                        ),
                    )
                else:
                    self.creds.remove_refresh(key.ref)
                # Header sink: one registry write sets the header AND clears
                # oauth_pending, so the token and the awaiting flag flip in one
                # atomic write. `update` preserves oauth_pending, so this uses
                # the dedicated `set_oauth_header`. A confidential client
                # writes no file.
                value = f"{header.scheme} {tokens['access_token']}"
                remember_log_secrets(
                    [tokens["access_token"], str(tokens.get("refresh_token") or ""), value]
                )
                self.registry.set_oauth_header(key, header.name, value)
                child.spec = self.registry.get(key)
                if wrote_refresh:
                    self._start_refresh_task(key, child)
            else:
                if reauth:
                    # Stop the child before writing. A child that refreshes its
                    # own access token holds the OLD grant in memory and
                    # rewrites the token file from it, so a write under a live
                    # child can end up with the old grant's access token beside
                    # the new grant's refresh token. Unconditional, before the
                    # branch on `enabled` below: `disable` already tore a
                    # disabled child down, so this is defensive, and
                    # `_teardown` guards every step against `None`.
                    await self._teardown(child)
                    # Say so. The teardown dropped the provider and the
                    # transport, so `running` is now false, and a write below
                    # that raises would otherwise leave a child that reports
                    # `running`, serves nothing, and cannot be repaired:
                    # `enable` is a no-op on a child that is not `stopped`.
                    # The tail below overwrites this with `starting` on the way
                    # back up.
                    child.status = "stopped"
                    # The teardown awaited the lease drain: check the opener
                    # again, with no `await` from here to the writes.
                    self._authorize(flow.actor, key, admin=True)
                # File sink: client before token, no await between, so the old
                # token survives until the new one replaces it. The teardown
                # moved in front of the pair, never between it.
                if client_fmt is not None:
                    self.creds.write_client(key.ref, client_fmt, flow.client)
                self.creds.write_token(key.ref, token_fmt, tokens)
            if reauth:
                # Restart to load the new token, but only when the child is
                # still enabled. A disable during the flow is honored.
                if self.registry.get(key).enabled:
                    await self._teardown(child)
                    child.spec = self.registry.get(key)
                    if not self._start_unless_pending(child):
                        child.status = "stopped"
                else:
                    child.status = "stopped"
            elif child.status == "stopped":
                # Connect: the credential now exists, so `_check_creds` passes.
                # The gate still decides: a pending child stays `stopped`.
                self.registry.set_enabled(key, True)
                child.spec = self.registry.get(key)
                self._start_unless_pending(child)
        return True

    async def enable(self, key: ServerKey, actor: User) -> None:
        async with self._locked(key, actor) as child:
            # Idempotent: enable states an end state ("this child is on"), not
            # a transition. A child that is not `stopped` already meets it, so
            # enabling it again is a no-op. Starting a second task here would
            # let `_run_start` overwrite the live `child.transport` and append
            # a duplicate provider, leaking the old transport and its
            # subprocess. `restart` owns bouncing a `running` or `failed`
            # child; `enable` only turns a `stopped` one on.
            if child.status != "stopped":
                return
            self._check_creds(key, True, child.spec.oauth_pending)
            # Refuse a pending child before the write, so a refused enable
            # leaves `enabled` and the status unchanged.
            self._approved_record(key)
            self.registry.set_enabled(key, True)
            child.spec = self.registry.get(key)
            self._begin_start(child)

    async def disable(self, key: ServerKey, actor: User) -> None:
        async with self._locked(key, actor) as child:
            self.registry.set_enabled(key, False)
            child.spec = self.registry.get(key)
            await self._teardown(child)
            child.status = "stopped"

    async def restart(self, key: ServerKey, actor: User) -> None:
        async with self._locked(key, actor) as child:
            if child.status not in ("running", "failed"):
                # A pending child says so (the gate's text), not "enable it":
                # enable refuses it too.
                self._approved_record(key)
                raise RegistryError(f"{key.ref} is not running; enable it instead")
            await self._teardown(child)
            try:
                self._begin_start(child)
            except RegistryError:
                # The teardown already ran; say so before the refusal leaves.
                child.status = "stopped"
                raise

    async def write_source(
        self, key: ServerKey, files: dict[str, str], actor: User
    ) -> SourceWrite:
        """Write a source tree, then restart a `running` or `failed` child.

        The store write comes first and never awaits, so the swap completes
        before any restart starts (no interleave puts a restart between staging
        and swap). A `starting` child is not restarted: `restart` refuses it
        and the agent calls `mcpflow_restart_server` once it settles. A `stopped`
        child is not restarted: `enabled` owns the process, and a write must
        not turn a disabled child on. An orphan write (no child yet) returns
        `restarted=False`; the agent then calls `mcpflow_add_server`.

        Admin-only. `actor` is checked first, with no lock: the write does not
        need a child. The restart checks it again under the lock; a refusal
        there leaves the written files in place.
        """
        self._authorize(actor, key, admin=True)
        path = self.sources.write(key.ref, files)
        restarted = False
        child = self._children.get(key)
        if child is not None and child.status in ("running", "failed"):
            # `restart` may still raise RegistryError if the child moved
            # between this check and its lock; the files are already written,
            # so the agent retries only the restart.
            await self.restart(key, actor)
            restarted = True
        return SourceWrite(
            namespace=key.ref,
            path=path,
            files=len(files),
            bytes=total_bytes(files),
            restarted=restarted,
        )

    # --- visibility ------------------------------------------------------
    #
    # These are sync on purpose. A visibility change writes the registry and
    # then assigns two attributes of the already-mounted transform. There is
    # no await between the assignments, so no coroutine can observe a
    # half-applied state and the mutation needs no lock. Keeping the methods
    # sync makes that structural instead of a comment a later edit can break.

    def _apply(self, child: Child) -> None:
        """Push the resolved state onto the live transform of one child.

        Builds nothing and never touches `self.table.providers`. A child with
        no provider has no transform; its state lands in `_build_provider`
        when the probe commits.
        """
        if child.visibility is None:
            return
        hide_all, hidden = self.registry.visibility(child.spec)
        child.visibility.match_all = hide_all
        child.visibility.names = hidden

    def root_muted(self) -> bool:
        return self.registry.root_muted()

    def set_root_muted(self, muted: bool, actor: User) -> None:
        self._authorize(actor, None, admin=True)
        self.registry.set_root_muted(muted)
        # `children()` is a list copy, so a concurrent remove cannot raise.
        for child in self.children():
            self._apply(child)

    def mcpflow_muted(self) -> bool:
        return self.registry.admin_muted()

    def set_namespace_muted(self, key: ServerKey, muted: bool, actor: User) -> None:
        self._authorize(actor, key, admin=True)
        # The built-in namespace first, before the child lookup: it has no
        # `Child` and no `ServerSpec`. Both branches stay synchronous and
        # lock-free. There is no await between the assignments, so no
        # coroutine can observe a half-applied state.
        if key == _BUILTIN_KEY:
            self.registry.set_admin_muted(muted)
            self._apply_builtin()
            return
        child = self.get(key)
        self.registry.set_muted(key, muted)
        child.spec = self.registry.get(key)
        self._apply(child)

    def set_tool_muted(
        self, key: ServerKey, tool: str, muted: bool, actor: User
    ) -> None:
        """Mute or unmute one tool. `tool` is the bare child tool name."""
        self._authorize(actor, key, admin=True)
        if key == _BUILTIN_KEY:
            self.registry.set_admin_tool_muted(tool, muted)
            self._apply_builtin()
            return
        child = self.get(key)
        self.registry.set_tool_muted(key, tool, muted)
        child.spec = self.registry.get(key)
        self._apply(child)

    # --- reads -----------------------------------------------------------

    async def tools(self, reach: Reach, *, probe: bool = True) -> list[ToolView]:
        """The tool rows of the children `reach` holds, filtered by it.

        `reach` is required, so no caller can skip the filter, and the caller
        chooses the surface, so this method cannot widen the keys. A tool the
        policy hides gets no row at all: a "hidden" mark would leak its name.
        The mute is different: a muted tool keeps its row with
        `visible=False`, because the dashboard offers the control that unmutes
        it. The built-in rows are the admin tools, so only an admin sees them.

        The rows come from the snapshot of each generation (design D3), so a
        render awaits no child. With `probe` true, a stale snapshot of an
        `open` generation starts one background probe; its result shows in a
        later render. With `probe` false (a poll answer, D7) nothing starts.
        This method is the one owner of "may this render probe".
        """
        # The one await, before the pass: the built-in rows come first, because
        # that group has no child behind it.
        views = await self._builtin_views() if reach.user.is_admin else []
        # One synchronous pass: no await between the first read of a child and
        # the return, so `probing` called right after sees the same state.
        for child, session in self._open_children(reach):
            if probe and (
                session.probed_at is None
                or time.monotonic() - session.probed_at >= SNAPSHOT_MAX_AGE
            ):
                self._schedule_probe(child, session)
            if session.tools is None:
                continue
            views.extend(
                view
                for view in self._snapshot_views(child, session.tools)
                if reach.allows_tool(child.spec.key, view.tool)
            )
        return views

    def probing(self, reach: Reach) -> bool:
        """True while a probe of an `open` generation in `reach` is live.

        The poll mark of the tree (design D7): the tree polls while this is
        true, so it shows the result of the probe and then stops. Synchronous;
        reads no child. A done task counts as no probe (D4, F5), and a
        `closing` generation counts as none even while `running`.
        """
        return any(
            session.probe is not None and not session.probe.done()
            for _child, session in self._open_children(reach)
        )

    def _open_children(self, reach: Reach) -> Iterator[tuple[Child, ChildSession]]:
        """The one filter of `tools` and `probing`, so the rows and the poll
        mark can never drift apart: each `running` child whose key `reach`
        holds, with its generation read once. A generation that is not `open`
        contributes no row and starts no probe (D3 step 2), so a render during
        a teardown starts nothing after the teardown cancel."""
        keys = set(reach.keys)
        for child in self.children():
            if child.status != "running" or child.spec.key not in keys:
                continue
            session = child.session
            if session is None or session.state != "open":
                continue
            yield child, session

    def _schedule_probe(self, child: Child, session: ChildSession) -> None:
        """Start one probe of `session` unless one is live (design D5).

        Synchronous, called only by `tools`. The session holds the one strong
        reference, because the loop keeps only a weak one; the `finally` of
        `_probe_child` drops it. Never awaited: a render waits on no child.
        """
        if session.probe is None or session.probe.done():
            # A fresh context: the probe must not inherit the request user or
            # the FastMCP request context of the render that started it.
            session.probe = asyncio.create_task(
                self._probe_child(child, session), context=contextvars.Context()
            )

    async def actions(self, key: ServerKey) -> list[ActionView]:
        """Raw admitted metadata; the web boundary owns presentation masking."""
        child = self.get(key)
        if not child.spec.actions or child.status != "running":
            return []
        try:
            async with self._lease(child) as client:
                tools = await client.list_tools()
        except LeaseRefused:
            raise
        except Exception as exc:  # noqa: BLE001 -- the page renders the reason
            raise RuntimeError(str(exc) or repr(exc)) from None
        hide_all, hidden = self.registry.visibility(child.spec)
        views: list[ActionView] = []
        for tool in tools:
            if not is_tagged(tool):
                continue
            term = clause_violation(tool)
            if term is not None:
                logger.warning(
                    "%s: tool %s is not an action: %s", key.ref, tool.name, term
                )
                continue
            disabled = not action_enabled(
                tool, _visible(False, hide_all, hidden, tool.name)
            )
            views.append(
                ActionView(
                    name=tool.name,
                    title=tool.title or "",
                    description=tool.description or "",
                    schema=tool.input_schema,
                    disabled=disabled,
                    reason="muted" if disabled else "",
                )
            )
        return views

    async def run_action(
        self,
        key: ServerKey,
        name: str,
        form: Mapping[str, Any],
        actor: User,
        *,
        rendered_password_keys: frozenset[str] = frozenset(),
        rendered_secrets: frozenset[str] = frozenset(),
    ) -> ActionRun:
        """Classify, coerce, and call under one lease and one current listing.

        Rendered metadata adds secrecy, never execution authority. Accumulators
        survive failures at any await; only the web boundary masks their detail.

        Admin-only. `actor` is checked twice: at entry, before any outcome,
        lease, or listing; and again right before the call, inside the lease
        (a lease holder must not await the lock). Only these refusals leave
        as `PermissionError` or `KeyError`. The second one is held until the
        lease ends, and it wins over a fault of the lease exit: the tool did
        not run. Every other error, a `PermissionError` of the transport
        included, stays an `ActionRun` of the kind "transport".
        """
        child = self.get(key)
        self._authorize(actor, key, admin=True)
        password_keys = frozenset(rendered_password_keys)
        full = (
            frozenset(self._secrets_of(child.spec))
            | rendered_secrets
            | frozenset(
                value
                for key in password_keys
                if isinstance(value := form.get(key), str) and value
            )
        )
        if not child.spec.actions:
            return ActionRun("unknown", full, password_keys, None, "")
        if child.status != "running":
            return ActionRun(
                "transport", full, password_keys, None, f"{key.ref} is not running"
            )
        refused: PermissionError | KeyError | None = None
        run: ActionRun | None = None
        try:
            async with self._lease(child) as client:
                tools = await client.list_tools()
                admitted = [
                    tool
                    for tool in tools
                    if is_tagged(tool) and clause_violation(tool) is None
                ]
                full |= frozenset(
                    value
                    for tool in admitted
                    for value in secret_literals(tool.input_schema)
                )
                tool = next((t for t in admitted if t.name == name), None)
                if tool is None:
                    return ActionRun("unknown", full, password_keys, None, "")
                schema = tool.input_schema
                password_keys |= secret_keys(schema)
                full |= frozenset(
                    value
                    for key in password_keys
                    if isinstance(value := form.get(key), str) and value
                )
                hide_all, hidden = self.registry.visibility(child.spec)
                if not action_enabled(tool, _visible(False, hide_all, hidden, name)):
                    return ActionRun("muted", full, password_keys, None, "")
                try:
                    arguments = coerce_form(schema, form)
                    full |= _coerced_secret_literals(arguments, password_keys)
                except ValueError as exc:
                    return ActionRun(
                        "coerce_error", full, password_keys, None, str(exc)
                    )
                # Narrow on purpose: only the decision is caught here, so a
                # transport `PermissionError` stays "transport" below.
                try:
                    self._authorize(actor, key, admin=True)
                except (PermissionError, KeyError) as exc:
                    refused = exc
                else:
                    result = await client.call_tool_mcp(name, arguments)
                    return ActionRun("ran", full, password_keys, result, "")
        except LeaseRefused as exc:
            run = ActionRun("lease_refused", full, password_keys, None, str(exc))
        except Exception as exc:  # noqa: BLE001 -- the handler renders the reason
            run = ActionRun(
                "transport", full, password_keys, None, str(exc) or repr(exc)
            )
        # A held refusal wins over a fault of the lease exit: the tool did not
        # run. Raised outside every handler, so it carries no `__context__`
        # (the raw exit fault can hold a posted secret), and the lease has
        # ended: the refusal holds no lease.
        if refused is not None:
            raise refused
        if run is None:  # every other path of the `try` returns
            raise RuntimeError("run_action: the lease ended with no outcome")
        return run

    async def instructions_blocks(self, reach: Reach) -> list[tuple[str, str]]:
        """Read `instructions://self` from every running, unmuted child that
        `reach` allows as a server.

        Returns `(namespace, text)` pairs in registry order, one per child
        whose read returned non-blank text within `INSTRUCTIONS_READ_TIMEOUT`.
        The text is raw: no header, no cap. Never raises. Never changes a
        child's status. `reach` is required: the caller passes the `mcp`
        surface of the session's user, and a child outside it is never read.
        """
        # The gate resolves before the read: it decides whether to read at
        # all. `hidden` is not consulted, so a tool mute has no effect here.
        candidates = [
            c
            for c in self.children()
            if c.status == "running"
            and reach.allows_server(c.spec.key)
            and not self.registry.visibility(c.spec)[0]
        ]
        results = await asyncio.gather(
            *(self._read_instructions(c) for c in candidates),
            return_exceptions=True,
        )
        return [
            (c.spec.namespace, text)
            for c, text in zip(candidates, results, strict=True)
            if isinstance(text, str)
        ]

    async def _read_instructions(self, child: Child) -> str | None:
        """One child's instructions read. Logs and swallows every failure.

        Unlike `_probe_child`, a failure here takes no lock and changes no
        status, `last_error`, or provider: a hung resource read is not proof
        of a dead child.
        """
        namespace = child.spec.namespace
        # Captured before the await, the same rule as `_probe_child`.
        secrets = self._secrets_of(child.spec)
        try:
            # The bound wraps the read only, never the lease acquire. Borrow the
            # generation's client and read on it. A refused lease raises
            # `LeaseRefused`, which the `except Exception` below logs and
            # swallows like any other read failure.
            async with self._lease(child) as client:
                contents = await asyncio.wait_for(
                    client.read_resource(INSTRUCTIONS_URI), INSTRUCTIONS_READ_TIMEOUT
                )
        except TimeoutError:
            logger.warning(
                "instructions://self read timed out for %s after %.1fs",
                namespace,
                INSTRUCTIONS_READ_TIMEOUT,
            )
            return None
        except Exception as exc:  # noqa: BLE001 -- a read failure never fails initialize
            logger.warning(
                "instructions://self read failed for %s: %s",
                namespace,
                scrub_secrets(str(exc) or repr(exc), secrets),
            )
            return None
        text = next(
            (i.text for i in contents if isinstance(i, TextResourceContents)), None
        )
        if text is None:
            logger.warning("instructions://self returned no text for %s", namespace)
            return None
        return text if text.strip() else None

    async def _builtin_views(self) -> list[ToolView]:
        """Build the rows of the built-in admin server.

        Lists the tools from the `FastMCP` object in process, never through
        the mount table. The reason matches `_probe_child`: the dashboard must
        list a muted tool to offer the control that unmutes it, so the read
        must skip the transforms. This read needs no network and no timeout,
        so it cannot fail the way a child probe fails.
        """
        if self._builtin is None:
            return []
        # `FastMCP.list_tools` applies no provider transform, so this read
        # sees every admin tool, muted or not.
        tools = await self._builtin.list_tools()
        hide_all, hidden = self.registry.admin_visibility()
        views: list[ToolView] = []
        for tool in tools:
            name = tool.name
            pinned = name in PINNED_ADMIN_TOOLS
            views.append(
                ToolView(
                    namespace=RESERVED_NAMESPACE,
                    name=f"{RESERVED_NAMESPACE}_{name}",
                    description=tool.description or "",
                    schema_summary=_summarize_schema(tool.parameters),
                    status="running",
                    tool=name,
                    visible=_visible(pinned, hide_all, hidden, name),
                    pinned=pinned,
                    ref=RESERVED_NAMESPACE,
                )
            )
        return views

    def _snapshot_views(self, child: Child, tools: list[Tool]) -> list[ToolView]:
        """The rows of one snapshot, in list order. Synchronous; raises nothing.

        The snapshot is raw, read from the child and not through the mount
        table, so the visibility transform never touched it. That is
        load-bearing: the dashboard must list a muted tool to offer the control
        that unmutes it. The policy resolves here, at render time, so a mute
        answer shows the new mark with no probe (design D3), and every row of
        one call sees one policy.
        """
        spec = child.spec
        namespace = spec.namespace
        hide_all, hidden = self.registry.visibility(spec)
        return [
            ToolView(
                namespace=namespace,
                name=f"{namespace}_{tool.name}",
                description=tool.description or "",
                # getattr: one odd tool object must not fail every tree (D11).
                schema_summary=_summarize_schema(getattr(tool, "input_schema", None)),
                status="running",
                tool=tool.name,
                visible=_visible(False, hide_all, hidden, tool.name),
                ref=spec.key.ref,
                owner=spec.owner,
            )
            for tool in tools
        ]

    async def _probe_child(self, child: Child, session: ChildSession) -> None:
        """The snapshot probe of one generation (design D4). Raises no
        `Exception`, and writes only `session`, the generation it was started
        for, so a late write lands on a dead object that no render reads.

        Success writes `tools` and `probed_at`. A superseded session or a
        refused lease writes `probed_at` only, so a stale render never waits
        for ever. Any other `Exception`, a cancel FastMCP swallowed included,
        runs the failure path and writes no snapshot. A cancel that takes
        effect raises `CancelledError`, which runs only the `finally`.
        """
        # Capture the secret set of this generation before the await. A
        # concurrent `update` can swap `child.spec` while `list_tools` runs, so
        # a post-await read would scrub the failure text with the wrong
        # generation's secrets and leak this one's.
        secrets = self._secrets_of(child.spec)
        try:
            # The task can first run after a restart replaced the generation.
            # This check and the `acquire` inside `_lease` run with no
            # suspension between them, so the lease lands on `session` or not
            # at all: a probe of g never leases g+1 (D4 step 2).
            if child.session is not session:
                session.probed_at = time.monotonic()
                return
            # This client talks to the child, not through the mount table, so
            # the visibility transform does not apply here. That is
            # load-bearing: the snapshot must keep a muted tool. Do not route
            # this read through the table.
            try:
                async with self._lease(child) as client:
                    tools = await client.list_tools()
            except LeaseRefused:
                # A refusal is not proof of a dead child: the generation is
                # starting or tearing down. Take no lock, log nothing, change
                # no status. Stamp it, so the snapshot stops being stale.
                session.probed_at = time.monotonic()
                return
            except Exception as exc:  # noqa: BLE001 -- one child's error must not stop the others
                # The lease released as the exception left its `async with`
                # block, so this lock is taken only after the lease block exits
                # (L1). No snapshot and no `probed_at` on this path.
                async with child.lock:
                    # Re-check under the lock: a concurrent disable/stop may
                    # have left "running", and a restart may have installed
                    # generation g+1. Mark `failed` only for the generation that
                    # failed (D7), and only while it is `open`: a `closing`
                    # generation belongs to `_teardown`. That covers `shutdown`,
                    # which holds no lock, so a swallowed cancel finds the lock
                    # free and the session still current (D4 step 6).
                    if (
                        child.status != "running"
                        or child.session is not session
                        or session.state != "open"
                    ):
                        return
                    child.status = "failed"
                    self._record_error(child, str(exc) or repr(exc), secrets)
                    if (
                        child.provider is not None
                        and child.provider in self.table.providers
                    ):
                        self.table.providers.remove(child.provider)
                    child.provider = None
                    child.visibility = None
                return
            # Write the captured generation, never `child.session`: a read that
            # outlived the drain bound can end here after a restart.
            session.tools = list(tools)
            session.probed_at = time.monotonic()
        finally:
            # Drop the strong reference, but only when it is still this task.
            if session.probe is asyncio.current_task():
                session.probe = None

    def child_secrets(self, key: ServerKey) -> list[str]:
        """The configured secret strings of one child, for the web redactor.

        A public accessor over `_secrets_of(child.spec)`, so the actions page
        can union the configured secrets with the request-local posted ones.
        `get` raises `KeyError` for an unknown key.
        """
        return self._secrets_of(self.get(key).spec)

    def _secrets_of(self, spec: ServerSpec) -> list[str]:
        """The secret strings of one spec generation: every non-empty `env`
        and `headers` value, the credential component of an auth header, and the
        credential of the `source` URL.

        A header value is stored whole (`Authorization: Bearer <token>`), but a
        child error can echo the token alone (`invalid token <token>`). Register
        the part after a known scheme prefix as well, so the token masks even
        without its scheme. A `source` (`git+https://oauth2:<token>@host/o/r`)
        carries a credential in its user information; `uvx`/`npx` echo the
        source on a clone failure, so register its credential too — the user
        information only, so the failed source stays readable. `scrub_secrets`
        drops the ones under the length floor and de-duplicates.
        """
        values = [*spec.env.values(), *spec.headers.values()]
        for value in spec.headers.values():
            low = value.lower()
            for scheme in _AUTH_SCHEMES:
                if low.startswith(scheme):
                    values.append(value[len(scheme) :].strip())
        values.extend(source_secrets(spec.source))
        # A remote child's HTTP error echoes its URL; mask the URL credential.
        values.extend(url_secrets(spec.url))
        return values

    def _scrub(self, child: Child, text: str) -> str:
        """Mask this child's currently-configured secrets in diagnostic text.

        Binds the child to its secret set and hands it to `scrub_secrets`, the
        one owner of the rule. Reads the live `child.spec`, so a read always
        masks the current configuration.
        """
        return scrub_secrets(text, self._secrets_of(child.spec))

    def _record_error(self, child: Child, text: str, secrets: list[str]) -> None:
        """The one writer of a stored diagnostic error.

        Scrubs `secrets` from the exception text before it is stored, so a
        header or env value in an exception never reaches `last_error` and the
        surfaces that read it. The caller passes the secret set it captured
        when the operation began, not `child.spec`, because a concurrent
        `update` can swap `child.spec` to a different generation while the
        operation runs; the error text belongs to the generation that produced
        it. The process-wide log secrets join the set, so a token that a
        concurrent refresh rotated while the operation ran is masked too.
        """
        child.last_error = scrub_secrets(text, [*secrets, *_LOG_SECRETS])

    def log_tail(self, key: ServerKey, lines: int = 100) -> str:
        child = self.get(key)
        path = self._log_path(key)
        if not path.exists():
            return ""
        return self._scrub(child, _read_tail(path, lines))
