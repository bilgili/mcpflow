"""Child lifecycle, transports, and the mount table.

The supervisor owns one `AggregateProvider` mount table. For each running
child it appends one namespaced `ProxyProvider` and removes it on stop. The
public operation owns the status transition; `_teardown` owns the mechanics.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from fastmcp import Client, FastMCP
from fastmcp.client.transports import (
    ClientTransport,
    SSETransport,
    StdioTransport,
    StreamableHttpTransport,
)
from fastmcp.server.providers import AggregateProvider, FastMCPProvider, Provider
from fastmcp.server.providers.proxy import ProxyProvider
from fastmcp.server.transforms import Namespace, Visibility

from .catalog import SECRET_MASK
from .config import Settings
from .oauth import ClientCreds, CredStore, HeaderSpec, PendingFlow, PendingFlows
from .registry import (
    PINNED_ADMIN_TOOLS,
    RESERVED_NAMESPACE,
    Registry,
    RegistryError,
    ServerSpec,
    build_command,
    source_secrets,
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
    if not schema:
        return ""
    props = schema.get("properties", {})
    parts = [f"{name}: {spec.get('type', 'any')}" for name, spec in props.items()]
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
    ) -> None:
        self.registry = registry
        self.settings = settings
        self.creds = creds
        self.flows = flows
        self.sources = SourceStore(settings.data_dir / "servers")
        self.table = AggregateProvider(provider_error_strategy="warn")
        self._children: dict[str, Child] = {
            spec.namespace: _new_child(spec) for spec in registry.list()
        }
        # Namespaces a `remove` holds until its teardown returns. Separate from
        # `_children`, which `remove` empties before the await so `children()`
        # never lists a half torn down child. A reclaim inside that window
        # would let the old process write a file the replacement inherits, so
        # `add` refuses a namespace this set holds.
        self._removing: set[str] = set()
        # The built-in admin server. It is deliberately NOT a `_children`
        # entry: `startup` starts every child, `set_root_muted` applies the
        # root to every child, `children()` publishes every child to
        # `/servers` and to `mcpflow_list_servers`, and `remove` accepts every
        # child key. None of the four may reach the built-in mount.
        self._builtin: FastMCP | None = None
        self._builtin_visibility: Visibility | None = None

    # --- environment, command, transport ---------------------------------

    def _build_env(self, spec: ServerSpec) -> dict[str, str]:
        env = dict(os.environ)
        for key in _SCRUB:
            env.pop(key, None)
        for key in [k for k in env if k.startswith("UV_PUBLISH_")]:
            del env[key]
        env.update(spec.env)
        return env

    def _log_path(self, namespace: str):
        return self.settings.data_dir / "logs" / f"{namespace}.log"

    def _build_transport(self, spec: ServerSpec) -> ClientTransport:
        if spec.kind == "remote":
            if spec.transport == "sse":
                return SSETransport(spec.url, headers=spec.headers)
            return StreamableHttpTransport(spec.url, headers=spec.headers)
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
        log_path = self._log_path(spec.namespace)
        log_path.write_text("")  # truncate on each start
        return StdioTransport(
            command=command,
            args=args,
            env=self._build_env(spec),
            keep_alive=True,
            log_file=log_path,
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
        return (
            ProxyProvider(self._make_factory(child.transport))
            .wrap_transform(visibility)
            .wrap_transform(Namespace(child.spec.namespace))
        )

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

    def _make_factory(self, transport: ClientTransport):
        timeout = self.settings.child_start_timeout

        def factory() -> Client:
            return Client(transport, timeout=timeout)

        return factory

    # --- lifecycle -------------------------------------------------------

    async def startup(self) -> None:
        for child in self._children.values():
            if child.spec.enabled:
                child.status = "starting"
                child.task = asyncio.create_task(self._run_start(child.spec.namespace))
            else:
                child.status = "stopped"

    async def shutdown(self) -> None:
        for child in list(self._children.values()):
            await self._teardown(child)

    def children(self) -> list[Child]:
        return list(self._children.values())

    def get(self, namespace: str) -> Child:
        return self._children[namespace]

    async def _run_start(self, namespace: str) -> None:
        child = self._children[namespace]
        spec = child.spec
        # The secret set of this generation, captured before the probe. A
        # concurrent `update` cancels this task, so its error is normally never
        # stored; the capture keeps the scrub correct even so.
        secrets = self._secrets_of(spec)
        try:
            try:
                transport = self._build_transport(spec)
                child.transport = transport
                async with asyncio.timeout(self.settings.child_start_timeout):
                    async with Client(
                        transport, timeout=self.settings.child_start_timeout
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
                child.last_error = None
                child.status = "running"
        finally:
            # Clear the in-flight task, but only when it is still this task.
            # A concurrent teardown/restart may have installed a newer task.
            if child.task is asyncio.current_task():
                child.task = None

    def _still_current(self, namespace: str, child: Child) -> None:
        """Fail if this child is no longer the one that owns the namespace.

        A mutator resolves its child before it awaits `child.lock`, so a
        queued waiter can hold a generation that a completed `remove` already
        dropped and a later `add` already replaced. The lock of a dead
        generation is uncontended, so the waiter would wake and mutate the
        registry and `_children` entries of the replacement while tearing
        down its own stale object.

        The lock cannot prevent this on its own: it belongs to the `Child`,
        so it serialises one generation, not the namespace. Re-check identity
        after acquiring it.
        """
        if self._children.get(namespace) is not child:
            raise RegistryError(
                f"{namespace} changed while the operation waited; try again"
            )

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

        It is not total against `BaseException`, and it does not promise the
        subprocess died. A close that raises `Exception` or `CancelledError`
        is swallowed and the transport handle dropped anyway, so a wedged
        child can outlive the gateway's record of it; another `BaseException`
        escapes before the handle is dropped. Both gaps predate the caller
        ordering and neither is addressed here.
        """
        if child.task is not None:
            child.task.cancel()
            try:
                await child.task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001, S110 -- best-effort teardown
                pass
            child.task = None
        if child.provider is not None and child.provider in self.table.providers:
            self.table.providers.remove(child.provider)
        child.provider = None
        child.visibility = None
        if child.transport is not None:
            try:
                await child.transport.close()
            except (asyncio.CancelledError, Exception):  # noqa: BLE001, S110 -- see the docstring
                pass
            child.transport = None

    # --- public operations ----------------------------------------------

    def _check_source(self, spec: ServerSpec) -> None:
        """Reject a source under the store root that is not this namespace's.

        A source that resolves inside `DATA_DIR/servers` must resolve to
        exactly this namespace's own directory. One guard for every write path
        (form, REST, admin MCP), so no child runs from another child's tree
        and no `remove` deletes a directory a sibling owns. `RegistryError` is
        a `ValueError`, so the REST layer answers 400 and the admin tool a
        `ToolError` with no new mapping.
        """
        owner = self.sources.owner_of(spec.source)
        if owner is not None and not self.sources.owns(spec.source, spec.namespace):
            root = self.sources.root
            if owner == "":
                raise RegistryError(
                    f"source: {spec.source} is inside DATA_DIR/servers but is "
                    f"not {root}/{spec.namespace}"
                )
            raise RegistryError(
                f"source: {spec.source} belongs to namespace {owner}"
            )

    def _check_creds(
        self, namespace: str, enabled: bool, oauth_pending: bool = False
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
        if enabled and (self.creds.awaiting(namespace) or oauth_pending):
            raise RegistryError(
                f"{namespace} awaits authorization; delete it and connect again"
            )

    async def add(
        self,
        spec: ServerSpec,
        client_fmt: str | None = None,
        client: ClientCreds | None = None,
    ) -> Child:
        """Register a child, and for an OAuth connect write its client file.

        `client_fmt` and `client` carry the file sink's client credentials, so
        the register and the write happen here with no `await` between them.
        The web layer must not do that pair itself: `add` awaits the child lock
        after the install, and a `remove` that interleaves there would leave a
        `client.json` for a namespace the registry no longer lists.
        """
        ns = spec.namespace
        if ns in self._removing:
            # A `remove` holds the namespace until its teardown returns. Its
            # old process may still be alive and may still write its token
            # file, which a replacement registered now would inherit.
            raise RegistryError(f"namespace {ns} is being removed")
        self._check_source(spec)
        self._check_creds(ns, spec.enabled, spec.oauth_pending)
        self.registry.add(spec)
        # `registry.add` raises on a duplicate, so reaching here proves the
        # namespace was free, so any credential directory under it is residue
        # of a removal that a restart interrupted. Delete it AFTER that proof,
        # never before: before it, a duplicate `add` would delete the live
        # child's credential and only then raise. No `await` from the registry
        # write to the install below, so nothing can interleave.
        self.creds.remove(ns)
        child = _new_child(spec)
        self._children[spec.namespace] = child
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
            self.creds.write_client(ns, client_fmt, client)
        async with child.lock:
            if spec.enabled:
                child.status = "starting"
                child.task = asyncio.create_task(self._run_start(spec.namespace))
            else:
                child.status = "stopped"
        return child

    async def update(self, spec: ServerSpec) -> Child:
        child = self._children[spec.namespace]
        async with child.lock:
            self._still_current(spec.namespace, child)
            self._check_source(spec)
            # oauth_pending is registry-owned and preserved by registry.update,
            # so an edit that omits it (defaulting False) must not lower the
            # guard: read the stored value, not the incoming spec's.
            self._check_creds(
                spec.namespace, spec.enabled, child.spec.oauth_pending
            )
            old_secrets = set(self._secrets_of(child.spec))
            self.registry.update(spec)
            await self._teardown(child)
            # `registry.update` merges the visibility state and `created_at`
            # into the stored record. Read it back: installing the incoming
            # `spec` here would drop the merge, and `_build_provider` reads
            # `child.spec`, so the restart would republish a muted tool.
            child.spec = self.registry.get(spec.namespace)
            if spec.enabled:
                child.status = "starting"
                child.task = asyncio.create_task(self._run_start(spec.namespace))
            else:
                # A restart truncates the log in `_build_transport`, so the
                # enabled branch drops prior-generation output. The disabled
                # branch does not restart. When the secret set changed, the
                # retained log holds a secret that `_scrub` can no longer mask
                # (it is no longer in `child.spec`), so discard the log. Only
                # local children have one; `missing_ok` covers a remote child.
                child.status = "stopped"
                if set(self._secrets_of(child.spec)) != old_secrets:
                    self._log_path(spec.namespace).unlink(missing_ok=True)
        return child

    async def remove(self, namespace: str) -> None:
        child = self._children[namespace]
        async with child.lock:
            self._still_current(namespace, child)
            # Write first, like the other persisted lifecycle mutators here.
            # Tearing down first and then failing the write would unpublish
            # the provider and drop the transport handle while the registry still
            # listed the child and its status still read `running`, and
            # nothing could repair that. The mirror exposure is narrower, not
            # absent: `_teardown` swallows `Exception` and `CancelledError`,
            # so no ordinary failure returns control part-way, but another
            # `BaseException` still escapes. See its docstring.
            self.registry.remove(namespace)
            # Reserve the namespace for the rest of this removal. Not at the
            # entry of this method: the first `await` here is the child lock
            # above, so reserving at entry would hold the namespace while this
            # call queues behind another operation that `_still_current` may
            # then reject anyway.
            self._removing.add(namespace)
            try:
                # Drop the open flow and the credential files in the same
                # window, right after the registry write and before the first
                # `await`. A callback that arrives after this would otherwise
                # write a token file for a namespace that no longer exists, or
                # enable a reconnected child with a token issued to the old
                # client. `discard` and `remove` are both no-ops when absent.
                # This delete runs while the process is still up: it is the one
                # stated exception to "touch a credential only while no process
                # of that namespace runs", and it races only the file of the
                # child being removed.
                self.flows.discard(namespace)
                self.creds.remove(namespace)
                # Drop the child before the first await, so `children()` never
                # sees a child that is half torn down. Nothing between the
                # write and the `del` suspends.
                child.status = "stopped"
                del self._children[namespace]
                await self._teardown(child)
                # Delete again now the teardown has closed the transport. A
                # child that rewrites its own token file, as one that refreshes
                # its access token does, can have recreated `token.json` after
                # the first delete; `rmtree(ignore_errors=True)` reports
                # nothing. No child-table guard: the reservation admits no
                # replacement, so there is nothing here to protect.
                self.creds.remove(namespace)
                # Same for the source directory, and for the same reason it
                # waits for the teardown: no delete pulls files out from under
                # a live process. `owns` answers whether the directory is ours
                # to delete at all, since a `source` may name a foreign path.
                if self.sources.owns(child.spec.source, namespace):
                    self.sources.remove(namespace)
            finally:
                # Release whatever the teardown or the deletes did. An `OSError`
                # from the source delete propagates with the namespace free.
                self._removing.discard(namespace)

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
        token and the awaiting flag flip in one atomic `servers.json` write. No
        file is written.

        Then, for connect enable a `stopped` child; for re-auth restart only a
        child the registry still says is enabled (a disable during the flow is
        honored — never force-enable).

        Returns `True` when applied, `False` when the flow was gone (removed or
        expired during the exchange) or the child changed.
        """
        namespace = flow.namespace
        child = self._children.get(namespace)
        if child is None:
            # The child was removed during the exchange; its flow is already
            # discarded. Consume the state in case it somehow survived.
            self.flows.pop(flow.state)
            return False
        async with child.lock:
            if self._children.get(namespace) is not child:
                # A remove-then-add replaced the child during the exchange.
                self.flows.pop(flow.state)
                return False
            if self.flows.pop(flow.state) is None:
                # Removed or expired during the exchange: write nothing.
                return False
            if header is not None:
                # Header sink: one registry write sets the header AND clears
                # oauth_pending, so the token and the awaiting flag flip in one
                # atomic write. `update` preserves oauth_pending, so this uses
                # the dedicated `set_oauth_header`. No file is written.
                self.registry.set_oauth_header(
                    namespace,
                    header.name,
                    f"{header.scheme} {tokens['access_token']}",
                )
                child.spec = self.registry.get(namespace)
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
                # File sink: client before token, no await between, so the old
                # token survives until the new one replaces it. The teardown
                # moved in front of the pair, never between it.
                if client_fmt is not None:
                    self.creds.write_client(namespace, client_fmt, flow.client)
                self.creds.write_token(namespace, token_fmt, tokens)
            if reauth:
                # Restart to load the new token, but only when the child is
                # still enabled. A disable during the flow is honored.
                if self.registry.get(namespace).enabled:
                    await self._teardown(child)
                    child.spec = self.registry.get(namespace)
                    child.status = "starting"
                    child.task = asyncio.create_task(self._run_start(namespace))
                else:
                    child.status = "stopped"
            elif child.status == "stopped":
                # Connect: the credential now exists, so `_check_creds` passes.
                self.registry.set_enabled(namespace, True)
                child.spec = self.registry.get(namespace)
                child.status = "starting"
                child.task = asyncio.create_task(self._run_start(namespace))
        return True

    async def enable(self, namespace: str) -> None:
        child = self._children[namespace]
        async with child.lock:
            self._still_current(namespace, child)
            # Idempotent: enable states an end state ("this child is on"), not
            # a transition. A child that is not `stopped` already meets it, so
            # enabling it again is a no-op. Starting a second task here would
            # let `_run_start` overwrite the live `child.transport` and append
            # a duplicate provider, leaking the old transport and its
            # subprocess. `restart` owns bouncing a `running` or `failed`
            # child; `enable` only turns a `stopped` one on.
            if child.status != "stopped":
                return
            self._check_creds(namespace, True, child.spec.oauth_pending)
            self.registry.set_enabled(namespace, True)
            child.spec = self.registry.get(namespace)
            child.status = "starting"
            child.task = asyncio.create_task(self._run_start(namespace))

    async def disable(self, namespace: str) -> None:
        child = self._children[namespace]
        async with child.lock:
            self._still_current(namespace, child)
            self.registry.set_enabled(namespace, False)
            child.spec = self.registry.get(namespace)
            await self._teardown(child)
            child.status = "stopped"

    async def restart(self, namespace: str) -> None:
        child = self._children[namespace]
        async with child.lock:
            self._still_current(namespace, child)
            if child.status not in ("running", "failed"):
                raise RegistryError(f"{namespace} is not running; enable it instead")
            await self._teardown(child)
            child.status = "starting"
            child.task = asyncio.create_task(self._run_start(namespace))

    async def write_source(self, namespace: str, files: dict[str, str]) -> SourceWrite:
        """Write a source tree, then restart a `running` or `failed` child.

        The store write comes first and never awaits, so the swap completes
        before any restart starts (no interleave puts a restart between staging
        and swap). A `starting` child is not restarted: `restart` refuses it
        and the agent calls `mcpflow_restart_server` once it settles. A `stopped`
        child is not restarted: `enabled` owns the process, and a write must
        not turn a disabled child on. An orphan write (no child yet) returns
        `restarted=False`; the agent then calls `mcpflow_add_server`.
        """
        path = self.sources.write(namespace, files)
        restarted = False
        child = self._children.get(namespace)
        if child is not None and child.status in ("running", "failed"):
            # `restart` may still raise RegistryError if the child moved
            # between this check and its lock; the files are already written,
            # so the agent retries only the restart.
            await self.restart(namespace)
            restarted = True
        return SourceWrite(
            namespace=namespace,
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

    def set_root_muted(self, muted: bool) -> None:
        self.registry.set_root_muted(muted)
        # `children()` is a list copy, so a concurrent remove cannot raise.
        for child in self.children():
            self._apply(child)

    def mcpflow_muted(self) -> bool:
        return self.registry.admin_muted()

    def set_namespace_muted(self, namespace: str, muted: bool) -> None:
        # The built-in namespace first, before the child lookup: it has no
        # `Child` and no `ServerSpec`. Both branches stay synchronous and
        # lock-free. There is no await between the assignments, so no
        # coroutine can observe a half-applied state.
        if namespace == RESERVED_NAMESPACE:
            self.registry.set_admin_muted(muted)
            self._apply_builtin()
            return
        child = self._children[namespace]
        self.registry.set_muted(namespace, muted)
        child.spec = self.registry.get(namespace)
        self._apply(child)

    def set_tool_muted(self, namespace: str, tool: str, muted: bool) -> None:
        """Mute or unmute one tool. `tool` is the bare child tool name."""
        if namespace == RESERVED_NAMESPACE:
            self.registry.set_admin_tool_muted(tool, muted)
            self._apply_builtin()
            return
        child = self._children[namespace]
        self.registry.set_tool_muted(namespace, tool, muted)
        child.spec = self.registry.get(namespace)
        self._apply(child)

    # --- reads -----------------------------------------------------------

    async def tools(self) -> list[ToolView]:
        # Probe every running child concurrently: dashboard latency becomes the
        # slowest single probe, not the sum. gather preserves input order, so
        # the flattened result keeps namespace-then-tool ordering. The built-in
        # rows come first, because that group has no child behind it.
        running = [c for c in self.children() if c.status == "running"]
        results = await asyncio.gather(*(self._probe_child(c) for c in running))
        return [
            *await self._builtin_views(),
            *(view for sub in results for view in sub),
        ]

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
                )
            )
        return views

    async def _probe_child(self, child: Child) -> list[ToolView]:
        namespace = child.spec.namespace
        # Capture the secret set of this generation before the await. A
        # concurrent `update` can swap `child.spec` while `list_tools` runs, so
        # a post-await read would scrub the failure text with the wrong
        # generation's secrets and leak this one's.
        secrets = self._secrets_of(child.spec)
        # This client talks to the child, not through the mount table, so the
        # visibility transform does not apply here. That is load-bearing: the
        # dashboard must list a muted tool to offer the control that unmutes
        # it. Do not route this read through the table.
        try:
            async with Client(
                child.transport, timeout=self.settings.child_start_timeout
            ) as c:
                tools = await c.list_tools()
            # Resolve the policy after the await, so one rendered tree never
            # mixes a pre-await policy with a post-await tool inventory.
            hide_all, hidden = self.registry.visibility(child.spec)
            views: list[ToolView] = []
            for tool in tools:
                schema = getattr(tool, "input_schema", None) or getattr(
                    tool, "inputSchema", None
                )
                views.append(
                    ToolView(
                        namespace=namespace,
                        name=f"{namespace}_{tool.name}",
                        description=tool.description or "",
                        schema_summary=_summarize_schema(schema),
                        status="running",
                        tool=tool.name,
                        visible=_visible(False, hide_all, hidden, tool.name),
                    )
                )
            return views
        except Exception as exc:  # noqa: BLE001 -- one child's error must not stop the others
            async with child.lock:
                # Re-check under the lock: a concurrent disable/stop may have
                # left "running". Do not clobber that transition.
                if child.status != "running":
                    return []
                child.status = "failed"
                self._record_error(child, str(exc) or repr(exc), secrets)
                if (
                    child.provider is not None
                    and child.provider in self.table.providers
                ):
                    self.table.providers.remove(child.provider)
                child.provider = None
                child.visibility = None
            return []

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
        it.
        """
        child.last_error = scrub_secrets(text, secrets)

    def log_tail(self, namespace: str, lines: int = 100) -> str:
        child = self.get(namespace)
        path = self._log_path(child.spec.namespace)
        if not path.exists():
            return ""
        return self._scrub(child, _read_tail(path, lines))
