"""Assembly and lifespan.

`build_app` wires the registry, the token store, the supervisor, the FastMCP
gateway, and the UI routes into one Starlette app on one port.
"""

from __future__ import annotations

import contextlib
import logging
from pathlib import Path
from urllib.parse import unquote_plus

from fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from .admin_mcp import build_admin_server
from .api import API_EXCEPTION_HANDLERS, build_api_routes
from .auth import AdminTokenGate, HashedTokenVerifier, SessionGate, TokenStore
from .catalog import SECRET_MASK
from .config import Settings
from .identity import LocalIdentityProvider
from .instructions import ChildInstructionsMiddleware
from .oauth import CALLBACK_SECRET_PARAMS, CredStore, PendingFlows
from .policy import AccessPolicy, RuleStore
from .registry import Registry
from .router import CallerRouter
from .supervisor import Supervisor, install_log_redaction
from .usage import UsageMiddleware, UsageStore
from .web import USER_ROUTES, WEB_EXCEPTION_HANDLERS, build_routes

# Bearer-only paths: no cookie, so `SessionGate` exempts them from the
# cross-site check. Each one must also be a public prefix.
_BEARER_PREFIXES: tuple[str, ...] = ("/mcp", "/api/")
_PUBLIC_PREFIXES = ("/health", "/login", "/static/", "/.well-known/", *_BEARER_PREFIXES)

# The SDK client transports log the outgoing `tools/call` request, arguments
# included, at DEBUG. The gateway is the only in-process user of those
# transports, so it owns the one floor: raise each below INFO to INFO, so an
# app-wide DEBUG never traces a posted secret (F2, codex review 3).
_TRANSPORT_LOGGERS = ("mcp.client.sse", "mcp.client.stdio", "mcp.client.streamable_http")


def _pin_transport_log_floor() -> None:
    for name in _TRANSPORT_LOGGERS:
        lg = logging.getLogger(name)
        if lg.level == logging.NOTSET or lg.level < logging.INFO:
            lg.setLevel(logging.INFO)


def _mask_query(target: str) -> str:
    """Mask the value of each credential parameter in a request target.

    Splits like Starlette's `parse_qsl` (`&` only, `unquote_plus` names), so
    every value the callback route reads as `code` or `state` is masked. The
    path, the other parameters, and their order stay as logged.
    """
    path, sep, query = target.partition("?")
    if not sep:
        return target
    pieces = []
    for piece in query.split("&"):
        name = piece.partition("=")[0]
        if unquote_plus(name) in CALLBACK_SECRET_PARAMS:
            piece = f"{name}={SECRET_MASK}"
        pieces.append(piece)
    return f"{path}?{'&'.join(pieces)}"


# The loggers that write an inbound request target, query included:
# `uvicorn.access` (the HTTP request line) and `uvicorn.error` (the WebSocket
# handshake line at INFO, and the websockets `< GET` request line at DEBUG).
_REQUEST_TARGET_LOGGERS = ("uvicorn.access", "uvicorn.error")


class _AccessQueryMask(logging.Filter):
    """Keep the OAuth callback `code`/`state` out of the request-target loggers.

    uvicorn logs the request target, query included, as one item of
    `record.args`. Rewrite every str item rather than a tuple position, so a
    change of uvicorn's argument order opens no gap. Never drops a record.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(
                _mask_query(a) if isinstance(a, str) and "?" in a else a
                for a in record.args
            )
        return True


def _mask_access_log() -> None:
    # Installed before uvicorn applies its logging config: dictConfig replaces
    # a logger's handlers but never removes its filters. Once per process.
    for name in _REQUEST_TARGET_LOGGERS:
        lg = logging.getLogger(name)
        if not any(isinstance(f, _AccessQueryMask) for f in lg.filters):
            lg.addFilter(_AccessQueryMask())


def build_app(settings: Settings) -> Starlette:
    _pin_transport_log_floor()
    _mask_access_log()
    install_log_redaction()
    # Identity first: it creates the bootstrap `admin` on the first start and
    # applies `admin-password.hash` from the data dir, and every later owner
    # asks it.
    identity = LocalIdentityProvider(settings.data_dir / "users.json")
    identity.load()
    if settings.ignored_admin_env:
        logging.getLogger("mcpflow.gateway").warning(
            "%s set but ignored: users.json owns the admin password; "
            "use mcpflow set-admin-password",
            ", ".join(settings.ignored_admin_env),
        )

    tokens = TokenStore(
        settings.data_dir / "tokens.json",
        settings.data_dir / "user_tokens.json",
        max_user_tokens=settings.max_user_tokens,
    )
    tokens.load()

    registry = Registry(
        settings.data_dir / "servers.json",
        settings.data_dir / "user_servers.json",
        max_user_servers=settings.max_user_servers,
    )
    registry.load()

    # The rule store loads after the registry and the token store; the policy
    # reads all four owners and is the one owner of every access decision.
    rules = RuleStore(settings.data_dir / "rules.json")
    rules.load()
    # The usage store does no file I/O until `start`; the policy forgets a
    # re-created user through it (D14).
    usage = UsageStore(settings.data_dir / "usage.sqlite3")
    policy = AccessPolicy(identity, rules, tokens, registry, usage)

    # One credential store and one pending-flow table, shared by the
    # supervisor (the owner of teardown) and the web layer (the owner of the
    # connect and callback routes).
    creds = CredStore(settings.data_dir)
    flows = PendingFlows()

    # The policy exists before the supervisor: the supervisor's read methods
    # take a `Reach`, and the adapters reach the policy through it.
    supervisor = Supervisor(registry, settings, creds, flows, policy)

    gateway = FastMCP(
        "mcpflow",
        auth=HashedTokenVerifier(tokens, identity),
        mask_error_details=True,
    )
    # D5: the router is the one gateway provider of the children and the only
    # reader of `supervisor.table`. It serves each request the components of
    # its caller's `Reach`; the table is never mounted here.
    gateway.add_provider(CallerRouter(supervisor, policy))
    # Each new session carries the live instructions of the running children
    # that the session's user may reach.
    gateway.add_middleware(ChildInstructionsMiddleware(supervisor, policy))
    # Counts each `tools/call` that a child tool answers (D1, D3).
    gateway.add_middleware(UsageMiddleware(usage, policy))

    # Mount the built-in admin server beside the router. The
    # supervisor owns the whole provider chain, the namespace `mcpflow` included,
    # so the rule "a visibility transform matches the bare tool name" has one
    # owner. `add_provider` therefore takes no `namespace` keyword: a keyword
    # here would apply a second namespace on top of the one in the chain.
    # The supervisor holds the mount outside its child map, so no lifecycle op
    # can remove it and it never enters `servers.json`.
    gateway.add_provider(supervisor.register_builtin(build_admin_server(supervisor)))

    mcp_app = gateway.http_app(path="/mcp")

    # F1: FastMCP 4.2 keeps one server-wide input-schema cache keyed by the wire
    # tool name. `ns@user` servers share names, so one caller's listing would decide
    # another caller's `Mcp-Param-*` check. The SDK hook is not caller-scoped. With
    # no hook the SDK checks against the caller's own `tools/list`, and
    # `CallerRouter` owns that view. The guard fires when FastMCP stops setting
    # the old name (it follows an SDK rename): its hook would then stay live under
    # the new name. An SDK-only rename leaves the SDK hook unset, which is safe.
    if not hasattr(gateway._mcp_server, "get_tool_input_schema"):
        raise RuntimeError("FastMCP no longer has get_tool_input_schema; re-check F1")
    gateway._mcp_server.get_tool_input_schema = None

    async def health(request: Request) -> JSONResponse:
        counts = {"running": 0, "failed": 0, "starting": 0}
        for child in supervisor.children():
            if child.status in counts:
                counts[child.status] += 1
        return JSONResponse({"status": "ok", "children": counts})

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette):
        # D7: the store outlives the MCP app. Its exit waits for every MCP
        # request task, so the last `record` runs before the final flush.
        await usage.start()
        try:
            async with mcp_app.lifespan(app):
                await supervisor.startup()
                try:
                    yield
                finally:
                    await supervisor.shutdown()
        finally:
            await usage.stop()

    static_dir = Path(__file__).parent / "static"

    # The `/api` sub-app carries its own gate and error handlers. `AdminTokenGate`
    # owns the bearer check; `SessionGate` skips `/api/` through the public
    # prefix, and `/api/` is a bearer prefix, exempt from the cross-site
    # check. Mount it before `Mount("/", mcp_app)`, whose catch-all would
    # otherwise swallow every `/api` path.
    api_app = Starlette(
        routes=build_api_routes(supervisor),
        middleware=[Middleware(AdminTokenGate, store=tokens, identity=identity)],
        exception_handlers=API_EXCEPTION_HANDLERS,
    )

    app = Starlette(
        routes=[
            Route("/health", health),
            *build_routes(supervisor, tokens, settings, creds, flows, identity, usage),
            Mount("/static", app=StaticFiles(directory=static_dir), name="static"),
            Mount("/api", app=api_app),
            Mount("/", app=mcp_app),
        ],
        middleware=[
            Middleware(
                SessionGate,
                secret=settings.secret_key,
                identity=identity,
                public_prefixes=_PUBLIC_PREFIXES,
                user_routes=USER_ROUTES,
                bearer_prefixes=_BEARER_PREFIXES,
            )
        ],
        # A write-time refusal that leaves a web route answers 403 (the
        # `/api` sub-app answers its own first).
        exception_handlers=WEB_EXCEPTION_HANDLERS,
        lifespan=lifespan,
    )
    # The supervisor is the app's live state. Exposing it here keeps the
    # assembly introspectable without a second lookup path. The registry is
    # deliberately NOT exposed: a writer that bypasses the supervisor would
    # change the persisted policy without applying it to the live transforms.
    app.state.supervisor = supervisor
    # The policy is the one writer of rules.json, so exposing it opens no
    # bypass. The supervisor holds the same object.
    app.state.policy = policy
    return app
