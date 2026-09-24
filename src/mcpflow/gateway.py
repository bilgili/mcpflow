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
from .instructions import ChildInstructionsMiddleware
from .oauth import CALLBACK_SECRET_PARAMS, CredStore, PendingFlows
from .registry import Registry
from .supervisor import Supervisor, install_log_redaction
from .web import build_routes

_PUBLIC_PREFIXES = ("/health", "/login", "/static/", "/mcp", "/api/", "/.well-known/")

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
    registry = Registry(settings.data_dir / "servers.json")
    registry.load()

    tokens = TokenStore(settings.data_dir / "tokens.json")
    tokens.load()

    # One credential store and one pending-flow table, shared by the
    # supervisor (the owner of teardown) and the web layer (the owner of the
    # connect and callback routes).
    creds = CredStore(settings.data_dir)
    flows = PendingFlows()

    supervisor = Supervisor(registry, settings, creds, flows)

    gateway = FastMCP(
        "mcpflow",
        auth=HashedTokenVerifier(tokens),
        mask_error_details=True,
    )
    gateway.add_provider(supervisor.table)
    # Each new session carries the live instructions of the running children.
    gateway.add_middleware(ChildInstructionsMiddleware(supervisor))

    # Mount the built-in admin server beside the aggregate table. The
    # supervisor owns the whole provider chain, the namespace `mcpflow` included,
    # so the rule "a visibility transform matches the bare tool name" has one
    # owner. `add_provider` therefore takes no `namespace` keyword: a keyword
    # here would apply a second namespace on top of the one in the chain.
    # The supervisor holds the mount outside its child map, so no lifecycle op
    # can remove it and it never enters `servers.json`.
    gateway.add_provider(supervisor.register_builtin(build_admin_server(supervisor)))

    mcp_app = gateway.http_app(path="/mcp")

    async def health(request: Request) -> JSONResponse:
        counts = {"running": 0, "failed": 0, "starting": 0}
        for child in supervisor.children():
            if child.status in counts:
                counts[child.status] += 1
        return JSONResponse({"status": "ok", "children": counts})

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette):
        async with mcp_app.lifespan(app):
            await supervisor.startup()
            try:
                yield
            finally:
                await supervisor.shutdown()

    static_dir = Path(__file__).parent / "static"

    # The `/api` sub-app carries its own gate and error handlers. `AdminTokenGate`
    # owns the bearer check; `SessionGate` skips `/api/` through the public
    # prefix. Mount it before `Mount("/", mcp_app)`, whose catch-all would
    # otherwise swallow every `/api` path.
    api_app = Starlette(
        routes=build_api_routes(supervisor, tokens),
        middleware=[Middleware(AdminTokenGate, store=tokens)],
        exception_handlers=API_EXCEPTION_HANDLERS,
    )

    app = Starlette(
        routes=[
            Route("/health", health),
            *build_routes(supervisor, tokens, settings, creds, flows),
            Mount("/static", app=StaticFiles(directory=static_dir), name="static"),
            Mount("/api", app=api_app),
            Mount("/", app=mcp_app),
        ],
        middleware=[
            Middleware(
                SessionGate,
                secret=settings.secret_key,
                password_hash=settings.admin_password_hash,
                public_prefixes=_PUBLIC_PREFIXES,
            )
        ],
        lifespan=lifespan,
    )
    # The supervisor is the app's live state. Exposing it here keeps the
    # assembly introspectable without a second lookup path. The registry is
    # deliberately NOT exposed: a writer that bypasses the supervisor would
    # change the persisted policy without applying it to the live transforms.
    app.state.supervisor = supervisor
    return app
