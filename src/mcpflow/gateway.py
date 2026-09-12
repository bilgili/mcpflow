"""Assembly and lifespan.

`build_app` wires the registry, the token store, the supervisor, the FastMCP
gateway, and the UI routes into one Starlette app on one port.
"""

from __future__ import annotations

import contextlib
from pathlib import Path

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
from .config import Settings
from .oauth import CredStore, PendingFlows
from .registry import Registry
from .supervisor import Supervisor
from .web import build_routes

_PUBLIC_PREFIXES = ("/health", "/login", "/static/", "/mcp", "/api/", "/.well-known/")


def build_app(settings: Settings) -> Starlette:
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
