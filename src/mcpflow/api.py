"""The JSON REST API under `/api`.

This module is a thin adapter, the JSON mirror of the HTML handlers in
`web.py`. Every route parses the body, calls one owner method on `Supervisor`
or `TokenStore`, and serializes the result. No route holds a `try` block: the
sub-app maps every error through `API_EXCEPTION_HANDLERS`, so the adapter holds
no rules. `Supervisor` and `TokenStore` stay the single owners of each write.
"""

from __future__ import annotations

import json

from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import BaseRoute, Route

from .auth import TokenRecord, TokenStore
from .registry import redact_source, spec_from_dict
from .supervisor import Child, Supervisor, ToolView

# --- body reading and serialization ------------------------------------------


async def _json_object(request: Request) -> dict:
    """Read the request body as a JSON object.

    `json.loads` raises `json.JSONDecodeError`, a `ValueError`, on a non-JSON
    body. A JSON value that is not an object (a list, a number) raises
    `ValueError` here. One reader guards every body route, so `spec_from_dict`
    and the visibility handlers never see a `TypeError` the `ValueError`
    mapping would miss.
    """
    data = json.loads(await request.body())
    if not isinstance(data, dict):
        # ValueError, not TypeError: the sub-app maps ValueError to 400. A
        # TypeError would escape that mapping and answer 500 for a client error.
        raise ValueError("request body must be a JSON object")  # noqa: TRY004
    return data


def _bool_field(body: dict, key: str) -> bool:
    value = body.get(key)
    if not isinstance(value, bool):
        # ValueError, not TypeError: it maps to 400 through the sub-app.
        raise ValueError(f"{key} must be a boolean")  # noqa: TRY004
    return value


def _str_field(body: dict, key: str) -> str:
    value = body.get(key)
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{key} is required")
    return value


def child_json(child: Child) -> dict:
    """Serialize a child. `Child` holds a lock, a task, and a transport, so
    the API never dumps it directly; it copies the spec plus the live status.
    `mode="json"` turns `created_at` into a string that `json.dumps` accepts.
    """
    data = child.spec.model_dump(mode="json")
    # Never return the raw credential of a source URL; the API is the one
    # surface a remote client reads.
    data["source"] = redact_source(child.spec.source)
    data["status"] = child.status
    data["last_error"] = child.last_error
    data["tool_count"] = child.tool_count
    data["started_at"] = child.started_at.isoformat() if child.started_at else None
    return data


def tools_json(root_muted: bool, mcpflow_muted: bool, views: list[ToolView]) -> dict:
    """Serialize the dashboard view.

    `mcpflow_muted` carries the namespace level of the built-in admin server. No
    row can carry it: a row `visible` value cannot separate a muted namespace
    from every tool muted one by one. The argument has no default, because a
    default would let one of the three callers report `false` forever.
    """
    return {
        "root_muted": root_muted,
        "mcpflow_muted": mcpflow_muted,
        "tools": [
            {
                "namespace": v.namespace,
                "name": v.name,
                "tool": v.tool,
                "description": v.description,
                "schema_summary": v.schema_summary,
                "status": v.status,
                "visible": v.visible,
                "pinned": v.pinned,
            }
            for v in views
        ],
    }


def _token_json(record: TokenRecord) -> dict:
    """Serialize a token record without its digest."""
    return {
        "id": record.id,
        "name": record.name,
        "scope": record.scope,
        "created_at": record.created_at.isoformat(),
        "last_used_at": (
            record.last_used_at.isoformat() if record.last_used_at else None
        ),
    }


# --- error mapping -----------------------------------------------------------
#
# Four keys, four owners. The three typed keys route to `ExceptionMiddleware`,
# which does not re-raise, so a client error never logs a traceback and never
# raises inside `TestClient`. The `Exception` key routes to
# `ServerErrorMiddleware`, which sends the 500 and then re-raises so the server
# logs the traceback. That split is the point; a single `Exception` key would
# re-raise on every duplicate namespace.


def _err_value(request: Request, exc: Exception) -> Response:
    return JSONResponse({"error": str(exc)}, status_code=400)


def _err_key(request: Request, exc: KeyError) -> Response:
    # `str(KeyError("x"))` is `"'x'"` with quotes, so read `args[0]`.
    return JSONResponse({"error": f"{exc.args[0]} not found"}, status_code=404)


def _err_http(request: Request, exc: HTTPException) -> Response:
    # Keep the router's own 404, 405, and OPTIONS answers as JSON, with the
    # `Allow` header a 405 carries.
    return JSONResponse(
        {"error": exc.detail}, status_code=exc.status_code, headers=exc.headers
    )


def _err_internal(request: Request, exc: Exception) -> Response:
    return JSONResponse({"error": "internal error"}, status_code=500)


API_EXCEPTION_HANDLERS = {
    ValueError: _err_value,
    KeyError: _err_key,
    HTTPException: _err_http,
    Exception: _err_internal,
}


# --- routes ------------------------------------------------------------------


def build_api_routes(supervisor: Supervisor, tokens: TokenStore) -> list[BaseRoute]:
    # --- servers ---------------------------------------------------------

    async def servers_list(request: Request) -> Response:
        return JSONResponse([child_json(c) for c in supervisor.children()])

    async def servers_add(request: Request) -> Response:
        spec = spec_from_dict(await _json_object(request))
        child = await supervisor.add(spec)
        return JSONResponse(child_json(child), status_code=201)

    async def server_get(request: Request) -> Response:
        child = supervisor.get(request.path_params["ns"])
        return JSONResponse(child_json(child))

    async def server_update(request: Request) -> Response:
        ns = request.path_params["ns"]
        body = await _json_object(request)
        # The path namespace wins: a PUT names its resource in the URL, so a
        # body namespace never moves the child.
        body["namespace"] = ns
        spec = spec_from_dict(body)
        child = await supervisor.update(spec)
        return JSONResponse(child_json(child))

    async def server_delete(request: Request) -> Response:
        await supervisor.remove(request.path_params["ns"])
        return Response(status_code=204)

    def _action(op):
        async def handler(request: Request) -> Response:
            ns = request.path_params["ns"]
            await op(ns)
            return JSONResponse(child_json(supervisor.get(ns)))

        return handler

    async def server_log(request: Request) -> Response:
        ns = request.path_params["ns"]
        # A non-integer `lines` raises `ValueError` and answers 400.
        lines = int(request.query_params.get("lines", "100"))
        text = supervisor.log_tail(ns, min(lines, 1000))
        return PlainTextResponse(text, media_type="text/plain")

    # --- tools and visibility -------------------------------------------

    async def _tools_body(request: Request) -> Response:
        views = await supervisor.tools()
        return JSONResponse(
            tools_json(supervisor.root_muted(), supervisor.mcpflow_muted(), views)
        )

    async def visibility_root(request: Request) -> Response:
        supervisor.set_root_muted(_bool_field(await _json_object(request), "muted"))
        return await _tools_body(request)

    async def visibility_namespace(request: Request) -> Response:
        muted = _bool_field(await _json_object(request), "muted")
        supervisor.set_namespace_muted(request.path_params["ns"], muted)
        return await _tools_body(request)

    async def visibility_tool(request: Request) -> Response:
        body = await _json_object(request)
        # The tool name travels in the body, the same as the HTML control: a
        # child names its own tools, and a name in the URL path could
        # normalise into a different route.
        tool = _str_field(body, "tool")
        muted = _bool_field(body, "muted")
        supervisor.set_tool_muted(request.path_params["ns"], tool, muted)
        return await _tools_body(request)

    # --- tokens ----------------------------------------------------------

    async def tokens_list(request: Request) -> Response:
        return JSONResponse([_token_json(r) for r in tokens.list()])

    async def tokens_add(request: Request) -> Response:
        body = await _json_object(request)
        name = str(body.get("name", ""))
        # A missing scope defaults to `mcp`; a bad scope raises `ValueError`
        # in the store, the one owner of the check, and answers 400.
        record, clear = tokens.create(name, body.get("scope", "mcp"))
        payload = _token_json(record)
        payload["token"] = clear
        return JSONResponse(payload, status_code=201)

    async def tokens_delete(request: Request) -> Response:
        tokens.revoke(request.path_params["id"])
        return Response(status_code=204)

    return [
        Route("/servers", servers_list, methods=["GET"]),
        Route("/servers", servers_add, methods=["POST"]),
        Route("/servers/{ns}", server_get, methods=["GET"]),
        Route("/servers/{ns}", server_update, methods=["PUT"]),
        Route("/servers/{ns}", server_delete, methods=["DELETE"]),
        Route("/servers/{ns}/enable", _action(supervisor.enable), methods=["POST"]),
        Route("/servers/{ns}/disable", _action(supervisor.disable), methods=["POST"]),
        Route("/servers/{ns}/restart", _action(supervisor.restart), methods=["POST"]),
        Route("/servers/{ns}/log", server_log, methods=["GET"]),
        Route("/tools", _tools_body, methods=["GET"]),
        Route("/visibility/root", visibility_root, methods=["PUT"]),
        Route("/visibility/namespaces/{ns}", visibility_namespace, methods=["PUT"]),
        Route(
            "/visibility/namespaces/{ns}/tools", visibility_tool, methods=["PUT"]
        ),
        Route("/tokens", tokens_list, methods=["GET"]),
        Route("/tokens", tokens_add, methods=["POST"]),
        Route("/tokens/{id}", tokens_delete, methods=["DELETE"]),
    ]
