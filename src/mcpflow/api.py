"""The JSON REST API under `/api`.

This module is a thin adapter, the JSON mirror of the HTML handlers in
`web.py`. Every route parses the body, calls one owner method on `Supervisor`
or `AccessPolicy` with the user of the request as the actor, and serializes
the result. No route holds a `try` block: the sub-app maps every error through
`API_EXCEPTION_HANDLERS`, and `errors.refusal` owns the status, so the adapter
holds no rules. `AdminTokenGate` puts the user into `request.state.user`.

No body holds a secret: no token digest, no password hash, and a server
record only through `redact_spec`. The clear token appears once, in the
create answer; a setup code appears once, in the user create and reset
answers. No body sets a password: each user chooses their own.
"""

from __future__ import annotations

import json

from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import BaseRoute, Route

from .auth import TokenRecord
from .errors import REFUSALS, refusal
from .identity import User
from .policy import GrantRule
from .registry import ServerKey, redact_spec, revision, spec_from_dict
from .supervisor import Child, RevisionConflict, Supervisor, ToolView

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
    spec = child.spec
    # Never return a raw credential: `redact_spec` is the one outward view of a
    # stored record (source and url credentials, every env/header value). REST
    # and every admin MCP tool that returns a child go through here.
    # `Registry.update` keeps the stored value when a write echoes the mask.
    # `approved_revision` stays internal: `approval` and `revision` derive
    # from it, and a client posts `revision` back to approve. Both derive
    # from the STORED spec, never the masked view, so the revision a client
    # reads is the one `approve` compares against.
    data = redact_spec(spec).model_dump(mode="json", exclude={"approved_revision"})
    data["ref"] = spec.key.ref
    data["approval"] = spec.approval
    data["revision"] = None if spec.owner is None else revision(spec)
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
                # `github` and `github@alice` share a namespace; `ref` names the
                # row's server for the `{ref}` routes, `owner` its owner.
                "ref": v.ref,
                "owner": v.owner,
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
        "user_id": record.user_id,
        "created_at": record.created_at.isoformat(),
        "last_used_at": (
            record.last_used_at.isoformat() if record.last_used_at else None
        ),
    }


def _user_json(user: User) -> dict:
    """A user without any credential: `User` holds no password hash and no
    setup code. `pending` is a status: the user has not set a password yet."""
    return {
        "id": user.id,
        "name": user.name,
        "admin": user.is_admin,
        "groups": sorted(user.groups),
        "pending": user.pending,
    }


def _refuse_password(body: dict) -> None:
    # A silent ignore would let a client believe it set a password (D8).
    if "password" in body:
        raise ValueError(
            "password: users set their own password with a setup code; "
            "use POST /api/users/{id}/setup-code to reset one"
        )


def _rule_json(rule: GrantRule) -> dict:
    return {
        "id": rule.id,
        "subject_kind": rule.subject_kind,
        "subject": rule.subject,
        "level": rule.level,
        "server": rule.server,
        "tool": rule.tool,
        "effect": rule.effect,
        "created_at": rule.created_at.isoformat(),
    }


# --- error mapping -----------------------------------------------------------
#
# The typed keys route to `ExceptionMiddleware`, which does not re-raise, so a
# client error never logs a traceback and never raises inside `TestClient`. The
# `Exception` key routes to `ServerErrorMiddleware`, which sends the 500 and
# then re-raises so the server logs the traceback. That split is the point; a
# single `Exception` key would re-raise on every duplicate namespace.


def _err_refusal(request: Request, exc: Exception) -> Response:
    status, text = refusal(exc)
    body = {"error": text}
    if isinstance(exc, RevisionConflict):
        body["revision"] = exc.revision  # the stored revision (F1)
    return JSONResponse(body, status_code=status)


def _err_http(request: Request, exc: HTTPException) -> Response:
    # Keep the router's own 404, 405, and OPTIONS answers as JSON, with the
    # `Allow` header a 405 carries.
    return JSONResponse(
        {"error": exc.detail}, status_code=exc.status_code, headers=exc.headers
    )


def _err_internal(request: Request, exc: Exception) -> Response:
    return JSONResponse({"error": "internal error"}, status_code=500)


API_EXCEPTION_HANDLERS = {
    **{cls: _err_refusal for cls in REFUSALS},
    HTTPException: _err_http,
    Exception: _err_internal,
}


# --- routes ------------------------------------------------------------------


def _key(request: Request) -> ServerKey:
    """The key the `{ref}` path segment names. A reference that
    `ServerKey.parse` refuses names no child, so it answers 404."""
    ref = request.path_params["ref"]
    try:
        return ServerKey.parse(ref)
    except ValueError:
        raise KeyError(ref) from None


def _str_list(body: dict, key: str) -> list[str]:
    value = body.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"{key} must be a list of strings")
    return value


def _opt_str(body: dict, key: str) -> str | None:
    value = body.get(key)
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{key} must be a string")
    return value


def build_api_routes(supervisor: Supervisor) -> list[BaseRoute]:
    policy = supervisor.policy

    def actor(request: Request) -> User:
        # `AdminTokenGate` resolved it; every write passes it to its owner.
        return request.state.user

    # --- servers ---------------------------------------------------------

    async def servers_list(request: Request) -> Response:
        return JSONResponse([child_json(c) for c in supervisor.children()])

    async def servers_add(request: Request) -> Response:
        # `Supervisor.add` stamps the owner from the actor (an admin: owner
        # `None`), so a body `owner` or `approved_revision` has no effect, and
        # `approval` and `revision` are not spec fields.
        spec = spec_from_dict(await _json_object(request))
        child = await supervisor.add(spec, actor(request))
        return JSONResponse(child_json(child), status_code=201)

    async def server_get(request: Request) -> Response:
        child = supervisor.get(_key(request))
        return JSONResponse(child_json(child))

    async def server_update(request: Request) -> Response:
        key = _key(request)
        body = await _json_object(request)
        # The path reference wins: a PUT names its resource in the URL, so a
        # body namespace never moves the child. `update` stamps the owner
        # from the key and keeps the stored approval.
        body["namespace"] = key.namespace
        spec = spec_from_dict(body)
        child = await supervisor.update(key, spec, actor(request))
        return JSONResponse(child_json(child))

    async def server_delete(request: Request) -> Response:
        await supervisor.remove(_key(request), actor(request))
        return Response(status_code=204)

    def _action(op):
        async def handler(request: Request) -> Response:
            key = _key(request)
            await op(key, actor(request))
            return JSONResponse(child_json(supervisor.get(key)))

        return handler

    async def server_log(request: Request) -> Response:
        # A non-integer `lines` raises `ValueError` and answers 400.
        lines = int(request.query_params.get("lines", "100"))
        text = supervisor.log_tail(_key(request), min(lines, 1000))
        return PlainTextResponse(text, media_type="text/plain")

    # --- approvals -------------------------------------------------------

    async def approvals_list(request: Request) -> Response:
        return JSONResponse(
            [child_json(c) for c in supervisor.children() if c.spec.approval == "pending"]
        )

    async def server_approve(request: Request) -> Response:
        key = _key(request)
        supervisor.get(key)  # an unknown child answers 404 before the body
        # An empty body is a missing revision, not a malformed one.
        body = await _json_object(request) if await request.body() else {}
        posted = body.get("revision")
        if not isinstance(posted, str):
            raise ValueError("revision is required")  # noqa: TRY004 -- maps to 400
        # `approve` refuses an admin-owned child (400) before it compares the
        # revision (409), and changes nothing on either refusal.
        child = await supervisor.approve(key, posted, actor(request))
        return JSONResponse(child_json(child))

    # --- tools and visibility -------------------------------------------

    async def _tools_body(request: Request) -> Response:
        # `AdminTokenGate` set the user; `/api` reads the `dashboard` surface.
        reach = policy.keys_for(actor(request), "dashboard")
        views = await supervisor.tools(reach)
        return JSONResponse(
            tools_json(supervisor.root_muted(), supervisor.mcpflow_muted(), views)
        )

    async def visibility_root(request: Request) -> Response:
        muted = _bool_field(await _json_object(request), "muted")
        supervisor.set_root_muted(muted, actor(request))
        return await _tools_body(request)

    async def visibility_namespace(request: Request) -> Response:
        muted = _bool_field(await _json_object(request), "muted")
        supervisor.set_namespace_muted(_key(request), muted, actor(request))
        return await _tools_body(request)

    async def visibility_tool(request: Request) -> Response:
        body = await _json_object(request)
        # The tool name travels in the body, the same as the HTML control: a
        # child names its own tools, and a name in the URL path could
        # normalise into a different route.
        tool = _str_field(body, "tool")
        muted = _bool_field(body, "muted")
        supervisor.set_tool_muted(_key(request), tool, muted, actor(request))
        return await _tools_body(request)

    # --- tokens ----------------------------------------------------------

    async def tokens_list(request: Request) -> Response:
        return JSONResponse([_token_json(r) for r in policy.tokens_for(actor(request))])

    async def tokens_add(request: Request) -> Response:
        body = await _json_object(request)
        # `mint_token` owns who may mint what for whom and refuses an unknown
        # user (400); `TokenStore.create` owns the scope check (400).
        record, clear = policy.mint_token(
            actor(request),
            str(body.get("name", "")),
            body.get("scope", "mcp"),
            _opt_str(body, "user_id"),
        )
        payload = _token_json(record)
        payload["token"] = clear  # the clear text, this once
        return JSONResponse(payload, status_code=201)

    async def tokens_delete(request: Request) -> Response:
        policy.revoke_token(actor(request), request.path_params["id"])
        return Response(status_code=204)

    # --- users and groups ------------------------------------------------

    async def users_list(request: Request) -> Response:
        return JSONResponse([_user_json(u) for u in policy.list_users(actor(request))])

    def _user(request: Request, user_id: str) -> User:
        user = next((u for u in policy.list_users(actor(request)) if u.id == user_id), None)
        if user is None:
            raise KeyError(user_id)
        return user

    async def users_add(request: Request) -> Response:
        body = await _json_object(request)
        _refuse_password(body)
        # An absent `admin` is `None`: the groups alone decide the role.
        admin = _bool_field(body, "admin") if "admin" in body else None
        user, code = policy.create_user(
            actor(request),
            _str_field(body, "id"),
            name=_opt_str(body, "name") or "",
            admin=admin,
            groups=_str_list(body, "groups"),
        )
        return JSONResponse({**_user_json(user), "setup_code": code}, status_code=201)

    async def user_update(request: Request) -> Response:
        user_id = request.path_params["id"]
        body = await _json_object(request)
        if "name" in body:
            # The identity provider has no rename; refuse rather than drop it.
            raise ValueError("name: a user name cannot change")
        _refuse_password(body)
        # Validate every field first, then make at most one write. With
        # `groups`, `admin` (or its absence) rides along into one `set_groups`
        # that keeps or refuses a change of `admins` (design D8, R1).
        admin = _bool_field(body, "admin") if "admin" in body else None
        groups = _str_list(body, "groups") if "groups" in body else None
        if groups is not None:
            policy.set_groups(actor(request), user_id, groups, admin=admin)
        elif admin is not None:
            policy.set_admin(actor(request), user_id, admin)
        return JSONResponse(_user_json(_user(request, user_id)))

    async def user_setup_code(request: Request) -> Response:
        # Reset: the user turns pending; the code appears in this answer only.
        # The old password, every session, and every token end at once.
        user_id = request.path_params["id"]
        code = policy.issue_setup_code(actor(request), user_id)
        return JSONResponse({**_user_json(_user(request, user_id)), "setup_code": code})

    async def user_delete(request: Request) -> Response:
        policy.delete_user(actor(request), request.path_params["id"])
        return Response(status_code=204)

    async def groups_list(request: Request) -> Response:
        users = policy.list_users(actor(request))
        return JSONResponse([
            {"name": g, "members": [u.id for u in users if g in u.groups]}
            for g in policy.list_groups(actor(request))
        ])

    async def groups_add(request: Request) -> Response:
        name = _str_field(await _json_object(request), "name")
        policy.create_group(actor(request), name)
        return JSONResponse({"name": name, "members": []}, status_code=201)

    async def group_delete(request: Request) -> Response:
        policy.delete_group(actor(request), request.path_params["name"])
        return Response(status_code=204)

    # --- rules -----------------------------------------------------------

    async def rules_list(request: Request) -> Response:
        return JSONResponse([_rule_json(r) for r in policy.list_rules(actor(request))])

    async def rules_add(request: Request) -> Response:
        body = await _json_object(request)
        # `add_rule` owns the shape check and names the bad field (400).
        rule = policy.add_rule(
            actor(request),
            subject_kind=body.get("subject_kind"),
            subject=body.get("subject"),
            level=body.get("level"),
            server=body.get("server"),
            tool=body.get("tool"),
            effect=body.get("effect"),
        )
        return JSONResponse(_rule_json(rule), status_code=201)

    async def rule_delete(request: Request) -> Response:
        # An unknown id raises `KeyError`: 404 with `<id> not found`.
        policy.remove_rule(actor(request), request.path_params["id"])
        return Response(status_code=204)

    return [
        Route("/servers", servers_list, methods=["GET"]),
        Route("/servers", servers_add, methods=["POST"]),
        Route("/servers/{ref}", server_get, methods=["GET"]),
        Route("/servers/{ref}", server_update, methods=["PUT"]),
        Route("/servers/{ref}", server_delete, methods=["DELETE"]),
        Route("/servers/{ref}/enable", _action(supervisor.enable), methods=["POST"]),
        Route("/servers/{ref}/disable", _action(supervisor.disable), methods=["POST"]),
        Route("/servers/{ref}/restart", _action(supervisor.restart), methods=["POST"]),
        Route("/servers/{ref}/approve", server_approve, methods=["POST"]),
        Route("/servers/{ref}/log", server_log, methods=["GET"]),
        Route("/approvals", approvals_list, methods=["GET"]),
        Route("/tools", _tools_body, methods=["GET"]),
        Route("/visibility/root", visibility_root, methods=["PUT"]),
        Route("/visibility/namespaces/{ref}", visibility_namespace, methods=["PUT"]),
        Route(
            "/visibility/namespaces/{ref}/tools", visibility_tool, methods=["PUT"]
        ),
        Route("/tokens", tokens_list, methods=["GET"]),
        Route("/tokens", tokens_add, methods=["POST"]),
        Route("/tokens/{id}", tokens_delete, methods=["DELETE"]),
        Route("/users", users_list, methods=["GET"]),
        Route("/users", users_add, methods=["POST"]),
        Route("/users/{id}", user_update, methods=["PUT"]),
        Route("/users/{id}", user_delete, methods=["DELETE"]),
        Route("/users/{id}/setup-code", user_setup_code, methods=["POST"]),
        Route("/groups", groups_list, methods=["GET"]),
        Route("/groups", groups_add, methods=["POST"]),
        Route("/groups/{name}", group_delete, methods=["DELETE"]),
        Route("/rules", rules_list, methods=["GET"]),
        Route("/rules", rules_add, methods=["POST"]),
        Route("/rules/{id}", rule_delete, methods=["DELETE"]),
    ]
