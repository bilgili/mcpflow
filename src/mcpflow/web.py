"""Starlette routes, Jinja2 templates, and HTMX partials.

The session gate guards these routes at the app level, so a handler here may
assume an authenticated admin, except `/login` which the gate leaves public.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import shlex
import time
from dataclasses import dataclass, replace
from pathlib import Path

import httpx
from jinja2 import Environment, FileSystemLoader, select_autoescape
from mcp.types import TextContent
from starlette.requests import Request
from starlette.responses import (
    HTMLResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from starlette.routing import BaseRoute, Route

from . import oauth as _oauth
from .actions import (
    ActionView,
    FormField,
    form_fields,
    redact,
    redact_schema,
    secret_keys,
    secret_literals,
)
from .auth import COOKIE_NAME, TokenStore, sign_session, verify_password
from .catalog import BUILTIN_DIR, CATEGORIES, Catalog, CatalogEntry, build_spec
from .config import Settings
from .importer import parse_config_block
from .oauth import (
    CLIENT_FORMATS,
    TOKEN_FORMATS,
    ClientCreds,
    CredStore,
    HeaderSpec,
    PendingFlows,
    ProviderRegistry,
    authorize_url,
    token_request,
)
from .registry import (
    RegistryError,
    ServerSpec,
    redact_spec,
    spec_command,
    spec_from_dict,
)
from .supervisor import LeaseRefused, Supervisor

logger = logging.getLogger(__name__)

_TEMPLATES = Path(__file__).parent / "templates"


def _kv_lines(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key.strip()] = value.strip()
    return out


def _spec_from_form(form, *, namespace: str | None = None) -> ServerSpec:
    # Presence semantics: an unchecked HTML checkbox is omitted from the POST
    # body, so absence means disabled. `enabled` is persisted intent.
    enabled = form.get("enabled") is not None
    data = {
        "namespace": (namespace or form.get("namespace", "")).strip(),
        "kind": form.get("kind", "").strip(),
        "package": (form.get("package") or "").strip() or None,
        "source": (form.get("source") or "").strip() or None,
        "args": (form.get("args") or "").split(),
        "url": (form.get("url") or "").strip() or None,
        "transport": (form.get("transport") or "http").strip() or "http",
        "headers": _kv_lines(form.get("headers", "")),
        "command": (form.get("command") or "").strip() or None,
        "env": _kv_lines(form.get("env", "")),
        "enabled": enabled,
        "description": (form.get("description") or "").strip(),
        "cache_ttl": (form.get("cache_ttl") or "").strip() or None,
    }
    return spec_from_dict(data)


def _form_values(spec: ServerSpec | None) -> dict:
    if spec is None:
        return {}
    return {
        "namespace": spec.namespace,
        "kind": spec.kind,
        "package": spec.package or "",
        "source": spec.source or "",
        "args": " ".join(spec.args),
        "url": spec.url or "",
        "transport": spec.transport,
        "headers": "\n".join(f"{k}={v}" for k, v in spec.headers.items()),
        "command": spec.command or "",
        "env": "\n".join(f"{k}={v}" for k, v in spec.env.items()),
        "description": spec.description,
        "cache_ttl": "" if spec.cache_ttl is None else f"{spec.cache_ttl:g}",
        "enabled": spec.enabled,
    }


def _base_url(settings: Settings, request: Request) -> str:
    """The gateway's externally reachable base URL, no trailing slash.

    PUBLIC_URL when set (correct behind a reverse proxy that hides the real
    host/scheme), otherwise the request's own scheme and Host header. Owns the
    trailing-slash normalization so callers only append a path.
    """
    base = (
        settings.public_url
        or f"{request.url.scheme}://{request.headers.get('host', 'localhost')}"
    )
    return base.rstrip("/")


def _mcp_config(settings: Settings, request: Request, token: str) -> dict[str, str]:
    """Build the MCP client config for a freshly created token.

    Returns the /mcp URL, a pretty JSON block, and a Claude Code CLI one-liner,
    all with the token embedded.
    """
    mcp_url = _base_url(settings, request) + "/mcp"
    config = {
        "mcpServers": {
            "mcpflow": {
                "type": "http",
                "url": mcp_url,
                "headers": {"Authorization": f"Bearer {token}"},
            }
        }
    }
    mcp_json = json.dumps(config, indent=2)
    header = f"Authorization: Bearer {token}"
    mcp_cli = (
        f"claude mcp add --transport http mcpflow {shlex.quote(mcp_url)} "
        f"--header {shlex.quote(header)}"
    )
    return {"mcp_url": mcp_url, "mcp_json": mcp_json, "mcp_cli": mcp_cli}


def _admin_curl(settings: Settings, request: Request, token: str) -> str:
    """A ready-to-run `curl` against `/api/servers` for a fresh admin token.

    An `admin` token authenticates `/api` and `/mcp`; the tokens page shows this
    `curl` example against `/api/servers` for an `admin` token, one valid use of
    it, alongside the MCP client config.
    """
    url = _base_url(settings, request) + "/api/servers"
    header = f"Authorization: Bearer {token}"
    return f"curl -H {shlex.quote(header)} {shlex.quote(url)}"


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _same_json(text: str, value: object) -> bool:
    """`text` parses to `value`. Canonical form, so `true` never equals `1`."""
    try:
        return _canonical(json.loads(text)) == _canonical(value)
    except (ValueError, RecursionError):
        return False


def _is_mirror(text: str, structured: object) -> bool:
    """A text block FastMCP derived from the structured content (design.md).

    (a) the JSON of the whole structured content; (b) for a non-object return
    wrapped as `{"result": v}`, `v` itself: a `str` as is, any other as JSON.
    """
    if structured is None:
        return False
    if _same_json(text, structured):
        return True
    if isinstance(structured, dict) and list(structured) == ["result"]:
        v = structured["result"]
        return text == v if isinstance(v, str) else _same_json(text, v)
    return False


@dataclass(frozen=True)
class _ActionSnapshot:
    name: str
    fields: tuple[FormField, ...]
    password_keys: frozenset[str]


@dataclass(frozen=True)
class _PageSnapshot:
    namespace: str
    expires: float
    actions: dict[str, _ActionSnapshot]
    secrets: frozenset[str]


def build_routes(
    supervisor: Supervisor,
    tokens: TokenStore,
    settings: Settings,
    creds: CredStore,
    flows: PendingFlows,
) -> list[BaseRoute]:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES)),
        autoescape=select_autoescape(),
    )
    action_snapshots: dict[str, _PageSnapshot] = {}

    def render(
        name: str, request: Request, *, status_code: int = 200, **ctx
    ) -> HTMLResponse:
        html = env.get_template(name).render(request=request, **ctx)
        return HTMLResponse(html, status_code=status_code)

    def is_htmx(request: Request) -> bool:
        return request.headers.get("HX-Request") == "true"

    async def servers_response(request: Request) -> Response:
        """The answer to a successful action.

        An htmx caller gets the tool tree, the element the dashboard shows the
        child in. A plain caller posted from the server window, so the page
        reload closes the dialog and shows the new state.
        """
        if is_htmx(request):
            return await tools_tree(request, "_tools_tree.html")
        return RedirectResponse("/", status_code=303)

    # --- auth ------------------------------------------------------------

    async def login_get(request: Request) -> Response:
        return render(
            "login.html",
            request,
            next=request.query_params.get("next", "/"),
            error=None,
        )

    async def login_post(request: Request) -> Response:
        form = await request.form()
        password = form.get("password", "")
        next_ = form.get("next", "/")
        # Offload the 600k-iteration PBKDF2 verify off the event loop so it does
        # not block /mcp and /health.
        ok = await asyncio.to_thread(
            verify_password, password, settings.admin_password_hash
        )
        if not ok:
            await asyncio.sleep(1)
            return render("login.html", request, next=next_, error="Wrong password.")
        if not next_.startswith("/") or next_.startswith("//"):
            next_ = "/"
        expires_at = int(time.time()) + settings.session_ttl
        value = sign_session(
            settings.secret_key, settings.admin_password_hash, expires_at
        )
        resp = RedirectResponse(next_, status_code=303)
        resp.set_cookie(
            COOKIE_NAME,
            value,
            max_age=settings.session_ttl,
            httponly=True,
            samesite="lax",
            path="/",
            secure=settings.cookie_secure,
        )
        return resp

    async def logout(request: Request) -> Response:
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(COOKIE_NAME, path="/")
        return resp

    # --- dashboard and servers ------------------------------------------

    async def tools_tree(request: Request, name: str = "dashboard.html") -> Response:
        """Render the tool tree.

        Every group renders collapsed, in every render: the page load, the
        poll answer, and a control answer alike. The browser owns the open
        state; `dashboard.html` records it before a tree swap and restores it
        after. A server-side hint would name the group that was open when the
        admin clicked, not when the answer lands, so it would re-open a group
        the admin collapsed during the round trip.
        """
        views = await supervisor.tools()
        return render(
            name,
            request,
            tools=views,
            children=supervisor.children(),
            root_muted=supervisor.root_muted(),
            # The `mcpflow` group has no `Child`, so its namespace control reads
            # this flag instead of `c.spec.muted`.
            mcpflow_muted=supervisor.mcpflow_muted(),
            spec_command=spec_command,
            awaiting=_awaiting(),
            reauthable=_reauthable(),
            catalog_names=_catalog_names(),
        )

    async def dashboard(request: Request) -> Response:
        return await tools_tree(request)

    async def tools_tree_partial(request: Request) -> Response:
        """The poll's route. No parameters: the tree carries no open state."""
        return await tools_tree(request, "_tools_tree.html")

    # --- visibility ------------------------------------------------------
    #
    # Presence semantics, the same as the `enabled` checkbox on the server
    # form: an unchecked HTML checkbox is omitted from the POST body, so
    # absence means muted. Every control answers with the updated tree.

    def _muted(form) -> bool:
        return form.get("visible") is None

    async def visibility_root(request: Request) -> Response:
        form = await request.form()
        supervisor.set_root_muted(_muted(form))
        return await tools_tree(request, "_tools_tree.html")



    async def visibility_namespace(request: Request) -> Response:
        form = await request.form()
        try:
            supervisor.set_namespace_muted(request.path_params["ns"], _muted(form))
        except KeyError:
            return PlainTextResponse("not found", status_code=404)
        return await tools_tree(request, "_tools_tree.html")

    async def visibility_tool(request: Request) -> Response:
        # The tool name travels in the body, never in the path. A child names
        # its own tools, and a name like `../../servers/x/delete` in a URL
        # normalises in the browser into a different authenticated route.
        form = await request.form()
        tool = form.get("tool")
        # Take the name verbatim. The child owns that string and visibility
        # matching is exact, so trimming it would persist a name that matches
        # nothing and leave the real tool published.
        if not isinstance(tool, str) or tool == "":
            return PlainTextResponse("tool is required", status_code=400)
        try:
            supervisor.set_tool_muted(request.path_params["ns"], tool, _muted(form))
        except KeyError:
            return PlainTextResponse("not found", status_code=404)
        return await tools_tree(request, "_tools_tree.html")

    async def servers(request: Request) -> Response:
        """The old servers page. The dashboard is the one page for the child
        servers now, so a bookmark lands there."""
        return RedirectResponse("/", status_code=303)

    def _add_window(
        request: Request,
        *,
        tab: str,
        values: dict,
        error: str | None = None,
        paste: str = "",
        status_code: int = 200,
        page: bool | None = None,
    ) -> Response:
        """The add-server window: the partial in the dialog, the page without.

        `page` forces the full page for a plain form post, which answers a
        reload rather than a swap.
        """
        as_page = (not is_htmx(request)) if page is None else page
        return render(
            "server_form.html" if as_page else "_server_form.html",
            request,
            status_code=status_code,
            page=as_page,
            tab=tab,
            values=values,
            error=error,
            editing=False,
            paste=paste,
        )

    async def server_new(request: Request) -> Response:
        # `new` is a legal namespace, so `GET /servers/{ns}` owns that space
        # and the add window lives at its own path.
        return _add_window(request, tab=request.query_params.get("tab", "python"), values={})

    async def server_create(request: Request) -> Response:
        form = await request.form()
        try:
            spec = _spec_from_form(form)
            await supervisor.add(spec)
        except RegistryError as exc:
            # The form posts without htmx, so the answer is the full page with
            # the typed values, the same as the marketplace connect.
            return _add_window(
                request,
                tab=form.get("kind", "python"),
                values=dict(form),
                error=str(exc),
                status_code=400,
                page=True,
            )
        return RedirectResponse("/", status_code=303)

    async def _server_detail_ctx(
        ns: str,
        request: Request,
        values: dict | None = None,
        error: str | None = None,
    ) -> dict | None:
        """The server window's render context, or None for an unknown namespace.

        The window reads the registry and the catalog, and nothing else. It
        does not call `Supervisor.tools()`: the child's group on the dashboard
        owns the tool list, and that call probes every running child and marks
        one `failed` when its probe raises, so filling a one-child page from it
        could change an unrelated child's status.

        The form shows `redact_spec(child.spec)`, the same outward view as the
        API: every `env`/`headers` value and the `source`/`url` credentials are
        masked. A save echoes the masks and `Registry.update` keeps the stored
        secrets. `_form_values` stays a plain formatter because the JSON import
        preview formats a fresh paste that must stay raw.

        `values` carries the typed values back on a 400; `None` reads them from
        the stored spec.
        """
        try:
            child = supervisor.get(ns)
        except KeyError:
            return None
        entry = _catalog().get(child.spec.catalog) if child.spec.catalog else None
        return {
            "ns": ns,
            "c": child,
            "values": (
                _form_values(redact_spec(child.spec)) if values is None else values
            ),
            "tab": child.spec.kind,
            "editing": True,
            "command": spec_command(child.spec),
            "awaiting": _awaiting(),
            "reauthable": _reauthable(),
            "e": entry,
            "error": error,
        }

    async def server_detail(request: Request) -> Response:
        ctx = await _server_detail_ctx(request.path_params["ns"], request)
        if ctx is None:
            return PlainTextResponse("not found", status_code=404)
        if is_htmx(request):
            return render("_server_detail.html", request, page=False, **ctx)
        return render("server_detail.html", request, page=True, **ctx)

    async def server_edit(request: Request) -> Response:
        """The old edit page. The window holds the edit form now."""
        return RedirectResponse(
            f"/servers/{request.path_params['ns']}", status_code=303
        )

    async def server_update(request: Request) -> Response:
        ns = request.path_params["ns"]
        try:
            supervisor.get(ns)
        except KeyError:
            return PlainTextResponse("not found", status_code=404)
        form = await request.form()
        try:
            spec = _spec_from_form(form, namespace=ns)
            await supervisor.update(spec)
        except RegistryError as exc:
            ctx = await _server_detail_ctx(
                ns, request, values=dict(form), error=str(exc)
            )
            if ctx is None:  # pragma: no cover - a delete raced the save
                return PlainTextResponse("not found", status_code=404)
            return render(
                "server_detail.html", request, status_code=400, page=True, **ctx
            )
        return RedirectResponse("/", status_code=303)

    def _action(op):
        async def handler(request: Request) -> Response:
            ns = request.path_params["ns"]
            try:
                await op(ns)
            except KeyError:
                return PlainTextResponse("not found", status_code=404)
            except RegistryError as exc:
                # An htmx caller reads the bare reason. A plain caller posted
                # from the server window, so it gets the window back with the
                # reason on it.
                if is_htmx(request):
                    return PlainTextResponse(str(exc), status_code=400)
                ctx = await _server_detail_ctx(ns, request, error=str(exc))
                if ctx is None:  # pragma: no cover - a delete raced the action
                    return PlainTextResponse(str(exc), status_code=400)
                return render(
                    "server_detail.html", request, status_code=400, page=True, **ctx
                )
            return await servers_response(request)

        return handler

    async def server_log(request: Request) -> Response:
        ns = request.path_params["ns"]
        lines = int(request.query_params.get("lines", "100"))
        try:
            text = supervisor.log_tail(ns, lines)
        except KeyError:
            return PlainTextResponse("not found", status_code=404)
        return PlainTextResponse(text, media_type="text/plain")

    # --- actions ---------------------------------------------------------

    def _prune_action_snapshots() -> None:
        now = time.monotonic()
        for token, snapshot in list(action_snapshots.items()):
            if snapshot.expires <= now:
                del action_snapshots[token]

    def _actions_page(
        request: Request,
        ns: str,
        child,
        *,
        configured: frozenset[str],
        inherited_metadata: frozenset[str] = frozenset(),
        request_secrets: frozenset[str] = frozenset(),
        password_keys: frozenset[str] = frozenset(),
        status_code: int = 200,
        page: bool = True,
        actions: list[ActionView] | None = None,
        error: str | None = None,
        active: str | None = None,
        values: dict[str, str] | None = None,
        form_error: str | None = None,
        result: dict | None = None,
    ) -> Response:
        views = actions or []
        # Metadata secrets alone may persist. The complete request union is used
        # once on each original presentation value, never saved in a snapshot.
        metadata_secrets = (
            inherited_metadata
            | configured
            | frozenset(
                value for view in views for value in secret_literals(view.schema)
            )
        )
        full = metadata_secrets | request_secrets
        cards = []
        snapshots = {}
        values = values or {}
        for card_index, view in enumerate(views):
            alias = f"a{card_index}"
            on = view.name == active
            effective_keys = secret_keys(view.schema) | (
                password_keys if on else frozenset()
            )
            fields = tuple(
                replace(
                    field, control="password", enum=(), default="", default_on=False
                )
                if field.name in effective_keys
                else field
                for field in form_fields(view.schema)
            )
            # FormField contains only immutable scalar/tuple metadata, detached
            # from the child's mutable schema. It holds no request values.
            snapshots[alias] = _ActionSnapshot(view.name, fields, effective_keys)
            controls = []
            for field_index, field in enumerate(fields):
                raw_value = values.get(field.name, "") if on else field.default
                value = redact(raw_value, full)
                if not on and value != raw_value:
                    value = ""
                controls.append(
                    {
                        "alias": f"f{field_index}",
                        "id": f"a-{card_index}-f-{field_index}",
                        "label": redact(field.name, full),
                        "control": field.control,
                        "required": field.required,
                        "value": "" if field.control == "password" else value,
                        "checked": field.name in values if on else field.default_on,
                        "options": [
                            {
                                "alias": f"o{i}",
                                "label": redact(option, full),
                                "selected": option == raw_value,
                            }
                            for i, option in enumerate(field.enum)
                        ],
                    }
                )
            cards.append(
                {
                    "alias": alias,
                    "active": on,
                    "name": redact(view.name, full),
                    "title": redact(view.title, full),
                    "description": redact(view.description, full),
                    "schema": redact(redact_schema(view.schema), full),
                    "disabled": view.disabled,
                    "reason": redact(view.reason, full),
                    "fields": controls,
                }
            )
        token = None
        if cards and not error:
            _prune_action_snapshots()
            while len(action_snapshots) >= 256:
                del action_snapshots[next(iter(action_snapshots))]
            token = secrets.token_urlsafe(32)
            action_snapshots[token] = _PageSnapshot(
                ns, time.monotonic() + settings.session_ttl, snapshots, metadata_secrets
            )
        shown_result = None
        if result is not None:
            structured = result["structured"]
            shown_result = {
                "text": [redact(text, full) for text in result["text"]],
                "structured": None
                if structured is None
                else json.dumps(redact(structured, full), indent=2, ensure_ascii=False),
            }
        return render(
            "server_actions.html" if page else "_server_actions.html",
            request,
            status_code=status_code,
            ns=ns,
            c=child,
            actions=cards,
            form_token=token,
            error=None if error is None else redact(error, full),
            active=None if active is None else redact(active, full),
            form_error=None if form_error is None else redact(form_error, full),
            result=shown_result,
            page=page,
        )

    async def server_actions(request: Request) -> Response:
        ns = request.path_params["ns"]
        try:
            child = supervisor.get(ns)
            configured = frozenset(supervisor.child_secrets(ns))
            views = await supervisor.actions(ns)
        except KeyError:
            return PlainTextResponse("not found", status_code=404)
        except RuntimeError as exc:
            return _actions_page(
                request,
                ns,
                child,
                configured=configured,
                page=not is_htmx(request),
                error=str(exc),
            )
        return _actions_page(
            request,
            ns,
            child,
            configured=configured,
            page=not is_htmx(request),
            actions=views,
        )

    async def server_action_submit(request: Request) -> Response:
        """Restore identities, check current membership, then execute once."""
        ns = request.path_params["ns"]
        action = request.path_params["action"]
        posted = await request.form()
        legacy = "form_token" not in request.query_params
        if legacy:
            form = dict(posted)
            password_keys = frozenset(form)
            rendered_secrets = frozenset()
        else:
            _prune_action_snapshots()
            snapshot = action_snapshots.get(request.query_params["form_token"])
            card = None if snapshot is None else snapshot.actions.get(action)
            if snapshot is None or snapshot.namespace != ns or card is None:
                return PlainTextResponse(
                    "Invalid form. Reload the actions page.", status_code=400
                )
            fields = {f"f{i}": field for i, field in enumerate(card.fields)}
            form = {}
            for alias, value in posted.multi_items():
                field = fields.get(alias)
                if field is None or not isinstance(value, str):
                    return PlainTextResponse(
                        "Invalid form. Reload the actions page.", status_code=400
                    )
                if field.control == "enum":
                    options = {f"o{i}": option for i, option in enumerate(field.enum)}
                    if value == "" and not field.required:
                        value = ""
                    elif value in options:
                        value = options[value]
                    else:
                        return PlainTextResponse(
                            "Invalid form. Reload the actions page.", status_code=400
                        )
                form[field.name] = value
            action = card.name
            password_keys = card.password_keys
            rendered_secrets = snapshot.secrets
        request_secrets = rendered_secrets | frozenset(
            value
            for key in password_keys
            if isinstance(value := form.get(key), str) and value
        )
        try:
            child = supervisor.get(ns)
            configured = frozenset(supervisor.child_secrets(ns))
            views = await supervisor.actions(ns)
        except KeyError:
            return PlainTextResponse("not found", status_code=404)
        except RuntimeError as exc:
            return _actions_page(
                request,
                ns,
                child,
                configured=configured,
                inherited_metadata=rendered_secrets,
                request_secrets=request_secrets,
                status_code=503 if isinstance(exc, LeaseRefused) else 400,
                error=str(exc),
            )
        view = next((v for v in views if v.name == action), None)
        if view is None:
            return PlainTextResponse("not found", status_code=404)
        request_secrets |= frozenset(
            value
            for key in secret_keys(view.schema)
            if isinstance(value := form.get(key), str) and value
        )
        try:
            run = await supervisor.run_action(
                ns,
                action,
                form,
                rendered_password_keys=password_keys,
                rendered_secrets=rendered_secrets,
            )
        except KeyError:
            return PlainTextResponse("not found", status_code=404)
        if run.kind == "unknown":
            return PlainTextResponse("not found", status_code=404)

        logger.info("running action %s of %s", view.name, ns)
        password_keys |= run.password_keys
        request_secrets |= run.secrets
        # Refills remain raw until the complete page union has been assembled.
        values = (
            {}
            if legacy or run.kind in ("transport", "lease_refused")
            else {
                key: value
                for key, value in form.items()
                if isinstance(value, str) and key not in password_keys
            }
        )
        context = {
            "configured": configured,
            "inherited_metadata": rendered_secrets,
            "request_secrets": request_secrets,
            # Legacy all-key secrecy describes the request, not past controls.
            "password_keys": frozenset() if legacy else password_keys,
            "actions": views,
            "active": action,
            "values": values,
        }
        if run.kind in ("muted", "coerce_error"):
            return _actions_page(
                request,
                ns,
                child,
                **context,
                status_code=400,
                form_error="muted" if run.kind == "muted" else run.detail,
            )
        if run.kind in ("lease_refused", "transport"):
            return _actions_page(
                request,
                ns,
                child,
                **context,
                status_code=503 if run.kind == "lease_refused" else 400,
                error=run.detail,
            )
        res = run.result
        texts = [b.text for b in res.content if isinstance(b, TextContent)]
        if res.is_error:
            return _actions_page(
                request,
                ns,
                child,
                **context,
                status_code=400,
                form_error="\n".join(texts) or "the action failed",
            )
        structured = res.structured_content
        return _actions_page(
            request,
            ns,
            child,
            **context,
            result={
                "text": [text for text in texts if not _is_mirror(text, structured)],
                "structured": structured,
            },
        )

    # --- imports ---------------------------------------------------------

    async def import_json(request: Request) -> Response:
        """Parse a pasted config block into the add window.

        The answer is the whole window, pre-filled, so the dialog keeps one
        owner and the footer button switches from `Parse` to `Add server`. A
        parse error answers the same window with the paste still in place.
        """
        form = await request.form()
        paste = form.get("config", "")
        try:
            specs = parse_config_block(paste)
        except RegistryError as exc:
            return _add_window(
                request, tab="json", values={}, error=str(exc), paste=paste,
                status_code=400,
            )
        values = _form_values(specs[0])
        return _add_window(request, tab=values["kind"], values=values)

    # --- marketplace -----------------------------------------------------

    local_catalog_dir = settings.data_dir / "catalog"

    def _providers() -> ProviderRegistry:
        # A fresh snapshot per request, the same rule as `_catalog`. Built-in
        # providers ship under the package; admin overrides live under
        # DATA_DIR/catalog/providers/.
        return ProviderRegistry.load(
            BUILTIN_DIR / "providers", local_catalog_dir / "providers"
        )

    def _catalog() -> Catalog:
        # A fresh snapshot per request, so a file dropped into
        # DATA_DIR/catalog/ shows up with no restart and no handler shares
        # mutable state across an await. The known provider ids and format
        # names are passed in so the catalog rejects a bad `oauth` entry at
        # load without importing the oauth module.
        return Catalog.load(
            BUILTIN_DIR,
            local_catalog_dir,
            providers=_providers().ids(),
            client_formats=CLIENT_FORMATS,
            token_formats=TOKEN_FORMATS,
        )

    def _awaiting() -> set[str]:
        """Namespaces awaiting their OAuth token: a file sink child with a
        client file and no token file, or a header sink child whose registry
        flag `oauth_pending` is set."""
        return {
            c.spec.namespace
            for c in supervisor.children()
            if creds.awaiting(c.spec.namespace) or c.spec.oauth_pending
        }

    def _header_authorized(entry: CatalogEntry, spec) -> bool:
        """A header sink child is authorized once its Authorization header is
        set and it is no longer pending."""
        return entry.oauth.header.name in spec.headers and not spec.oauth_pending

    def _reauthable() -> set[str]:
        """Namespaces whose catalog entry has an `oauth` block and whose child
        is authorized (a token file for a file sink, the header set for a header
        sink), so re-authorization applies."""
        catalog = _catalog()
        out: set[str] = set()
        for c in supervisor.children():
            tag = c.spec.catalog
            if not tag:
                continue
            entry = catalog.get(tag)
            if entry is None or entry.oauth is None:
                continue
            authorized = (
                _header_authorized(entry, c.spec)
                if entry.oauth.header is not None
                else creds.has_token(c.spec.namespace)
            )
            if authorized:
                out.add(c.spec.namespace)
        return out

    def _connected() -> dict[str, list[str]]:
        """Catalog entry id -> namespaces of the children tagged with it."""
        out: dict[str, list[str]] = {}
        for child in supervisor.children():
            if child.spec.catalog:
                out.setdefault(child.spec.catalog, []).append(child.spec.namespace)
        return out

    def _catalog_names() -> dict[str, str]:
        """Catalog entry id -> entry name.

        The server row and the window head name the marketplace entry a child
        came from. A tag that matches no entry is absent from the map, so the
        page shows nothing rather than a dangling id.
        """
        return {e.id: e.name for e in _catalog().entries()}

    def _market_ctx(request: Request) -> dict:
        catalog = _catalog()
        q = request.query_params.get("q", "")
        cat = request.query_params.get("cat") or None
        if cat not in CATEGORIES:
            cat = None
        entries = catalog.entries()
        return {
            "q": q,
            "cat": cat,
            "shown": catalog.search(q, cat),
            "total": len(entries),
            "categories": CATEGORIES,
            "counts": catalog.counts(),
            "connected": _connected(),
            "errors": catalog.errors,
            "origins": {
                "builtin": sum(e.origin == "builtin" for e in entries),
                "local": sum(e.origin == "local" for e in entries),
            },
        }

    def _detail_ctx(
        entry: CatalogEntry,
        namespace: str,
        args: list[str] | None,
        error: str | None,
        request: Request,
    ) -> dict:
        # Secrets the admin typed are never echoed back into the form, and
        # the preview masks every setup value, on the GET and on a 400 alike.
        ctx = {
            "e": entry,
            "namespace": namespace,
            "args": " ".join(entry.spec.args if args is None else args),
            "error": error,
            "connected": _connected().get(entry.id, []),
            "preview": json.dumps(
                entry.preview(namespace, args), indent=2, ensure_ascii=False
            ),
            "run_command": entry.run_command(args),
            "provider": None,
            "redirect_uri": None,
        }
        if entry.oauth is not None:
            # The template branches on the presence of the block; it reads the
            # provider name, help text, and link, and shows the exact redirect
            # URI the admin registers at the vendor.
            ctx["provider"] = _providers().get(entry.oauth.provider)
            ctx["redirect_uri"] = _base_url(settings, request) + "/oauth/callback"
        return ctx

    async def marketplace(request: Request) -> Response:
        return render("marketplace.html", request, **_market_ctx(request))

    async def marketplace_grid(request: Request) -> Response:
        return render("_marketplace_grid.html", request, **_market_ctx(request))

    async def marketplace_detail(request: Request) -> Response:
        entry = _catalog().get(request.path_params["id"])
        if entry is None:
            return PlainTextResponse("not found", status_code=404)
        ctx = _detail_ctx(entry, entry.id, None, None, request)
        if is_htmx(request):
            return render("_marketplace_detail.html", request, page=False, **ctx)
        return render("marketplace_detail.html", request, page=True, **ctx)

    def _connect_error(
        entry: CatalogEntry, namespace: str, args: list[str] | None, reason: str, request
    ) -> Response:
        return render(
            "marketplace_detail.html",
            request,
            status_code=400,
            page=True,
            **_detail_ctx(entry, namespace or entry.id, args, reason, request),
        )

    async def marketplace_connect(request: Request) -> Response:
        entry = _catalog().get(request.path_params["id"])
        if entry is None:
            return PlainTextResponse("not found", status_code=404)
        form = await request.form()
        namespace = (form.get("namespace") or "").strip()
        if entry.oauth is not None:
            return await _connect_oauth(request, entry, namespace, form)
        # The form shows an args field only for an entry that has args, so
        # an absent field means "the entry's own args"; a posted value wins
        # verbatim, an emptied one included.
        args = (form.get("args") or "").split() if "args" in form else None
        values = {f.key: form.get(f"setup_{f.key}", "") for f in entry.setup}
        try:
            spec = build_spec(entry, namespace, values, args)
            await supervisor.add(spec)
        except RegistryError as exc:
            return _connect_error(entry, namespace, args, str(exc), request)
        return RedirectResponse("/servers", status_code=303)

    async def _connect_oauth(
        request: Request, entry: CatalogEntry, namespace: str, form
    ) -> Response:
        # A missing field re-renders the detail with 400 and writes nothing.
        # The secret is never placed back into the re-rendered form.
        provider = _providers().get(entry.oauth.provider)
        if provider is None:  # pragma: no cover - catalog skips an unknown provider
            return _connect_error(entry, namespace, None, "unknown provider", request)
        client_id = (form.get("client_id") or "").strip()
        # A public client has no secret: a posted one is ignored.
        client_secret = (
            "" if provider.public_client else (form.get("client_secret") or "").strip()
        )
        if not client_id:
            return _connect_error(entry, namespace, None, "client_id is required", request)
        if not client_secret and not provider.public_client:
            return _connect_error(
                entry, namespace, None, "client_secret is required", request
            )
        # `Supervisor.add` registers the namespace and writes the file sink's
        # client file, in that order and with no await between. The pair lives
        # there, not here: the supervisor owns every credential call, and a
        # write before the register would be destroyed by the residue purge
        # inside `add`. A rejected namespace writes nothing. A header sink
        # writes no file: build_spec sets oauth_pending, and the callback
        # writes the token into the registry header.
        client = ClientCreds(client_id=client_id, client_secret=client_secret)
        header_sink = entry.oauth.header is not None
        client_fmt = None if header_sink else entry.oauth.client_file.format
        try:
            cred_paths = None if header_sink else creds.paths(namespace)
            spec = build_spec(entry, namespace, {}, None, cred_paths)
            await supervisor.add(spec, client_fmt, client)
        except RegistryError as exc:
            return _connect_error(entry, namespace, None, str(exc), request)
        flow = flows.create(namespace, entry.id, client)
        redirect_uri = _base_url(settings, request) + "/oauth/callback"
        return RedirectResponse(
            authorize_url(provider, entry.oauth, redirect_uri, flow), status_code=303
        )

    def _oauth_error(request: Request, reason: str) -> Response:
        return render("oauth_error.html", request, status_code=400, reason=reason)

    async def oauth_callback(request: Request) -> Response:
        # `state` names the flow; the flow names the namespace and the entry;
        # the entry names the provider. One route serves every provider.
        #
        # The flow is peeked, not popped, before the token exchange await: the
        # supervisor's finish_oauth does the one-shot pop under the child lock,
        # so a delete during the exchange invalidates it and nothing is
        # written. The terminal error paths write nothing, so they pop the
        # flow themselves to spend the one-shot.
        state = request.query_params.get("state", "")
        flow = flows.peek(state)
        if flow is None:
            return _oauth_error(request, "authorization expired")
        # One token exchange per state. A concurrent duplicate callback for the
        # same state is rejected here, before it POSTs a second time; the
        # `peek` above did not consume, so without this guard both would reach
        # the token endpoint. The one-shot `pop` in finish_oauth still gates
        # the apply; this only spares the redundant POST.
        if not flows.begin_exchange(state):
            return _oauth_error(request, "authorization already in progress")
        try:
            error = request.query_params.get("error")
            if error:
                flows.pop(state)
                return _oauth_error(request, error)
            entry = _catalog().get(flow.entry_id)
            provider = _providers().get(entry.oauth.provider) if entry else None
            if entry is None or provider is None:  # pragma: no cover - defensive
                flows.pop(state)
                return _oauth_error(request, "unknown entry")
            code = request.query_params.get("code", "")
            redirect_uri = _base_url(settings, request) + "/oauth/callback"
            url, body = token_request(provider, redirect_uri, code, flow)
            try:
                # Call through the module so a test can `monkeypatch` the factory.
                async with _oauth.http_client() as client:
                    resp = await client.post(url, data=body)
            except httpx.HTTPError:
                # A connect failure or a timeout. Do not log the exception; it
                # can carry the URL and the request body. The child stays
                # disabled.
                flows.pop(state)
                return _oauth_error(request, "could not reach the token endpoint")
            if resp.status_code // 100 != 2:
                # Do not log the response body; it may echo the code or the
                # secret. Surface only the provider's error word and the status.
                flows.pop(state)
                try:
                    payload = resp.json()
                except ValueError:
                    payload = {}
                reason = payload.get("error") or payload.get("error_description") or "token request failed"
                return _oauth_error(request, f"{reason} ({resp.status_code})")
            token_json = resp.json()
            # Refuse a malformed token response here, before the apply. A
            # header sink builds no file (None); a file sink builds it in the
            # entry's token format. `finish_oauth` pops the flow and, on a
            # re-auth, tears the child down before it writes the token, so a
            # fault raised inside the apply cannot restore the namespace. This
            # guard joins the pre-commit cluster above: consume the flow, yield
            # the error page, change nothing.
            token_fmt = (
                None if entry.oauth.header is not None else entry.oauth.token_file.format
            )
            # A public client header sink keeps its grant in `refresh.json`,
            # so its `expires_in` is checked like a file sink's.
            refreshable = entry.oauth.header is not None and provider.public_client
            try:
                _oauth.check_token_response(token_fmt, token_json, refresh=refreshable)
            except _oauth.OAuthTokenError as exc:
                flows.pop(state)
                return _oauth_error(request, str(exc))
            if entry.oauth.header is not None:
                # Header sink: no file; finish_oauth writes the token into the
                # registry Authorization header in one update.
                spec = HeaderSpec(
                    entry.oauth.header.name,
                    entry.oauth.header.scheme,
                    provider.token_url if refreshable else None,
                )
                ok = await supervisor.finish_oauth(
                    flow, None, token_json, reauth=flow.reauth, header=spec
                )
            elif flow.reauth:
                ok = await supervisor.finish_oauth(
                    flow,
                    entry.oauth.token_file.format,
                    token_json,
                    client_fmt=entry.oauth.client_file.format,
                    reauth=True,
                )
            else:
                ok = await supervisor.finish_oauth(
                    flow, entry.oauth.token_file.format, token_json
                )
            if not ok:
                return _oauth_error(
                    request, "the server was removed during sign-in; connect again"
                )
            return RedirectResponse("/servers", status_code=303)
        finally:
            flows.end_exchange(state)

    # --- re-authorize ----------------------------------------------------

    def _reauth_entry(ns: str):
        """(child, entry) when the child exists and its catalog entry carries
        an `oauth` block, else (None, None) so the route answers 404."""
        try:
            child = supervisor.get(ns)
        except KeyError:
            return None, None
        entry = _catalog().get(child.spec.catalog) if child.spec.catalog else None
        if entry is None or entry.oauth is None:
            return None, None
        return child, entry

    def _reauth_ctx(ns: str, entry, request: Request, error: str | None = None) -> dict:
        provider = _providers().get(entry.oauth.provider)
        return {
            "ns": ns,
            "e": entry,
            "provider": provider,
            "redirect_uri": _base_url(settings, request) + "/oauth/callback",
            "error": error,
        }

    async def reauthorize_get(request: Request) -> Response:
        ns = request.path_params["ns"]
        child, entry = _reauth_entry(ns)
        if child is None:
            return PlainTextResponse("not found", status_code=404)
        return render("reauthorize.html", request, **_reauth_ctx(ns, entry, request))

    async def reauthorize_post(request: Request) -> Response:
        ns = request.path_params["ns"]
        # Read the form BEFORE validating, so a concurrent delete during the
        # await cannot make the child/token checks stale: everything below runs
        # on the current state and no flow is opened for a gone namespace. (The
        # callback's finish_oauth still gates the apply, so this is defence in
        # depth, and it also keeps the re-entered secret out of memory for a
        # server that was just deleted.)
        form = await request.form()
        child, entry = _reauth_entry(ns)
        if child is None:
            return PlainTextResponse("not found", status_code=404)

        def bad(reason: str) -> Response:
            return render(
                "reauthorize.html",
                request,
                status_code=400,
                **_reauth_ctx(ns, entry, request, reason),
            )

        # Re-auth replaces a token; a child with no token is an unfinished
        # connect, not a re-auth target. A file sink child is authorized when it
        # has a token file; a header sink child when its registry header is set.
        if entry.oauth.header is not None:
            authorized = _header_authorized(entry, child.spec)
        else:
            authorized = creds.has_token(ns)
        if not authorized:
            return bad("this server is not yet authorized; connect it first")
        provider = _providers().get(entry.oauth.provider)
        if provider is None:  # pragma: no cover - catalog skips an unknown provider
            return bad("unknown provider")
        client_id = (form.get("client_id") or "").strip()
        # A public client has no secret: a posted one is ignored.
        client_secret = (
            "" if provider.public_client else (form.get("client_secret") or "").strip()
        )
        if not client_id:
            return bad("client_id is required")
        if not client_secret and not provider.public_client:
            return bad("client_secret is required")
        if flows.has_open(ns):
            return bad("a re-authorization is already in progress")
        # The client rides in the flow's memory; nothing is written until the
        # callback succeeds, so a failed re-auth leaves the old token in place.
        client = ClientCreds(client_id=client_id, client_secret=client_secret)
        flow = flows.create(ns, entry.id, client, reauth=True)
        redirect_uri = _base_url(settings, request) + "/oauth/callback"
        return RedirectResponse(
            authorize_url(provider, entry.oauth, redirect_uri, flow), status_code=303
        )

    # --- tokens ----------------------------------------------------------

    async def tokens_page(request: Request) -> Response:
        return render(
            "tokens.html",
            request,
            tokens=tokens.list(),
            new_token=None,
            mcp=None,
            curl=None,
        )

    async def token_create(request: Request) -> Response:
        form = await request.form()
        scope = (form.get("scope") or "mcp").strip()
        # `TokenStore.create` owns the scope check. A hand-typed off-table
        # scope raises `ValueError`; answer 400 rather than a rendered page.
        try:
            _record, clear = tokens.create((form.get("name") or "").strip(), scope)
        except ValueError as exc:
            return PlainTextResponse(str(exc), status_code=400)
        # The MCP config fits every scope. An `admin` token also authenticates
        # `/api`, so it additionally gets the `curl` example. The template owns
        # which tab opens first; the handler owns which content exists.
        return render(
            "tokens.html",
            request,
            tokens=tokens.list(),
            new_token=clear,
            mcp=_mcp_config(settings, request, clear),
            curl=_admin_curl(settings, request, clear) if scope == "admin" else None,
        )

    async def token_delete(request: Request) -> Response:
        try:
            tokens.revoke(request.path_params["id"])
        except KeyError:
            return PlainTextResponse("not found", status_code=404)
        return RedirectResponse("/tokens", status_code=303)

    return [
        Route("/login", login_get, methods=["GET"]),
        Route("/login", login_post, methods=["POST"]),
        Route("/logout", logout, methods=["POST"]),
        Route("/", dashboard, methods=["GET"]),
        # The poll's route. Not a public prefix, so the session gate covers it.
        Route("/tools/tree", tools_tree_partial, methods=["GET"]),
        Route("/visibility/root", visibility_root, methods=["POST"]),
        # Namespaces live under their own prefix: `root` is a legal namespace
        # name, so `/visibility/{ns}` would shadow the gateway-wide route.
        Route("/visibility/namespaces/{ns}", visibility_namespace, methods=["POST"]),
        Route(
            "/visibility/namespaces/{ns}/tool", visibility_tool, methods=["POST"]
        ),
        Route("/servers", servers, methods=["GET"]),
        Route("/add-server", server_new, methods=["GET"]),
        Route("/servers", server_create, methods=["POST"]),
        Route("/servers/{ns}/edit", server_edit, methods=["GET"]),
        Route("/servers/{ns}", server_update, methods=["POST"]),
        Route("/servers/{ns}/enable", _action(supervisor.enable), methods=["POST"]),
        Route("/servers/{ns}/disable", _action(supervisor.disable), methods=["POST"]),
        Route("/servers/{ns}/restart", _action(supervisor.restart), methods=["POST"]),
        Route("/servers/{ns}/delete", _action(supervisor.remove), methods=["POST"]),
        Route("/servers/{ns}/log", server_log, methods=["GET"]),
        Route("/servers/{ns}/reauthorize", reauthorize_get, methods=["GET"]),
        Route("/servers/{ns}/reauthorize", reauthorize_post, methods=["POST"]),
        Route("/servers/{ns}/actions", server_actions, methods=["GET"]),
        Route(
            "/servers/{ns}/actions/{action}", server_action_submit, methods=["POST"]
        ),
        # Declared after the literal suffixes above so `/log`, `/edit`,
        # `/reauthorize`, and `/actions` keep matching their own routes.
        Route("/servers/{ns}", server_detail, methods=["GET"]),
        Route("/import/json", import_json, methods=["POST"]),
        Route("/marketplace", marketplace, methods=["GET"]),
        Route("/marketplace/grid", marketplace_grid, methods=["GET"]),
        Route("/marketplace/{id}", marketplace_detail, methods=["GET"]),
        Route("/marketplace/{id}/connect", marketplace_connect, methods=["POST"]),
        # `/oauth` is not in `_PUBLIC_PREFIXES`, so the session gate covers it.
        Route("/oauth/callback", oauth_callback, methods=["GET"]),
        Route("/tokens", tokens_page, methods=["GET"]),
        Route("/tokens", token_create, methods=["POST"]),
        Route("/tokens/{id}/delete", token_delete, methods=["POST"]),
    ]
