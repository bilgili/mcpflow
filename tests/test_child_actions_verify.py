"""Verifier tests for change `child-actions-page`.

Derived from the spec scenarios and the frozen design contracts, as a
complement to `test_child_actions.py`. Each test names the requirement or the
security probe it covers. The `test_gap_*` tests pinned design gaps as strict
xfails; the 2026-09-17 amendment (flatness rule F0-F7) closed them.
"""

from __future__ import annotations

import html
import json
import logging
import re

import httpx
import jinja2
import pytest
from action_browser import action_post
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.providers.addressing import hash_tool
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from test_child_actions import PAGE, SECRET, call, cards, list_names, start, store_spec
from test_visibility import ROOT, admin, call_log, mute, tool_path

from mcpflow.actions import ActionScopeFilter, clause_violation, coerce_form, is_tagged

ADD = PAGE + "/add_store"


def _spy_admin_call(monkeypatch) -> list:
    # F4: the submit path calls `Supervisor.run_action`, not `call_tool_as_admin`.
    # Spying `run_action` proves the route refused before any tool call.
    from mcpflow import supervisor as supervisor_mod

    seen: list = []
    real = supervisor_mod.Supervisor.run_action

    async def spy(self, ns, name, arguments, **kwargs):
        seen.append(f"{ns}_{name}")
        return await real(self, ns, name, arguments, **kwargs)

    monkeypatch.setattr("mcpflow.supervisor.Supervisor.run_action", spy)
    return seen


def _result_block(body: str) -> str:
    m = re.search(r'<div class="result">(.*?)</div>', body, re.DOTALL)
    assert m, "no result block"
    return m.group(1)


def _variants(secret: str) -> set[str]:
    """Every form a secret takes in a JSON rendering, raw and HTML-escaped."""
    raw = {
        secret,
        json.dumps(secret)[1:-1],
        json.dumps(secret, ensure_ascii=False)[1:-1],
    }
    return raw | {html.escape(v) for v in raw} | {html.escape(v, quote=False) for v in raw}


# --- Reserved metadata namespace ---------------------------------------------


def test_other_keys_under_the_reserved_namespace_are_ignored():
    class T:
        def __init__(self, meta):
            self.meta = meta
            self.input_schema = {"type": "object", "properties": {}}

    assert is_tagged(T({"mcpflow": {"action": True, "label": "x", "action2": False}}))
    assert not is_tagged(T({"mcpflow": {"label": True}}))
    assert not is_tagged(T({"other": {"action": True}}))


@pytest.mark.asyncio
async def test_filter_does_not_touch_resources_templates_or_prompts():
    # Requirement: the filter SHALL NOT touch a resource, a resource template,
    # or a prompt, and SHALL NOT read `_meta["mcpflow"]` for them. A tagged
    # resource and prompt stay visible to a session with no token.
    server = FastMCP("local")
    tag = {"mcpflow": {"action": True}}

    @server.resource("res://x", meta=tag)
    def res() -> str:
        return "x"

    @server.resource("res://{id}", meta=tag)
    def tmpl(id: str) -> str:
        return id

    @server.prompt(meta=tag)
    def pr() -> str:
        return "p"

    f = ActionScopeFilter()
    resources = await server.list_resources()
    templates = await server.list_resource_templates()
    prompts = await server.list_prompts()
    assert resources and templates and prompts
    assert list(await f.list_resources(resources)) == list(resources)
    assert list(await f.list_resource_templates(templates)) == list(templates)
    assert list(await f.list_prompts(prompts)) == list(prompts)

    async def next_resource(uri, *, version=None):
        return resources[0]

    async def next_prompt(name, *, version=None):
        return prompts[0]

    assert await f.get_resource("res://x", next_resource) is resources[0]
    assert await f.get_prompt("pr", next_prompt) is prompts[0]


# --- Admin scope rule on the MCP surface -------------------------------------


def test_mcp_session_can_call_an_ordinary_tool_of_a_filtered_child(server_factory):
    # The filter drops only actions on `get_tool` too: a copy of `ScopeFilter`
    # or a `get_tool` that skips `call_next` would break this call.
    server, h = start(server_factory, store_spec())
    assert call(server.base_url, h["mcp"], "store_list_stores") == "git1, dir1"
    assert call_log(server) == ["list_stores"]


def test_proxy_cache_never_carries_an_admin_view_to_an_mcp_session(server_factory):
    # The child provider caches its tool list. An admin list and call inside
    # the cache TTL must not open the action to an `mcp` session after it.
    server, h = start(server_factory, store_spec())
    assert "store_set_writable" in list_names(server.base_url, h["admin"])
    assert call(server.base_url, h["admin"], "store_set_writable", {"name": "a"}) == "writable: a"
    assert "store_set_writable" not in list_names(server.base_url, h["mcp"])
    with pytest.raises(ToolError, match="Unknown tool"):
        call(server.base_url, h["mcp"], "store_set_writable", {"name": "b"})
    assert call_log(server) == ["set_writable"]


def test_muted_action_is_hidden_from_an_admin_tools_list(server_factory):
    # Scenario: A muted action is hidden from an admin session.
    server, h = start(server_factory, store_spec())
    with admin(server) as client:
        mute(client, tool_path("store"), tool="set_writable")
    names = set(list_names(server.base_url, h["admin"]))
    assert "store_set_writable" not in names
    assert "store_add_store" in names


def test_no_hashed_name_reaches_a_conforming_action(server_factory):
    # Probe (a): sweep the hashed address space an `mcp` session can guess for
    # both conforming actions. Every `<12 hex>_<name>` either misses or lands
    # on the stated residual `hashed` (a clause violator), never on an action.
    server, h = start(server_factory, store_spec())
    apps = ("fake", "store", "mcpflow", "FastMCP", "")
    names = []
    for action in ("set_writable", "add_store"):
        for app in apps:
            for tool in (action, f"store_{action}"):
                digest = hash_tool(app, tool)
                names += [f"{digest}_{action}", f"{digest}_store_{action}"]
        names += [f"{'f' * 12}_{action}", f"{'0' * 12}_store_{action}"]
    for name in names:
        with pytest.raises(ToolError, match="Unknown tool"):
            call(server.base_url, h["mcp"], name, {"name": "x"})
    assert call_log(server) == []


# --- A muted action is marked and not submitted ------------------------------


def test_root_mute_marks_every_action_and_refuses_submit_before_the_helper(
    server_factory, monkeypatch
):
    seen = _spy_admin_call(monkeypatch)
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        mute(client, ROOT)
        body = client.get(PAGE).text
        resp = action_post(client, ADD, data={"name": "n", "kind": "git", "secret_key": SECRET})
    by_name = cards(body)
    assert by_name and all(c.startswith('<details class="action muted"') for c in by_name.values())
    assert resp.status_code == 400
    assert '<p class="error">muted</p>' in cards(resp.text)["add_store"]
    assert SECRET not in resp.text
    # A4 F1: the handler ALWAYS calls run_action; the mute is detected inside it
    # (its own listing + action_enabled re-check), not before it. The guarantee
    # is now "the CHILD is not called for a muted submit": run_action returns
    # kind "muted" before any call_tool_mcp, so the call log stays empty.
    assert seen == ["store_add_store"]
    assert call_log(server) == []


def test_tool_mute_refuses_submit_before_call_tool_as_admin(server_factory, monkeypatch):
    # A4 F1: the handler always calls run_action; run_action re-checks the mute
    # on its own listing and returns kind "muted" before any call_tool_mcp. The
    # guarantee is "the CHILD is not called for a muted submit": call_log empty,
    # form_error muted.
    seen = _spy_admin_call(monkeypatch)
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        mute(client, tool_path("store"), tool="set_writable")
        resp = action_post(client, PAGE + "/set_writable", data={"name": "s3main"})
    assert resp.status_code == 400
    assert '<p class="error">muted</p>' in cards(resp.text)["set_writable"]
    assert seen == ["store_set_writable"]
    assert call_log(server) == []


# --- Actions page: forms, result rendering ------------------------------------


def test_forms_post_without_htmx(server_factory):
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        body = client.get(PAGE).text
    for card in cards(body).values():
        form = re.search(r"<form [^>]*>", card).group(0)
        assert 'method="post"' in form
        assert "hx-" not in card
        assert "multipart" not in form


def test_structured_result_renders_once(server_factory):
    # FastMCP mirrors structured output as a JSON text block. The handler
    # drops that mirror block (mirror condition a), so the result shows once.
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        resp = action_post(client, ADD, data={"name": "s3main", "kind": "s3", "secret_key": "k"})
    assert resp.status_code == 200, resp.text
    block = html.unescape(_result_block(resp.text))
    pres = re.findall(r"<pre>(.*?)</pre>", block, re.DOTALL)
    assert len(pres) == 1
    assert json.loads(pres[0])["name"] == "s3main"
    assert '{\n  "name": "s3main"' in pres[0]  # pretty JSON


def test_text_result_renders_when_there_is_no_structured_content(server_factory):
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        resp = action_post(client, PAGE + "/set_writable", data={"name": "s3main"})
    assert resp.status_code == 200, resp.text
    # FastMCP 4.0.4 wraps the `str` return as structured `{"result": ...}`, so
    # the result is that structured content; the text block `writable: s3main`
    # is its mirror (condition b) and does not render.
    pres = re.findall(r"<pre>(.*?)</pre>", _result_block(resp.text), re.DOTALL)
    assert len(pres) == 1
    assert json.loads(html.unescape(pres[0])) == {"result": "writable: s3main"}


# --- Probe (c): the secret never echoes ---------------------------------------


@pytest.mark.parametrize(
    "secret",
    ['q"uo\\te-S3CRET-1', "ünï-cödé-S3CRET-2", "<b>&amp;-S3CRET-3</b>", "a'b S3CRET 4"],
)
def test_awkward_secret_is_masked_in_every_rendering(server_factory, caplog, secret):
    caplog.set_level(logging.DEBUG)
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        ok = action_post(
            client,
            ADD,
            data={"name": "s3main", "kind": "s3", "secret_key": secret, "tags": secret},
        )
        err = action_post(client, ADD, data={"name": "fail", "kind": "git", "secret_key": secret})
    assert ok.status_code == 200, ok.text
    assert err.status_code == 400, err.text
    # The result block holds the secret twice: in `secret_key` and inside the
    # `tags` array. The `tags` textarea itself re-fills by spec, so only the
    # result block and the error card are checked.
    block = _result_block(ok.text)
    err_card = cards(err.text)["add_store"]
    for v in _variants(secret):
        assert v not in block, v
        assert v not in err_card, v
    assert "***" in block and "***" in err_card
    assert not [r for r in caplog.records if any(v in r.getMessage() for v in _variants(secret))]


def test_secret_absent_from_a_coercion_error_page(server_factory, caplog):
    caplog.set_level(logging.DEBUG)
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        for data in (
            {"name": "n", "kind": "git", "secret_key": SECRET, "port": "abc"},
            {"name": "n", "kind": "nope", "secret_key": SECRET},
            {"name": "n", "kind": "git", "secret_key": SECRET, "extra": "{"},
            {"name": "n", "kind": "git", "secret_key": SECRET, "ratio": "inf"},
        ):
            resp = action_post(client, ADD, data=data)
            assert resp.status_code == 400, data
            assert SECRET not in resp.text
            if data["kind"] == "nope":
                assert resp.text == "Invalid form. Reload the actions page."
            else:
                assert "value=" not in re.findall(r'<input[^>]*type="password"[^>]*>', resp.text)[0]
    assert call_log(server) == []
    assert not [r for r in caplog.records if SECRET in r.getMessage()]


def test_tool_error_path_logs_no_secret_and_no_arguments(server_factory, caplog):
    caplog.set_level(logging.DEBUG)
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        resp = action_post(client, ADD, data={"name": "fail", "kind": "git", "secret_key": SECRET})
    assert resp.status_code == 400
    messages = [r.getMessage() for r in caplog.records]
    assert not [m for m in messages if SECRET in m]
    assert not [m for m in messages if "'secret_key'" in m or '"secret_key"' in m]


def test_admin_token_never_reaches_a_template_or_a_log(server_factory, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    contexts: list[dict] = []
    real = jinja2.Template.render

    def spy(self, *args, **kwargs):
        contexts.append(dict(*args, **kwargs))
        return real(self, *args, **kwargs)

    monkeypatch.setattr(jinja2.Template, "render", spy)
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        ok = action_post(client, PAGE + "/set_writable", data={"name": "s3main"})
        err = action_post(client, PAGE + "/set_writable", data={"name": "git1"})
    assert (ok.status_code, err.status_code) == (200, 400)

    def walk(value, depth=0):
        assert not isinstance(value, (AccessToken, AuthenticatedUser)), value
        if depth > 4:
            return
        if isinstance(value, dict):
            for v in value.values():
                walk(v, depth + 1)
        elif isinstance(value, (list, tuple)):
            for v in value:
                walk(v, depth + 1)

    assert contexts
    for ctx in contexts:
        walk({k: v for k, v in ctx.items() if k != "request"})
    for resp in (ok, err):
        assert "mcpflow-ui" not in resp.text
    assert not [r for r in caplog.records if "mcpflow-ui" in r.getMessage()]


def test_template_values_never_hold_a_password_key(server_factory, monkeypatch):
    # Amendment 5 sends only masked presentation records to the template.
    # Password controls remain empty; ordinary tokenized controls still refill.
    contexts: list[dict] = []
    real = jinja2.Template.render

    def spy(self, *args, **kwargs):
        contexts.append(dict(*args, **kwargs))
        return real(self, *args, **kwargs)

    monkeypatch.setattr(jinja2.Template, "render", spy)
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        action_post(client, ADD, data={"name": "s3main", "kind": "s3", "secret_key": SECRET})
        action_post(client, ADD, data={"name": "fail", "kind": "git", "secret_key": SECRET})
        action_post(client, ADD, data={"name": "n", "kind": "git", "secret_key": SECRET, "port": "x"})
    posted = [c for c in contexts if c.get("active") == "add_store"]
    assert len(posted) == 3
    for ctx in posted:
        active = next(card for card in ctx["actions"] if card["active"])
        fields = {field["label"]: field for field in active["fields"]}
        assert fields["name"]["value"] in {"s3main", "fail", "n"}
        assert fields["secret_key"]["control"] == "password"
        assert fields["secret_key"]["value"] == ""
        presentation = {k: v for k, v in ctx.items() if k not in ("request", "c")}
        assert SECRET not in json.dumps(presentation)



# --- Probe (d): the session gate and cross-site protection --------------------


def test_cross_origin_post_is_refused_before_the_handler(server_factory, monkeypatch):
    seen = _spy_admin_call(monkeypatch)
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        resp = action_post(
            client,
            PAGE + "/set_writable",
            data={"name": "x"},
            headers={"Origin": "https://evil.example"},
        )
    assert resp.status_code == 403
    assert seen == [] and call_log(server) == []


def test_bearer_tokens_do_not_open_the_ui_submit(server_factory, monkeypatch):
    # An `mcp` token and an `admin` API token both lack the session cookie.
    seen = _spy_admin_call(monkeypatch)
    server, h = start(server_factory, store_spec())
    for token in (h["mcp"], h["admin"]):
        headers = {"Authorization": f"Bearer {token}"}
        resp = httpx.post(server.base_url + PAGE + "/set_writable",
                          data={"name": "x"}, headers=headers)
        assert resp.status_code == 401
        get = httpx.get(server.base_url + PAGE, headers=headers, follow_redirects=False)
        assert get.status_code == 303 and get.headers["location"].startswith("/login")
    assert seen == [] and call_log(server) == []


# --- Probe (f): coercion at the trust boundary --------------------------------


@pytest.mark.parametrize("raw", ["-inf", "Infinity", "1e999", "NaN", " nan "])
def test_non_finite_numbers_are_rejected(raw):
    schema = {"type": "object", "properties": {"n": {"type": "number"}}}
    with pytest.raises(ValueError, match="^n:"):
        coerce_form(schema, {"n": raw})


@pytest.mark.parametrize("raw", ["[NaN]", '{"a": Infinity}', "-Infinity"])
def test_non_finite_json_constants_are_rejected(raw):
    schema = {"type": "object", "properties": {"j": {}}}
    with pytest.raises(ValueError, match="^j:"):
        coerce_form(schema, {"j": raw})


def test_enum_value_outside_the_enum_is_rejected_even_when_optional():
    schema = {"type": "object", "properties": {
        "e": {"anyOf": [{"type": "string", "enum": ["a"]}, {"type": "null"}]}}}
    assert coerce_form(schema, {"e": ""}) == {}
    with pytest.raises(ValueError, match="^e:"):
        coerce_form(schema, {"e": "b"})


def test_deeply_nested_json_is_a_coercion_failure():
    # Requirement: a coercion failure answers 400 with the reason. A JSON
    # textarea with deep nesting makes `json.loads` raise `RecursionError`,
    # which is not a `ValueError`.
    schema = {"type": "object", "properties": {"j": {}}}
    with pytest.raises(ValueError, match="^j:"):
        coerce_form(schema, {"j": "[" * 100_000})


def test_deeply_nested_json_answers_400_not_500(server_factory):
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        resp = action_post(
            client,
            ADD, data={"name": "n", "kind": "git", "secret_key": SECRET, "extra": "[" * 100_000}
        )
    assert resp.status_code == 400
    assert SECRET not in resp.text
    assert call_log(server) == []


# --- Probe (b): design gaps, pinned -------------------------------------------


def _tagged(props: dict, defs: dict | None = None):
    class T:
        def __init__(self) -> None:
            self.meta = {"mcpflow": {"action": True}}
            self.input_schema = {
                "type": "object", "properties": props, **({"$defs": defs} if defs else {})
            }

    return T()


def test_gap_password_in_array_items_is_not_flat():
    # `list[SecretStr]` in pydantic emits exactly this property.
    prop = {"type": "array", "items": {"type": "string", "format": "password", "writeOnly": True}}
    assert clause_violation(_tagged({"keys": prop})) is not None


def test_gap_ref_to_a_password_is_not_flat():
    defs = {"Secret": {"type": "string", "format": "password"}}
    assert clause_violation(_tagged({"key": {"$ref": "#/$defs/Secret"}}, defs)) is not None


def test_gap_ref_to_a_nested_model_is_not_flat():
    # A pydantic model argument emits `$ref`; its fields can hold a secret.
    defs = {"Cfg": {"type": "object", "properties": {"secret_key": {
        "type": "string", "format": "password"}}}}
    for prop in ({"$ref": "#/$defs/Cfg"}, {"allOf": [{"$ref": "#/$defs/Cfg"}]},
                 {"oneOf": [{"$ref": "#/$defs/Cfg"}, {"type": "string"}]}):
        assert clause_violation(_tagged({"cfg": prop}, defs)) is not None, prop
