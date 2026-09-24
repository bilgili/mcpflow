"""Child actions: the admin scope filter, the contract clause, and the page.

Scenarios from `specs/mcp-gateway/spec.md` (Reserved metadata namespace,
Action contract clause, Admin tools are visible to admin sessions only),
`specs/tool-visibility/spec.md` (A muted action is marked and not submitted),
and `specs/web-ui/spec.md` (Actions page), for change `child-actions-page`.

The MCP tests drive the real app over Streamable HTTP with a bearer token,
because the filter reads `get_access_token()`. Fixture mode `action` appends
one line per tool call to `calls.log`, so a refused call proves itself by an
empty log.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from html import unescape
from pathlib import Path

import pytest
from action_browser import action_post, control
from conftest import fake_child_spec
from fastmcp import FastMCP
from fastmcp.exceptions import NotFoundError, ToolError
from fastmcp.server.providers.addressing import hash_tool
from fastmcp.server.transforms import Namespace, Visibility
from mcp.server.auth.middleware.auth_context import auth_context_var
from test_visibility import _seed, admin, call_log, mute, ns_path, tool_path, unmute

from mcpflow import actions as actions_mod
from mcpflow.actions import (
    ActionScopeFilter,
    AuthorizedHashProvider,
    call_tool_as_admin,
    clause_violation,
    coerce_form,
    is_action,
    is_tagged,
)
from mcpflow.auth import TokenStore

SECRET = "S3CRET-verifier-0123456789"
PAGE = "/servers/store/actions"


def _client(base: str, token: str):
    from fastmcp import Client
    from fastmcp.client.transports import StreamableHttpTransport

    return Client(
        StreamableHttpTransport(
            base + "/mcp", headers={"Authorization": f"Bearer {token}"}
        )
    )


def list_names(base: str, token: str) -> list[str]:
    async def run():
        async with _client(base, token) as c:
            return [t.name for t in await c.list_tools()]

    return asyncio.run(run())


def call(base: str, token: str, name: str, args: dict | None = None):
    async def run():
        async with _client(base, token) as c:
            return (await c.call_tool(name, args or {})).data

    return asyncio.run(run())


def start(server_factory, *specs, running: int = 1):
    """A live gateway with an `mcp` and an `admin` token in `holder`."""
    holder: dict = {}
    inner = _seed(*specs, holder=holder)

    def seed(data_dir: Path) -> None:
        inner(data_dir)
        store = TokenStore(data_dir / "tokens.json")
        store.load()
        holder["mcp"] = holder["clear"]
        holder["admin"] = store.create("admin", "admin")[1]

    server = server_factory(seed)
    counts = server.wait(running=running)
    assert counts["running"] == running, counts
    return server, holder


def store_spec(**extra):
    # F2 revised: the store child is action-capable. mcpflow honours its action
    # tags only when `spec.actions` is true, so every actions-page and MCP-surface
    # test for the store runs against a capable child.
    extra.setdefault("actions", True)
    return fake_child_spec("store", "action", **extra)


def cards(body: str) -> dict[str, str]:
    """Action name -> the HTML of its card."""
    out = {}
    for m in re.finditer(r'<details class="action[^"]*".*?\n      </details>', body, re.DOTALL):
        name = re.search(r'<span class="name">([^<]+)</span>', m.group(0)).group(1)
        out[name] = m.group(0)
    return out


def password_inputs(html: str) -> list[str]:
    return re.findall(r'<input[^>]*type="password"[^>]*>', html)


# --- E-1: what an action is --------------------------------------------------


def test_actions_are_the_tagged_conforming_tools_in_order(server_factory):
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        body = client.get(PAGE).text
    assert list(cards(body)) == ["set_writable", "add_store"]


def test_a_non_boolean_tag_is_not_a_tag(server_factory):
    server, h = start(server_factory, store_spec())
    with admin(server) as client:
        body = client.get(PAGE).text
    assert "yes_tag" not in cards(body)
    assert "store_yes_tag" in list_names(server.base_url, h["mcp"])


def test_tag_shapes():
    class T:
        def __init__(self, meta, schema=None):
            self.meta = meta
            self.input_schema = schema or {"type": "object", "properties": {}}

    assert is_tagged(T({"mcpflow": {"action": True}}))
    for meta in (None, {}, {"mcpflow": True}, {"mcpflow": {"action": 1}},
                 {"mcpflow": {"action": "yes"}}, {"mcpflow": []}):
        assert not is_tagged(T(meta))


# --- E-2: one form per action over the schema subset --------------------------


def test_page_renders_one_form_per_action(server_factory):
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        resp = client.get(PAGE)
    assert resp.status_code == 200
    body = resp.text
    assert body.count('<form method="post" action="/servers/store/actions/') == 2
    card = cards(body)["add_store"]
    selects = re.findall(r"<select[^>]*>.*?</select>", card, re.DOTALL)
    assert len(selects) == 1
    assert re.findall(r'<option value="o[0-9]+"[^>]*>([^<]*)</option>', selects[0]) == ["git", "directory", "s3"]
    assert control(card, "tags").startswith("<textarea")
    assert control(card, "extra").startswith("<textarea")
    assert 'type="number"' in control(card, "port")
    assert 'type="checkbox"' in control(card, "path_style")
    assert " required" in control(card, "name")
    # The schema sits in a collapsed <details>.
    assert re.search(r"<details>\s*<summary[^>]*>schema</summary>", card)


def test_page_and_partial_render_the_same_cards(server_factory):
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        page = client.get(PAGE).text
        partial = client.get(PAGE, headers={"HX-Request": "true"}).text
    assert "<html" in page and "<html" not in partial
    assert list(cards(page)) == list(cards(partial))


def test_array_textarea_coerces_to_lines(server_factory):
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        resp = action_post(
            client,
            PAGE + "/add_store",
            data={"name": "s3main", "kind": "s3", "secret_key": "x", "tags": "a\nb\n",
                  "extra": '{"k": 1}', "port": "9000"},
        )
    assert resp.status_code == 200, resp.text
    assert '"tags": [\n    "a",\n    "b"\n  ]' in resp.text.replace("&#34;", '"')


def test_coercion_table():
    schema = {
        "type": "object",
        "properties": {
            "s": {"type": "string"},
            "e": {"type": "string", "enum": ["a", "b"]},
            "i": {"anyOf": [{"type": "integer"}, {"type": "null"}]},
            "n": {"type": ["number", "null"]},
            "b": {"type": "boolean"},
            "arr": {"type": "array", "items": {"type": "string"}},
            "j": {},
        },
        "required": ["s"],
    }
    assert coerce_form(schema, {"s": "", "i": "", "n": ""}) == {"s": "", "b": False}
    assert coerce_form(
        schema,
        {"s": "x", "e": "b", "i": "3", "n": "1.5", "b": "on", "arr": " a \n\nb", "j": "[1]"},
    ) == {"s": "x", "e": "b", "i": 3, "n": 1.5, "b": True, "arr": ["a", "b"], "j": [1]}
    for bad, prop in (({"e": "c"}, "e"), ({"i": "1.5"}, "i"), ({"n": "nan"}, "n"),
                      ({"n": "inf"}, "n"), ({"j": "{"}, "j"), ({"j": "NaN"}, "j")):
        with pytest.raises(ValueError, match=f"^{prop}:"):
            coerce_form(schema, {"s": "x", **bad})


def test_bad_number_rerenders_with_a_reason_and_no_call(server_factory):
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        resp = action_post(
            client,
            PAGE + "/add_store",
            data={"name": "n", "kind": "git", "secret_key": SECRET, "port": "abc"},
        )
    assert resp.status_code == 400
    card = cards(resp.text)["add_store"]
    assert re.search(r'<p class="error">port: not an integer</p>', card)
    assert "add_store" not in call_log(server)


# --- E-3: a password never echoes ---------------------------------------------


def test_password_is_masked_on_render_rerender_result_and_log(server_factory, caplog):
    caplog.set_level(logging.DEBUG)
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        first = client.get(PAGE).text
        resp = action_post(
            client,
            PAGE + "/add_store",
            data={"name": "s3main", "kind": "s3", "secret_key": SECRET},
        )
    assert resp.status_code == 200, resp.text
    for html in (first, resp.text):
        inputs = password_inputs(html)
        assert len(inputs) == 1
        assert "value=" not in inputs[0]
        assert 'autocomplete="new-password"' in inputs[0]
    assert SECRET not in resp.text
    assert "***" in resp.text
    # The other controls re-fill from the posted values.
    card = cards(resp.text)["add_store"]
    assert 'value="s3main"' in card and re.search(r'<option value="o[0-9]+" selected>s3</option>', card)
    assert "add_store" in call_log(server)
    assert not [r for r in caplog.records if SECRET in r.getMessage()]


def test_tool_error_text_masks_the_password(server_factory):
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        resp = action_post(
            client,
            PAGE + "/add_store",
            data={"name": "fail", "kind": "git", "secret_key": SECRET},
        )
    assert resp.status_code == 400
    card = cards(resp.text)["add_store"]
    assert "rejected secret ***" in card
    assert SECRET not in resp.text
    assert "value=" not in password_inputs(card)[0]


# --- E-4: submit under admin scope --------------------------------------------


def test_submit_runs_the_action_against_one_generation(server_factory, monkeypatch):
    # F4: the submit calls `Supervisor.run_action`, which lists, re-checks, and
    # calls on one leased generation. No `call_tool_as_admin`, no second name
    # resolution through the gateway.
    from mcpflow import supervisor as supervisor_mod

    seen = []
    real = supervisor_mod.Supervisor.run_action

    async def spy(self, ns, name, form, **kwargs):
        # A4 F1: run_action now takes the RAW posted form (a Mapping), not the
        # coerced arguments dict. Normalise it for the equality assert.
        seen.append((ns, name, dict(form)))
        return await real(self, ns, name, form, **kwargs)

    monkeypatch.setattr("mcpflow.supervisor.Supervisor.run_action", spy)
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        resp = action_post(client, PAGE + "/set_writable", data={"name": "s3main"})
    assert resp.status_code == 200, resp.text
    assert seen == [("store", "set_writable", {"name": "s3main"})]
    assert call_log(server) == ["set_writable"]
    assert "Last result" in resp.text and "writable: s3main" in resp.text
    assert "set_writable" in re.search(r'<details class="action" open>.*?</summary>',
                                       resp.text, re.DOTALL).group(0)


# --- E-5: empty and stopped ---------------------------------------------------


def test_child_with_no_action_renders_no_actions(server_factory):
    server, _h = start(server_factory, fake_child_spec("time", "good"))
    with admin(server) as client:
        resp = client.get("/servers/time/actions")
    assert resp.status_code == 200
    assert "no actions" in resp.text and "<form method=\"post\" action=\"/servers/time/actions" not in resp.text


def test_stopped_child_opens_no_client(server_factory, monkeypatch):
    server, _h = start(server_factory, store_spec(enabled=False), running=0)

    def boom(*a, **kw):
        raise AssertionError("opened a client")

    monkeypatch.setattr("mcpflow.supervisor.Client", boom)
    with admin(server) as client:
        resp = client.get(PAGE)
    assert resp.status_code == 200
    assert "no actions" in resp.text and "<form method=\"post\"" not in resp.text


# --- E-6: the session gate ----------------------------------------------------


def test_unauthenticated_request_redirects_and_skips_the_handler(
    server_factory, monkeypatch
):
    server, _h = start(server_factory, store_spec())
    ran = []

    async def spy(self, ns):
        ran.append(ns)
        return []

    monkeypatch.setattr("mcpflow.supervisor.Supervisor.actions", spy)
    resp = server.get(PAGE, follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/login")
    assert server.post(PAGE + "/set_writable", data={"name": "x"}).status_code == 401
    assert ran == []


# --- E-7: mutes ---------------------------------------------------------------


def test_muted_action_is_marked_and_refused_before_the_call(server_factory):
    server, h = start(server_factory, store_spec())
    with admin(server) as client:
        mute(client, tool_path("store"), tool="set_writable")
        body = client.get(PAGE).text
        resp = action_post(client, PAGE + "/set_writable", data={"name": "s3main"})
    card = cards(body)["set_writable"]
    assert card.startswith('<details class="action muted"')
    assert '<span class="badge">muted</span>' in card
    for tag in re.findall(r"<(?:input|select|textarea|button)[^>]*>", card):
        assert "disabled" in tag, tag
    other = cards(body)["add_store"]
    assert "muted" not in other.split("</summary>")[0]
    assert "<button class=\"primary\" type=\"submit\">" in other
    assert resp.status_code == 400
    assert '<p class="error">muted</p>' in cards(resp.text)["set_writable"]
    assert call_log(server) == []

    # An admin session gets the unknown-tool error, and the child no call.
    with pytest.raises(ToolError, match="Unknown tool"):
        call(server.base_url, h["admin"], "store_set_writable", {"name": "x"})
    assert call_log(server) == []


def test_namespace_mute_marks_every_action_and_unmute_restores(server_factory):
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        mute(client, ns_path("store"))
        muted = cards(client.get(PAGE).text)
        unmute(client, ns_path("store"))
        restored = cards(client.get(PAGE).text)
    assert muted and all(c.startswith('<details class="action muted"') for c in muted.values())
    assert all("<button type=\"submit\" disabled>" in c for c in muted.values())
    for c in restored.values():
        assert c.startswith('<details class="action"')
        assert "badge" not in c and "<button class=\"primary\" type=\"submit\">" in c


# --- E-8: the filter ----------------------------------------------------------


def test_build_provider_installs_the_filter_innermost(server_factory):
    # F1/F2 revised: on an action-capable child the chain is wrapped by
    # `AuthorizedHashProvider` (outermost). Inside it the order is unchanged:
    # ActionScopeFilter innermost, then the visibility and namespace transforms.
    server, _h = start(server_factory, store_spec())
    outer = server.supervisor.get("store").provider
    assert isinstance(outer, AuthorizedHashProvider)
    provider = outer._chain
    assert [type(t) for t in provider._transforms] == [Namespace]
    assert [type(t) for t in provider._inner._transforms] == [Visibility]
    proxy = provider._inner._inner
    assert [type(t) for t in proxy.transforms] == [ActionScopeFilter]


def _local_tools():
    server = FastMCP("local")

    @server.tool(meta={"mcpflow": {"action": True}})
    def act(name: str) -> str:
        return f"ran {name}"

    @server.tool
    def plain() -> str:
        return "plain"

    @server.tool(meta={"mcpflow": {"action": True}, "fastmcp": {"tool_hash": "0" * 12},
                       "ui": {"visibility": ["app"]}})
    def hashed() -> str:
        return "hashed"

    @server.tool(meta={"mcpflow": {"action": True}})
    def nested(cfg: dict) -> str:
        return "nested"

    return server


@pytest.mark.asyncio
async def test_filter_with_no_token_hides_a_tagged_tool_only():
    assert auth_context_var.get() is None
    tools = {t.name: t for t in await _local_tools().list_tools()}
    f = ActionScopeFilter()
    kept = [t.name for t in await f.list_tools(list(tools.values()))]
    # F1: `_hides` is now `is_tagged`, so the filter drops EVERY tagged tool for
    # a caller with no token, the hash-reachable `hashed` included. Only the
    # untagged `plain` survives; `AuthorizedHashProvider` closes the hashed path.
    assert kept == ["plain"]

    async def call_next(name, *, version=None):
        return tools.get(name)

    assert await f.get_tool("act", call_next) is None
    assert await f.get_tool("nested", call_next) is None
    assert (await f.get_tool("plain", call_next)).name == "plain"
    # The hash-reachable tagged tool is now hidden on both seams too.
    assert await f.get_tool("hashed", call_next) is None
    assert await f.get_tool("nope", call_next) is None


def test_clause_terms():
    class T:
        def __init__(self, meta=None, props=None):
            self.meta = {"mcpflow": {"action": True}, **(meta or {})}
            self.input_schema = {"type": "object", "properties": props or {}}

    assert clause_violation(T()) is None
    assert clause_violation(T({"fastmcp": {"tool_hash": "h"}, "ui": {"visibility": ["app"]}})) == "fastmcp.tool_hash"
    assert clause_violation(T({"ui": {"visibility": ["model"]}})) == "ui.visibility"
    bad = {
        "o": {"type": "object"},
        "o2": {"anyOf": [{"type": "object"}, {"type": "null"}]},
        "a": {"type": "array", "items": {"type": "integer"}},
        "a2": {"type": "array"},
        "p": {"type": "integer", "format": "password"},
        "p2": {"format": "password"},
    }
    for name, prop in bad.items():
        assert clause_violation(T(props={name: prop})) == f"schema:{name}", name
    # `{"type": "null"}` has no type name left after `null` goes, so it has no
    # effective type: a JSON textarea, flat since the 2026-09-17 amendment.
    ok = {"s": {"type": "string", "format": "password"}, "x": {}, "nul": {"type": "null"},
          "l": {"anyOf": [{"type": "array", "items": {"type": "string"}}, {"type": "null"}]}}
    assert clause_violation(T(props=ok)) is None
    assert is_action(T(props=ok))


# --- E-9: the product never learns the word -----------------------------------


def test_no_source_file_names_skill():
    root = Path(__file__).parent.parent / "src" / "mcpflow"
    for path in root.rglob("*"):
        # Catalog recipes name integrations; gateway behavior stays generic.
        if path.suffix == ".json" and path.is_relative_to(root / "catalog"):
            continue
        if path.is_file() and path.suffix in {".py", ".html", ".css", ".js", ".json"}:
            assert "skill" not in path.read_text().lower(), path


# --- E-10: clause violators ---------------------------------------------------


def _warnings(caplog) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == "mcpflow.supervisor" and r.levelno == logging.WARNING
    ]


def test_hashed_and_nested_tags_are_not_actions(server_factory, caplog):
    caplog.set_level(logging.WARNING, logger="mcpflow.supervisor")
    server, h = start(server_factory, store_spec())
    caplog.clear()
    with admin(server) as client:
        body = client.get(PAGE).text
    names = cards(body)
    for tool in ("hashed", "nested", "nested_pw"):
        assert tool not in names
    warnings = _warnings(caplog)
    assert warnings.count("store: tool hashed is not an action: fastmcp.tool_hash") == 1
    assert warnings.count("store: tool nested is not an action: schema:cfg") == 1
    assert warnings.count("store: tool nested_pw is not an action: schema:keys") == 1
    # F1: every tagged tool is now hidden from an mcp session, the
    # hash-reachable `hashed` included. `AuthorizedHashProvider` closes the
    # hashed path, so the filter no longer keeps an exception for it.
    listed = set(list_names(server.base_url, h["mcp"]))
    assert not listed & {"store_hashed", "store_nested", "store_nested_pw",
                         "store_half", "store_fake"}


# --- error table and probe failure -------------------------------------------


def test_unknown_namespace_and_unknown_action_answer_404(server_factory):
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        assert client.get("/servers/nope/actions").status_code == 404
        assert action_post(client, "/servers/nope/actions/x").status_code == 404
        assert action_post(client, PAGE + "/nope").status_code == 404
    assert call_log(server) == []


def test_tool_error_rerenders_the_card_and_keeps_the_others(server_factory):
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        resp = action_post(client, PAGE + "/set_writable", data={"name": "git1"})
    assert resp.status_code == 400
    by_name = cards(resp.text)
    assert list(by_name) == ["set_writable", "add_store"]
    assert '<p class="error">' in by_name["set_writable"]
    assert "git1 is read-only" in by_name["set_writable"]
    assert '<p class="error">' not in by_name["add_store"]


def test_probe_failure_renders_the_scrubbed_page_error(server_factory, tmp_path):
    # The failure is real now: while the flag exists the child's `tools/list`
    # raises over its own transport (the old technique swapped `Client`, which
    # the owned-client model removed). The child holds a configured secret in
    # its env; the actions read scrubs the failure text with that secret set,
    # so no configured secret ever reaches the page.
    flag = tmp_path / "break"
    server, _h = start(
        server_factory, store_spec(env={"MCPFLOW_BREAK": str(flag), "API_KEY": SECRET})
    )
    flag.write_text("")
    with admin(server) as client:
        get = client.get(PAGE)
        post = action_post(client, PAGE + "/set_writable", data={"name": "x"})
    assert (get.status_code, post.status_code) == (200, 400)
    for resp in (get, post):
        assert "Could not read actions from store: " in resp.text
        assert SECRET not in resp.text
        assert "<form method=\"post\"" not in resp.text
    assert server.supervisor.get("store").status == "running"


def test_a_failing_tools_list_renders_the_error_frame(server_factory, tmp_path):
    flag = tmp_path / "break"
    server, _h = start(server_factory, store_spec(env={"MCPFLOW_BREAK": str(flag)}))
    flag.write_text("")
    with admin(server) as client:
        resp = client.get(PAGE)
    assert resp.status_code == 200
    assert '<p class="error">Could not read actions from store: ' in resp.text
    assert "<form method=\"post\"" not in resp.text
    assert server.supervisor.get("store").status == "running"


def test_server_window_links_to_the_page(server_factory):
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        body = client.get("/servers/store").text
    assert '<a class="btn" href="/servers/store/actions">Actions</a>' in body


def test_server_window_has_no_link_for_a_stopped_child(server_factory):
    server, _h = start(server_factory, store_spec(enabled=False), running=0)
    with admin(server) as client:
        body = client.get("/servers/store").text
    assert "/servers/store/actions" not in body


# --- AC-19: the MCP surface ---------------------------------------------------


def test_mcp_session_sees_no_action_and_keeps_ordinary_tools(server_factory):
    server, h = start(server_factory, store_spec())
    names = set(list_names(server.base_url, h["mcp"]))
    assert "store_list_stores" in names and "store_get_current_time" in names
    assert not names & {"store_set_writable", "store_add_store"}


def test_mcp_session_cannot_call_an_action(server_factory):
    server, h = start(server_factory, store_spec())
    with pytest.raises(ToolError, match="Unknown tool"):
        call(server.base_url, h["mcp"], "store_set_writable", {"name": "x"})
    assert call_log(server) == []


def test_admin_session_sees_and_calls_an_action(server_factory):
    server, h = start(server_factory, store_spec())
    assert "store_set_writable" in list_names(server.base_url, h["admin"])
    assert call(server.base_url, h["admin"], "store_set_writable", {"name": "s"}) == "writable: s"
    assert call_log(server) == ["set_writable"]


def test_hashed_name_of_an_action_is_unknown_to_an_mcp_session(server_factory):
    server, h = start(server_factory, store_spec())
    for name in (
        f"{hash_tool('fake', 'set_writable')}_set_writable",
        f"{hash_tool('store', 'set_writable')}_store_set_writable",
        f"{'0' * 12}_set_writable",
        # F1: the hash of the violator `hashed` used to resolve to `hashed` for
        # an mcp session (ProxyProvider matches the hash alone). The
        # `AuthorizedHashProvider` now re-runs the named decision, which the
        # filter refuses for a non-admin caller, so this residual is closed.
        f"{hash_tool('fake', 'hashed')}_set_writable",
        f"{hash_tool('fake', 'hashed')}_hashed",
    ):
        with pytest.raises(ToolError, match="Unknown tool"):
            call(server.base_url, h["mcp"], name, {"name": "x"})
    assert call_log(server) == []


def test_hashed_path_honours_scope_and_mute(server_factory):
    # F1: the `AuthorizedHashProvider` re-runs the named decision on the tool
    # the hashed path resolves, so scope and mute now guard the hashed path too.
    # A muted hash-reachable tool no longer runs by hash for any scope, and an
    # mcp session cannot reach it by name or by hash.
    server, h = start(server_factory, store_spec())
    with admin(server) as client:
        mute(client, tool_path("store"), tool="hashed")
    for token in (h["mcp"], h["admin"]):
        with pytest.raises(ToolError, match="Unknown tool"):
            call(server.base_url, token, "store_hashed")
        with pytest.raises(ToolError, match="Unknown tool"):
            call(server.base_url, token, f"{hash_tool('fake', 'hashed')}_hashed")
    assert call_log(server) == []


def test_no_action_reaches_the_initialize_catalog(server_factory):
    server, h = start(server_factory, store_spec())

    async def run():
        async with _client(server.base_url, h["mcp"]) as c:
            dumped = json.dumps(
                c.initialize_result.model_dump(mode="json") if c.initialize_result else {}
            )
            return dumped, [t.name for t in await c.list_tools()]

    dumped, names = asyncio.run(run())
    assert "set_writable" not in dumped and "add_store" not in dumped
    assert not {"store_set_writable", "store_add_store"} & set(names)


def test_path_segment_never_names_a_gateway_tool(server_factory, monkeypatch):
    # F4.4: a POST with an `{action}` that `Supervisor.actions(ns)` did not
    # return answers 404 before `run_action` runs, and calls no tool.
    called = []

    async def spy(self, ns, name, arguments, **kwargs):
        called.append((ns, name))

    monkeypatch.setattr("mcpflow.supervisor.Supervisor.run_action", spy)
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        for action in ("mcpflow_list_servers", "list_stores", "hashed", "store_set_writable"):
            assert action_post(client, f"{PAGE}/{action}").status_code == 404
    assert called == [] and call_log(server) == []


# --- the token lifetime -------------------------------------------------------


@pytest.mark.asyncio
async def test_call_tool_as_admin_passes_the_filter_outside_a_request():
    from fastmcp.server.providers import FastMCPProvider

    provider = FastMCPProvider(_local_tools())
    provider.add_transform(ActionScopeFilter())
    gateway = FastMCP("gw")
    gateway.add_provider(provider)

    with pytest.raises(NotFoundError):
        await gateway.call_tool("act", {"name": "x"})
    result = await call_tool_as_admin(gateway, "act", {"name": "x"})
    assert result.content[0].text == "ran x"
    assert auth_context_var.get() is None


@pytest.mark.asyncio
async def test_call_tool_as_admin_resets_the_token_on_error():
    seen = []

    class Gateway:
        async def call_tool(self, name, arguments):
            seen.append(auth_context_var.get().access_token.scopes)
            raise ToolError("boom")

    with pytest.raises(ToolError):
        await call_tool_as_admin(Gateway(), "x", {})
    assert seen == [["admin"]]
    assert auth_context_var.get() is None


# --- amendments 2026-09-17: D-A flatness, D-B fail closed, D-C result ---------


class _T:
    def __init__(self, schema=None, meta=None, props=None):
        self.meta = {"mcpflow": {"action": True}} if meta is None else meta
        self.input_schema = schema or {"type": "object", "properties": props or {}}


_CFG = {"type": "object", "properties": {"k": {"type": "string"}}}

# Condition -> (flat properties, non-flat properties). Each flat one must stay
# flat alone, and each non-flat one must fail alone.
FLATNESS = {
    "F1": ([{"type": "string"}], ["string", True, None]),
    "F2": (
        [{"type": "string", "description": "a $ref is not a key here"}],
        [{"$ref": "#/$defs/Cfg"}, {"not": {"type": "string"}},
         {"type": "array", "items": {"type": "string", "$dynamicRef": "#x"}},
         {"$recursiveRef": "#"}, {"allOf": [_CFG]}, {"oneOf": [_CFG, {"type": "string"}]}],
    ),
    "F3": (
        [{"anyOf": [{"type": "integer"}, {"type": "null"}]},
         {"anyOf": [{"type": "null"}, {"type": "string", "enum": ["a"]}]}],
        [{"anyOf": [{"type": "string"}, {"type": "integer"}, {"type": "null"}]},
         {"anyOf": [{"$ref": "#/$defs/Cfg"}, {"type": "null"}]},
         {"anyOf": [{"type": "string"}, {"type": "integer"}]},
         {"anyOf": [{"type": "array", "items": {"anyOf": [{"type": "string"}, {"type": "null"}]}},
                    {"type": "null"}]},
         {"type": "array", "items": {"anyOf": [{"type": "string"}, {"type": "null"}]}}],
    ),
    "F4": (
        [{"anyOf": [{"type": "string", "format": "password"}, {"type": "null"}]}],
        [{"type": "array", "items": {"type": "string", "format": "password"}},
         {"type": "string", "default": {"format": "password"}}],
    ),
    "F5": (
        [{}, {"type": ["integer", "null"]}, {"type": ["string", "integer"]},
         {"type": "string", "anyOf": [{"type": "integer"}, {"type": "null"}]}],
        [{"type": "object"}, {"type": ["object", "null"]},
         {"anyOf": [{"type": "object"}, {"type": "null"}]}],
    ),
    "F6": (
        [{"type": "array", "items": {"type": "string"}},
         {"anyOf": [{"type": "array", "items": {"type": "string"}}, {"type": "null"}]}],
        [{"type": "array"}, {"type": "array", "items": {"type": "integer"}},
         {"type": "array", "items": [{"type": "string"}]}],
    ),
    "F7": (
        [{"type": "string", "format": "password"},
         {"format": "password", "anyOf": [{"type": "string"}, {"type": "null"}]}],
        [{"format": "password"}, {"type": "integer", "format": "password"},
         {"format": "password", "anyOf": [{"type": "integer"}, {"type": "null"}]},
         {"type": ["string", "integer"], "format": "password"}],
    ),
}


@pytest.mark.parametrize("condition", sorted(FLATNESS))
def test_flatness_rule_per_condition(condition):
    flat, not_flat = FLATNESS[condition]
    for prop in flat:
        assert clause_violation(_T(props={"p": prop})) is None, prop
    for prop in not_flat:
        assert clause_violation(_T(props={"p": prop, "ok": {"type": "string"}})) == "schema:p", prop


def test_flatness_rule_f0_outer_schema():
    props = {"token": {"type": "string"}}
    ok = {"type": "object", "properties": props,
          "$defs": {"S": {"type": "string"}}, "additionalProperties": False}
    assert clause_violation(_T(schema=ok)) is None
    for extra in (
        {"allOf": [{"properties": {"token": {"format": "password"}}}]},
        {"not": {"required": ["token"]}},
        {"anyOf": [{"required": ["token"]}]},
        {"$defs": {"S": {"type": "string", "format": "password"}}},
        {"$defs": {"S": {"$dynamicRef": "#x"}}},
    ):
        assert clause_violation(_T(schema={**ok, **extra})) == "schema", extra


def test_secret_declared_outside_properties_is_not_flat():
    schema = {"type": "object", "properties": {"token": {"type": "string"}},
              "allOf": [{"properties": {"token": {"format": "password"}}}]}
    assert clause_violation(_T(schema=schema)) == "schema"


def test_is_secret_reads_the_head_and_drives_the_control():
    member = {"type": "string", "anyOf": [{"type": "string", "format": "password"},
                                          {"type": "null"}]}
    beside = {"format": "password", "anyOf": [{"type": "string", "format": "date"},
                                              {"type": "null"}]}
    for prop in (member, beside):
        assert actions_mod.is_secret(prop)
        assert clause_violation(_T(props={"key": prop})) is None
        assert [f.control for f in actions_mod.form_fields(
            {"type": "object", "properties": {"key": prop}})] == ["password"]
    assert not actions_mod.is_secret({"type": "array", "items": {"format": "password"}})
    assert not actions_mod.is_secret("password")


def test_mcp_session_cannot_call_a_clause_violator(server_factory):
    server, h = start(server_factory, store_spec())
    for name in ("store_nested", "store_half", "store_fake"):
        with pytest.raises(ToolError, match="Unknown tool"):
            call(server.base_url, h["mcp"], name, {"cfg": {}} if name == "store_nested" else {})
    assert call_log(server) == []


def test_mcp_session_cannot_reach_a_hash_reachable_violator(server_factory):
    # F1 scenario "A hash-reachable clause violator is hidden and refused": the
    # `AuthorizedHashProvider` closes the residual the old model accepted.
    server, h = start(server_factory, store_spec())
    with pytest.raises(ToolError, match="Unknown tool"):
        call(server.base_url, h["mcp"], f"{hash_tool('fake', 'hashed')}_hashed")
    assert call_log(server) == []


def test_admin_session_lists_every_violator_and_the_page_shows_none(server_factory):
    server, h = start(server_factory, store_spec())
    violators = {"nested", "nested_pw", "half", "hashed", "fake"}
    assert {f"store_{v}" for v in violators} <= set(list_names(server.base_url, h["admin"]))
    with admin(server) as client:
        assert not violators & set(cards(client.get(PAGE).text))


def more_spec():
    return fake_child_spec("store", "action", "more", actions=True)


def _pres(body: str) -> list[str]:
    m = re.search(r'<div class="result">(.*?)</div>', body, re.DOTALL)
    assert m, "no result block"
    return [unescape(p) for p in re.findall(r"<pre>(.*?)</pre>", m.group(1), re.DOTALL)]


def test_result_shapes_render_by_the_mirror_rule(server_factory):
    server, _h = start(server_factory, more_spec())
    with admin(server) as client:
        report = _pres(action_post(client, PAGE + "/report", data={"name": "s3main"}).text)
        differ = _pres(action_post(client, PAGE + "/differ").text)
        count = _pres(action_post(client, PAGE + "/count").text)
        finish = _pres(action_post(client, PAGE + "/finish").text)
    # A real text block stays beside the structured content; the mirror goes.
    assert report == ['{\n  "name": "s3main"\n}', "store added"]
    # `1` is not `true`: the canonical form tells them apart.
    assert differ == ['{\n  "ok": true\n}', '{"ok":1}']
    # A wrapped scalar renders once, as the structured content.
    assert count == ['{\n  "result": 3\n}']
    assert finish == ['{\n  "result": "done"\n}']


@pytest.mark.parametrize("action", ["member_secret", "beside_secret"])
def test_is_secret_cases_render_masked_on_the_page(server_factory, action):
    server, _h = start(server_factory, more_spec())
    with admin(server) as client:
        first = cards(client.get(PAGE).text)[action]
        resp = action_post(client, f"{PAGE}/{action}", data={"key": SECRET})
    assert resp.status_code == 200, resp.text
    for card in (first, cards(resp.text)[action]):
        inputs = password_inputs(card)
        assert len(inputs) == 1 and "value=" not in inputs[0]
    assert SECRET not in resp.text
    assert _pres(resp.text) == ['{\n  "result": "got ***"\n}']
