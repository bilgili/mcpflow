"""Verifier tests for the 2026-09-19 amendment (section 16) of change
`child-actions-page`: codex review 2 findings F1-F7.

Every test derives from a spec scenario, not from the implementation:

- `specs/web-ui/spec.md` — "Actions page" scenarios for F1-F6.
- `specs/mcp-gateway/spec.md` — "Action contract clause" scenario
  "A malformed root schema is not an action" for F7.

The store child is action-capable (`store_spec`/`more_spec` set `actions=True`).
Supervisor-level tests use the in-process `make_supervisor` fixture so they can
await `run_action`/`actions` directly and inspect the lease client. Web-level
tests drive the real gateway over HTTP through `server_factory`.
"""

from __future__ import annotations

import contextlib
import html
import logging
import re

import pytest
from action_browser import action_post, control
from conftest import fake_child_spec
from test_child_actions import (
    PAGE,
    SECRET,
    admin,
    call_log,
    cards,
    more_spec,
    password_inputs,
    start,
    store_spec,
)
from test_supervisor import make_supervisor  # noqa: F401 -- async fixture

from mcpflow.actions import redact, redact_schema, secret_literals
from mcpflow.supervisor import ActionRun, LeaseRefused, Supervisor

VIS_OFF = {"fastmcp": {"_internal": {"visibility": False}}}


def more_env_spec(**env):
    """`more_spec` with configured `env` secrets."""
    return fake_child_spec("store", "action", "more", actions=True, env=env)


def _input_value(card: str, name: str) -> str | None:
    """The `value=` of the text input named `name` in one card, unescaped."""
    tag = control(card, name)
    v = re.search(r'value="([^"]*)"', tag)
    return html.unescape(v.group(1)) if v else None


def _schema_text(card: str) -> str:
    m = re.search(r"<details>\s*<summary[^>]*>schema</summary>(.*?)</details>", card, re.DOTALL)
    assert m, "no schema disclosure"
    return html.unescape(m.group(1))


def _result_text(body: str) -> str:
    m = re.search(r'<div class="result">(.*?)</div>', body, re.DOTALL)
    assert m, "no result block"
    return html.unescape(m.group(1))


# =============================================================================
# F1: bind classification to the tool that executes (16.F1.2)
# Scenario "A restart between the check and the call does not swap the tool".
# =============================================================================


@pytest.mark.asyncio
async def test_f1_run_action_single_listing(make_supervisor):  # noqa: F811
    """One submit does exactly one listing and one call on one lease, and it
    calls the raw result API (`call_tool_mcp`), never the parsing `call_tool`,
    so no second name resolution runs."""
    sup = make_supervisor()
    child = await sup.add(store_spec())
    await child.task
    client = child.session.client
    assert client is not None, "stdio generation must own a client"

    counts = {"list": 0, "mcp": 0, "call": 0}
    orig_list, orig_mcp, orig_call = (
        client.list_tools,
        client.call_tool_mcp,
        client.call_tool,
    )

    async def w_list(*a, **k):
        counts["list"] += 1
        return await orig_list(*a, **k)

    async def w_mcp(*a, **k):
        counts["mcp"] += 1
        return await orig_mcp(*a, **k)

    async def w_call(*a, **k):
        counts["call"] += 1
        return await orig_call(*a, **k)

    client.list_tools = w_list
    client.call_tool_mcp = w_mcp
    client.call_tool = w_call

    run = await sup.run_action("store", "set_writable", {"name": "s3main"})
    # A4 F1: run_action returns an ActionRun; kind "ran" carries the raw result.
    assert run.kind == "ran" and not run.result.is_error
    # One listing, one raw call, and never the parsing call_tool.
    assert counts == {"list": 1, "mcp": 1, "call": 0}


# =============================================================================
# F2: log no posted secret; hold the full secret set (16.F2.3)
# =============================================================================


@pytest.mark.asyncio
async def test_f2_parse_failure_logs_no_posted_secret(make_supervisor, caplog):  # noqa: F811
    """Scenario "A parse failure logs no posted secret": the child returns the
    posted password in a field whose declared type fails the structured-result
    parser. `run_action` uses the raw API that runs no parser, so no log line
    holds the secret, and it returns the raw result carrying it."""
    sup = make_supervisor()
    child = await sup.add(more_spec())
    await child.task
    with caplog.at_level(logging.DEBUG):
        run = await sup.run_action("store", "parse_fail", {"secret_key": SECRET})
    # A4 F1: kind "ran"; the raw result carries the secret (no parser ran, no
    # exception logged it).
    assert run.kind == "ran"
    assert run.result.structured_content == {"when": SECRET}
    assert SECRET not in caplog.text


def test_f2_transport_error_web_renders_redacted_400(server_factory, monkeypatch, caplog):
    """Scenario "A transport failure renders a redacted error, not a 500": a
    `RuntimeError` from `run_action` whose text carries a posted secret becomes
    a redacted 400 page error, not a 500, and no log line holds the secret."""

    async def boom(self, ns, name, form, **kwargs):
        # A4 F1: run_action returns an ActionRun for every renderable outcome. A
        # transport failure carries RAW detail plus the full secret set; the web
        # boundary scrubs detail ONCE with run.secrets, so the secret masks.
        return ActionRun(
            "transport",
            frozenset({SECRET}),
            frozenset(),
            None,
            f"transport closed while sending {SECRET}",
        )

    monkeypatch.setattr(Supervisor, "run_action", boom)
    server, _h = start(server_factory, more_spec())
    with caplog.at_level(logging.DEBUG), admin(server) as client:
        resp = action_post(
            client,
            PAGE + "/add_store",
            data={"name": "s3main", "kind": "git", "secret_key": SECRET},
        )
    assert resp.status_code == 400, resp.text
    assert SECRET not in resp.text
    assert "***" in resp.text
    assert "Traceback" not in resp.text
    assert SECRET not in caplog.text


def test_f2_lease_refusal_web_answers_503(server_factory, monkeypatch):
    """Scenario "A lease refusal answers 503": a `LeaseRefused` from
    `run_action` becomes a 503 redacted page error and runs no tool."""

    async def refuse(self, ns, name, form, **kwargs):
        # A4 F1: run_action catches LeaseRefused and returns kind "lease_refused".
        return ActionRun("lease_refused", frozenset(), frozenset(), None, "at capacity")

    monkeypatch.setattr(Supervisor, "run_action", refuse)
    server, _h = start(server_factory, more_spec())
    with admin(server) as client:
        resp = action_post(
            client,
            PAGE + "/add_store",
            data={"name": "s3main", "kind": "git", "secret_key": "x"},
        )
    assert resp.status_code == 503, resp.text
    assert "Traceback" not in resp.text
    assert call_log(server) == []


@pytest.mark.asyncio
async def test_f2_run_action_lease_refused_becomes_a_kind(make_supervisor, monkeypatch):  # noqa: F811
    """A4 F1: run_action catches a `LeaseRefused` at the lease and returns kind
    "lease_refused" carrying the RAW reason text (which holds no argument). The
    submit maps that kind to 503. Every renderable outcome is a returned
    ActionRun; only an unknown namespace raises (KeyError)."""
    sup = make_supervisor()
    child = await sup.add(store_spec())
    await child.task

    @contextlib.asynccontextmanager
    async def refuse(child):
        raise LeaseRefused("store", 1, "at capacity")
        yield  # pragma: no cover

    monkeypatch.setattr(sup, "_lease", refuse)
    run = await sup.run_action("store", "set_writable", {"name": "s3main"})
    assert run.kind == "lease_refused"
    assert "at capacity" in run.detail
    assert run.result is None


@pytest.mark.asyncio
async def test_f2_run_action_carries_raw_detail_and_full_set_on_transport_error(
    make_supervisor,  # noqa: F811
    monkeypatch,
):
    """A4 F1/F3: the scrub moves to the WEB boundary. A transport failure carrying
    a configured secret returns kind "transport" with RAW (unscrubbed) detail and
    the configured secret in `secrets`, so the handler scrubs it ONCE with the
    full set. run_action no longer scrubs detail itself (no two-stage scrub)."""
    sup = make_supervisor()
    child = await sup.add(store_spec(env={"API_KEY": SECRET}))
    await child.task
    client = child.session.client

    async def boom(*a, **k):
        raise RuntimeError(f"connection reset, token {SECRET}")

    monkeypatch.setattr(client, "call_tool_mcp", boom)
    run = await sup.run_action("store", "set_writable", {"name": "s3main"})
    assert run.kind == "transport"
    # detail is RAW: the secret is present, unscrubbed, in run_action's return.
    assert SECRET in run.detail
    # the full secret set carries the configured secret, so the web handler masks
    # it once at the render boundary.
    assert SECRET in run.secrets
    # a re-scrub of the raw detail with run.secrets masks whole.
    assert SECRET not in redact(run.detail, run.secrets)


# =============================================================================
# F3: one string-redaction primitive for keys and values (16.F3.2)
# =============================================================================


def test_f3_redact_masks_keys_and_overlap():
    """Scenarios "A secret in a result dict key is redacted" and "Two
    overlapping secrets mask whole" at the `redact` owner."""
    assert redact({"S3CRET": "x"}, {"S3CRET"}) == {"***": "x"}
    # Two overlapping secrets mask the whole run, never a fragment.
    assert redact("abcdefg", {"abcd", "cdefg"}) == "***"


def test_f3_secret_in_result_key_is_redacted_e2e(server_factory):
    """The child returns the posted secret as a dict KEY; the rendered result
    shows `***` in that key, not the secret."""
    server, _h = start(server_factory, more_spec())
    with admin(server) as client:
        resp = action_post(client, PAGE + "/keyed", data={"secret_key": SECRET})
    assert resp.status_code == 200, resp.text
    assert SECRET not in resp.text
    assert "***" in _result_text(resp.text)


def test_f3_two_overlapping_secrets_mask_whole_e2e(server_factory):
    """Two configured secrets that overlap in one result string mask whole."""
    server, _h = start(server_factory, store_spec(env={"A": "abcd", "B": "cdefg"}))
    with admin(server) as client:
        resp = action_post(client, PAGE + "/set_writable", data={"name": "abcdefg"})
    assert resp.status_code == 200, resp.text
    result = _result_text(resp.text)
    assert "abcd" not in result and "cdefg" not in result
    assert "writable: ***" in result


# =============================================================================
# F4: strip secret enums and register secret literals (16.F4.3)
# Scenario "A secret enum literal is stripped and redacted".
# =============================================================================


def test_f4_secret_enum_stripped_from_schema():
    """`redact_schema` drops a secret property's `enum`; `secret_literals`
    collects it for result redaction."""
    schema = {
        "type": "object",
        "properties": {
            "secret_key": {"type": "string", "format": "password", "enum": ["S3CRET"]}
        },
    }
    assert "enum" not in redact_schema(schema)["properties"]["secret_key"]
    assert "S3CRET" in secret_literals(schema)


def test_f4_enum_literal_stripped_and_redacted_e2e(server_factory):
    """The collapsed raw schema shows no `enum`, and the child-side default
    `S3CRET` that the omitted field takes is redacted in the result, because
    `secret_literals` registered it."""
    server, _h = start(server_factory, more_spec())
    with admin(server) as client:
        first = cards(client.get(PAGE).text)["enumed"]
        # Post nothing for the optional password: the child returns its default.
        resp = action_post(client, PAGE + "/enumed", data={})
    assert "enum" not in _schema_text(first)
    assert "S3CRET" not in first
    assert resp.status_code == 200, resp.text
    assert "S3CRET" not in resp.text
    assert "stored ***" in _result_text(resp.text)


# =============================================================================
# F5: redact the display values with the full secret set (16.F5.2)
# =============================================================================


def test_f5_configured_secret_in_ordinary_field_redacted_on_success(server_factory):
    """Scenario "A configured secret in an ordinary field is redacted on
    re-render": a configured secret typed into an ordinary field shows `***`
    in the refilled control on a success render."""
    server, _h = start(server_factory, more_env_spec(API_KEY=SECRET))
    with admin(server) as client:
        resp = action_post(
            client,
            PAGE + "/add_store",
            data={"name": SECRET, "kind": "git", "secret_key": "pw"},
        )
    assert resp.status_code == 200, resp.text
    card = cards(resp.text)["add_store"]
    assert _input_value(card, "name") == "***"
    assert SECRET not in resp.text


def test_f5_configured_secret_in_ordinary_field_redacted_on_failure(server_factory):
    """The same holds on a failure render (a bad number re-renders at 400)."""
    server, _h = start(server_factory, more_env_spec(API_KEY=SECRET))
    with admin(server) as client:
        resp = action_post(
            client,
            PAGE + "/add_store",
            data={"name": SECRET, "kind": "git", "secret_key": "pw", "port": "abc"},
        )
    assert resp.status_code == 400, resp.text
    card = cards(resp.text)["add_store"]
    assert _input_value(card, "name") == "***"
    assert SECRET not in resp.text


def test_f5_duplicated_password_redacted_on_re_render(server_factory):
    """Scenario "A duplicated password is redacted on re-render": the same value
    posted into a password field and an ordinary field renders the password
    control empty and the ordinary control as `***`."""
    dup = "DUP-PASSWORD-abcdefeg-123"
    server, _h = start(server_factory, more_spec())
    with admin(server) as client:
        resp = action_post(
            client,
            PAGE + "/add_store",
            data={"name": dup, "kind": "git", "secret_key": dup},
        )
    assert resp.status_code == 200, resp.text
    card = cards(resp.text)["add_store"]
    # The ordinary `name` field is masked.
    assert _input_value(card, "name") == "***"
    assert dup not in resp.text
    # The password control carries no value at all.
    inputs = password_inputs(card)
    assert len(inputs) == 1 and "value=" not in inputs[0]


# =============================================================================
# F6: one effective-enabled predicate for the page and the chain (16.F6.2)
# Scenario "A child-marked-disabled action is refused by the page".
# =============================================================================


def _mark_set_writable_disabled(client):
    """Wrap the lease client's `list_tools` so the conforming action
    `set_writable` arrives carrying `meta.fastmcp._internal.visibility = false`,
    the mark a child can publish that FastMCP's `is_enabled` refuses. A real
    stdio child cannot emit a listed-but-marked tool over the wire, so the mark
    is injected at the exact object boundary `action_enabled` inspects."""
    orig = client.list_tools

    async def wrapped(*a, **k):
        tools = await orig(*a, **k)
        for t in tools:
            if t.name == "set_writable":
                t.meta = {**(t.meta or {}), **VIS_OFF}
        return tools

    client.list_tools = wrapped


@pytest.mark.asyncio
async def test_f6_visibility_mark_disables_the_view(make_supervisor):  # noqa: F811
    """The page marks a child-disabled conforming action disabled with reason
    `muted`, even though no registry mute is set."""
    sup = make_supervisor()
    child = await sup.add(store_spec())
    await child.task
    _mark_set_writable_disabled(child.session.client)
    views = {v.name: v for v in await sup.actions("store")}
    assert views["set_writable"].disabled is True
    assert views["set_writable"].reason == "muted"
    # A sibling with no mark stays enabled.
    assert views["add_store"].disabled is False


@pytest.mark.asyncio
async def test_f6_visibility_mark_refused_by_run_action(make_supervisor):  # noqa: F811
    """`run_action` refuses a child-disabled action with reason `muted` and
    calls no tool: the direct route runs only what the chain permits."""
    sup = make_supervisor()
    child = await sup.add(store_spec())
    await child.task
    _mark_set_writable_disabled(child.session.client)
    calls = []
    orig = child.session.client.call_tool_mcp

    async def spy(*a, **k):
        calls.append(a)
        return await orig(*a, **k)

    child.session.client.call_tool_mcp = spy
    # A4 F1: run_action returns kind "muted" before it reaches call_tool_mcp.
    run = await sup.run_action("store", "set_writable", {"name": "s3main"})
    assert run.kind == "muted"
    assert calls == []


def test_f6_marked_action_submit_answers_400_muted(server_factory, monkeypatch):
    """The submit of a child-disabled action answers 400 with
    `form_error = "muted"` and calls no tool (the run_action `muted` mapping)."""

    async def muted(self, ns, name, form, **kwargs):
        # A4 F1: run_action returns kind "muted"; the handler maps it to 400 with
        # form_error "muted" and calls no tool.
        return ActionRun("muted", frozenset(), frozenset(), None, "")

    monkeypatch.setattr(Supervisor, "run_action", muted)
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        resp = action_post(client, PAGE + "/set_writable", data={"name": "s3main"})
    assert resp.status_code == 400, resp.text
    assert "muted" in resp.text
    assert call_log(server) == []


# =============================================================================
# F7: reject a malformed root schema at admission (16.F7.2)
# Scenario "A malformed root schema is not an action".
# =============================================================================


@pytest.mark.asyncio
async def test_f7_malformed_root_no_view_and_run_action_unknown(make_supervisor, caplog):  # noqa: F811
    """A tagged tool with `required: [{}]` gets no view, logs one WARNING naming
    `schema`, and `run_action` returns kind `unknown` — the page and the submit
    never touch `set(required)`, so neither crashes."""
    sup = make_supervisor()
    child = await sup.add(more_spec())
    await child.task
    with caplog.at_level(logging.WARNING):
        views = {v.name for v in await sup.actions("store")}
    assert "bad_root" not in views
    warnings = [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING and "bad_root" in r.getMessage()
    ]
    assert len(warnings) == 1 and "schema" in warnings[0]
    # A4 F1: run_action returns kind "unknown" (a clause violator is not a
    # conforming action), never touching `set(required)`.
    run = await sup.run_action("store", "bad_root", {"name": "x"})
    assert run.kind == "unknown"


def test_f7_page_and_submit_render_without_crash(server_factory):
    """The actions page and a submit of a valid sibling both render at 200 while
    a malformed-root tool is present on the child; no `set(required)` crash."""
    server, _h = start(server_factory, more_spec())
    with admin(server) as client:
        page = client.get(PAGE)
        submit = action_post(client, PAGE + "/set_writable", data={"name": "s3main"})
    assert page.status_code == 200
    assert "bad_root" not in cards(page.text)
    assert submit.status_code == 200, submit.text
