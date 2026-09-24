"""Verifier tests for the 2026-09-19 amendment (section 17) of change
`child-actions-page`: codex review 3, Amendment 4, findings F1-F9.

Every test derives from a spec scenario, not from the implementation:

- `specs/web-ui/spec.md` — "Actions page" scenarios for F1, F2, F4, F5, F8.
- `specs/mcp-gateway/spec.md` — "Action contract clause" scenarios for F6, F9.

Supervisor-level tests use the in-process `make_supervisor` fixture so they can
await `run_action`/`actions` directly and inspect the lease client. Web-level
tests drive the real gateway over HTTP through `server_factory`. Malformed meta
(F6) and null root members (F9) cannot cross the MCP wire (FastMCP owns the
`fastmcp` meta key and normalises a null `properties`/`required` away), so those
shapes are injected at the exact object boundary the clause inspects, the same
technique the section-16 F6 test uses for a child visibility mark.
"""

from __future__ import annotations

import html
import logging
import re

import pytest
from action_browser import action_post
from conftest import fake_child_spec
from fake_mcp_server import (
    R3_DEFAULT_SECRET,
    R3_DESC_SECRET,
    R3_LEAK_DEFAULT,
    R3_TITLE_SECRET,
)
from test_child_actions import PAGE, SECRET, cards, more_spec, start, store_spec
from test_supervisor import make_supervisor  # noqa: F401 -- async fixture
from test_visibility import admin

from mcpflow.actions import clause_violation, redact
from mcpflow.supervisor import Supervisor


def _result_text(body: str) -> str:
    m = re.search(r'<div class="result">(.*?)</div>', body, re.DOTALL)
    assert m, "no result block"
    return html.unescape(m.group(1))


def _schema_text(card: str) -> str:
    m = re.search(
        r"<details>\s*<summary[^>]*>schema</summary>(.*?)</details>", card, re.DOTALL
    )
    assert m, "no schema disclosure"
    return html.unescape(m.group(1))


class _Tool:
    """A minimal tool for a pure `clause_violation` unit assertion."""

    def __init__(self, meta, schema):
        self.meta = meta
        self.input_schema = schema


def _more_env(**env):
    return fake_child_spec("store", "action", "more", actions=True, env=env)


# =============================================================================
# F1, F3, F7: one execution context (17.F1.6)
# Scenarios "The mask binds to the execution listing",
# "One scrub masks two overlapping secrets in an error".
# =============================================================================


@pytest.mark.asyncio
async def test_r3_f1_one_context(make_supervisor):  # noqa: F811
    """`run_action` runs ONE listing and ONE call under one lease, and the mask
    binds to THAT listing: an optional password whose child-side default the
    result echoes is masked, because `run_action` collected the default from its
    own listing (the handler has no other secret source)."""
    sup = make_supervisor()
    child = await sup.add(more_spec())
    await child.task
    client = child.session.client
    counts = {"list": 0, "mcp": 0}
    orig_list, orig_mcp = client.list_tools, client.call_tool_mcp

    async def w_list(*a, **k):
        counts["list"] += 1
        return await orig_list(*a, **k)

    async def w_mcp(*a, **k):
        counts["mcp"] += 1
        return await orig_mcp(*a, **k)

    client.list_tools = w_list
    client.call_tool_mcp = w_mcp

    # Post the optional password empty: the child runs with its default and
    # echoes it in the result.
    run = await sup.run_action("store", "echo_default", {})
    assert run.kind == "ran"
    assert counts == {"list": 1, "mcp": 1}  # ONE listing, ONE call, one lease
    # The mask set carries the execution listing's default literal.
    assert R3_LEAK_DEFAULT in run.secrets
    text = "\n".join(
        b.text for b in run.result.content if getattr(b, "text", None) is not None
    )
    assert R3_LEAK_DEFAULT in text  # raw result carries the default
    assert R3_LEAK_DEFAULT not in redact(text, run.secrets)  # the mask covers it

    # "One scrub masks two overlapping secrets in an error": one redact pass over
    # the raw text with the full set merges overlapping spans, leaving no fragment.
    assert redact("abcdefg", run.secrets | {"abcd", "cdefg"}) == "***"


def test_r3_f1_mask_binds_render(server_factory):
    """End to end: the rendered result masks the execution listing's default,
    proving the handler renders only from `ActionRun.secrets`."""
    server, _h = start(server_factory, more_spec())
    with admin(server) as client:
        resp = action_post(client, PAGE + "/echo_default", data={})
    assert resp.status_code == 200, resp.text
    assert R3_LEAK_DEFAULT not in resp.text
    assert "used ***" in _result_text(resp.text)


def test_r3_f1_overlapping_error_scrubs_once(server_factory, monkeypatch):
    """Scenario "One scrub masks two overlapping secrets in an error": the
    handler scrubs the RAW transport detail once with the full set, so two
    overlapping secrets mask whole with no stranded fragment."""
    from mcpflow.supervisor import ActionRun

    async def overlap(self, ns, name, form, **kwargs):
        return ActionRun(
            "transport", frozenset({"abcd", "cdefg"}), frozenset(), None, "abcdefg"
        )

    monkeypatch.setattr(Supervisor, "run_action", overlap)
    server, _h = start(server_factory, more_spec())
    with admin(server) as client:
        resp = action_post(client, PAGE + "/set_writable", data={"name": "s3main"})
    assert resp.status_code == 400
    assert "abcd" not in resp.text and "cdefg" not in resp.text
    assert "***" in resp.text


def test_r3_f7_concurrent_removal_404(server_factory, monkeypatch):
    """Scenario "A concurrent child removal answers 404, not 500": `actions()`
    returns the card list, then the child is removed before execution, so
    `run_action`'s own `self.get` raises `KeyError`. The handler maps that to
    404 (it no longer looks the namespace up again), never a 500 traceback."""

    async def gone(self, ns, name, form, **kwargs):
        raise KeyError(ns)  # the child was removed between the probe and the run

    monkeypatch.setattr(Supervisor, "run_action", gone)
    server, _h = start(server_factory, more_spec())
    with admin(server) as client:
        resp = action_post(client, PAGE + "/set_writable", data={"name": "s3main"})
    assert resp.status_code == 404
    assert "Traceback" not in resp.text


# =============================================================================
# F2: the Client construction owns the logging policy (17.F2.3)
# Scenarios "The transport logs no posted secret",
# "A child log notification with a secret is dropped".
# =============================================================================


def test_r3_f2_no_secret_in_logs(server_factory, caplog):
    """No posted secret reaches a log line, even with the SDK transport at DEBUG:
    the three transport logger floors are pinned to INFO, and the child `Client`
    uses a drop `log_handler` that swallows a child log notification echoing the
    secret."""
    server, _h = start(server_factory, more_spec())
    # The gateway build pins each transport logger floor at or above INFO, so the
    # outgoing-arguments DEBUG line is suppressed.
    for name in ("mcp.client.sse", "mcp.client.stdio", "mcp.client.streamable_http"):
        assert logging.getLogger(name).isEnabledFor(logging.DEBUG) is False, name

    with caplog.at_level(logging.DEBUG), admin(server) as client:
        # Sink 1: the outgoing tools/call request carries the argument.
        r1 = action_post(
            client,
            PAGE + "/add_store",
            data={"name": "s3main", "kind": "git", "secret_key": SECRET},
        )
        # Sink 2: the child echoes the posted secret in a log notification.
        r2 = action_post(client, PAGE + "/log_secret", data={"secret_key": SECRET})
    assert r1.status_code == 200, r1.text
    assert r2.status_code == 200, r2.text
    assert SECRET not in caplog.text


# =============================================================================
# F4: the display-schema sanitation owner (17.F4.2)
# Scenarios "A secret in a property title is redacted on the page",
# "A secret in an ordinary default is redacted in the schema disclosure".
# =============================================================================


def test_r3_f4_display_sanitation(server_factory):
    """A configured secret in a property title, a property description, and an
    ordinary property default is masked on the page and in the schema disclosure.
    Amendment 5 leaves `ActionView` raw; the web boundary masks presentation."""
    server, _h = start(
        server_factory,
        _more_env(T=R3_TITLE_SECRET, D=R3_DESC_SECRET, F=R3_DEFAULT_SECRET),
    )
    with admin(server) as client:
        page = client.get(PAGE).text
    # None of the three configured secrets survives anywhere on the page.
    for secret in (R3_TITLE_SECRET, R3_DESC_SECRET, R3_DEFAULT_SECRET):
        assert secret not in page, secret
    card = cards(page)["titled"]
    schema = _schema_text(card)
    assert "***" in schema  # the schema disclosure masks the display secrets


# =============================================================================
# F5, F8: representation-aware and collision-safe redaction (17.F5.2)
# Scenarios "A numeric password in a result is redacted",
# "A JSON-escaped password in a text block is redacted",
# "Two secret dict keys keep both entries".
# =============================================================================


def test_r3_f5_f8_representation_and_collision():
    """Mask matching canonical scalars and JSON-escaped secrets, preserve
    ordinary booleans, and keep both entries when masked dict keys collide."""
    # F5 numeric scalar: json.dumps(123456) == "123456".
    assert redact(123456, {"123456"}) == "***"
    assert redact({"n": 123456}, {"123456"}) == {"n": "***"}
    # Amendment 5 includes booleans in exact canonical JSON matching.
    assert redact(True, {"true", "True"}) == "***"
    assert redact({"flag": True}, {"true"}) == {"flag": "***"}
    # Without a matching secret, ordinary booleans keep their value and type.
    assert redact(True, {"unrelated"}) is True
    assert redact(False, {"unrelated"}) is False
    assert redact({"flag": True}, {"unrelated"}) == {"flag": True}
    # F5 JSON-escaped: secret a"b appears in a text block as a\"b.
    text = '{"v": "a\\"b"}'
    out = redact(text, {'a"b'})
    assert out == '{"v": "***"}'
    # F8 collision: two secret keys keep both entries, distinct masked keys.
    masked = redact({"SECRET_A": "failed", "SECRET_B": "succeeded"},
                    {"SECRET_A", "SECRET_B"})
    assert set(masked.values()) == {"failed", "succeeded"}
    assert set(masked) == {"***", "***#2"}


def test_r3_f5_numeric_password_render(server_factory):
    """End to end: a posted password returned as a numeric scalar renders `***`."""
    server, _h = start(server_factory, more_spec())
    with admin(server) as client:
        resp = action_post(client, PAGE + "/numeric", data={"secret_key": "123456"})
    assert resp.status_code == 200, resp.text
    assert "123456" not in resp.text
    assert "***" in _result_text(resp.text)


def test_r3_f8_two_secret_keys_keep_both_entries_render(server_factory):
    """End to end: two configured secrets used as dict keys keep both entries,
    so a failure entry is never silently dropped."""
    server, _h = start(server_factory, _more_env(A="SECRET_A", B="SECRET_B"))
    with admin(server) as client:
        resp = action_post(client, PAGE + "/two_keys", data={})
    assert resp.status_code == 200, resp.text
    result = _result_text(resp.text)
    assert "SECRET_A" not in result and "SECRET_B" not in result
    assert "failed" in result and "succeeded" in result  # both entries survive
    assert "***#2" in result  # the colliding key is disambiguated


# =============================================================================
# F6: reject malformed visibility metadata at the clause (17.F6.2)
# Scenarios "A malformed visibility meta is not an action",
# "A null internal meta is not an action".
# =============================================================================


def _inject(client, tool_name, *, meta=None, schema=None):
    """Wrap the lease client's `list_tools` so the named tool arrives carrying a
    shape a real child cannot emit over the wire."""
    orig = client.list_tools

    async def wrapped(*a, **k):
        tools = await orig(*a, **k)
        for t in tools:
            if t.name == tool_name:
                if meta is not None:
                    t.meta = meta(t)
                if schema is not None:
                    t.input_schema = schema
        return tools

    client.list_tools = wrapped


def test_r3_f6_clause_returns_meta_for_malformed_shapes():
    """The clause owner returns the term `meta` for a null `fastmcp` and a null
    `_internal`, the two shapes that crash FastMCP's `is_enabled`."""
    flat = {"type": "object", "properties": {}}
    assert clause_violation(
        _Tool({"mcpflow": {"action": True}, "fastmcp": None}, flat)
    ) == "meta"
    assert clause_violation(
        _Tool({"mcpflow": {"action": True}, "fastmcp": {"_internal": None}}, flat)
    ) == "meta"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad_fastmcp",
    [None, {"_internal": None}],
    ids=["null_fastmcp", "null_internal"],
)
async def test_r3_f6_malformed_meta(make_supervisor, caplog, bad_fastmcp):  # noqa: F811
    """A conforming tagged tool with `meta.fastmcp = null` or
    `meta.fastmcp._internal = null` gets no view, logs one WARNING naming `meta`,
    and does not crash `actions` or `run_action` (the guard runs at the clause,
    before `action_enabled`/`is_enabled` could dereference the null)."""
    sup = make_supervisor()
    child = await sup.add(store_spec())
    await child.task
    _inject(
        child.session.client,
        "set_writable",
        meta=lambda t: {**(t.meta or {}), "fastmcp": bad_fastmcp},
    )
    with caplog.at_level(logging.WARNING):
        views = {v.name for v in await sup.actions("store")}
    assert "set_writable" not in views  # no view, no crash inside actions
    warnings = [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING and "set_writable" in r.getMessage()
    ]
    assert len(warnings) == 1 and "meta" in warnings[0]
    # The submit path stays inside its error boundary too: kind "unknown".
    run = await sup.run_action("store", "set_writable", {"name": "s3main"})
    assert run.kind == "unknown"


# =============================================================================
# F9: reject an explicit null root member at the clause (17.F9.2)
# Scenario "A null root member is not an action".
# =============================================================================


def test_r3_f9_clause_returns_schema_for_null_root_members():
    """The clause owner checks key PRESENCE apart from the value type, so
    `properties: null` and `required: null` both return the term `schema`."""
    tag = {"mcpflow": {"action": True}}
    assert clause_violation(
        _Tool(tag, {"type": "object", "properties": None})
    ) == "schema"
    assert clause_violation(
        _Tool(tag, {"type": "object", "properties": {}, "required": None})
    ) == "schema"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad_schema",
    [
        {"type": "object", "properties": None},
        {"type": "object", "properties": {}, "required": None},
    ],
    ids=["null_properties", "null_required"],
)
async def test_r3_f9_null_root_member(make_supervisor, caplog, bad_schema):  # noqa: F811
    """A tagged tool with `properties: null` or `required: null` gets no view and
    logs one WARNING naming `schema`; the page and the submit never crash."""
    sup = make_supervisor()
    child = await sup.add(store_spec())
    await child.task
    _inject(child.session.client, "set_writable", schema=bad_schema)
    with caplog.at_level(logging.WARNING):
        views = {v.name for v in await sup.actions("store")}
    assert "set_writable" not in views
    warnings = [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING and "set_writable" in r.getMessage()
    ]
    assert len(warnings) == 1 and "schema" in warnings[0]
    run = await sup.run_action("store", "set_writable", {"name": "s3main"})
    assert run.kind == "unknown"
