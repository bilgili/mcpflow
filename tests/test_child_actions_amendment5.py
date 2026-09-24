"""Amendment 5 scenarios: browser snapshots, page unions and error contexts.

Expectations come from web-ui delta requirements and design gate round 4.
The fixture runs real routes, form decoding, Supervisor.actions/run_action and
redaction with a deterministic lease client; only child transport is replaced.
Authentication remains independently covered by the live HTTP suite.
"""

import inspect
import json
import re
from contextlib import asynccontextmanager
from copy import deepcopy
from html import unescape
from types import SimpleNamespace

import pytest
from action_browser import control
from mcp.types import CallToolResult, TextContent
from starlette.applications import Starlette
from starlette.testclient import TestClient
from test_child_actions import PAGE, cards, store_spec
from test_supervisor import make_supervisor  # noqa: F401

from mcpflow.actions import redact
from mcpflow.supervisor import LeaseRefused
from mcpflow.web import build_routes

OLD = "OLD-default-8901"
NEW = "NEW-default-8902"
POSTED = "POSTED-password-8903"
CONFIGURED = "CONFIGURED-secret-8904"
RESULT_ONLY = "result-sentinel-8905"


def tool(name="save", *, default=OLD, password=True, extra=None):
    props = {
        "p": {
            "type": "string",
            **({"format": "password", "default": default} if password else {}),
        }
    }
    props.update(extra or {})
    return SimpleNamespace(
        name=name,
        title="",
        description="",
        meta={"mcpflow": {"action": True}},
        input_schema={"type": "object", "properties": props},
    )


def target(body, name="save"):
    return unescape(re.search(r'<form[^>]*action="([^"]+)"', cards(body)[name])[1])


def token(url):
    return url.split("form_token=")[1]


@pytest.fixture
def harness(make_supervisor, monkeypatch):  # noqa: F811
    spec = store_spec(env={"R5_SECRET": CONFIGURED})
    sup = make_supervisor(spec)
    child = SimpleNamespace(spec=spec, status="running")
    monkeypatch.setattr(sup, "get", lambda ns: child)
    state = SimpleNamespace(
        tools=[tool()], calls=[], phase=None, error=None, listings=0
    )

    async def listing():
        state.listings += 1
        if state.phase == "list":
            raise state.error
        return state.tools

    async def call(name, arguments):
        state.calls.append((name, deepcopy(arguments)))
        if state.phase == "call":
            raise state.error
        text = json.dumps(
            {"args": arguments, "old": OLD, "new": NEW, "sentinel": RESULT_ONLY},
            ensure_ascii=False,
        )
        return CallToolResult(content=[TextContent(type="text", text=text)])

    @asynccontextmanager
    async def lease(_child):
        if state.phase == "enter":
            raise state.error
        yield SimpleNamespace(list_tools=listing, call_tool_mcp=call)
        if state.phase == "exit":
            raise state.error

    monkeypatch.setattr(sup, "_lease", lease)
    routes = build_routes(sup, None, sup.settings, None, None)
    endpoint = next(r.endpoint for r in routes if r.path.endswith("/actions/{action}"))
    snapshots = inspect.getclosurevars(endpoint).nonlocals["action_snapshots"]
    with TestClient(Starlette(routes=routes)) as client:
        yield SimpleNamespace(client=client, sup=sup, state=state, snapshots=snapshots)


def test_call_exception_preserves_password_and_default(harness):
    h = harness
    url = target(h.client.get(PAGE).text)
    h.state.phase, h.state.error = "call", RuntimeError(f"{POSTED} {OLD} {CONFIGURED}")
    response = h.client.post(url, data={"f0": POSTED})
    assert response.status_code == 400
    assert len(h.state.calls) == 1
    assert all(secret not in response.text for secret in (POSTED, OLD, CONFIGURED))
    assert "***" in response.text


def test_actual_get_downgrade_and_second_rerender_submission(harness):
    h = harness
    original = target(h.client.get(PAGE).text)
    h.state.tools = [tool(password=False), tool("other", default=NEW)]
    for url in [original, original]:
        response = h.client.post(url, data={"f0": POSTED})
        assert response.status_code == 200
        assert all(secret not in response.text for secret in (OLD, NEW, POSTED))
        password = control(cards(response.text)["save"], "p")
        assert 'type="password"' in password and "value=" not in password
        fresh = target(response.text)
        assert h.snapshots[token(fresh)].actions["a0"].password_keys == {"p"}
    response = h.client.post(fresh, data={"f0": POSTED + "-second"})
    assert response.status_code == 200 and POSTED not in response.text
    assert h.state.calls[-1] == ("save", {"p": POSTED + "-second"})
    assert OLD in h.snapshots[token(original)].secrets


def test_replacement_tokens_preserve_metadata_secrets_after_repeated_downgrade(harness):
    h = harness
    url = target(h.client.get(PAGE).text)
    assert OLD in h.snapshots[token(url)].secrets
    posted_passwords = [f"{POSTED}-round-{i}" for i in range(3)]
    responses = []
    replacements = []

    for default, posted in zip((OLD, NEW, OLD), posted_passwords):
        current = tool(password=False)
        current.input_schema["properties"]["p"]["default"] = default
        h.state.tools = [current]
        response = h.client.post(url, data={"f0": posted})
        assert response.status_code == 200
        assert h.state.calls[-1] == ("save", {"p": posted})
        assert posted not in response.text
        password = control(cards(response.text)["save"], "p")
        assert 'type="password"' in password and "value=" not in password

        fresh = target(response.text)
        assert token(fresh) != token(url)
        snapshot = h.snapshots[token(fresh)]
        assert snapshot.actions["a0"].password_keys == {"p"}
        persistent = repr(h.snapshots)
        assert all(value not in persistent for value in posted_passwords)
        assert RESULT_ONLY not in persistent
        responses.append(response)
        replacements.append(snapshot)
        url = fresh

    assert len(h.state.calls) == len(posted_passwords)
    # Check every transition before reporting a lost declaration, so retention
    # assertions still run for all replacement snapshots on the failing code.
    for response in responses:
        assert OLD not in response.text
    for snapshot in replacements:
        assert OLD in snapshot.secrets


def test_default_drift_preserves_both_actual_get_and_execution_literals(harness):
    h = harness
    url = target(h.client.get(PAGE).text)
    h.state.tools = [tool(default=NEW)]
    response = h.client.post(url, data={"f0": POSTED})
    assert response.status_code == 200
    assert all(secret not in response.text for secret in (OLD, NEW, POSTED))


def test_crosscard_get_post_and_overlapping_masks(harness):
    h = harness
    a, b = (
        tool(default="abcd"),
        tool(
            "second",
            default="cdefg",
            extra={"ordinary": {"type": "string", "default": "xxabcdefgyy"}},
        ),
    )
    b.description = "prefix abcdefg suffix"
    h.state.tools = [a, b]
    body = h.client.get(PAGE).text
    assert "prefix *** suffix" in body and "abcdefg" not in body
    assert 'value="xx***yy"' not in body  # Never send a redaction marker as a default.
    assert 'value=""' in control(cards(body)["second"], "ordinary")
    url = target(body)
    b.description = "echo " + POSTED
    response = h.client.post(url, data={"f0": POSTED})
    assert response.status_code == 200 and POSTED not in response.text
    assert "echo ***" in cards(response.text)["second"]


def test_raw_keyword_and_secret_identities_roundtrip(harness):
    h = harness
    identity = "PRIVATE-identity-8931"
    h.state.tools = [
        tool(
            identity,
            default="password",
            extra={
                identity: {
                    "type": "string",
                    "enum": [identity, "normal"],
                    "default": identity,
                },
                "declaration": {
                    "type": "string",
                    "format": "password",
                    "default": identity,
                },
            },
        )
    ]
    body = h.client.get(PAGE).text
    assert identity not in body
    card = cards(body)["***"]
    password = control(card, "p")
    assert 'type="password"' in password and "value=" not in password
    assert "<select" in control(card, "***")
    assert 'value="o0" selected>***</option>' in card
    response = h.client.post(target(body, "***"), data={"f0": POSTED, "f1": "o0"})
    assert response.status_code == 200 and identity not in response.text
    assert h.state.calls[-1] == (identity, {"p": POSTED, identity: identity})


@pytest.mark.parametrize("ascii_mode", [True, False])
def test_both_unicode_json_encodings(ascii_mode, harness):
    secret = 'Türkçe雪"\\line\n'
    text = json.dumps({"value": secret}, ensure_ascii=ascii_mode)
    assert redact(text, {secret}) == '{"value": "***"}'
    h = harness
    url = target(h.client.get(PAGE).text)
    h.state.phase, h.state.error = "call", RuntimeError(text)
    response = h.client.post(url, data={"f0": secret})
    assert response.status_code == 400
    assert "Türkçe" not in response.text and "\\u00fc" not in response.text
    assert "***" in response.text


@pytest.mark.parametrize("phase", ["enter", "list"])
def test_presentation_lease_refusal_is_typed_and_503(phase, harness):
    h = harness
    url = target(h.client.get(PAGE).text)
    h.state.phase, h.state.error = phase, LeaseRefused("store", 1, f"{OLD} {POSTED}")
    response = h.client.post(url, data={"f0": POSTED})
    assert response.status_code == 503 and not h.state.calls
    assert OLD not in response.text and POSTED not in response.text
    assert h.client.get(PAGE).status_code == 200


@pytest.mark.parametrize(
    "invalid",
    [
        "unknown",
        "empty",
        "malformed",
        "namespace",
        "action",
        "field",
        "option",
        "expired",
    ],
)
def test_invalid_snapshot_and_alias_never_execute(invalid, harness, monkeypatch):
    h = harness
    h.state.tools = [tool(extra={"choice": {"type": "string", "enum": ["one", "two"]}})]
    url = target(h.client.get(PAGE).text)
    data = {"f0": POSTED}
    if invalid in ("unknown", "empty", "malformed"):
        url = (
            url.split("=")[0]
            + "="
            + {"unknown": "not-a-token", "empty": "", "malformed": "%00%7Bbad%7D"}[
                invalid
            ]
        )
    elif invalid == "namespace":
        url = url.replace("/store/", "/elsewhere/")
    elif invalid == "action":
        url = url.replace("/a0?", "/a99?")
    elif invalid == "field":
        data["bogus"] = POSTED
    elif invalid == "option":
        data["f1"] = "one"  # A raw option is not an opaque option alias.
    else:
        from mcpflow import web

        monkeypatch.setattr(
            web,
            "time",
            SimpleNamespace(monotonic=lambda: h.snapshots[token(url)].expires + 1),
        )
    before = h.state.listings
    response = h.client.post(url, data=data)
    assert response.status_code == 400
    assert response.text == "Invalid form. Reload the actions page."
    assert POSTED not in response.text and not h.state.calls
    assert h.state.listings == before


def test_legacy_refills_nothing_preserves_native_controls(harness):
    h = harness
    h.state.tools = [
        tool(
            extra={
                "text": {"type": "string"},
                "choice": {"type": "string", "enum": ["one", "two"]},
                "flag": {"type": "boolean"},
            }
        )
    ]
    response = h.client.post(
        PAGE + "/save",
        data={"p": POSTED, "text": "ordinary-posted", "choice": "two", "flag": "on"},
    )
    assert response.status_code == 200
    card = cards(response.text)["save"]
    assert POSTED not in response.text and "ordinary-posted" not in response.text
    assert 'type="text" value=""' in control(card, "text")
    assert 'type="checkbox"' in control(card, "flag") and " checked" not in control(
        card, "flag"
    )
    assert control(card, "choice").startswith("<select")
    assert " selected" not in card
    assert h.snapshots[token(target(response.text))].actions["a0"].password_keys == {
        "p"
    }
    assert (
        "two" not in response.text
    )  # Legacy ordinary strings are request secrets too.


def test_snapshot_capacity_is_pages_and_large_page_all_aliases_work(harness):
    h = harness
    h.state.tools = [tool(f"card{i}") for i in range(257)]
    body = h.client.get(PAGE).text
    assert len(h.snapshots) == 1
    urls = [target(body, f"card{i}") for i in (0, 256)]
    assert token(urls[0]) == token(urls[1])
    for url in urls:
        assert h.client.post(url, data={"f0": POSTED}).status_code == 200
    assert [name for name, args in h.state.calls] == ["card0", "card256"]
    h.state.tools = [tool()]
    first = target(h.client.get(PAGE).text)
    for _ in range(256):
        h.client.get(PAGE)
    assert len(h.snapshots) == 256
    assert h.client.post(first, data={"f0": POSTED}).status_code == 400


def test_snapshot_metadata_detached_and_never_persists_request_state(harness):
    h = harness
    raw = tool(extra={"choice": {"type": "string", "enum": ["old-option", "second"]}})
    h.state.tools = [raw]
    url = target(h.client.get(PAGE).text)
    saved = h.snapshots[token(url)]
    before = repr(saved)
    raw.input_schema["properties"]["choice"]["enum"][0] = "new-option"
    raw.input_schema["properties"]["p"]["default"] = NEW
    h.sup.get("store").spec.env["R5_SECRET"] = "changed-config-secret"
    assert repr(saved) == before
    # Old option still decodes to old-option, which CURRENT coercion rejects.
    response = h.client.post(url, data={"f0": POSTED, "f1": "o0"})
    assert response.status_code == 400 and not h.state.calls
    response = h.client.post(url, data={"f0": POSTED})
    assert response.status_code == 200
    persistent = repr(h.snapshots)
    assert POSTED not in persistent and RESULT_ONLY not in persistent
    assert "ActionRun" not in persistent and "CallToolResult" not in persistent
    assert NEW in persistent and OLD in persistent


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "outcome,phase",
    [
        ("ran", None),
        ("unknown", None),
        ("muted", None),
        ("coerce_error", None),
        ("transport", "enter"),
        ("transport", "list"),
        ("transport", "call"),
        ("lease_refused", "enter"),
        ("lease_refused", "list"),
        ("lease_refused", "call"),
        ("lease_refused", "exit"),
    ],
)
async def test_all_run_kinds_keep_accumulated_context(outcome, phase, harness):
    h = harness
    current = tool(
        default=NEW,
        extra={
            "current": {"type": "string", "format": "password"},
            "count": {"type": "integer"},
        },
    )
    h.state.tools = [current, tool("other", default="other-default-secret")]
    if outcome == "muted":
        current.meta["fastmcp"] = {"_internal": {"visibility": False}}
    h.state.phase = phase
    h.state.error = (
        LeaseRefused("store", 1, "late failure")
        if outcome == "lease_refused"
        else RuntimeError("call failure")
    )
    form = {
        "p": POSTED,
        "current": "current-password",
        "count": "bad" if outcome == "coerce_error" else "12",
    }
    run = await h.sup.run_action(
        "store",
        "absent" if outcome == "unknown" else "save",
        form,
        rendered_password_keys=frozenset({"p"}),
        rendered_secrets=frozenset({OLD}),
    )
    assert run.kind == outcome
    assert {CONFIGURED, OLD, POSTED} <= run.secrets
    assert "p" in run.password_keys
    if phase not in ("enter", "list"):
        assert {NEW, "other-default-secret"} <= run.secrets
        if outcome != "unknown":
            assert "current-password" in run.secrets and "current" in run.password_keys
    if outcome == "ran":
        assert h.state.calls == [
            ("save", {"p": POSTED, "current": "current-password", "count": 12})
        ]
    elif outcome in ("unknown", "muted", "coerce_error") or phase in ("enter", "list"):
        assert not h.state.calls


@pytest.mark.asyncio
async def test_actions_returns_raw_admitted_metadata(harness):
    h = harness
    raw = tool(extra={"title_field": {"type": "string", "title": OLD}})
    raw.title = OLD
    raw.description = CONFIGURED
    h.state.tools = [raw]
    [view] = await h.sup.actions("store")
    assert view.name == raw.name and view.title == OLD
    assert view.description == CONFIGURED and view.schema == raw.input_schema
    body = h.client.get(PAGE).text
    assert OLD not in body and CONFIGURED not in body
