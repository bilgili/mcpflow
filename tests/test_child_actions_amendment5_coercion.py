"""R5-2 regressions for secrecy across current-schema coercion.

The supervisor converts a rendered password before dispatch. Its secret context
must cover the converted data. Snapshots must retain metadata only.
"""

import json
import re
from html import unescape

import pytest
import test_child_actions_amendment5 as amendment5
import test_supervisor
from action_browser import control
from test_child_actions import PAGE, cards
from test_child_actions_amendment5 import (
    CONFIGURED,
    target,
    token,
    tool,
)

harness = amendment5.harness
make_supervisor = test_supervisor.make_supervisor

_NOTE = "ordinary-field-keeps-its-value"
_COERCIONS = [
    pytest.param(
        {"type": "integer"},
        "00123456789",
        123456789,
        ("123456789",),
        id="integer-leading-zeroes",
    ),
    pytest.param(
        {"type": "array", "items": {"type": "string"}},
        "  R5-ARRAY-SECRET-901  ",
        ["R5-ARRAY-SECRET-901"],
        ("R5-ARRAY-SECRET-901",),
        id="array-trimmed-element",
    ),
    pytest.param(
        {},
        '{"token":"R5-JSON-SECRET-902","nested":["R5-JSON-SECRET-903",246813579]}',
        {
            "token": "R5-JSON-SECRET-902",
            "nested": ["R5-JSON-SECRET-903", 246813579],
        },
        ("R5-JSON-SECRET-902", "R5-JSON-SECRET-903", "246813579"),
        id="json-nested-string-and-number",
    ),
]


def _render_then_downgrade(h, schema):
    extra = {"note": {"type": "string"}}
    h.state.tools = [tool(extra=extra)]
    response = h.client.get(PAGE)
    assert response.status_code == 200
    password = control(cards(response.text)["save"], "p")
    assert 'type="password"' in password and "value=" not in password

    current = tool(password=False, extra=extra)
    current.input_schema["properties"]["p"] = schema
    h.state.tools = [current]
    return target(response.text)


def _assert_request_secrets_not_stored(h, raw, derived):
    snapshots = tuple(h.snapshots.values())
    assert snapshots
    assert all(CONFIGURED in snapshot.secrets for snapshot in snapshots)
    stored = repr(snapshots)
    assert all(secret not in stored for secret in (raw, *derived))
    assert _NOTE not in stored
    assert "ActionRun" not in stored and "CallToolResult" not in stored


@pytest.mark.parametrize("schema,raw,expected,derived", _COERCIONS)
def test_downgraded_password_echo_is_masked(harness, schema, raw, expected, derived):
    h = harness
    url = _render_then_downgrade(h, schema)
    response = h.client.post(url, data={"f0": raw, "f1": _NOTE})

    assert response.status_code == 200
    assert h.state.calls == [("save", {"p": expected, "note": _NOTE})]
    password = control(cards(response.text)["save"], "p")
    assert 'type="password"' in password and "value=" not in password
    _assert_request_secrets_not_stored(h, raw, derived)

    result = unescape(
        re.search(r'<div class="result">(.*?)</div>', response.text, re.DOTALL)[1]
    )
    assert _NOTE in result
    assert all(secret not in result for secret in (raw, *derived)), result
    assert "***" in result


@pytest.mark.parametrize("schema,raw,expected,derived", _COERCIONS)
def test_downgraded_password_call_error_is_masked(
    harness, schema, raw, expected, derived
):
    h = harness
    url = _render_then_downgrade(h, schema)
    h.state.phase = "call"
    h.state.error = RuntimeError(
        "coerced-call-failed " + json.dumps({"p": expected, "note": _NOTE})
    )
    response = h.client.post(url, data={"f0": raw, "f1": _NOTE})

    assert response.status_code == 400
    assert h.state.calls == [("save", {"p": expected, "note": _NOTE})]
    _assert_request_secrets_not_stored(h, raw, derived)
    body = unescape(response.text)
    assert "coerced-call-failed" in body and _NOTE in body
    assert all(secret not in body for secret in (raw, *derived)), body
    assert "***" in body


@pytest.mark.parametrize("schema,raw,expected,derived", _COERCIONS)
def test_downgraded_password_secrets_stay_request_local(
    harness, schema, raw, expected, derived
):
    h = harness
    url = _render_then_downgrade(h, schema)
    before = set(h.snapshots)
    response = h.client.post(url, data={"f0": raw, "f1": _NOTE})

    assert response.status_code == 200
    assert h.state.calls == [("save", {"p": expected, "note": _NOTE})]
    replacement_token = token(target(response.text))
    assert set(h.snapshots) - before == {replacement_token}
    assert h.snapshots[replacement_token].actions["a0"].password_keys == {"p"}
    _assert_request_secrets_not_stored(h, raw, derived)
