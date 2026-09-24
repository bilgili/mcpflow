"""Keep optional presentation sentinels separate from secret result data."""

import inspect
import json
import re
from html import unescape
from pathlib import Path
from types import SimpleNamespace

import pytest
from starlette.requests import Request

from mcpflow.actions import ActionView
from mcpflow.supervisor import Supervisor
from mcpflow.web import build_routes


@pytest.fixture(
    params=[
        pytest.param((None, {"null", "None"}), id="null"),
        pytest.param((True, {"true", "True"}), id="true"),
        pytest.param((False, {"false", "False"}), id="false"),
        pytest.param(([], {"[]"}), id="empty-list"),
        pytest.param(({}, {"{}"}), id="empty-dictionary"),
    ]
)
def secret_case(request):
    value, secrets = request.param
    return value, frozenset(secrets)


@pytest.fixture
def render_actions_page():
    settings = SimpleNamespace(data_dir=Path(__file__).parent, session_ttl=60)
    # Route registration needs bound lifecycle methods; this test calls none.
    supervisor = object.__new__(Supervisor)
    routes = build_routes(supervisor, None, settings, None, None)
    endpoint = next(r.endpoint for r in routes if r.path == "/servers/{ns}/actions")
    render_page = inspect.getclosurevars(endpoint).nonlocals["_actions_page"]
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/servers/store/actions",
            "headers": [],
            "query_string": b"",
            "scheme": "http",
            "server": ("testserver", 80),
        }
    )
    child = SimpleNamespace(status="running", spec=SimpleNamespace(kind="stdio"))
    view = ActionView(
        name="save",
        title="",
        description="",
        schema={
            "type": "object",
            "properties": {"p": {"type": "string", "format": "password"}},
        },
        disabled=False,
        reason="",
    )

    def render(secrets, *, result=None, active=None):
        response = render_page(
            request,
            "store",
            child,
            configured=frozenset(),
            request_secrets=secrets,
            actions=[view],
            error=None,
            form_error=None,
            active=active,
            result=result,
        )
        assert response.status_code == 200
        return response.body.decode()

    return render


def assert_no_synthetic_error(body):
    assert "Could not read actions" not in body
    assert '<p class="error">' not in body
    assert '<form method="post" action="/servers/store/actions/a0?form_token=' in body


def result_blocks(body):
    section = re.search(r'<div class="result">(.*?)</div>', body, re.DOTALL)
    assert section is not None, "A successful result must remain visible"
    return [
        unescape(block)
        for block in re.findall(r"<pre>(.*?)</pre>", section.group(1), re.DOTALL)
    ]


def test_secret_result_data_masks_without_creating_optional_errors(
    render_actions_page, secret_case
):
    value, secrets = secret_case
    body = render_actions_page(
        secrets,
        active="save",
        result={
            "text": ["result-ready"],
            "structured": {"echo": value, "ordinary": "kept"},
        },
    )
    assert_no_synthetic_error(body)
    assert "Last result" in body
    blocks = result_blocks(body)
    assert len(blocks) == 2
    assert json.loads(blocks[0]) == {"echo": "***", "ordinary": "kept"}
    assert blocks[1] == "result-ready"


def test_absent_result_stays_absent_when_secret_set_matches_null_or_falsy_data(
    render_actions_page, secret_case
):
    _, secrets = secret_case
    body = render_actions_page(secrets)
    assert_no_synthetic_error(body)
    assert "Last result" not in body
    assert '<div class="result">' not in body


def test_text_only_result_preserves_absent_structured_data_and_active_action(
    render_actions_page, secret_case
):
    _, secrets = secret_case
    body = render_actions_page(
        secrets, result={"text": ["result-ready"], "structured": None}
    )
    assert_no_synthetic_error(body)
    assert result_blocks(body) == ["result-ready"]
    heading = re.search(r"Last result.*?<code>(.*?)</code>", body, re.DOTALL)
    assert heading is not None
    assert "***" not in heading.group(1), "An absent active action is not secret data"
