"""The `Mcp-Param` header check uses the schema of the caller (schema-cache-per-caller).

F1 of the fastmcp-4-2 design review: FastMCP 4.2 keeps one server-wide cache
of input schemas, keyed by the wire tool name, and the SDK validates the
`Mcp-Param-*` headers of a modern `tools/call` against it. `github@alice` and
`github@bob` both publish `github_x`; only Alice's `x` declares
`x-mcp-header: Tz` on `timezone`. The last listing of one caller must not
decide the check of the other caller.
"""

from __future__ import annotations

import httpx
import pytest
from mcp.shared.inbound import (
    CLIENT_CAPABILITIES_META_KEY,
    HEADER_MISMATCH,
    MODERN_PROTOCOL_VERSIONS,
    PROTOCOL_VERSION_META_KEY,
)
from router_live import Child, start_live

PAIR = (
    Child("github@alice", "gh", ("x",), {"cache_ttl": 0}, args=("--header", "Tz")),
    Child("github@bob", "gh", ("x",)),
)
VERSION = MODERN_PROTOCOL_VERSIONS[-1]


@pytest.fixture(scope="module")
def live(tmp_path_factory):
    lv, stop = start_live(tmp_path_factory.mktemp("schema_cache"), PAIR)
    yield lv
    stop()


@pytest.fixture
def env(live):
    live.reset()
    yield live
    live.reset()


def modern_call(env, uid: str, name: str, args: dict, headers: dict | None = None):
    """One stateless (modern) `tools/call`; the SDK runs the header check first."""
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": args,
            "_meta": {PROTOCOL_VERSION_META_KEY: VERSION, CLIENT_CAPABILITIES_META_KEY: {}},
        },
    }
    return httpx.post(
        env.base_url + "/mcp",
        json=body,
        timeout=30,
        headers={
            "Authorization": f"Bearer {env.tokens[uid]}",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": VERSION,
            "Mcp-Method": "tools/call",
            "Mcp-Name": name,
            **(headers or {}),
        },
    )


def refused_by_header_check(response) -> bool:
    return response.status_code == 400 and response.json()["error"]["code"] == HEADER_MISMATCH


def test_the_listing_of_another_caller_does_not_refuse_a_good_call(env):
    # Alice lists last: the server-wide entry `github_x` holds her schema.
    assert "github_x" in env.names("bob")
    assert "github_x" in env.names("alice")
    # Bob's `x` declares no header, so his call carries none.
    response = modern_call(env, "bob", "github_x", {"timezone": "UTC"})
    assert not refused_by_header_check(response), response.text
    assert response.status_code == 200, response.text
    assert "github@bob:x" in response.text
    assert env.calls("github@bob") == ["call:x"]


def test_the_listing_of_another_caller_does_not_skip_the_check(env):
    # Bob lists last: the server-wide entry `github_x` holds his schema.
    assert "github_x" in env.names("alice")
    assert "github_x" in env.names("bob")
    # Alice's `x` declares `Tz`, so a call without `Mcp-Param-Tz` is refused.
    response = modern_call(env, "alice", "github_x", {"timezone": "UTC"})
    assert refused_by_header_check(response), response.text
    assert env.calls("github@alice") == []


def test_a_matching_header_passes_for_its_caller(env):
    assert "github_x" in env.names("bob")
    response = modern_call(env, "alice", "github_x", {"timezone": "UTC"}, {"Mcp-Param-Tz": "UTC"})
    assert response.status_code == 200, response.text
    assert "github@alice:x" in response.text
    assert env.calls("github@alice") == ["call:x"]


def test_a_cold_start_still_checks(env):
    # No caller has listed: empty the server-wide cache, as a fresh process has it.
    # A rename of the field fails here, not as an order-dependent pass.
    env.gateway._wire_input_schemas.clear()
    assert env.gateway._mcp_server.get_tool_input_schema is None
    response = modern_call(env, "alice", "github_x", {"timezone": "UTC"})
    assert refused_by_header_check(response), response.text
    assert env.calls("github@alice") == []


def test_a_caller_that_does_not_reach_the_name_gets_no_header_verdict(env):
    assert "github_x" in env.names("alice")
    response = modern_call(env, "carol", "github_x", {"timezone": "UTC"})
    assert not refused_by_header_check(response), response.text
    assert "unknown tool" in response.text.lower(), response.text
    assert env.calls("github@alice") == []
    assert env.calls("github@bob") == []
