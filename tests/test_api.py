"""The JSON REST API under `/api`.

Scenarios from `specs/admin-api/spec.md` (Admin API authentication, error
semantics, Server resources, Tool and visibility resources, Token resources)
and the `/api/*` exemption in `specs/auth/spec.md`.

The suite drives the real `build_app` through Starlette's `TestClient` with
`raise_server_exceptions=True`, so a client error that re-raised in the server
would fail the test. A `custom` child that runs the fake stdio MCP server
stands in for a `uvx`/`npx` child, so no test needs the network.
"""

from __future__ import annotations

import json
import sys
import time
from types import SimpleNamespace

import pytest
from conftest import FAKE_SERVER, fake_child_spec, make_settings
from starlette.testclient import TestClient

from mcpflow.auth import TokenStore
from mcpflow.gateway import build_app
from mcpflow.registry import Registry


@pytest.fixture
def api(tmp_path):
    """Return a `make(*specs)` factory. Each call seeds a fresh data dir with
    the given children and one `admin` token, builds the app, and enters its
    lifespan so enabled children start."""
    clients: list[TestClient] = []
    counter = {"n": 0}

    def make(*specs) -> SimpleNamespace:
        counter["n"] += 1
        data = tmp_path / f"d{counter['n']}"
        (data / "logs").mkdir(parents=True)
        reg = Registry(data / "servers.json")
        reg.load()
        for spec in specs:
            reg.add(spec)
        store = TokenStore(data / "tokens.json")
        store.load()
        record, token = store.create("admin", "admin")
        app = build_app(make_settings(data))
        client = TestClient(app, raise_server_exceptions=True)
        client.__enter__()
        clients.append(client)
        return SimpleNamespace(
            client=client,
            data=data,
            token=token,
            token_id=record.id,
            headers={"Authorization": f"Bearer {token}"},
        )

    yield make

    for client in clients:
        client.__exit__(None, None, None)


def _custom_body(namespace: str, mode: str = "good") -> dict:
    return {
        "namespace": namespace,
        "kind": "custom",
        "command": sys.executable,
        "args": [FAKE_SERVER, mode],
    }


def _wait_running(a: SimpleNamespace, ns: str, timeout: float = 40.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        resp = a.client.get(f"/api/servers/{ns}", headers=a.headers)
        if resp.status_code == 200 and resp.json().get("status") == "running":
            return
        time.sleep(0.1)
    raise AssertionError(f"{ns} did not reach running")


# --- Admin API authentication (5.3) ------------------------------------------


def test_admin_token_accepted(api):
    a = api()
    resp = a.client.get("/api/servers", headers=a.headers)
    assert resp.status_code == 200


def test_mcp_token_refused(api):
    a = api()
    made = a.client.post(
        "/api/tokens", json={"name": "m", "scope": "mcp"}, headers=a.headers
    )
    mcp_token = made.json()["token"]
    resp = a.client.get(
        "/api/servers", headers={"Authorization": f"Bearer {mcp_token}"}
    )
    assert resp.status_code == 401
    assert resp.headers.get("www-authenticate") == "Bearer"


def test_session_cookie_refused(api):
    a = api()
    login = a.client.post("/login", data={"password": "secret", "next": "/"})
    assert login.status_code == 200  # followed the 303 to "/"
    assert a.client.cookies.get("mcpflow_session")
    resp = a.client.get("/api/servers")  # cookie, no bearer
    assert resp.status_code == 401
    assert "location" not in resp.headers


def test_missing_token(api):
    a = api()
    resp = a.client.post("/api/servers", json=_custom_body("time"))
    assert resp.status_code == 401
    assert resp.headers.get("www-authenticate") == "Bearer"
    # The registry did not change.
    assert not (a.data / "servers.json").exists()


# --- Source field (git-source-packages) --------------------------------------

_RAW_SOURCE = "git+https://oauth2:SEKRETTOKEN@host/o/r"
_REDACTED_SOURCE = "git+https://***@host/o/r"


def _sourced_body(ns: str, source: str = _RAW_SOURCE) -> dict:
    # `enabled: False` keeps uvx from starting a real child in the test.
    return {
        "namespace": ns,
        "kind": "python",
        "package": "my-tool",
        "source": source,
        "enabled": False,
    }


def test_api_source_redacted_raw_persisted(api):
    a = api()
    resp = a.client.post("/api/servers", json=_sourced_body("tool"), headers=a.headers)
    assert resp.status_code == 201
    assert resp.json()["source"] == _REDACTED_SOURCE
    # GET is redacted too.
    got = a.client.get("/api/servers", headers=a.headers).json()
    assert got[0]["source"] == _REDACTED_SOURCE
    # servers.json holds the raw credential.
    disk = json.loads((a.data / "servers.json").read_text())
    assert disk["servers"][0]["source"] == _RAW_SOURCE


def test_api_bad_source_400(api):
    a = api()
    body = _sourced_body("tool", source="ftp://x")
    resp = a.client.post("/api/servers", json=body, headers=a.headers)
    assert resp.status_code == 400
    assert "source" in resp.json()["error"]


def test_api_put_echo_keeps_raw_new_adopts(api):
    a = api()
    a.client.post("/api/servers", json=_sourced_body("tool"), headers=a.headers)
    # A client echoes the redacted GET body back to PUT: the raw source is kept.
    body = a.client.get("/api/servers/tool", headers=a.headers).json()
    assert body["source"] == _REDACTED_SOURCE
    put = a.client.put("/api/servers/tool", json=body, headers=a.headers)
    assert put.status_code == 200
    disk = json.loads((a.data / "servers.json").read_text())
    assert disk["servers"][0]["source"] == _RAW_SOURCE
    # A new credential is adopted.
    body["source"] = "git+https://oauth2:NEWTOKEN@host/o/r"
    a.client.put("/api/servers/tool", json=body, headers=a.headers)
    disk = json.loads((a.data / "servers.json").read_text())
    assert disk["servers"][0]["source"] == "git+https://oauth2:NEWTOKEN@host/o/r"


def test_api_failed_source_start_no_token_in_last_error(api):
    a = api()
    body = {
        "namespace": "tool",
        "kind": "python",
        "package": "my-tool",
        "source": "git+https://oauth2:SEKRETTOKEN@127.0.0.1:9/o/r",
    }
    resp = a.client.post("/api/servers", json=body, headers=a.headers)
    assert resp.status_code == 201
    end = time.time() + 30
    child = resp.json()
    while time.time() < end:
        child = a.client.get("/api/servers/tool", headers=a.headers).json()
        if child["status"] == "failed":
            break
        time.sleep(0.1)
    assert child["status"] == "failed"
    assert "SEKRETTOKEN" not in (child["last_error"] or "")
    assert child["source"] == "git+https://***@127.0.0.1:9/o/r"


# --- Admin API error semantics (5.4, error paths) ---------------------------


def test_duplicate_namespace(api):
    a = api(fake_child_spec("time", "good"))
    resp = a.client.post("/api/servers", json=_custom_body("time"), headers=a.headers)
    assert resp.status_code == 400
    assert resp.json() == {"error": "namespace time already exists"}


def test_unknown_namespace(api):
    a = api()
    resp = a.client.post("/api/servers/nope/restart", headers=a.headers)
    assert resp.status_code == 404
    assert resp.json() == {"error": "nope not found"}


def test_malformed_body(api):
    a = api()
    resp = a.client.post("/api/servers", json=[1, 2], headers=a.headers)
    assert resp.status_code == 400
    assert not (a.data / "servers.json").exists()


def test_unknown_path_is_json(api):
    a = api()
    resp = a.client.get("/api/nope", headers=a.headers)
    assert resp.status_code == 404
    assert resp.json() == {"error": "Not Found"}


def test_wrong_method_is_json(api):
    a = api()
    resp = a.client.patch("/api/servers", headers=a.headers)
    assert resp.status_code == 405
    assert "error" in resp.json()


def test_client_error_does_not_raise(api):
    # The fixture sets raise_server_exceptions=True. A duplicate namespace
    # answers 400 without an exception propagating into the client.
    a = api(fake_child_spec("time", "good"))
    resp = a.client.post("/api/servers", json=_custom_body("time"), headers=a.headers)
    assert resp.status_code == 400


# --- Server resources (5.4) --------------------------------------------------


def test_add_server(api):
    a = api()
    resp = a.client.post("/api/servers", json=_custom_body("time"), headers=a.headers)
    assert resp.status_code == 201
    body = resp.json()
    assert body["namespace"] == "time"
    assert body["status"] == "starting"
    assert "time" in (a.data / "servers.json").read_text()


def test_list_servers(api):
    a = api(fake_child_spec("time", "good"), fake_child_spec("clock", "good"))
    _wait_running(a, "time")
    _wait_running(a, "clock")
    resp = a.client.get("/api/servers", headers=a.headers)
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 2
    for child in body:
        assert "status" in child
        assert "tool_count" in child


def test_update_keeps_visibility(api):
    a = api(fake_child_spec("time", "good", disabled_tools=["get_current_time"]))
    body = _custom_body("time")  # omits disabled_tools
    resp = a.client.put("/api/servers/time", json=body, headers=a.headers)
    assert resp.status_code == 200
    assert resp.json()["disabled_tools"] == ["get_current_time"]
    stored = json.loads((a.data / "servers.json").read_text())
    (spec,) = stored["servers"]
    assert spec["disabled_tools"] == ["get_current_time"]


def test_update_omitted_enabled_starts_the_child(api):
    a = api(fake_child_spec("time", "good", enabled=False))
    body = _custom_body("time")  # omits enabled -> default True
    resp = a.client.put("/api/servers/time", json=body, headers=a.headers)
    assert resp.status_code == 200
    assert resp.json()["enabled"] is True
    assert resp.json()["status"] == "starting"
    stored = json.loads((a.data / "servers.json").read_text())
    assert stored["servers"][0]["enabled"] is True


def test_disable_then_enable(api):
    a = api(fake_child_spec("time", "good"))
    _wait_running(a, "time")
    off = a.client.post("/api/servers/time/disable", headers=a.headers)
    assert off.json()["enabled"] is False
    assert off.json()["status"] == "stopped"
    on = a.client.post("/api/servers/time/enable", headers=a.headers)
    assert on.json()["enabled"] is True


def test_remove(api):
    a = api(fake_child_spec("time", "good"))
    resp = a.client.delete("/api/servers/time", headers=a.headers)
    assert resp.status_code == 204
    missing = a.client.get("/api/servers/time", headers=a.headers)
    assert missing.status_code == 404
    assert missing.json() == {"error": "time not found"}
    stored = json.loads((a.data / "servers.json").read_text())
    assert all(s["namespace"] != "time" for s in stored["servers"])


def test_log_tail(api):
    a = api(fake_child_spec("time", "good"))
    _wait_running(a, "time")
    # Pin the tail deterministically: the child is idle after its startup
    # probe, so overwrite its log with known content and read the last lines.
    (a.data / "logs" / "time.log").write_text(
        "".join(f"line{i}\n" for i in range(10))
    )
    resp = a.client.get("/api/servers/time/log?lines=3", headers=a.headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    assert resp.text == "line7\nline8\nline9\n"


def test_log_tail_default_and_cap(api):
    a = api(fake_child_spec("time", "good"))
    _wait_running(a, "time")
    (a.data / "logs" / "time.log").write_text(
        "".join(f"line{i}\n" for i in range(1100))
    )
    # Default is 100 lines.
    default = a.client.get("/api/servers/time/log", headers=a.headers)
    assert len(default.text.splitlines()) == 100
    # lines is capped at 1000, load-bearing for the tail read.
    capped = a.client.get("/api/servers/time/log?lines=5000", headers=a.headers)
    assert len(capped.text.splitlines()) == 1000
    # A negative lines is harmless: empty body, no error.
    neg = a.client.get("/api/servers/time/log?lines=-1", headers=a.headers)
    assert neg.status_code == 200
    assert neg.text == ""


# --- Tool and visibility resources (5.5) -------------------------------------


def test_list_tools(api):
    a = api(fake_child_spec("time", "good"))
    _wait_running(a, "time")
    resp = a.client.get("/api/tools", headers=a.headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["root_muted"] is False
    match = [t for t in body["tools"] if t["name"] == "time_get_current_time"]
    assert match and match[0]["tool"] == "get_current_time"
    assert match[0]["visible"] is True


def test_mute_one_tool(api):
    a = api(fake_child_spec("time", "good"))
    _wait_running(a, "time")
    resp = a.client.put(
        "/api/visibility/namespaces/time/tools",
        json={"tool": "get_current_time", "muted": True},
        headers=a.headers,
    )
    assert resp.status_code == 200
    match = [t for t in resp.json()["tools"] if t["name"] == "time_get_current_time"]
    assert match and match[0]["visible"] is False
    stored = json.loads((a.data / "servers.json").read_text())
    assert stored["servers"][0]["disabled_tools"] == ["get_current_time"]


def test_mute_root(api):
    a = api(fake_child_spec("time", "good"))
    _wait_running(a, "time")
    resp = a.client.put(
        "/api/visibility/root", json={"muted": True}, headers=a.headers
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["root_muted"] is True
    # The root covers the child tools only. Every `mcpflow_*` tool keeps its own
    # value, so an admin session can always unmute the root over MCP.
    child = [t for t in body["tools"] if t["namespace"] != "mcpflow"]
    assert child and all(t["visible"] is False for t in child)
    assert all(t["visible"] is True for t in body["tools"] if t["namespace"] == "mcpflow")


def test_bad_visibility_body(api):
    a = api(fake_child_spec("time", "good"))
    _wait_running(a, "time")
    resp = a.client.put(
        "/api/visibility/root", json={"muted": "yes"}, headers=a.headers
    )
    assert resp.status_code == 400


# --- Token resources (5.6) ---------------------------------------------------


def test_create_mcp_token(api):
    a = api()
    resp = a.client.post("/api/tokens", json={"name": "laptop"}, headers=a.headers)
    assert resp.status_code == 201
    body = resp.json()
    assert body["scope"] == "mcp"
    assert body["token"].startswith("mcpflow_")
    # tokens.json holds only the digest, never the clear text.
    assert body["token"] not in (a.data / "tokens.json").read_text()


def test_bad_scope(api):
    a = api()
    before = (a.data / "tokens.json").read_text()
    resp = a.client.post(
        "/api/tokens", json={"name": "x", "scope": "root"}, headers=a.headers
    )
    assert resp.status_code == 400
    assert (a.data / "tokens.json").read_text() == before


def test_non_string_scope_is_400_not_500(api):
    # A JSON body can carry an unhashable scope. `x in frozenset` would raise
    # TypeError and escape the ValueError->400 mapping into a re-raised 500.
    a = api()
    resp = a.client.post(
        "/api/tokens", json={"name": "x", "scope": ["admin"]}, headers=a.headers
    )
    assert resp.status_code == 400


def test_list_hides_digests(api):
    a = api()
    resp = a.client.get("/api/tokens", headers=a.headers)
    assert resp.status_code == 200
    for record in resp.json():
        assert "sha256" not in record
        assert "token" not in record


def test_revoke_self(api):
    a = api()
    resp = a.client.delete(f"/api/tokens/{a.token_id}", headers=a.headers)
    assert resp.status_code == 204
    after = a.client.get("/api/tokens", headers=a.headers)
    assert after.status_code == 401
