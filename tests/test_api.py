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
        reg = Registry(data / "servers.json", data / "user_servers.json")
        reg.load()
        for spec in specs:
            reg.add(spec)
        store = TokenStore(data / "tokens.json", data / "user_tokens.json")
        store.load()
        record, token = store.create("admin", "admin", "admin")
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


# --- Cache TTL round-trip (child-catalog-freshness) --------------------------


def test_cache_ttl_round_trip(api):
    a = api()
    body = {**_custom_body("skills"), "cache_ttl": 0}
    resp = a.client.post("/api/servers", json=body, headers=a.headers)
    assert resp.status_code == 201
    assert resp.json()["cache_ttl"] == 0.0
    listed = a.client.get("/api/servers", headers=a.headers).json()
    assert [c["cache_ttl"] for c in listed if c["namespace"] == "skills"] == [0.0]
    stored = json.loads((a.data / "servers.json").read_text())["servers"]
    assert stored[0]["cache_ttl"] == 0.0


def test_cache_ttl_omitted_is_null(api):
    a = api()
    resp = a.client.post("/api/servers", json=_custom_body("time"), headers=a.headers)
    assert resp.status_code == 201
    assert resp.json()["cache_ttl"] is None


def test_negative_cache_ttl_400(api):
    a = api()
    body = {**_custom_body("skills"), "cache_ttl": -5}
    resp = a.client.post("/api/servers", json=body, headers=a.headers)
    assert resp.status_code == 400
    assert "cache_ttl" in resp.text


# --- A malformed reference is not found (ServerKey shape, 1317096) -----------


@pytest.mark.parametrize("ref", ["github@alice", "Bad"])
def test_a_malformed_namespace_path_answers_404(api, ref):
    """`/api/servers/{ns}` answers 404 for a reference that is not an
    admin-owned namespace, and never resolves it to admin-owned `github`."""
    a = api(fake_child_spec("github", "good", enabled=False))
    for method, path in (("get", f"/api/servers/{ref}"),
                         ("post", f"/api/servers/{ref}/restart"),
                         ("post", f"/api/servers/{ref}/enable"),
                         ("delete", f"/api/servers/{ref}")):
        resp = getattr(a.client, method)(path, headers=a.headers)
        assert resp.status_code == 404, (method, path, resp.text)
    assert a.client.get("/api/servers/github", headers=a.headers).status_code == 200


# =============================================================================
# 10G (multi-user-access): the `/api` scenarios of `specs/admin-api`, over one
# seeded gateway (tests/dashboard_site.py): users alice and bob, admin-owned
# `time`, running `github@alice` and `github@bob`, an admin token `ops`.
# =============================================================================

from dashboard_site import (  # noqa: F401
    ALICE_PW,
    api_headers,
    assert_no_secrets,
    bearer,
    make_mu_site,
    mcp_tools,
    on_disk_secrets,
)

from mcpflow.registry import ServerKey, revision

GH_ALICE = ServerKey("alice", "github")
UNAUTHORIZED = {"error": "unauthorized"}
ENV_SECRET = "S3CR3T-VALUE-ZZ9"


def _token_files(site) -> dict[str, bytes]:
    return {n: (site.data / n).read_bytes() for n in ("tokens.json", "user_tokens.json")
            if (site.data / n).exists()}


def _registry_files(site) -> dict[str, bytes]:
    return {n: (site.data / n).read_bytes() for n in ("servers.json", "user_servers.json")
            if (site.data / n).exists()}


def _mint(site, **body):
    return site.client.post("/api/tokens", headers=api_headers(site), json=body)


def _assert_unauthorized(resp) -> None:
    assert resp.status_code == 401
    assert resp.headers.get("www-authenticate") == "Bearer"
    assert resp.json() == UNAUTHORIZED
    assert "location" not in resp.headers


# --- 10.36: authentication and token resources -----------------------------


def test_admin_token_of_an_admin_user_is_accepted(make_mu_site):
    """Scenario "Admin token accepted"."""
    site = make_mu_site()
    resp = site.client.get("/api/servers", headers=api_headers(site))
    assert resp.status_code == 200
    assert {"github@alice", "github@bob", "time"} <= {s["ref"] for s in resp.json()}


def test_an_mcp_token_is_refused_on_api(make_mu_site):
    """Scenario "MCP token refused"."""
    site = make_mu_site()
    token = _mint(site, name="m", scope="mcp", user_id="alice").json()["token"]
    _assert_unauthorized(site.client.get("/api/servers", headers=bearer(token)))


def test_an_admin_scope_token_of_a_non_admin_user_is_refused(make_mu_site):
    """Scenario "Admin-scope token of a non-admin user refused"."""
    site = make_mu_site()
    h = api_headers(site)
    made = site.client.post("/api/users", headers=h, json={
        "id": "dave", "admin": True})
    assert made.status_code == 201, made.text
    token = _mint(site, name="dave-admin", scope="admin", user_id="dave").json()["token"]
    assert site.client.get("/api/servers", headers=bearer(token)).status_code == 200
    demoted = site.client.put("/api/users/dave", headers=h, json={"admin": False})
    assert demoted.status_code == 200, demoted.text
    _assert_unauthorized(site.client.get("/api/servers", headers=bearer(token)))
    # Not even a read of another resource, and not a write.
    _assert_unauthorized(site.client.get("/api/users", headers=bearer(token)))
    _assert_unauthorized(site.client.post("/api/rules", headers=bearer(token), json={}))


def test_a_session_cookie_is_refused_on_api(make_mu_site):
    """Scenario "Session cookie refused": a valid session of the admin."""
    site = make_mu_site()
    cookie = {"Cookie": f"mcpflow_session={site.login('admin')}"}
    assert site.client.get("/", headers=cookie).status_code == 200  # the cookie is valid
    for path in ("/api/servers", "/api/tokens", "/api/users"):
        _assert_unauthorized(site.client.get(path, headers=cookie))
    site.client.cookies.clear()


def test_a_missing_token_is_refused_and_the_registry_does_not_change(make_mu_site):
    """Scenario "Missing token"."""
    site = make_mu_site()
    before = _registry_files(site)
    resp = site.client.post("/api/servers", json={
        "namespace": "x", "kind": "python", "package": "p", "enabled": False})
    _assert_unauthorized(resp)
    assert _registry_files(site) == before


def test_create_an_mcp_token_stores_only_the_digest(make_mu_site):
    """Scenario "Create an mcp token"."""
    site = make_mu_site()
    resp = _mint(site, name="laptop")
    assert resp.status_code == 201
    body = resp.json()
    assert (body["scope"], body["user_id"]) == ("mcp", "admin")
    assert body["token"].startswith("mcpflow_")
    assert "sha256" not in body
    files = b"".join(_token_files(site).values())
    assert body["token"].encode() not in files
    assert on_disk_secrets(site.data)["token digest"]
    # The clear text is shown once: a later list never returns it.
    listing = site.client.get("/api/tokens", headers=api_headers(site))
    assert body["token"] not in listing.text


def test_create_a_token_for_another_user_ac7(make_mu_site):
    """Scenario "Create a token for another user (AC-7)": the token
    authenticates `/mcp` as `alice`, not as an admin."""
    site = make_mu_site()
    resp = _mint(site, name="alice-laptop", user_id="alice")
    assert resp.status_code == 201
    assert resp.json()["user_id"] == "alice"
    names = mcp_tools(site, resp.json()["token"])
    assert names == {"github_get_current_time"}  # her own server only
    assert not any(n.startswith(("mcpflow_", "time_")) for n in names)
    # The record lives with alice.
    listed = site.client.get("/api/tokens", headers=api_headers(site)).json()
    assert next(t for t in listed if t["id"] == resp.json()["id"])["user_id"] == "alice"


def test_an_unknown_token_user_answers_400(make_mu_site):
    """Requirement "Token resources": a `user_id` that names no user is 400.
    The user is a body name, not a path target (private-cascade-halves D6)."""
    site = make_mu_site()
    before = _token_files(site)
    resp = _mint(site, name="x", user_id="nobody")
    assert resp.status_code == 400
    assert resp.json() == {"error": "user_id: unknown user nobody"}
    resp = _mint(site, name="x", user_id="")
    assert resp.status_code == 400
    assert resp.json() == {"error": "user_id: unknown user "}
    assert _token_files(site) == before


def test_bad_scope_answers_400_and_no_token_file_changes(make_mu_site):
    """Scenario "Bad scope"."""
    site = make_mu_site()
    before = _token_files(site)
    resp = _mint(site, name="x", scope="root")
    assert resp.status_code == 400
    assert _token_files(site) == before


def test_list_hides_digests_and_names_the_user(make_mu_site):
    """Scenario "List hides digests"."""
    site = make_mu_site()
    resp = site.client.get("/api/tokens", headers=api_headers(site))
    assert resp.status_code == 200
    tokens = resp.json()
    assert tokens, "the fixture holds tokens"
    for obj in tokens:
        assert "sha256" not in obj and "token" not in obj
        assert obj["user_id"]
    assert_no_secrets(resp.text, site.data)


def test_revoke_self_answers_204_then_401(make_mu_site):
    """Scenario "Revoke self"."""
    site = make_mu_site()
    h = api_headers(site)
    mine = next(t for t in site.client.get("/api/tokens", headers=h).json()
                if t["name"] == "ops")
    assert site.client.delete(f"/api/tokens/{mine['id']}", headers=h).status_code == 204
    _assert_unauthorized(site.client.get("/api/tokens", headers=h))


# --- 10.37: server references and approvals --------------------------------


def _edit_as_alice(site, package: str, env: str | None = f"TOKEN={ENV_SECRET}"):
    """Alice saves `github@alice` with a new package and one env secret: the
    server goes back to pending (the browser sends `enabled` when checked)."""
    data = {"kind": "npm", "namespace": "github", "package": package, "enabled": "on"}
    if env:
        data["env"] = env
    resp = site.request("alice", "POST", "/servers/github@alice", data=data)
    assert resp.status_code == 303, resp.text


def _child(site, ref: str) -> dict:
    resp = site.client.get(f"/api/servers/{ref}", headers=api_headers(site))
    assert resp.status_code == 200, resp.text
    return resp.json()


def _stored_revision(site, key: ServerKey = GH_ALICE) -> str:
    reg = Registry(site.data / "servers.json", site.data / "user_servers.json")
    reg.load()
    return revision(reg.get(key))


def test_list_user_servers_with_owner_approval_and_revision(make_mu_site):
    """Scenario "List user servers"."""
    site = make_mu_site()
    _edit_as_alice(site, "@acme/mcp@2.0.0")
    resp = site.client.get("/api/servers", headers=api_headers(site))
    assert resp.status_code == 200
    by_ref = {s["ref"]: s for s in resp.json()}
    time_ = by_ref["time"]
    assert (time_["owner"], time_["approval"], time_["revision"]) == (None, "approved", None)
    alice = by_ref["github@alice"]
    assert (alice["owner"], alice["approval"]) == ("alice", "pending")
    assert alice["revision"] == _stored_revision(site)
    assert alice["namespace"] == "github"
    assert by_ref["github@bob"]["owner"] == "bob"
    assert_no_secrets(resp.text, site.data)


def test_manage_a_user_server_restart_answers_200_starting(make_mu_site):
    """Scenario "Manage a user server"."""
    site = make_mu_site()
    resp = site.client.post("/api/servers/github@alice/restart", headers=api_headers(site))
    assert resp.status_code == 200, resp.text
    assert resp.json()["ref"] == "github@alice"
    assert resp.json()["status"] == "starting"


def test_a_body_cannot_pick_the_owner(make_mu_site):
    """Scenario "A body cannot pick the owner" (`enabled: false` keeps `uvx`
    from running; the response fields are the scenario's)."""
    site = make_mu_site()
    h = api_headers(site)
    resp = site.client.post("/api/servers", headers=h, json={
        "namespace": "x", "kind": "python", "package": "p", "enabled": False,
        "owner": "alice", "approval": "pending", "approved_revision": "forged",
        "revision": "forged"})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert (body["ref"], body["owner"], body["approval"], body["revision"]) == \
        ("x", None, "approved", None)
    assert "x@alice" not in {s["ref"] for s in
                             site.client.get("/api/servers", headers=h).json()}
    stored = json.loads((site.data / "servers.json").read_text())["servers"]
    assert "owner" not in next(s for s in stored if s["namespace"] == "x") or \
        next(s for s in stored if s["namespace"] == "x")["owner"] is None


def test_approve_over_the_api_ac7(make_mu_site):
    """Scenario "Approve over the API (AC-7)"."""
    site = make_mu_site()
    _edit_as_alice(site, "@acme/mcp@2.0.0")
    r1 = _child(site, "github@alice")["revision"]
    before = site.launches()
    resp = site.client.post("/api/servers/github@alice/approve", headers=api_headers(site),
                            json={"revision": r1})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert (body["approval"], body["revision"], body["status"]) == ("approved", r1, "starting")
    assert_no_secrets(resp.text, site.data)
    site.wait_running(GH_ALICE)
    assert site.launches() == before + 1


def test_a_stale_revision_answers_409_with_the_stored_revision_f1(make_mu_site):
    """Scenario "A stale revision answers 409 (F1)"."""
    site = make_mu_site()
    _edit_as_alice(site, "@acme/mcp@2.0.0")
    r1 = _child(site, "github@alice")["revision"]
    _edit_as_alice(site, "@acme/mcp@2.0.1")  # alice changes it: revision R2
    r2 = _stored_revision(site)
    assert r2 != r1
    before, launches = _registry_files(site), site.launches()
    resp = site.client.post("/api/servers/github@alice/approve", headers=api_headers(site),
                            json={"revision": r1})
    assert resp.status_code == 409
    assert resp.json() == {"error": "revision mismatch", "revision": r2}
    assert _registry_files(site) == before
    assert site.status(GH_ALICE) == "stopped"
    assert _child(site, "github@alice")["approval"] == "pending"
    assert site.launches() == launches, "a process ran"
    assert_no_secrets(resp.text, site.data)


def test_approve_without_a_revision_answers_400(make_mu_site):
    """Scenario "Approve without a revision"."""
    site = make_mu_site()
    _edit_as_alice(site, "@acme/mcp@2.0.0")
    h = api_headers(site)
    for body in ({}, {"revision": 5}, {"revision": None}):
        resp = site.client.post("/api/servers/github@alice/approve", headers=h, json=body)
        assert resp.status_code == 400, (body, resp.status_code)
    assert _child(site, "github@alice")["approval"] == "pending"
    assert site.status(GH_ALICE) == "stopped"


def test_approve_of_an_admin_owned_child_answers_400_before_any_revision_compare(make_mu_site):
    """Requirement "Approval resources": 400, never 409, and `time` is untouched."""
    site = make_mu_site()
    before = _registry_files(site)
    for revision_ in ("not-a-revision", "0" * 64):
        resp = site.client.post("/api/servers/time/approve", headers=api_headers(site),
                                json={"revision": revision_})
        assert resp.status_code == 400, (revision_, resp.status_code, resp.text)
    assert _registry_files(site) == before
    assert site.status(ServerKey(None, "time")) == "running"


def test_list_pending_servers_holds_the_pending_one_only(make_mu_site):
    """Scenario "List pending servers"."""
    site = make_mu_site()
    h = api_headers(site)
    assert site.client.get("/api/approvals", headers=h).json() == []
    _edit_as_alice(site, "@acme/mcp@2.0.0")
    resp = site.client.get("/api/approvals", headers=h)
    assert resp.status_code == 200
    assert [s["ref"] for s in resp.json()] == ["github@alice"]
    assert resp.json()[0]["revision"] == _stored_revision(site)
    assert_no_secrets(resp.text, site.data)


def test_reject_over_the_api_removes_the_pending_server(make_mu_site):
    """Requirement "Approval resources": a reject is `DELETE /api/servers/{ref}`."""
    site = make_mu_site()
    _edit_as_alice(site, "@acme/mcp@2.0.0")
    h = api_headers(site)
    assert site.client.delete("/api/servers/github@alice", headers=h).status_code in (200, 204)
    assert site.client.get("/api/approvals", headers=h).json() == []
    assert site.client.get("/api/servers/github@alice", headers=h).status_code == 404


# --- 10.38: users, groups, and rules ----------------------------------------


def _post(site, path: str, **body):
    return site.client.post(path, headers=api_headers(site), json=body)


def _users(site) -> list[dict]:
    return site.client.get("/api/users", headers=api_headers(site)).json()


def test_the_secret_value_is_on_disk_so_the_masking_checks_are_real(make_mu_site):
    site = make_mu_site()
    _edit_as_alice(site, "@acme/mcp@2.0.0")
    assert ENV_SECRET in on_disk_secrets(site.data)["env/header value"]


def test_create_a_user_over_the_api_ac7(make_mu_site):
    """Scenario "Create a user over the API (AC-7)"."""
    site = make_mu_site()
    assert _post(site, "/api/groups", name="eng").status_code == 201
    resp = _post(site, "/api/users", id="dave", groups=["eng"])
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["id"] == "dave" and body["groups"] == ["eng"]
    assert not {k for k in body if "pass" in k or "hash" in k}
    code = body["setup_code"]  # the admin chooses no password: a one-time code instead
    assert_no_secrets(resp.text, site.data)
    listing = site.client.get("/api/users", headers=api_headers(site))
    assert code not in listing.text
    assert_no_secrets(listing.text, site.data)
    assert not {k for u in listing.json() for k in u if "pass" in k or "hash" in k}


def test_create_a_group_over_the_api_ac7(make_mu_site):
    """Scenario "Create a group over the API (AC-7)"."""
    site = make_mu_site()
    assert _post(site, "/api/groups", name="eng").status_code == 201
    listing = site.client.get("/api/groups", headers=api_headers(site))
    assert listing.status_code == 200
    assert "eng" in json.dumps(listing.json())


def test_demote_the_bootstrap_admin_answers_400(make_mu_site):
    """Scenario "Demote the bootstrap admin"."""
    site = make_mu_site()
    resp = site.client.put("/api/users/admin", headers=api_headers(site),
                           json={"admin": False})
    assert resp.status_code == 400
    assert next(u for u in _users(site) if u["id"] == "admin")["admin"] is True


def test_deleting_the_bootstrap_admin_answers_400(make_mu_site):
    """Requirement "User and group resources": a forbidden change is 400."""
    site = make_mu_site()
    resp = site.client.delete("/api/users/admin", headers=api_headers(site))
    assert resp.status_code == 400
    assert "admin" in {u["id"] for u in _users(site)}
    assert site.client.get("/api/servers", headers=api_headers(site)).status_code == 200


def test_delete_a_user_who_owns_a_server_is_refused_and_deletes_nothing(make_mu_site):
    """Scenario "Delete a user who owns a server"."""
    site = make_mu_site()
    h = api_headers(site)
    files, servers = _token_files(site), {s["ref"] for s in
                                          site.client.get("/api/servers", headers=h).json()}
    resp = site.client.delete("/api/users/alice", headers=h)
    assert resp.status_code == 400
    assert "alice" in {u["id"] for u in _users(site)}
    assert {s["ref"] for s in site.client.get("/api/servers", headers=h).json()} == servers
    assert _token_files(site) == files, "a token of alice was deleted"
    assert site.status(GH_ALICE) == "running"


def _member(site) -> str:
    """A member of group `eng` with an `mcp` token; return the token."""
    assert _post(site, "/api/groups", name="eng").status_code == 201
    assert _post(site, "/api/users", id="dave", groups=["eng"]).status_code == 201
    return _mint(site, name="dave-mcp", user_id="dave").json()["token"]


def _eng_rule(site):
    return _post(site, "/api/rules", subject_kind="group", subject="eng",
                 level="server", server="time", effect="allow")


def test_add_a_rule_over_the_api_ac7(make_mu_site):
    """Scenario "Add a rule over the API (AC-7)"."""
    site = make_mu_site()
    token = _member(site)
    assert not any(n.startswith("time_") for n in mcp_tools(site, token))
    resp = _eng_rule(site)
    assert resp.status_code == 201, resp.text
    assert resp.json()["id"]
    assert "time_get_current_time" in mcp_tools(site, token)
    assert resp.json()["id"] in {r["id"] for r in
                                 site.client.get("/api/rules", headers=api_headers(site)).json()}


def test_remove_a_rule_over_the_api(make_mu_site):
    """Scenario "Remove a rule over the API"."""
    site = make_mu_site()
    token = _member(site)
    rule = _eng_rule(site).json()
    assert "time_get_current_time" in mcp_tools(site, token)
    resp = site.client.delete(f"/api/rules/{rule['id']}", headers=api_headers(site))
    assert resp.status_code == 204
    assert not any(n.startswith("time_") for n in mcp_tools(site, token))


def test_an_unknown_rule_answers_404(make_mu_site):
    """Scenario "Unknown rule"."""
    site = make_mu_site()
    resp = site.client.delete("/api/rules/nope", headers=api_headers(site))
    assert resp.status_code == 404
    assert resp.json() == {"error": "nope not found"}


# --- Users without an admin-chosen password (user-self-service-password, 7.5) -
#
# Scenarios of the admin-api delta "User and group resources": create with a
# setup code, a `password` key refused, reset, and the list that shows a
# pending user and no code.


def _users_file(site) -> bytes:
    return (site.data / "users.json").read_bytes()


def _redeem(site, user: str, code: str, password: str = "api-made-pw-123"):
    resp = site.client.post("/login/setup", data={
        "user": user, "code": code, "password": password, "confirm": password})
    site.client.cookies.clear()
    return resp


def _can_sign_in(site, user: str, password: str) -> bool:
    resp = site.client.post("/login", data={"user": user, "password": password, "next": "/"})
    site.client.cookies.clear()
    return resp.status_code == 303


def test_create_returns_a_pending_user_and_a_setup_code(make_mu_site):
    """Create a user over the API (AC-7): `201`, `pending`, `setup_code`, no hash."""
    site = make_mu_site()
    assert _post(site, "/api/groups", name="eng").status_code == 201
    resp = _post(site, "/api/users", id="dave", groups=["eng"])
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert (body["id"], body["groups"], body["pending"]) == ("dave", ["eng"], True)
    assert isinstance(body["setup_code"], str) and body["setup_code"]
    assert not {k for k in body if "hash" in k or k == "password"}
    # The code is real: it redeems at the setup page, and only once.
    assert _redeem(site, "dave", body["setup_code"]).status_code == 303
    assert _redeem(site, "dave", body["setup_code"]).status_code == 400
    assert _can_sign_in(site, "dave", "api-made-pw-123")


@pytest.mark.parametrize("value", ["pw", "", None])
def test_a_password_key_is_refused_on_create(make_mu_site, value):
    """A password key is refused on create: `400` naming `password`, no user."""
    site = make_mu_site()
    before = _users_file(site)
    resp = _post(site, "/api/users", id="erin", password=value)
    assert resp.status_code == 400
    assert "password" in resp.text
    assert "erin" not in {u["id"] for u in _users(site)}
    assert _users_file(site) == before


def test_a_password_key_is_refused_on_update(make_mu_site):
    """A password key is refused on update: `400`, nothing in the body applies."""
    site = make_mu_site()
    before_users = _users(site)
    before = _users_file(site)
    for body in ({"password": "pw", "admin": True},
                 {"admin": True, "groups": [], "password": ""},
                 {"password": None}):
        resp = site.client.put("/api/users/alice", headers=api_headers(site), json=body)
        assert resp.status_code == 400, body
        assert "password" in resp.text
    assert _users(site) == before_users
    assert next(u for u in _users(site) if u["id"] == "alice")["admin"] is False
    assert _users_file(site) == before
    assert _can_sign_in(site, "alice", ALICE_PW)  # her password is the one she had


def test_update_without_a_password_still_works(make_mu_site):
    site = make_mu_site()
    resp = site.client.put("/api/users/alice", headers=api_headers(site),
                           json={"admin": True})
    assert resp.status_code == 200, resp.text
    alice = next(u for u in _users(site) if u["id"] == "alice")
    assert alice["admin"] is True and alice["pending"] is False


def test_reset_a_user_over_the_api(make_mu_site):
    """Reset a user over the API."""
    site = make_mu_site()
    assert _can_sign_in(site, "alice", ALICE_PW)
    resp = site.client.post("/api/users/alice/setup-code", headers=api_headers(site))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["id"] == "alice" and body["pending"] is True
    code = body["setup_code"]
    assert isinstance(code, str) and code
    assert not _can_sign_in(site, "alice", ALICE_PW)
    listing = site.client.get("/api/users", headers=api_headers(site))
    assert code not in listing.text
    assert "setup_code" not in listing.text
    assert next(u for u in listing.json() if u["id"] == "alice")["pending"] is True
    # A second reset replaces the code.
    second = site.client.post("/api/users/alice/setup-code",
                              headers=api_headers(site)).json()["setup_code"]
    assert second != code
    assert _redeem(site, "alice", code).status_code == 400
    assert _redeem(site, "alice", second).status_code == 303


def test_reset_the_bootstrap_admin_answers_400(make_mu_site):
    """Reset the bootstrap admin."""
    site = make_mu_site()
    before = _users_file(site)
    resp = site.client.post("/api/users/admin/setup-code", headers=api_headers(site))
    assert resp.status_code == 400
    assert "setup_code" not in resp.text
    assert _users_file(site) == before
    assert _can_sign_in(site, "admin", "secret")


def test_reset_an_unknown_user_answers_404(make_mu_site):
    site = make_mu_site()
    before = _users_file(site)
    resp = site.client.post("/api/users/nobody/setup-code", headers=api_headers(site))
    assert resp.status_code == 404
    assert "error" in resp.json()
    assert _users_file(site) == before


def test_reset_needs_the_admin_token(make_mu_site):
    site = make_mu_site()
    before = _users_file(site)
    assert site.client.post("/api/users/alice/setup-code").status_code == 401
    assert site.client.post("/api/users/alice/setup-code",
                            headers=bearer("mcpflow_not-a-token")).status_code == 401
    assert _users_file(site) == before


def test_the_user_list_shows_pending_and_no_code(make_mu_site):
    """GET /api/users: `pending` on every user, no hash, no `setup_code`."""
    site = make_mu_site()
    created = _post(site, "/api/users", id="dave").json()
    users = {u["id"]: u for u in _users(site)}
    assert users["dave"]["pending"] is True
    assert users["alice"]["pending"] is False and users["admin"]["pending"] is False
    for user in users.values():
        assert {"id", "name", "admin", "groups", "pending"} <= set(user)
        assert "setup_code" not in user
        assert not {k for k in user if "hash" in k or "password" in k}
    text = site.client.get("/api/users", headers=api_headers(site)).text
    assert created["setup_code"] not in text
    assert_no_secrets(text, site.data)
