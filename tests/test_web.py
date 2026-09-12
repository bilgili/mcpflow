"""The admin web UI over HTTP.

Scenarios from `specs/auth/spec.md` (Session gate on UI routes, Cross-site
request protection, Login and session cookie, Public health endpoint) and
`specs/web-ui/spec.md` (Tools dashboard, Servers page, Add-server form with
tabs, API tokens page, JSON paste import).
"""

from __future__ import annotations

import re
import time

import httpx
import pytest
from conftest import fake_child_spec, make_settings, seed_registry

from mcpflow.auth import TokenStore, sign_session
from mcpflow.registry import Registry

# --- Session gate on UI routes (12.13) ---------------------------------------


def test_health_without_credentials(server_factory):
    server = server_factory()
    resp = server.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "children" in body


def test_unauthenticated_dashboard(server_factory):
    server = server_factory()
    resp = httpx.get(server.base_url + "/servers", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login?next=/servers"


def test_unauthenticated_action(server_factory):
    server = server_factory()
    resp = httpx.post(server.base_url + "/servers/time/restart")
    assert resp.status_code == 401


def test_cross_origin_post(server_factory):
    server = server_factory()
    resp = httpx.post(
        server.base_url + "/tokens",
        data={"name": "x"},
        headers={"Origin": "https://evil.test"},
    )
    assert resp.status_code == 403
    # No token was created.
    store = TokenStore(server.data_dir / "tokens.json")
    store.load()
    assert store.list() == []


# --- Login and session cookie (12.14) ----------------------------------------


def test_correct_password(server_factory):
    server = server_factory()
    resp = httpx.post(
        server.base_url + "/login",
        data={"password": "secret", "next": "/servers"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/servers"
    assert "mcpflow_session=" in resp.headers.get("set-cookie", "")


def test_open_redirect_refused(server_factory):
    server = server_factory()
    for evil in ("https://evil.test", "//evil.test"):
        resp = httpx.post(
            server.base_url + "/login",
            data={"password": "secret", "next": evil},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/"


def test_wrong_password(server_factory):
    server = server_factory()
    start = time.perf_counter()
    resp = httpx.post(
        server.base_url + "/login",
        data={"password": "nope", "next": "/"},
        follow_redirects=False,
    )
    elapsed = time.perf_counter() - start
    assert resp.status_code == 200
    assert elapsed >= 1.0
    assert "set-cookie" not in resp.headers
    assert "error" in resp.text.lower()


# --- Tools dashboard (12.15) -------------------------------------------------


def test_dashboard_rows(server_factory):
    server = server_factory(seed_registry(fake_child_spec("time", "good")))
    server.wait(running=1)
    client = server.login()
    resp = client.get("/")
    client.close()
    assert resp.status_code == 200
    body = resp.text
    assert "time_get_current_time" in body
    assert "timezone: string" in body
    assert "running" in body


def test_dashboard_groups_tools_by_namespace(server_factory):
    # One <details> group per namespace that publishes a tool.
    server = server_factory(
        seed_registry(
            fake_child_spec("time", "good"),
            fake_child_spec("clock", "good"),
        )
    )
    server.wait(running=2)
    client = server.login()
    resp = client.get("/")
    client.close()
    body = resp.text
    groups = re.findall(r"<details[^>]*class=\"ns-group\"[^>]*>", body)
    # Two child groups plus the built-in `mcpflow` group.
    assert len(groups) == 3
    # Every group is collapsed at load: no `open` attribute on any of them.
    assert not any("open" in g for g in groups)


def test_dashboard_group_header_shows_namespace_count_and_status(server_factory):
    server = server_factory(seed_registry(fake_child_spec("time", "good")))
    server.wait(running=1)
    client = server.login()
    resp = client.get("/")
    client.close()
    body = resp.text
    # The built-in `mcpflow` group renders first, so take the child header.
    headers = re.findall(r"<summary>(.*?)</summary>", body, re.DOTALL)
    assert len(headers) == 2
    assert "mcpflow" in headers[0]
    summary = headers[1]
    assert "time" in summary
    assert "1 tools" in summary
    assert "status-running" in summary


def test_dashboard_without_tools_shows_the_empty_message(server_factory):
    server = server_factory()
    client = server.login()
    resp = client.get("/")
    client.close()
    body = resp.text
    assert "No child tool runs." in body
    # The built-in `mcpflow` group always renders; no child group does.
    groups = re.findall(r"<details[^>]*class=\"ns-group\"[^>]*>", body)
    assert len(groups) == 1
    assert '<span class="ns">mcpflow</span>' in body


@pytest.mark.asyncio
async def test_dashboard_marks_a_failed_child(tmp_path):
    # A child that raises during list_tools while the dashboard renders is
    # shown as failed with its error; other children's tools still show.
    from starlette.applications import Starlette
    from starlette.middleware import Middleware

    from mcpflow.auth import SessionGate
    from mcpflow.supervisor import Supervisor
    from mcpflow.web import build_routes

    data_dir = tmp_path / "d"
    data_dir.mkdir()
    (data_dir / "logs").mkdir()
    reg = Registry(data_dir / "servers.json")
    reg.load()
    settings = make_settings(data_dir)
    from mcpflow.oauth import CredStore, PendingFlows

    sup = Supervisor(reg, settings, CredStore(data_dir), PendingFlows())
    tokens = TokenStore(data_dir / "tokens.json")
    tokens.load()

    good = await sup.add(fake_child_spec("time", "good"))
    broken = await sup.add(fake_child_spec("broken", "good"))
    # Capture the task refs before awaiting: a finished start clears child.task
    # to None (the in-flight task, else None).
    good_task, broken_task = good.task, broken.task
    await good_task
    await broken_task
    assert good.status == "running" and broken.status == "running"
    # Break broken's connection: list_tools on it now raises.
    broken.transport = sup._build_transport(fake_child_spec("broken", "fail"))

    routes = build_routes(sup, tokens, settings, sup.creds, sup.flows)
    app = Starlette(
        routes=routes,
        middleware=[
            Middleware(
                SessionGate,
                secret=settings.secret_key,
                password_hash=settings.admin_password_hash,
                public_prefixes=("/login", "/static/"),
            )
        ],
    )
    cookie = sign_session(
        settings.secret_key, settings.admin_password_hash, int(time.time()) + 3600
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
        cookies={"mcpflow_session": cookie},
    ) as client:
        resp = await client.get("/")
    await sup.shutdown()

    assert resp.status_code == 200
    body = resp.text
    # The failed child appears with a failed status.
    assert "broken" in body
    assert "status-failed" in body
    # The other child's tools still render.
    assert "time_get_current_time" in body
    # Both children render as their own collapsed group.
    groups = re.findall(r"<details[^>]*class=\"ns-group\"[^>]*>", body)
    assert len(groups) == 2
    assert not any("open" in g for g in groups)
    # The failed group carries its error in the group body.
    failed = re.search(
        r"<details[^>]*class=\"ns-group\"[^>]*>(?:(?!</details>).)*?"
        r"status-failed(?:(?!</details>).)*?</details>",
        body,
        re.DOTALL,
    )
    assert failed is not None
    assert 'class="error"' in failed.group(0)


def test_restart_action(server_factory):
    server = server_factory(seed_registry(fake_child_spec("time", "good")))
    server.wait(running=1)
    client = server.login()
    resp = client.post("/servers/time/restart", headers={"HX-Request": "true"})
    client.close()
    assert resp.status_code == 200
    assert "starting" in resp.text


def test_log_tail_view(server_factory):
    server = server_factory(seed_registry(fake_child_spec("broken", "fail")))
    server.wait(failed=1)
    client = server.login()
    # Give the stderr a moment to flush to the log file.
    body = ""
    for _ in range(30):
        resp = client.get("/servers/broken/log?lines=100")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/plain")
        body = resp.text
        if "child boom" in body:
            break
        time.sleep(0.1)
    client.close()
    assert "child boom" in body


# --- Add-server form with tabs (12.16) ---------------------------------------


def test_python_tab(server_factory):
    # Bound the background start probe so no test waits on the network.
    server = server_factory(CHILD_START_TIMEOUT="2")
    client = server.login()
    resp = client.post(
        "/servers",
        data={
            "kind": "python",
            "namespace": "time",
            "package": "mcp-server-time",
            "args": "--local-timezone UTC",
        },
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/servers"
    client.close()
    # The registry contains a child of kind python.
    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    spec = reg.get("time")
    assert spec.kind == "python"
    assert spec.package == "mcp-server-time"


def test_source_persists_redacted_in_table_raw_in_edit(server_factory):
    server = server_factory(CHILD_START_TIMEOUT="2")
    client = server.login()
    raw = "git+https://oauth2:SEKRETTOKEN@host/o/r"
    # `enabled` omitted -> disabled, so no real uvx start on this test.
    resp = client.post(
        "/servers",
        data={"kind": "python", "namespace": "tool", "package": "my-tool", "source": raw},
    )
    assert resp.status_code == 303
    # The raw credential is persisted.
    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    assert reg.get("tool").source == raw
    # The servers table shows the redacted value, never the token.
    table = client.get("/servers").text
    assert "git+https://***@host/o/r" in table
    assert "SEKRETTOKEN" not in table
    # The edit form shows the raw value, the same rule as raw env.
    edit = client.get("/servers/tool/edit").text
    client.close()
    assert raw in edit


def test_checkbox_disabled_persists(server_factory):
    # An unchecked "enabled" checkbox is omitted from the POST body; presence
    # semantics must persist the server as disabled.
    server = server_factory(CHILD_START_TIMEOUT="2")
    client = server.login()
    off = client.post(
        "/servers",
        data={"kind": "python", "namespace": "off", "package": "pkg"},
    )
    on = client.post(
        "/servers",
        data={
            "kind": "python",
            "namespace": "on",
            "package": "pkg",
            "enabled": "on",
        },
    )
    client.close()
    assert off.status_code == 303 and on.status_code == 303
    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    assert reg.get("off").enabled is False
    assert reg.get("on").enabled is True


def test_validation_error_shown(server_factory):
    server = server_factory(
        seed_registry(fake_child_spec("dup", "good", enabled=False))
    )
    client = server.login()
    resp = client.post(
        "/servers",
        data={"kind": "python", "namespace": "dup", "package": "x"},
    )
    client.close()
    assert resp.status_code == 400
    assert "already exists" in resp.text


def test_pages_render_without_a_build(server_factory):
    server = server_factory()
    client = server.login()
    resp = client.get("/")
    assert resp.status_code == 200
    assert "/static/htmx.min.js" in resp.text
    assert "/static/style.css" in resp.text
    static = client.get("/static/htmx.min.js")
    client.close()
    assert static.status_code == 200


# --- API tokens page (12.17) -------------------------------------------------


def test_create_token(server_factory):
    server = server_factory()
    client = server.login()
    resp = client.post("/tokens", data={"name": "laptop"})
    client.close()
    assert resp.status_code == 200
    assert "mcpflow_" in resp.text
    assert "laptop" in resp.text


def test_token_scope_column(server_factory):
    server = server_factory()
    client = server.login()
    client.post("/tokens", data={"name": "laptop", "scope": "mcp"})
    listing = client.get("/tokens")
    client.close()
    # The table carries a Scope column and the row shows the token's scope.
    assert "<th>Scope</th>" in listing.text
    assert "mcp" in listing.text


def test_admin_token_shows_curl_and_mcp(server_factory):
    import html as _html
    import json as _json
    import re as _re

    server = server_factory()
    client = server.login()
    resp = client.post("/tokens", data={"name": "ci", "scope": "admin"})
    client.close()
    assert resp.status_code == 200
    body = resp.text
    token = _re.search(r"mcpflow_[A-Za-z0-9_-]+", body).group(0)
    # The admin token gets the REST curl AND the MCP client config.
    assert "curl" in body
    assert "/api/servers" in body
    text = _html.unescape(body)
    assert '"mcpServers"' in text
    block = _re.search(r'\{\s*"mcpServers".*?\n\}', text, _re.DOTALL)
    cfg = _json.loads(block.group(0))
    assert (
        cfg["mcpServers"]["mcpflow"]["headers"]["Authorization"] == f"Bearer {token}"
    )
    # The curl example carries this token in the Authorization header and hits
    # /api/servers (one line, so the assertion ties the two together).
    assert _re.search(
        r"curl -H \S*Authorization: Bearer " + token + r"\S*\s+\S*/api/servers",
        text,
    )
    # The REST tab is the active, visible one; the MCP panes start hidden.
    assert _re.search(r'data-tab="curl"[^>]*class="active"', body)
    assert _re.search(r'data-tab="curl"[^>]*aria-selected="true"', body)
    assert not _re.search(r'id="tab-curl"[^>]*hidden', body)
    assert _re.search(r'id="tab-json"[^>]*\shidden>', body)
    assert _re.search(r'id="tab-cli"[^>]*\shidden>', body)
    # The panel warns that the entry also exposes the admin tools.
    assert "built-in admin tools" in body


def test_tokens_page_hand_typed_bad_scope(server_factory):
    server = server_factory()
    client = server.login()
    resp = client.post("/tokens", data={"name": "x", "scope": "root"})
    client.close()
    assert resp.status_code == 400
    # No token was created.
    store = TokenStore(server.data_dir / "tokens.json")
    store.load()
    assert store.list() == []


def test_revoke_token(server_factory):
    server = server_factory()
    client = server.login()
    created = client.post("/tokens", data={"name": "laptop"})
    match = re.search(r"tok_[0-9a-f]+", created.text)
    assert match
    token_id = match.group(0)
    # Read the stored digest for this token.
    store = TokenStore(server.data_dir / "tokens.json")
    store.load()
    digest = next(r.sha256 for r in store.list() if r.id == token_id)

    resp = client.post(f"/tokens/{token_id}/delete", follow_redirects=False)
    assert resp.status_code == 303
    listing = client.get("/tokens")
    client.close()
    assert "laptop" not in listing.text
    # tokens.json no longer contains the digest.
    assert digest not in (server.data_dir / "tokens.json").read_text()


# --- JSON import (12.19) -----------------------------------------------------


def test_import_json_prefill(server_factory):
    server = server_factory()
    client = server.login()
    resp = client.post(
        "/import/json",
        data={
            "config": '{"mcpServers": {"fs": {"command": "npx", '
            '"args": ["-y", "@scope/pkg", "/data"]}}}'
        },
        headers={"HX-Request": "true"},
    )
    client.close()
    assert resp.status_code == 200
    assert 'value="fs"' in resp.text
    assert "@scope/pkg" in resp.text


def test_create_token_shows_mcp_config(server_factory):
    # Creating a token renders a ready-to-paste MCP config with the token
    # embedded in the Authorization header, plus the Claude Code CLI form.
    server = server_factory()
    client = server.login()
    resp = client.post("/tokens", data={"name": "laptop"})
    client.close()
    assert resp.status_code == 200
    body = resp.text
    match = re.search(r"mcpflow_[A-Za-z0-9_-]+", body)
    assert match, "clear token missing"
    token = match.group(0)
    # JSON quotes are HTML-escaped in the page source (&#34;); the browser
    # renders them back and clipboard copy uses innerText, so this is correct.
    import html as _html

    text = _html.unescape(body)
    assert '"mcpServers"' in text
    assert '"type": "http"' in text
    assert "/mcp" in text
    assert f"Bearer {token}" in text
    assert "claude mcp add --transport http mcpflow" in text
    # The embedded JSON block parses.
    import json as _json
    import re as _re

    block = _re.search(r'\{\s*"mcpServers".*?\n\}', text, _re.DOTALL)
    assert block, "JSON block not found"
    cfg = _json.loads(block.group(0))
    assert (
        cfg["mcpServers"]["mcpflow"]["headers"]["Authorization"] == f"Bearer {token}"
    )
    # An `mcp` token cannot call `/api`, so no REST tab is rendered.
    assert 'id="tab-curl"' not in body
    # The JSON tab is the active, visible one; the CLI pane starts hidden.
    assert _re.search(r'data-tab="json"[^>]*class="active"', body)
    assert not _re.search(r'id="tab-json"[^>]*hidden', body)
    assert _re.search(r'id="tab-cli"[^>]*\shidden>', body)


def test_every_tab_has_a_pane(server_factory):
    # A `data-tab` value with no matching pane would hide every pane at click
    # time, which no server-side test can see. Assert the pairing in markup.
    import re as _re

    server = server_factory()
    client = server.login()
    for scope in ("mcp", "admin"):
        resp = client.post("/tokens", data={"name": scope, "scope": scope})
        body = resp.text
        tabs = set(_re.findall(r'data-tab="([a-z]+)"', body))
        panes = set(_re.findall(r'id="tab-([a-z]+)"', body))
        assert tabs, f"no tabs for scope {scope}"
        assert tabs == panes, f"scope {scope}: tabs {tabs} != panes {panes}"
    client.close()


def test_public_url_override_drives_every_url(server_factory):
    # PUBLIC_URL drives the /mcp URL and the /api/servers curl URL alike on one
    # admin create, regardless of the request Host header.
    server = server_factory(PUBLIC_URL="https://mcp.example.com/")
    client = server.login()
    resp = client.post("/tokens", data={"name": "ci", "scope": "admin"})
    client.close()
    assert resp.status_code == 200
    assert "https://mcp.example.com/mcp" in resp.text
    assert "https://mcp.example.com/api/servers" in resp.text
    assert "mcp.example.com//" not in resp.text


def test_public_url_override_in_mcp_config(server_factory):
    # PUBLIC_URL overrides the request-derived host so the config is correct
    # behind a reverse proxy. Trailing slash is normalized.
    server = server_factory(PUBLIC_URL="https://mcp.example.com/")
    client = server.login()
    resp = client.post("/tokens", data={"name": "laptop"})
    client.close()
    assert resp.status_code == 200
    assert "https://mcp.example.com/mcp" in resp.text
    assert "https://mcp.example.com//mcp" not in resp.text
