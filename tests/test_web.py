"""The admin web UI over HTTP.

Scenarios from `specs/auth/spec.md` (Session gate on UI routes, Cross-site
request protection, Login and session cookie, Public health endpoint) and
`specs/web-ui/spec.md` (Tools dashboard, Servers page, Add-server form with
tabs, API tokens page, JSON paste import).
"""

from __future__ import annotations

import asyncio
import re
import time

import httpx
import pytest
from conftest import (
    ADMIN_ACTOR,
    fake_child_spec,
    make_policy,
    make_settings,
    seed_registry,
)

from mcpflow.auth import TokenStore, sign_session
from mcpflow.registry import Registry, ServerKey

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
    store = TokenStore(server.data_dir / "tokens.json", server.data_dir / "user_tokens.json")
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
    resp = client.get("/tools/tree")
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
    resp = client.get("/tools/tree")
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
    resp = client.get("/tools/tree")
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
    resp = client.get("/tools/tree")
    client.close()
    body = resp.text
    assert "No servers yet." in body
    # The built-in `mcpflow` group always renders; no child group does.
    groups = re.findall(r"<details[^>]*class=\"ns-group\"[^>]*>", body)
    assert len(groups) == 1
    assert '<span class="ns">mcpflow</span>' in body


def test_the_dashboard_shell_loads_the_tree_without_probing(server_factory, monkeypatch):
    # `GET /` answers with the shell and a placeholder that loads the tree
    # after the page paints. It probes no child, so a slow child cannot hold
    # the page: the tools come from `GET /tools/tree` only.
    server = server_factory(seed_registry(fake_child_spec("time", "good")))
    server.wait(running=1)
    sup = server.supervisor
    calls = []
    real = sup.tools

    async def counting(*args, **kwargs):
        calls.append(1)
        return await real(*args, **kwargs)

    monkeypatch.setattr(sup, "tools", counting)
    client = server.login()
    shell = client.get("/")
    assert shell.status_code == 200
    assert calls == []
    tag = re.search(r'<[^>]*id="tools-tree"[^>]*>', shell.text)
    assert tag is not None
    assert 'hx-get="/tools/tree"' in tag.group(0)
    assert 'hx-trigger="load"' in tag.group(0)
    # outerHTML: the answer's own `#tools-tree` replaces the placeholder, so
    # the page never holds two elements with that id.
    assert 'hx-swap="outerHTML"' in tag.group(0)
    assert "hx-on::response-error=" in tag.group(0)
    assert 'id="detail"' in shell.text
    assert "time_get_current_time" not in shell.text
    tree = client.get("/tools/tree")
    client.close()
    assert tree.status_code == 200
    assert "time_get_current_time" in tree.text
    assert calls == [1]


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
    reg = Registry(data_dir / "servers.json", data_dir / "user_servers.json")
    reg.load()
    settings = make_settings(data_dir)
    from mcpflow.oauth import CredStore, PendingFlows

    sup = Supervisor(
        reg, settings, CredStore(data_dir), PendingFlows(), make_policy(data_dir, reg)
    )
    tokens = TokenStore(data_dir / "tokens.json", data_dir / "user_tokens.json")
    tokens.load()

    brk = data_dir / "broken_break"
    good = await sup.add(fake_child_spec("time", "good"), ADMIN_ACTOR)
    broken = await sup.add(fake_child_spec("broken", "action", env={"MCPFLOW_BREAK": str(brk)}), ADMIN_ACTOR)
    # Capture the task refs before awaiting: a finished start clears child.task
    # to None (the in-flight task, else None).
    good_task, broken_task = good.task, broken.task
    await good_task
    await broken_task
    assert good.status == "running" and broken.status == "running"
    # Break broken's connection through its real transport: while the flag
    # exists, its `tools/list` raises, so the dashboard probe marks it failed.
    brk.write_text("")

    from mcpflow.identity import LocalIdentityProvider
    from mcpflow.web import USER_ROUTES

    identity = LocalIdentityProvider(data_dir / "users.json", settings.admin_password_hash)
    identity.load()
    routes = build_routes(sup, tokens, settings, sup.creds, sup.flows, identity)
    app = Starlette(
        routes=routes,
        middleware=[
            Middleware(
                SessionGate,
                secret=settings.secret_key,
                identity=identity,
                public_prefixes=("/login", "/static/"),
                user_routes=USER_ROUTES,
            )
        ],
    )
    cookie = sign_session(
        settings.secret_key,
        "admin",
        settings.admin_password_hash,
        int(time.time()) + 3600,
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
        cookies={"mcpflow_session": cookie},
    ) as client:
        # Failure detection now comes from the background probe (D3/D4): make
        # the snapshot stale, load to start the probe, await it, then poll.
        # Capture the task the render creates: after the round trip the probe
        # can be done already, and its `finally` clears `session.probe`.
        probes: dict[str, asyncio.Task] = {}
        schedule = sup._schedule_probe

        def spy(child, session):
            schedule(child, session)
            probes[child.spec.namespace] = session.probe

        sup._schedule_probe = spy
        broken.session.probed_at = None
        await client.get("/tools/tree")
        assert "broken" in probes
        # Every probe of the load, so none is live when the poll answers.
        await asyncio.wait_for(asyncio.gather(*probes.values()), 15)
        resp = await client.get("/tools/tree?poll=1")
    await sup.shutdown()

    assert resp.status_code == 200
    body = resp.text
    # The probe ended, so the poll answer carries no poll.
    root = body[body.index('<div id="tools-tree"') :].split(">", 1)[0]
    assert "hx-trigger" not in root
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
    assert resp.headers["location"] == "/"
    client.close()
    # The registry contains a child of kind python.
    reg = Registry(server.data_dir / "servers.json", server.data_dir / "user_servers.json")
    reg.load()
    spec = reg.get(ServerKey(None, "time"))
    assert spec.kind == "python"
    assert spec.package == "mcp-server-time"


def test_source_persists_raw_redacted_in_row_and_window(server_factory):
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
    reg = Registry(server.data_dir / "servers.json", server.data_dir / "user_servers.json")
    reg.load()
    assert reg.get(ServerKey(None, "tool")).source == raw
    # The server row on the dashboard shows the command with the source
    # redacted, never the token.
    row = client.get("/tools/tree").text
    assert "uvx --from git+https://***@host/o/r my-tool" in row
    assert "SEKRETTOKEN" not in row
    # The window's form input holds the redacted form too; a save echoes it and
    # `Registry.update` keeps the stored credential.
    window = client.get("/servers/tool").text
    client.close()
    assert "SEKRETTOKEN" not in window
    assert 'name="source" value="git+https://***@host/o/r"' in window


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
    reg = Registry(server.data_dir / "servers.json", server.data_dir / "user_servers.json")
    reg.load()
    assert reg.get(ServerKey(None, "off")).enabled is False
    assert reg.get(ServerKey(None, "on")).enabled is True


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
    store = TokenStore(server.data_dir / "tokens.json", server.data_dir / "user_tokens.json")
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
    store = TokenStore(server.data_dir / "tokens.json", server.data_dir / "user_tokens.json")
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


# --- Cache TTL form field (child-catalog-freshness) --------------------------


def test_add_form_cache_ttl_blank_and_zero(server_factory):
    server = server_factory(CHILD_START_TIMEOUT="2")
    client = server.login()
    # `enabled` omitted -> disabled, so no child starts.
    blank = client.post(
        "/servers",
        data={"kind": "python", "namespace": "time", "package": "p", "cache_ttl": ""},
    )
    zero = client.post(
        "/servers",
        data={"kind": "python", "namespace": "skills", "package": "p", "cache_ttl": "0"},
    )
    client.close()
    assert blank.status_code == 303
    assert zero.status_code == 303 and zero.headers["location"] == "/"
    reg = Registry(server.data_dir / "servers.json", server.data_dir / "user_servers.json")
    reg.load()
    assert reg.get(ServerKey(None, "time")).cache_ttl is None
    assert reg.get(ServerKey(None, "skills")).cache_ttl == 0.0


def test_edit_form_keeps_cache_ttl(server_factory):
    server = server_factory(
        seed_registry(fake_child_spec("skills", "good", enabled=False, cache_ttl=0))
    )
    client = server.login()
    window = client.get("/servers/skills").text
    field = re.search(r'<input name="cache_ttl"[^>]*>', window).group(0)
    assert 'value="0"' in field
    # Save the form as the browser would: every field as shown, one changed.
    form = dict(re.findall(r'<input name="(\w+)"[^>]*value="([^"]*)"', window))
    form.update(kind="custom", description="changed")
    resp = client.post("/servers/skills", data=form)
    assert resp.status_code == 303, resp.text
    bad = client.post("/servers/skills", data={**form, "cache_ttl": "abc"})
    client.close()
    assert bad.status_code == 400
    assert "cache_ttl" in bad.text
    reg = Registry(server.data_dir / "servers.json", server.data_dir / "user_servers.json")
    reg.load()
    assert reg.get(ServerKey(None, "skills")).description == "changed"
    assert reg.get(ServerKey(None, "skills")).cache_ttl == 0.0


# --- 10.16 The dashboard tool list follows the policy (multi-user-access) -----
#
# Fixture `router_live.py`: admin-owned `time` (`get_current_time`,
# `convert_time`) and `github`; user-owned `github@alice` (`x`, `alice_only`)
# and `github@bob`. Each docstring names the TLA+ invariant of
# `specs/tla/multi_user_access.tla` that the test guards.

from router_live import start_live


@pytest.fixture(scope="module")
def live(tmp_path_factory):
    lv, stop = start_live(tmp_path_factory.mktemp("web"))
    yield lv
    stop()


@pytest.fixture
def env(live):
    live.reset()
    yield live
    live.reset()


def _signed_in(env, user: str, password: str) -> httpx.Client:
    client = httpx.Client(base_url=env.base_url, follow_redirects=False)
    resp = client.post("/login", data={"user": user, "password": password, "next": "/"})
    assert resp.status_code == 303, resp.text
    return client


def _deny_convert_time(env) -> None:
    env.grant("user", "alice", "server", "allow", "time")
    env.grant("user", "alice", "tool", "deny", "time", "convert_time")


def test_the_dashboard_hides_a_denied_tool_rows_ac8(env):
    """The dashboard hides a denied tool (AC-8), the row source:
    `Supervisor.tools` of the `dashboard` Reach of `alice` (section 4).
    Invariant: NoDashLeak."""
    _deny_convert_time(env)
    reach = env.policy.keys_for(env.user("alice"), "dashboard")
    rows = env.run(env.supervisor.tools(reach))
    time_rows = [r for r in rows if r.namespace == "time"]
    assert [r.name for r in time_rows] == ["time_get_current_time"]
    assert not [r for r in rows if "convert_time" in f"{r.name} {r.tool} {r.description}"]
    assert not [r for r in rows if r.owner == "bob"]


def test_the_dashboard_hides_a_denied_tool_page_ac8(env):
    """The dashboard hides a denied tool (AC-8), the page `alice` opens.
    Invariant: NoDashLeak."""
    _deny_convert_time(env)
    client = _signed_in(env, "alice", "pw-alice-0123456789")
    page = client.get("/tools/tree")
    client.close()
    assert page.status_code == 200
    assert "time_get_current_time" in page.text
    assert "convert_time" not in page.text


def test_the_admin_dashboard_lists_user_servers(env):
    """The admin dashboard lists user servers. Invariant: NoDashLeak (the
    admin `dashboard` surface holds every key; only the `mcp` surface
    excludes user servers)."""
    client = _signed_in(env, "", "secret")
    page = client.get("/tools/tree")
    client.close()
    assert page.status_code == 200
    assert "github@alice" in page.text
    assert "alice_only" in page.text
    group = page.text[page.text.index("github@alice"):]
    assert "alice" in group.replace("github@alice", "", 1)


# =============================================================================
# 10G (multi-user-access): the dashboard page scenarios, `specs/web-ui`.
# One seeded gateway per test (tests/dashboard_site.py): users alice and bob,
# admin-owned `time`, running `github@alice` and `github@bob`.
# =============================================================================

import html as _html
import json
import json as _json

from dashboard_site import (  # noqa: F401
    ALICE_PW,
    BOB_PW,
    admin_session,
    api_headers,
    assert_no_secrets,
    groups_on_page,
    make_mu_site,
    revisions_on_page,
)

_TOK = re.compile(r"mcpflow_[A-Za-z0-9_-]+")
_TOK_ID = re.compile(r"tok_[0-9a-f]+")


def _store(site) -> TokenStore:
    store = TokenStore(site.data / "tokens.json", site.data / "user_tokens.json")
    store.load()
    return store


def _row(body: str, token_id: str) -> str:
    return next(r for r in body.split("<tr>") if token_id in r)


def _create(site, uid: str, **form):
    before = {r.id for r in _store(site).list()}
    resp = site.request(uid, "POST", "/tokens", data=form)
    new = [r for r in _store(site).list() if r.id not in before]
    return resp, new


def _config_block(body: str) -> dict:
    text = _html.unescape(body)
    block = re.search(r'\{\s*"mcpServers".*?\n\}', text, re.DOTALL)
    return _json.loads(block.group(0))


def test_create_token_lists_the_new_token_with_scope_mcp(make_mu_site):
    """Scenario "Create token"."""
    site = make_mu_site()
    resp, new = _create(site, "admin", name="laptop")
    assert resp.status_code == 200
    assert _TOK.search(resp.text).group(0).startswith("mcpflow_")
    assert len(new) == 1 and new[0].name == "laptop" and new[0].scope == "mcp"
    listing = site.request("admin", "GET", "/tokens")
    row = _row(listing.text, new[0].id)
    assert "laptop" in row and "<td>mcp</td>" in row
    assert_no_secrets(resp.text, site.data)
    # The clear token appears in the create response only.
    assert _TOK.search(resp.text).group(0) not in listing.text


def test_a_user_mints_their_own_token_ac1(make_mu_site):
    """Scenario "A user mints their own token (AC-1)"."""
    site = make_mu_site()
    form = site.request("alice", "GET", "/tokens")
    assert 'name="scope"' not in form.text and 'name="user"' not in form.text
    resp, new = _create(site, "alice", name="laptop")
    assert resp.status_code == 200
    assert len(new) == 1
    assert (new[0].user_id, new[0].scope) == ("alice", "mcp")
    assert_no_secrets(resp.text, site.data)
    listing = site.request("alice", "GET", "/tokens")
    own = {r.id for r in _store(site).list() if r.user_id == "alice"}
    assert set(_TOK_ID.findall(listing.text)) == own
    assert "ops" not in listing.text  # the admin token of another user


def test_a_user_cannot_post_an_admin_scope_or_another_user(make_mu_site):
    """The form shows no selector, so a posted value must change nothing
    (`AccessPolicy.mint_token` refuses it)."""
    site = make_mu_site()
    before = {r.id for r in _store(site).list()}
    site.request("alice", "POST", "/tokens",
                 data={"name": "sneaky", "scope": "admin", "user": "admin"})
    grown = [r for r in _store(site).list() if r.id not in before]
    assert all(r.user_id == "alice" and r.scope == "mcp" for r in grown), grown


def test_the_token_page_answers_400_for_an_unknown_user(make_mu_site):  # noqa: F811
    """Scenario "The web route answers 400 for an unknown user"."""
    site = make_mu_site()
    before = {n: (site.data / n).read_bytes() for n in ("tokens.json", "user_tokens.json")
              if (site.data / n).exists()}
    resp = site.request("admin", "POST", "/tokens", data={"name": "x", "user": "ghost"})
    assert resp.status_code == 400
    assert resp.text == "user_id: unknown user ghost"
    assert resp.headers["content-type"].startswith("text/plain")
    after = {n: (site.data / n).read_bytes() for n in ("tokens.json", "user_tokens.json")
             if (site.data / n).exists()}
    assert after == before


def test_create_token_shows_the_mcp_config_and_no_curl_pane(make_mu_site):
    """Scenario "Create token shows MCP config"."""
    site = make_mu_site()
    resp, new = _create(site, "alice", name="cfg")
    token = _TOK.search(resp.text).group(0)
    entry = _config_block(resp.text)["mcpServers"]["mcpflow"]
    assert entry["type"] == "http" and entry["url"].endswith("/mcp")
    assert entry["headers"]["Authorization"] == f"Bearer {token}"
    text = _html.unescape(resp.text)
    assert "claude mcp add --transport http" in text
    cli = next(line for line in text.splitlines() if "claude mcp add" in line)
    assert entry["url"] in cli and token in cli
    assert 'id="tab-curl"' not in resp.text


def test_mcp_token_opens_on_the_json_tab(make_mu_site):
    """Scenario "Mcp token opens on the JSON tab"."""
    site = make_mu_site()
    resp, _ = _create(site, "alice", name="x")
    assert re.search(r'data-tab="json"[^>]*class="active"', resp.text)
    assert not re.search(r'id="tab-json"[^>]*\shidden>', resp.text)
    assert re.search(r'id="tab-cli"[^>]*\shidden>', resp.text)


def test_create_admin_token_shows_curl_and_mcp_config(make_mu_site):
    """Scenario "Create admin token shows curl and MCP config"."""
    site = make_mu_site()
    resp, new = _create(site, "admin", name="ci", scope="admin")
    assert resp.status_code == 200 and new[0].scope == "admin"
    body = resp.text
    token = _TOK.search(body).group(0)
    text = _html.unescape(body)
    assert re.search(
        r"curl -H \S*Authorization: Bearer " + token + r"\S*\s+\S*/api/servers", text)
    cfg = _config_block(body)
    assert cfg["mcpServers"]["mcpflow"]["headers"]["Authorization"] == f"Bearer {token}"
    assert_no_secrets(body, site.data)


def test_admin_token_opens_on_the_rest_tab(make_mu_site):
    """Scenario "Admin token opens on the REST tab"."""
    site = make_mu_site()
    body = _create(site, "admin", name="ci", scope="admin")[0].text
    assert re.search(r'data-tab="curl"[^>]*class="active"', body)
    assert re.search(r'data-tab="curl"[^>]*aria-selected="true"', body)
    assert not re.search(r'id="tab-curl"[^>]*\shidden>', body)
    assert re.search(r'id="tab-json"[^>]*\shidden>', body)
    assert re.search(r'id="tab-cli"[^>]*\shidden>', body)


def test_admin_token_warns_about_admin_tools(make_mu_site):
    """Scenario "Admin token warns about admin tools"."""
    site = make_mu_site()
    body = _create(site, "admin", name="ci", scope="admin")[0].text
    assert "built-in admin tools" in body


def test_the_admin_creates_a_token_for_a_user_ac7(make_mu_site):
    """Scenario "The admin creates a token for a user (AC-7)"."""
    site = make_mu_site()
    resp, new = _create(site, "admin", name="alice-laptop", user="alice")
    assert resp.status_code == 200
    assert (new[0].user_id, new[0].scope) == ("alice", "mcp")
    row = _row(site.request("admin", "GET", "/tokens").text, new[0].id)
    assert "alice-laptop" in row and "<td>alice</td>" in row


def test_hand_typed_bad_scope_answers_400_and_creates_nothing(make_mu_site):
    """Scenario "Hand-typed bad scope"."""
    site = make_mu_site()
    resp, new = _create(site, "admin", name="x", scope="root")
    assert resp.status_code == 400
    assert new == []
    assert _TOK.search(resp.text) is None


def test_public_url_override_wins_over_the_host_header(make_mu_site):
    """Scenario "Public URL override"."""
    site = make_mu_site(PUBLIC_URL="https://mcp.example.com")
    resp = site.client.post(
        "/tokens", data={"name": "ci", "scope": "admin"},
        headers={"Host": "evil.example", "Cookie": f"mcpflow_session={site.login('admin')}"})
    site.client.cookies.clear()
    text = _html.unescape(resp.text)
    assert _config_block(resp.text)["mcpServers"]["mcpflow"]["url"] == \
        "https://mcp.example.com/mcp"
    assert re.search(r"curl[^\n<]*https://mcp\.example\.com/api/servers", text)
    assert "evil.example" not in resp.text


@pytest.mark.parametrize("scope", ["mcp", "admin"])
def test_every_tab_has_a_pane_for_every_scope(make_mu_site, scope):
    """Scenario "Every tab has a pane"."""
    site = make_mu_site()
    body = _create(site, "admin", name="t", scope=scope)[0].text
    tabs = re.findall(r'data-tab="(\w+)"', body)
    assert tabs
    for tab in tabs:
        assert f'id="tab-{tab}"' in body, tab


def test_revoke_token_removes_the_row_and_the_digest(make_mu_site):
    """Scenario "Revoke token"."""
    site = make_mu_site()
    resp, new = _create(site, "alice", name="gone")
    digest = next(iter(_digests(site, new[0].id)))
    out = site.request("alice", "POST", f"/tokens/{new[0].id}/delete")
    assert out.status_code == 303
    assert new[0].id not in site.request("alice", "GET", "/tokens").text
    for name in ("tokens.json", "user_tokens.json"):
        path = site.data / name
        assert not path.exists() or digest not in path.read_text()


def _digests(site, token_id):
    return {r.sha256 for r in _store(site).list() if r.id == token_id}

GH_ALICE_KEY = ServerKey("alice", "github")


# --- 10.32: role-scoped dashboard -------------------------------------------


def _grant_time(site, uid: str = "alice") -> None:
    resp = site.client.post("/api/rules", headers=api_headers(site), json={
        "subject_kind": "user", "subject": uid, "level": "server",
        "server": "time", "effect": "allow"})
    assert resp.status_code == 201, resp.text


def _group_block(body: str, ref: str) -> str:
    start = body.index(f'data-ns="{ref}"')
    return body[start:body.index("</details>", start)]


def _propose(site, uid: str, namespace: str, package: str, **extra):
    return site.request(uid, "POST", "/servers", data={
        "kind": "npm", "namespace": namespace, "package": package,
        "enabled": "on",  # the checkbox of the form is checked by default
        **extra})


def test_the_form_asks_for_a_user(make_mu_site):
    """Scenario "The form asks for a user"."""
    site = make_mu_site()
    page = site.client.get("/login")
    assert page.status_code == 200
    assert re.search(r'<input[^>]*name="user"', page.text)
    assert re.search(r'<input[^>]*name="password"', page.text)


def test_the_header_names_the_user(make_mu_site):
    """Scenario "The header names the user"."""
    site = make_mu_site()
    page = site.request("alice", "GET", "/")
    assert page.status_code == 200
    header = page.text[page.text.index("<header>"):page.text.index("</header>")]
    assert re.search(r'class="user">\s*alice\b', header)
    assert 'action="/logout"' in header and "Sign out" in header


def test_a_user_sees_their_own_and_granted_servers(make_mu_site):
    """Scenario "A user sees their own and granted servers"."""
    site = make_mu_site()
    _grant_time(site)
    page = site.request("alice", "GET", "/tools/tree")
    assert page.status_code == 200
    assert sorted(groups_on_page(page.text)) == ["github@alice", "time"]
    assert "/visibility" not in page.text  # no mute control
    assert "github@bob" not in page.text
    assert_no_secrets(page.text, site.data)


def test_a_pending_server_shows_its_state(make_mu_site):
    """Scenario "A pending server shows its state"."""
    site = make_mu_site()
    assert _propose(site, "alice", "linear", "x@1.0.0").status_code == 303
    page = site.request("alice", "GET", "/tools/tree")
    block = _group_block(page.text, "linear@alice")
    assert "awaiting approval" in block
    assert "No tools yet." in block


def test_a_user_cannot_open_a_foreign_server_ac6(make_mu_site):
    """Scenario "A user cannot open a foreign server (AC-6)"."""
    site = make_mu_site()
    resp = site.request("bob", "GET", "/servers/github@alice")
    assert resp.status_code == 404
    assert "@acme/mcp" not in resp.text


def test_a_granted_shared_server_has_no_window_for_a_user(make_mu_site):
    """Scenario "A granted shared server has no window for a user"."""
    site = make_mu_site()
    _grant_time(site)
    assert site.request("alice", "GET", "/").status_code == 200
    assert site.request("alice", "GET", "/servers/time").status_code == 404


# --- 10.33: the user server form --------------------------------------------


def _reject(site, ref: str) -> None:
    resp = site.client.delete(f"/api/servers/{ref}", headers=api_headers(site))
    assert resp.status_code in (200, 204), resp.text


def test_the_user_form_offers_no_custom_kind(make_mu_site):
    """Requirement "User server form": python, npm, remote; never custom."""
    site = make_mu_site()
    page = site.request("alice", "GET", "/add-server")
    assert page.status_code == 200
    tabs = set(re.findall(r'href="/add-server\?tab=(\w+)"', page.text))
    assert {"python", "npm", "remote"} <= tabs and "custom" not in tabs
    refused = _propose(site, "alice", "mine", "x@1.0.0", kind="custom", command="/bin/sh")
    assert refused.status_code in (400, 403), refused.status_code
    assert not (site.data / "user_servers.json").exists() or \
        "mine" not in (site.data / "user_servers.json").read_text()
    assert "approves" in page.text or "approval" in page.text


def test_an_unpinned_package_is_refused_on_the_form_c4(make_mu_site):
    """Scenario "An unpinned package is refused on the form (C4)"."""
    site = make_mu_site()
    before = site.launches()
    resp = _propose(site, "alice", "x", "x@latest")
    assert resp.status_code == 400
    assert 'name="package"' in resp.text  # the form is re-rendered
    error = re.search(r'class="error"[^>]*>(.*?)</', resp.text, re.DOTALL).group(1)
    assert "package" in error and "exact version" in error
    assert not (site.data / "user_servers.json").exists() or \
        "x@latest" not in (site.data / "user_servers.json").read_text()
    assert site.launches() == before


def test_a_user_proposes_a_server_ac5(make_mu_site):
    """Scenario "A user proposes a server (AC-5)"."""
    site = make_mu_site()
    _reject(site, "github@alice")
    before = site.launches()
    resp = _propose(site, "alice", "github", "x@1.0.0")
    assert resp.status_code == 303 and resp.headers["location"] == "/"
    page = site.request("alice", "GET", "/tools/tree")
    assert "awaiting approval" in _group_block(page.text, "github@alice")
    assert site.status(GH_ALICE_KEY) == "stopped"
    assert site.launches() == before, "a pending server ran a process"


def test_a_user_edit_goes_back_to_pending(make_mu_site):
    """Scenario "A user edit goes back to pending"."""
    site = make_mu_site()
    assert site.status(GH_ALICE_KEY) == "running"
    resp = site.request("alice", "POST", "/servers/github@alice", data={
        "kind": "npm", "namespace": "github", "package": "@acme/mcp@2.0.0",
        "enabled": "on"})
    assert resp.status_code == 303, resp.text
    page = site.request("alice", "GET", "/tools/tree")
    block = _group_block(page.text, "github@alice")
    assert "awaiting approval" in block
    assert site.status(GH_ALICE_KEY) == "stopped"


# --- 10.34: users, groups, and rules pages ----------------------------------


def _section(body: str, name: str) -> str:
    """The HTML of one section of `/security` (`users`, `groups`, or `rules`)."""
    return body.split(f'<section id="{name}">')[1].split("</section>")[0]


def _user_row(body: str, uid: str) -> str:
    return next(r for r in body.split("<tr>") if f"<code>{uid}</code>" in r)


def _make_member(site, uid: str = "dave", group: str = "eng", password: str = "pw-dave-0123456789"):
    assert site.request("admin", "POST", "/groups", data={"name": group}).status_code == 303
    resp = site.request("admin", "POST", "/users", data={"id": uid, "groups": group})
    assert resp.status_code == 200, resp.text
    code = re.search(r'id="setup-code">([^<]+)<', resp.text).group(1)
    # The user redeems the one-time code and chooses the password (first sign-in).
    done = site.client.post("/login/setup", data={
        "user": uid, "code": code, "password": password, "confirm": password})
    assert done.status_code == 303, done.text
    site.cookies[uid] = done.cookies["mcpflow_session"]
    site.client.cookies.clear()


def _rule_ids(body: str) -> list[str]:
    return re.findall(r"<td><code>([^<]+)</code></td>\s*<td>(?:user|group) <code>", body)


def test_create_a_user_from_the_dashboard_ac7(make_mu_site):
    """Scenario "Create a user from the dashboard (AC-7)" (id `dave`: `alice`
    is already a seeded user in this fixture)."""
    site = make_mu_site()
    site.request("admin", "POST", "/groups", data={"name": "eng"})
    resp = site.request("admin", "POST", "/users", data={"id": "dave", "groups": "eng"})
    # The admin sets no password: the page shows a one-time code once (no redirect).
    assert resp.status_code == 200 and resp.headers["cache-control"] == "no-store"
    code = re.search(r'id="setup-code">([^<]+)<', resp.text).group(1)
    # The code shows in the Users section of the 200 response only.
    assert code in _section(resp.text, "users")
    assert code not in _section(resp.text, "groups") + _section(resp.text, "rules")
    page = site.request("admin", "GET", "/security")
    assert page.status_code == 200
    row = _user_row(_section(page.text, "users"), "dave")
    assert "<code>eng</code>" in row and "pending" in row
    assert code not in page.text
    assert_no_secrets(page.text, site.data)
    assert_no_secrets(resp.text, site.data)


def test_create_a_group_from_the_dashboard_ac7(make_mu_site):
    """Scenario "Create a group from the dashboard (AC-7)"."""
    site = make_mu_site()
    resp = site.request("admin", "POST", "/groups", data={"name": "eng"})
    assert resp.status_code == 303 and resp.headers["location"] == "/security#groups"
    page = site.request("admin", "GET", "/security")
    row = _user_row(_section(page.text, "groups"), "eng")
    assert "none" in row and "tag-x" not in row  # shown with no member


def test_the_bootstrap_admin_cannot_be_deleted(make_mu_site):
    """Scenario "The bootstrap admin cannot be deleted"."""
    site = make_mu_site()
    resp = site.request("admin", "POST", "/users/admin/delete")
    assert resp.status_code == 400
    # The refusal shows in the Users section.
    assert re.search(r'class="error"[^>]*>\s*\S', _section(resp.text, "users")), "no refusal text"
    page = site.request("admin", "GET", "/security")
    assert "<code>admin</code>" in _section(page.text, "users")
    # The admin still signs in, with the empty user name.
    assert site.client.post("/login", data={"user": "", "password": "secret"}
                            ).status_code == 303
    assert_no_secrets(resp.text, site.data)


def test_the_bootstrap_admin_cannot_be_demoted_on_the_dashboard(make_mu_site):
    """Bootstrap rule on the page: the route `/users/<id>/admin` is gone (404),
    and a picker post that unticks `admins` for `admin` is refused (400)."""
    site = make_mu_site()
    resp = site.request("admin", "POST", "/users/admin/admin", data={})
    assert resp.status_code == 404
    resp = site.request("admin", "POST", "/users/admin/groups", data={"was": ["admins"]})
    assert resp.status_code == 400
    users = site.client.get("/api/users", headers=api_headers(site)).json()
    assert next(u for u in users if u["id"] == "admin")["admin"] is True


def _add_eng_rule(site):
    before = set(_rule_ids(site.request("admin", "GET", "/security").text))
    resp = site.request("admin", "POST", "/rules", data={
        "subject_kind": "group", "subject": "eng", "level": "server",
        "server": "time", "effect": "allow"})
    after = _rule_ids(site.request("admin", "GET", "/security").text)
    return resp, [r for r in after if r not in before]


def test_add_a_rule_from_the_dashboard_ac7(make_mu_site):
    """Scenario "Add a rule from the dashboard (AC-7)"."""
    site = make_mu_site()
    _make_member(site)
    assert "time" not in groups_on_page(site.request("dave", "GET", "/tools/tree").text)
    resp, new = _add_eng_rule(site)
    assert resp.status_code == 303 and resp.headers["location"] == "/security#rules"
    assert len(new) == 1
    page = site.request("admin", "GET", "/security")
    row = _user_row(_section(page.text, "rules"), new[0])
    assert "eng" in row and "server" in row and "time" in row and "allow" in row
    # The next request of a member of `eng` lists the tools of `time`.
    dash = site.request("dave", "GET", "/tools/tree")
    assert "time" in groups_on_page(dash.text)
    block = _group_block(dash.text, "time")
    assert "time_" in block and "No tools yet." not in block


def test_delete_a_rule_from_the_dashboard(make_mu_site):
    """Scenario "Delete a rule from the dashboard"."""
    site = make_mu_site()
    _make_member(site)
    _, new = _add_eng_rule(site)
    assert "time" in groups_on_page(site.request("dave", "GET", "/tools/tree").text)
    resp = site.request("admin", "POST", f"/rules/{new[0]}/delete")
    assert resp.status_code == 303 and resp.headers["location"] == "/security#rules"
    assert new[0] not in _section(site.request("admin", "GET", "/security").text, "rules")
    assert "time" not in groups_on_page(site.request("dave", "GET", "/tools/tree").text)


# --- 10.35: the approvals page ----------------------------------------------

ENV_VALUE = "S3CR3T-VALUE-ZZ9"


def _pending(site, package: str = "x@1.0.0", env: str | None = f"TOKEN={ENV_VALUE}"):
    """Alice's `github` server goes pending as `x@1.0.0` with one env secret."""
    _reject(site, "github@alice")
    extra = {"env": env} if env else {}
    assert _propose(site, "alice", "github", package, **extra).status_code == 303


def _approvals(site):
    return site.request("admin", "GET", "/approvals")


def test_a_stale_approve_re_renders_with_409_f1(make_mu_site):
    """Scenario "A stale approve re-renders with 409 (F1)"."""
    site = make_mu_site()
    _pending(site)
    seen = revisions_on_page(_approvals(site).text)
    r1 = seen["github@alice"]
    before = site.launches()
    # alice changes the server after the admin opened the page.
    changed = site.request("alice", "POST", "/servers/github@alice", data={
        "kind": "npm", "namespace": "github", "package": "x@1.0.1", "enabled": "on"})
    assert changed.status_code == 303, changed.text
    resp = site.request("admin", "POST", "/approvals/github@alice/approve",
                        data={"revision": r1})
    assert resp.status_code == 409
    assert "the server changed since you opened this page" in resp.text
    r2 = revisions_on_page(resp.text)["github@alice"]
    assert r2 != r1
    assert site.status(GH_ALICE_KEY) == "stopped"
    assert "github@alice" in revisions_on_page(_approvals(site).text)
    assert site.launches() == before
    assert_no_secrets(resp.text, site.data)


def test_the_page_states_the_residual_risk_c4(make_mu_site):
    """Scenario "The page states the residual risk (C4)"."""
    site = make_mu_site()
    page = _approvals(site)
    assert page.status_code == 200
    assert "DATA_DIR" in page.text
    assert re.search(r"transitive dependencies\s+are not pinned", page.text)


def test_approve_from_the_dashboard_ac5_ac7(make_mu_site):
    """Scenario "Approve from the dashboard (AC-5, AC-7)"."""
    site = make_mu_site()
    _pending(site)
    assert site.status(GH_ALICE_KEY) == "stopped"
    r1 = revisions_on_page(_approvals(site).text)["github@alice"]
    before = site.launches()
    resp = site.request("admin", "POST", "/approvals/github@alice/approve",
                        data={"revision": r1})
    assert resp.status_code == 303 and resp.headers["location"] == "/approvals"
    assert "github@alice" not in revisions_on_page(_approvals(site).text)
    site.wait_running(GH_ALICE_KEY)
    assert site.launches() == before + 1


def test_the_row_shows_what_will_run_and_no_env_value(make_mu_site):
    """Scenario "The row shows what will run" (a distinct env value stands in
    for `abc`, which can occur inside a hex revision by chance)."""
    site = make_mu_site()
    _pending(site)
    page = _approvals(site)
    row = _user_row(page.text, "github@alice")
    assert "npx -y x@1.0.0" in row
    assert "TOKEN" in row
    assert ENV_VALUE not in page.text
    assert_no_secrets(page.text, site.data)
    assert ENV_VALUE in (site.data / "user_servers.json").read_text()  # real secret on disk


def test_reject_from_the_dashboard(make_mu_site):
    """Scenario "Reject from the dashboard"."""
    site = make_mu_site()
    _pending(site)
    resp = site.request("admin", "POST", "/approvals/github@alice/reject")
    assert resp.status_code == 303
    refs = {s["ref"] for s in site.client.get("/api/servers", headers=api_headers(site)).json()}
    assert "github@alice" not in refs
    stored = json.loads((site.data / "user_servers.json").read_text())["servers"]
    assert [s for s in stored if (s["owner"], s["namespace"]) == ("alice", "github")] == []


def test_a_non_admin_cannot_approve_on_the_dashboard(make_mu_site):
    """Approvals are admin-only (web-ui "Role-scoped dashboard")."""
    site = make_mu_site()
    _pending(site)
    r1 = revisions_on_page(_approvals(site).text)["github@alice"]
    resp = site.request("alice", "POST", "/approvals/github@alice/approve",
                        data={"revision": r1})
    assert resp.status_code == 403
    assert site.status(GH_ALICE_KEY) == "stopped"


def test_no_page_shows_a_source_credential_or_an_env_value(make_mu_site):
    """Secret check across the pages of 10.32 and 10.35: a pending python
    server with a credential in its git `source` and an `env` secret."""
    site = make_mu_site()
    sha = "0123456789abcdef0123456789abcdef01234567"
    secret = "oauth2:SEKRETTOKEN"
    resp = site.request("alice", "POST", "/servers", data={
        "kind": "python", "namespace": "tool", "package": "my-tool", "enabled": "on",
        "source": f"git+https://{secret}@host/o/r@{sha}", "env": f"TOKEN={ENV_VALUE}"})
    assert resp.status_code == 303, resp.text
    stored = (site.data / "user_servers.json").read_text()
    assert "SEKRETTOKEN" in stored and ENV_VALUE in stored
    bodies = [site.request("alice", "GET", "/").text,
              site.request("admin", "GET", "/").text,
              site.request("alice", "GET", "/tools/tree").text,
              site.request("admin", "GET", "/tools/tree").text,
              site.request("admin", "GET", "/approvals").text,
              site.request("alice", "GET", "/servers/tool@alice").text,
              site.client.get("/api/servers", headers=api_headers(site)).text,
              site.client.get("/api/approvals", headers=api_headers(site)).text]
    for body in bodies:
        assert "SEKRETTOKEN" not in body and ENV_VALUE not in body
        assert_no_secrets(body, site.data)
