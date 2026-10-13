"""Shared fixture for the 10G dashboard and `/api` scenario tests.

One real `build_app` over a seeded data dir (users `alice` and `bob`; admin-owned
`time`; approved, running `github@alice` and `github@bob`; a fake `npx` on `PATH`).
Requests go through Starlette's `TestClient` without redirects. The admin acts by
the empty user name (a session) or by the admin bearer token (`/api`).

`on_disk_secrets` reads the stored secrets from the data dir, so a test can assert
that no response body holds one. It derives the values from the files, not from
the code that renders a page.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import make_settings
from starlette.testclient import TestClient
from test_user_routes import Site, seed
from user_servers import fake_npx, path_with

from mcpflow.gateway import build_app

ALICE_PW = "pw-alice-0123456789"
BOB_PW = "pw-bob-0123456789"


def admin_session(site: Site) -> None:
    """Sign the bootstrap admin in (empty user name) and store the cookie."""
    resp = site.client.post("/login", data={"user": "", "password": "secret", "next": "/"})
    assert resp.status_code == 303, resp.text
    site.cookies["admin"] = resp.cookies["mcpflow_session"]
    site.client.cookies.clear()


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def api_headers(site: Site) -> dict[str, str]:
    return bearer(site.admin_token)


def groups_on_page(body: str) -> list[str]:
    """The server groups the dashboard renders, from their `data-ns` mark."""
    return re.findall(r'<details class="ns-group" data-ns="([^"]+)"', body)


def revisions_on_page(body: str) -> dict[str, str]:
    """`{ref: revision}` for every row of the approvals page."""
    rows = re.findall(
        r'<td><code>([^<]+)</code></td>.*?<code class="revision">([0-9a-f]+)</code>',
        body, re.DOTALL)
    return dict(rows)


def _strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _strings(v)


def on_disk_secrets(data: Path) -> dict[str, set[str]]:
    """Every stored secret, by kind: password hashes, token digests, and the
    `env` and `headers` values of every server record."""
    out: dict[str, set[str]] = {"password hash": set(), "token digest": set(),
                                "env/header value": set(),
                                "source credential": set()}
    users = json.loads((data / "users.json").read_text())
    for rec in users.get("users", []):
        for key, val in rec.items():
            if "hash" in key or "password" in key:
                # A pending user stores an empty hash; "" is in every body.
                out["password hash"].update(s for s in _strings(val) if s)
        # The digest of a pending user's setup code is a stored secret too.
        if isinstance(rec.get("setup"), dict):
            out["token digest"].add(rec["setup"]["sha256"])
    for name in ("tokens.json", "user_tokens.json"):
        path = data / name
        if path.exists():
            for rec in json.loads(path.read_text()).get("tokens", []):
                out["token digest"].add(rec["sha256"])
    for name in ("servers.json", "user_servers.json"):
        path = data / name
        if path.exists():
            for rec in json.loads(path.read_text()).get("servers", []):
                userinfo = re.search(r"://([^@/]+)@", rec.get("source") or "")
                if userinfo:
                    out["source credential"].add(userinfo.group(1))
                for field in ("env", "headers"):
                    out["env/header value"].update(_strings(list((rec.get(field) or {}).values())))
    return out


def assert_no_secrets(body: str, data: Path, *, kinds=("password hash", "token digest",
                                                       "env/header value",
                                                       "source credential")) -> None:
    secrets = on_disk_secrets(data)
    for kind in kinds:
        for value in secrets[kind]:
            assert value not in body, f"a {kind} leaked into the body"


@pytest.fixture
def make_mu_site(tmp_path, monkeypatch):
    """`make(**settings_override) -> Site` with `.data` (the data dir)."""
    clients: list[TestClient] = []
    log = fake_npx(tmp_path / "bin")
    monkeypatch.setenv("PATH", path_with(tmp_path / "bin"))

    def make(prepare: Callable[[Path], None] | None = None, **override) -> Site:
        data = tmp_path / f"d{len(clients)}"
        alice_tid, admin_token = seed(data)
        if prepare is not None:
            prepare(data)
        app = build_app(make_settings(data, **override))
        client = TestClient(app, raise_server_exceptions=False, follow_redirects=False)
        client.__enter__()
        clients.append(client)
        site = Site(app, client, alice_tid, admin_token, log)
        site.data = data
        site.wait_running(*[k for k in _seeded_keys()])
        admin_session(site)
        return site

    yield make
    for client in clients:
        client.__exit__(None, None, None)


def _seeded_keys():
    from mcpflow.registry import ServerKey
    return (ServerKey("alice", "github"), ServerKey("bob", "github"),
            ServerKey(None, "time"))


def mcp_tools(site: Site, token: str) -> set[str]:
    """The tool names `tools/list` of `/mcp` returns for one bearer token.

    A raw Streamable HTTP exchange: initialize, initialized, tools/list. The
    answer is JSON or one SSE `data:` line, so both are read.
    """
    base = {**bearer(token), "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json"}

    def rpc(payload: dict, headers: dict) -> object:
        resp = site.client.post("/mcp", headers=headers, json=payload)
        assert resp.status_code in (200, 202), (resp.status_code, resp.text)
        if not resp.text:
            return resp, None
        text = resp.text
        if text.lstrip().startswith("event:") or "data:" in text:
            text = next(line[5:] for line in text.splitlines() if line.startswith("data:"))
        return resp, json.loads(text)

    resp, _ = rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-03-26", "capabilities": {},
        "clientInfo": {"name": "t", "version": "1"}}}, base)
    headers = dict(base)
    if resp.headers.get("mcp-session-id"):
        headers["mcp-session-id"] = resp.headers["mcp-session-id"]
    rpc({"jsonrpc": "2.0", "method": "notifications/initialized"}, headers)
    _, out = rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, headers)
    return {t["name"] for t in out["result"]["tools"]}
