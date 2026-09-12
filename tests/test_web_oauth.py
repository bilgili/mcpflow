"""The OAuth connect and callback routes, end to end on a live gateway.

Scenarios from `specs/marketplace/spec.md` (Connect an OAuth entry),
`specs/oauth-client/spec.md` (Authorization request, Callback and token
exchange, Pending flows, Enable needs a token) and `specs/web-ui/spec.md`
(OAuth callback route, Awaiting authorization mark).

The token endpoint is replaced by an `httpx.MockTransport` through
`mcpflow.oauth.http_client`, so no test reaches the network. A `custom` fake
stdio child stands in for the `gmail` npm child wherever a running child is
needed; its catalog tag is `gmail`, so the callback enables it as the entry
asks.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from urllib.parse import parse_qs, parse_qsl, urlsplit

import httpx
import pytest
from conftest import fake_child_spec, seed_registry

from mcpflow.auth import TokenStore
from mcpflow.oauth import ClientCreds
from mcpflow.registry import Registry, ServerSpec

PUBLIC = "https://mcp.example"


def seed_with_admin(*specs: ServerSpec, holder: dict):
    def seed(data_dir: Path) -> None:
        reg = Registry(data_dir / "servers.json")
        reg.load()
        for spec in specs:
            reg.add(spec)
        store = TokenStore(data_dir / "tokens.json")
        store.load()
        _record, token = store.create("admin", "admin")
        holder["admin"] = token

    return seed


@pytest.fixture
def mock_token_endpoint(monkeypatch):
    """Replace the token endpoint. `state["body"]` records the POST form;
    `state["status"]`/`state["json"]` set the answer."""
    state: dict = {
        "status": 200,
        "json": {
            "access_token": "ACCESStoken123",
            "refresh_token": "REFRESHtoken456",
            "scope": "s",
            "token_type": "Bearer",
            "expires_in": 3600,
        },
        "body": None,
        "calls": 0,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        state["calls"] += 1
        state["body"] = dict(parse_qsl(request.content.decode()))
        if state.get("raise"):
            raise httpx.ConnectError("boom", request=request)
        return httpx.Response(state["status"], json=state["json"])

    def factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=15.0)

    monkeypatch.setattr("mcpflow.oauth.http_client", factory)
    return state


def _state_from_location(location: str) -> str:
    return parse_qs(urlsplit(location).query)["state"][0]


def _gmail_child() -> ServerSpec:
    return fake_child_spec("gmail", "good", enabled=False, catalog="gmail")


# --- 7.1 provider wiring -----------------------------------------------------


def test_local_provider_help_shows(server_factory):
    server = server_factory(PUBLIC_URL=PUBLIC)
    pdir = server.data_dir / "catalog" / "providers"
    pdir.mkdir(parents=True)
    (pdir / "google.json").write_text(json.dumps({
        "id": "google",
        "name": "Google",
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "help": "LOCAL-HELP-MARKER",
    }))
    client = server.login()
    html = client.get("/marketplace/gmail").text
    client.close()
    assert "LOCAL-HELP-MARKER" in html


def test_unknown_provider_entry_absent(server_factory):
    server = server_factory(PUBLIC_URL=PUBLIC)
    cdir = server.data_dir / "catalog"
    cdir.mkdir(parents=True)
    (cdir / "acme.json").write_text(json.dumps({
        "id": "acme",
        "name": "Acme",
        "vendor": "Acme",
        "category": "util",
        "description": "x",
        "auth": "oauth",
        "tools": ["t"],
        "spec": {"kind": "npm", "package": "p"},
        "oauth": {
            "provider": "acme",
            "scopes": ["s"],
            "client_file": {"env": "E1", "format": "google-client"},
            "token_file": {"env": "E2", "format": "google-auth-library"},
        },
    }))
    client = server.login()
    resp = client.get("/marketplace/acme")
    client.close()
    assert resp.status_code == 404


# --- 7.2 detail --------------------------------------------------------------


def test_detail_shows_redirect_uri_and_help(server_factory):
    server = server_factory(PUBLIC_URL=PUBLIC)
    client = server.login()
    html = client.get("/marketplace/gmail").text
    client.close()
    assert "https://mcp.example/oauth/callback" in html
    assert "developers.google.com/identity/protocols/oauth2" in html


# --- 7.3 connect -------------------------------------------------------------


def test_connect_registers_disabled_and_redirects(server_factory):
    server = server_factory(PUBLIC_URL=PUBLIC, CHILD_START_TIMEOUT="2")
    client = server.login()
    resp = client.post(
        "/marketplace/gmail/connect",
        data={"namespace": "gmail", "client_id": "abc", "client_secret": "shhh"},
    )
    client.close()
    assert resp.status_code == 303
    loc = resp.headers["location"]
    assert loc.startswith("https://accounts.google.com/o/oauth2/v2/auth")
    q = parse_qs(urlsplit(loc).query)
    assert q["client_id"] == ["abc"] and q["state"]
    assert q["redirect_uri"] == ["https://mcp.example/oauth/callback"]

    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    spec = reg.get("gmail")
    assert spec.enabled is False
    creds_dir = server.data_dir / "creds" / "gmail"
    assert spec.env["GMAIL_OAUTH_PATH"] == str(creds_dir / "client.json")
    assert spec.env["GMAIL_CREDENTIALS_PATH"] == str(creds_dir / "token.json")
    assert (creds_dir / "client.json").exists()
    assert server.health()["running"] == 0


def test_connect_missing_secret(server_factory):
    server = server_factory(PUBLIC_URL=PUBLIC)
    client = server.login()
    resp = client.post(
        "/marketplace/gmail/connect",
        data={"namespace": "gmail", "client_id": "abc", "client_secret": ""},
    )
    client.close()
    assert resp.status_code == 400
    assert "client_secret is required" in resp.text
    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    assert not any(s.namespace == "gmail" for s in reg.list())


def test_connect_second_on_pending(server_factory):
    server = server_factory(PUBLIC_URL=PUBLIC, CHILD_START_TIMEOUT="2")
    client = server.login()
    first = client.post(
        "/marketplace/gmail/connect",
        data={"namespace": "gmail", "client_id": "abc", "client_secret": "first-secret"},
    )
    assert first.status_code == 303
    second = client.post(
        "/marketplace/gmail/connect",
        data={"namespace": "gmail", "client_id": "abc", "client_secret": "second-secret"},
    )
    client.close()
    assert second.status_code == 400 and "already exists" in second.text
    client_file = server.data_dir / "creds" / "gmail" / "client.json"
    assert json.loads(client_file.read_text())["web"]["client_secret"] == "first-secret"


def test_secret_not_in_spec(server_factory):
    holder: dict = {}
    server = server_factory(seed_with_admin(holder=holder), PUBLIC_URL=PUBLIC, CHILD_START_TIMEOUT="2")
    client = server.login()
    client.post(
        "/marketplace/gmail/connect",
        data={"namespace": "gmail", "client_id": "abc", "client_secret": "topsecret"},
    )
    api = server.get(
        "/api/servers/gmail", headers={"Authorization": f"Bearer {holder['admin']}"}
    )
    edit = client.get("/servers/gmail/edit").text
    client.close()
    assert "topsecret" not in api.text
    assert "topsecret" not in edit
    env = api.json()["env"]
    assert set(env) == {"GMAIL_OAUTH_PATH", "GMAIL_CREDENTIALS_PATH"}


# --- 7.4 callback ------------------------------------------------------------


def test_callback_success(server_factory, mock_token_endpoint):
    server = server_factory(seed_registry(_gmail_child()), PUBLIC_URL=PUBLIC, CHILD_START_TIMEOUT="2")
    sup = server.supervisor
    sup.creds.write_client("gmail", "google-client", ClientCreds("abc", "shhh"))
    flow = sup.flows.create("gmail", "gmail", ClientCreds("abc", "shhh"))
    client = server.login()
    resp = client.get(f"/oauth/callback?state={flow.state}&code=the-code")
    client.close()
    assert resp.status_code == 303 and resp.headers["location"] == "/servers"
    assert mock_token_endpoint["body"]["code"] == "the-code"
    token_file = server.data_dir / "creds" / "gmail" / "token.json"
    assert token_file.exists()
    tok = json.loads(token_file.read_text())
    assert tok["access_token"] == "ACCESStoken123" and "expiry_date" in tok
    server.wait(running=1)
    assert server.health()["running"] == 1


def test_callback_provider_error(server_factory, mock_token_endpoint):
    server = server_factory(seed_registry(_gmail_child()), PUBLIC_URL=PUBLIC)
    sup = server.supervisor
    sup.creds.write_client("gmail", "google-client", ClientCreds("abc", "shhh"))
    flow = sup.flows.create("gmail", "gmail", ClientCreds("abc", "shhh"))
    client = server.login()
    resp = client.get(f"/oauth/callback?state={flow.state}&error=access_denied")
    client.close()
    assert resp.status_code == 400 and "access_denied" in resp.text
    assert not (server.data_dir / "creds" / "gmail" / "token.json").exists()
    assert mock_token_endpoint["calls"] == 0


def test_callback_token_rejected(server_factory, mock_token_endpoint):
    mock_token_endpoint["status"] = 400
    mock_token_endpoint["json"] = {"error": "invalid_grant"}
    server = server_factory(seed_registry(_gmail_child()), PUBLIC_URL=PUBLIC)
    sup = server.supervisor
    sup.creds.write_client("gmail", "google-client", ClientCreds("abc", "shhh"))
    flow = sup.flows.create("gmail", "gmail", ClientCreds("abc", "shhh"))
    client = server.login()
    resp = client.get(f"/oauth/callback?state={flow.state}&code=bad")
    client.close()
    assert resp.status_code == 400 and "invalid_grant" in resp.text
    assert not (server.data_dir / "creds" / "gmail" / "token.json").exists()
    assert server.health()["running"] == 0


def test_callback_transport_error(server_factory, mock_token_endpoint):
    mock_token_endpoint["raise"] = True
    server = server_factory(seed_registry(_gmail_child()), PUBLIC_URL=PUBLIC, CHILD_START_TIMEOUT="2")
    sup = server.supervisor
    sup.creds.write_client("gmail", "google-client", ClientCreds("abc", "shhh"))
    flow = sup.flows.create("gmail", "gmail", ClientCreds("abc", "shhh"))
    client = server.login()
    resp = client.get(f"/oauth/callback?state={flow.state}&code=c")
    client.close()
    assert resp.status_code == 400
    assert not (server.data_dir / "creds" / "gmail" / "token.json").exists()
    assert server.health()["running"] == 0
    # The flow is consumed, so a retry with the same state is expired.
    assert sup.flows.pop(flow.state) is None


def test_callback_duplicate_in_flight_400(server_factory, mock_token_endpoint):
    # A second callback for a state whose exchange is already in flight is
    # rejected before it POSTs the token endpoint again.
    server = server_factory(seed_registry(_gmail_child()), PUBLIC_URL=PUBLIC, CHILD_START_TIMEOUT="2")
    sup = server.supervisor
    sup.creds.write_client("gmail", "google-client", ClientCreds("abc", "shhh"))
    flow = sup.flows.create("gmail", "gmail", ClientCreds("abc", "shhh"))
    assert sup.flows.begin_exchange(flow.state) is True  # first exchange in flight
    client = server.login()
    resp = client.get(f"/oauth/callback?state={flow.state}&code=c")
    client.close()
    assert resp.status_code == 400 and "already in progress" in resp.text
    assert mock_token_endpoint["calls"] == 0
    assert not (server.data_dir / "creds" / "gmail" / "token.json").exists()


def test_callback_replay_400(server_factory, mock_token_endpoint):
    server = server_factory(seed_registry(_gmail_child()), PUBLIC_URL=PUBLIC, CHILD_START_TIMEOUT="2")
    sup = server.supervisor
    sup.creds.write_client("gmail", "google-client", ClientCreds("abc", "shhh"))
    flow = sup.flows.create("gmail", "gmail", ClientCreds("abc", "shhh"))
    client = server.login()
    first = client.get(f"/oauth/callback?state={flow.state}&code=c")
    second = client.get(f"/oauth/callback?state={flow.state}&code=c")
    client.close()
    assert first.status_code == 303
    assert second.status_code == 400 and "authorization expired" in second.text


def test_callback_expired_page(server_factory):
    server = server_factory(PUBLIC_URL=PUBLIC)
    client = server.login()
    resp = client.get("/oauth/callback?state=unknown&code=y")
    client.close()
    assert resp.status_code == 400
    assert "authorization expired" in resp.text
    assert "/marketplace" in resp.text


def test_callback_after_delete(server_factory, mock_token_endpoint):
    server = server_factory(seed_registry(_gmail_child()), PUBLIC_URL=PUBLIC, CHILD_START_TIMEOUT="2")
    sup = server.supervisor
    sup.creds.write_client("gmail", "google-client", ClientCreds("abc", "shhh"))
    flow = sup.flows.create("gmail", "gmail", ClientCreds("abc", "shhh"))
    client = server.login()
    assert client.post("/servers/gmail/delete").status_code in (200, 303)
    resp = client.get(f"/oauth/callback?state={flow.state}&code=c")
    client.close()
    assert resp.status_code == 400
    assert not (server.data_dir / "creds" / "gmail").exists()
    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    assert not any(s.namespace == "gmail" for s in reg.list())


def test_token_response_not_logged(server_factory, mock_token_endpoint, caplog):
    caplog.set_level(logging.DEBUG)
    server = server_factory(seed_registry(_gmail_child()), PUBLIC_URL=PUBLIC, CHILD_START_TIMEOUT="2", LOG_LEVEL="DEBUG")
    sup = server.supervisor
    sup.creds.write_client("gmail", "google-client", ClientCreds("abc", "shhh"))
    flow = sup.flows.create("gmail", "gmail", ClientCreds("abc", "shhh"))
    client = server.login()
    resp = client.get(f"/oauth/callback?state={flow.state}&code=c")
    client.close()
    assert resp.status_code == 303
    assert "ACCESStoken123" not in caplog.text
    assert "REFRESHtoken456" not in caplog.text


# --- 7.5 session gate --------------------------------------------------------


def test_callback_without_session(server_factory):
    server = server_factory(PUBLIC_URL=PUBLIC)
    resp = httpx.get(
        server.base_url + "/oauth/callback?state=x&code=y", follow_redirects=False
    )
    assert resp.status_code in (302, 303, 307)
    assert resp.headers["location"].startswith("/login")


# --- 7.6 awaiting mark -------------------------------------------------------


def test_servers_table_awaiting_mark(server_factory):
    server = server_factory(PUBLIC_URL=PUBLIC, CHILD_START_TIMEOUT="2")
    client = server.login()
    client.post(
        "/marketplace/gmail/connect",
        data={"namespace": "gmail", "client_id": "abc", "client_secret": "shhh"},
    )
    html = client.get("/servers").text
    client.close()
    assert "awaiting authorization" in html


def test_authorized_child_no_mark(server_factory, mock_token_endpoint):
    server = server_factory(seed_registry(_gmail_child()), PUBLIC_URL=PUBLIC, CHILD_START_TIMEOUT="2")
    sup = server.supervisor
    sup.creds.write_client("gmail", "google-client", ClientCreds("abc", "shhh"))
    flow = sup.flows.create("gmail", "gmail", ClientCreds("abc", "shhh"))
    client = server.login()
    client.get(f"/oauth/callback?state={flow.state}&code=c")
    server.wait(running=1)
    html = client.get("/servers").text
    client.close()
    assert "awaiting authorization" not in html


# --- re-authorize ------------------------------------------------------------


def _seed_connected_gmail(server):
    """Give the running server's gmail child a client and token so it is a
    connected, re-authorizable child."""
    sup = server.supervisor
    sup.creds.write_client("gmail", "google-client", ClientCreds("old-id", "old-secret"))
    sup.creds.write_token("gmail", "google-auth-library", {
        "access_token": "old", "refresh_token": "old-r", "scope": "s",
        "token_type": "Bearer", "expires_in": 3600,
    })


def test_reauth_form_shows_redirect_uri(server_factory):
    server = server_factory(seed_registry(_gmail_child()), PUBLIC_URL=PUBLIC, CHILD_START_TIMEOUT="2")
    _seed_connected_gmail(server)
    client = server.login()
    html = client.get("/servers/gmail/reauthorize").text
    client.close()
    assert "https://mcp.example/oauth/callback" in html
    assert "developers.google.com/identity/protocols/oauth2" in html
    assert 'type="password"' in html
    assert "Re-authorize with Google" in html


def test_reauth_form_non_oauth_404(server_factory):
    server = server_factory(seed_registry(fake_child_spec("plain", "good")), CHILD_START_TIMEOUT="2")
    client = server.login()
    resp = client.get("/servers/plain/reauthorize")
    client.close()
    assert resp.status_code == 404


def test_reauth_redirects_to_consent(server_factory):
    server = server_factory(seed_registry(_gmail_child()), PUBLIC_URL=PUBLIC, CHILD_START_TIMEOUT="2")
    _seed_connected_gmail(server)
    client = server.login()
    resp = client.post(
        "/servers/gmail/reauthorize",
        data={"client_id": "abc", "client_secret": "shhh"},
    )
    client.close()
    assert resp.status_code == 303
    loc = resp.headers["location"]
    assert loc.startswith("https://accounts.google.com/o/oauth2/v2/auth")
    q = parse_qs(urlsplit(loc).query)
    assert q["client_id"] == ["abc"] and q["state"]


def test_reauth_missing_secret(server_factory):
    server = server_factory(seed_registry(_gmail_child()), PUBLIC_URL=PUBLIC, CHILD_START_TIMEOUT="2")
    _seed_connected_gmail(server)
    client = server.login()
    resp = client.post("/servers/gmail/reauthorize", data={"client_id": "abc", "client_secret": ""})
    client.close()
    assert resp.status_code == 400 and "client_secret is required" in resp.text


def test_reauth_without_token_400(server_factory):
    server = server_factory(seed_registry(_gmail_child()), PUBLIC_URL=PUBLIC, CHILD_START_TIMEOUT="2")
    server.supervisor.creds.write_client("gmail", "google-client", ClientCreds("a", "b"))
    client = server.login()
    resp = client.post("/servers/gmail/reauthorize", data={"client_id": "abc", "client_secret": "shhh"})
    client.close()
    assert resp.status_code == 400 and "not yet authorized" in resp.text


def test_reauth_second_refused(server_factory):
    server = server_factory(seed_registry(_gmail_child()), PUBLIC_URL=PUBLIC, CHILD_START_TIMEOUT="2")
    _seed_connected_gmail(server)
    server.supervisor.flows.create("gmail", "gmail", ClientCreds("a", "b"), reauth=True)
    client = server.login()
    resp = client.post("/servers/gmail/reauthorize", data={"client_id": "abc", "client_secret": "shhh"})
    client.close()
    assert resp.status_code == 400 and "already in progress" in resp.text


def test_reauth_callback_replaces_token(server_factory, mock_token_endpoint):
    server = server_factory(
        seed_registry(fake_child_spec("gmail", "good", enabled=True, catalog="gmail")),
        PUBLIC_URL=PUBLIC, CHILD_START_TIMEOUT="2",
    )
    server.wait(running=1)
    sup = server.supervisor
    _seed_connected_gmail(server)
    flow = sup.flows.create("gmail", "gmail", ClientCreds("new-id", "new-secret"), reauth=True)
    client = server.login()
    resp = client.get(f"/oauth/callback?state={flow.state}&code=c")
    client.close()
    assert resp.status_code == 303 and resp.headers["location"] == "/servers"
    tok = json.loads((server.data_dir / "creds" / "gmail" / "token.json").read_text())
    assert tok["access_token"] == "ACCESStoken123"
    cli = json.loads((server.data_dir / "creds" / "gmail" / "client.json").read_text())
    assert cli["web"]["client_id"] == "new-id"


def test_reauth_stops_the_child_before_it_writes(server_factory, mock_token_endpoint):
    """A file sink re-authorization tears the child down before it writes.

    A child that refreshes its own access token holds the OLD grant in memory
    and rewrites the token file from it. Writing under a live child can
    therefore land the old grant's access token beside the new grant's refresh
    token, and the restarted child then serves calls on a superseded grant
    until it expires. `design_neg_reauth.cfg` states it as `TokenFileCoherent`.

    Scenario: `specs/oauth-client/spec.md`, "Re-authorization tears the child
    down before it writes".
    """
    server = server_factory(
        seed_registry(fake_child_spec("gmail", "good", enabled=True, catalog="gmail")),
        PUBLIC_URL=PUBLIC, CHILD_START_TIMEOUT="2",
    )
    server.wait(running=1)
    sup = server.supervisor
    _seed_connected_gmail(server)

    order: list[str] = []
    real_teardown = sup._teardown
    real_write_client = sup.creds.write_client
    real_write_token = sup.creds.write_token

    async def traced_teardown(child):
        order.append("teardown")
        await real_teardown(child)

    def traced_write_client(*a, **kw):
        order.append("write_client")
        return real_write_client(*a, **kw)

    def traced_write_token(*a, **kw):
        order.append("write_token")
        return real_write_token(*a, **kw)

    sup._teardown = traced_teardown
    sup.creds.write_client = traced_write_client
    sup.creds.write_token = traced_write_token

    flow = sup.flows.create(
        "gmail", "gmail", ClientCreds("new-id", "new-secret"), reauth=True
    )
    client = server.login()
    resp = client.get(f"/oauth/callback?state={flow.state}&code=c")
    client.close()
    assert resp.status_code == 303

    # The teardown precedes both writes, and nothing separates the two writes.
    assert order[:3] == ["teardown", "write_client", "write_token"], order


def test_reauth_callback_failure_keeps_token(server_factory, mock_token_endpoint):
    mock_token_endpoint["status"] = 400
    mock_token_endpoint["json"] = {"error": "invalid_grant"}
    server = server_factory(seed_registry(_gmail_child()), PUBLIC_URL=PUBLIC, CHILD_START_TIMEOUT="2")
    _seed_connected_gmail(server)
    sup = server.supervisor
    flow = sup.flows.create("gmail", "gmail", ClientCreds("new-id", "new-secret"), reauth=True)
    client = server.login()
    resp = client.get(f"/oauth/callback?state={flow.state}&code=c")
    client.close()
    assert resp.status_code == 400 and "invalid_grant" in resp.text
    tok = json.loads((server.data_dir / "creds" / "gmail" / "token.json").read_text())
    assert tok["access_token"] == "old"  # unchanged
    cli = json.loads((server.data_dir / "creds" / "gmail" / "client.json").read_text())
    assert cli["web"]["client_id"] == "old-id"  # unchanged


def test_callback_malformed_expiry_refused_before_apply(server_factory, mock_token_endpoint):
    """A 2xx token response whose `expires_in` cannot be parsed is refused
    before the apply: 400 error page, no token file, child disabled, and
    `finish_oauth` is never called, so nothing is written.

    Scenario: `specs/oauth-client/spec.md`, "Malformed token response is
    refused before the apply".
    """
    mock_token_endpoint["json"] = {
        "access_token": "a", "token_type": "Bearer", "expires_in": "later",
    }
    server = server_factory(seed_registry(_gmail_child()), PUBLIC_URL=PUBLIC, CHILD_START_TIMEOUT="2")
    sup = server.supervisor
    sup.creds.write_client("gmail", "google-client", ClientCreds("abc", "shhh"))
    flow = sup.flows.create("gmail", "gmail", ClientCreds("abc", "shhh"))

    called = {"finish_oauth": 0}
    real_finish = sup.finish_oauth

    async def spy_finish(*a, **kw):
        called["finish_oauth"] += 1
        return await real_finish(*a, **kw)

    sup.finish_oauth = spy_finish

    client = server.login()
    resp = client.get(f"/oauth/callback?state={flow.state}&code=c")
    client.close()
    assert resp.status_code == 400
    assert not (server.data_dir / "creds" / "gmail" / "token.json").exists()
    assert server.health()["running"] == 0
    assert called["finish_oauth"] == 0
    # The flow is consumed, so a replay is expired.
    assert sup.flows.pop(flow.state) is None


def test_reauth_callback_malformed_expiry_keeps_child_running(server_factory, mock_token_endpoint):
    """A malformed 2xx response on a re-authorization refuses before the apply,
    so the running child is not torn down and its token file is unchanged.

    Scenario: `specs/oauth-client/spec.md`, "Malformed token response on a
    re-authorization leaves the child running".
    """
    mock_token_endpoint["json"] = {
        "access_token": "a", "token_type": "Bearer", "expires_in": "later",
    }
    server = server_factory(
        seed_registry(fake_child_spec("gmail", "good", enabled=True, catalog="gmail")),
        PUBLIC_URL=PUBLIC, CHILD_START_TIMEOUT="2",
    )
    server.wait(running=1)
    sup = server.supervisor
    _seed_connected_gmail(server)

    torn = {"teardown": 0}
    real_teardown = sup._teardown

    async def spy_teardown(child):
        torn["teardown"] += 1
        return await real_teardown(child)

    sup._teardown = spy_teardown

    flow = sup.flows.create("gmail", "gmail", ClientCreds("new-id", "new-secret"), reauth=True)
    client = server.login()
    resp = client.get(f"/oauth/callback?state={flow.state}&code=c")
    client.close()
    assert resp.status_code == 400
    assert torn["teardown"] == 0  # the running child is untouched
    assert server.health()["running"] == 1
    tok = json.loads((server.data_dir / "creds" / "gmail" / "token.json").read_text())
    assert tok["access_token"] == "old"  # unchanged
    cli = json.loads((server.data_dir / "creds" / "gmail" / "client.json").read_text())
    assert cli["web"]["client_id"] == "old-id"  # unchanged


def test_servers_table_offers_reauth(server_factory):
    server = server_factory(seed_registry(_gmail_child()), PUBLIC_URL=PUBLIC, CHILD_START_TIMEOUT="2")
    _seed_connected_gmail(server)
    client = server.login()
    html = client.get("/servers").text
    client.close()
    assert 'href="/servers/gmail/reauthorize"' in html


# --- header sink (remote-oauth) ----------------------------------------------


def _linear_child():
    return fake_child_spec("linear", "good", enabled=False, catalog="linear", oauth_pending=True)


def test_connect_header_sink_registers_pending(server_factory):
    server = server_factory(PUBLIC_URL=PUBLIC, CHILD_START_TIMEOUT="2")
    client = server.login()
    resp = client.post(
        "/marketplace/linear/connect",
        data={"namespace": "linear", "client_id": "abc", "client_secret": "shhh"},
    )
    client.close()
    assert resp.status_code == 303
    loc = resp.headers["location"]
    assert loc.startswith("https://linear.app/oauth/authorize")
    # Linear wants comma-joined scopes (provider scope_separator).
    assert parse_qs(urlsplit(loc).query)["scope"] == ["read,write"]
    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    spec = reg.get("linear")
    assert spec.enabled is False and spec.oauth_pending is True and spec.headers == {}
    assert not (server.data_dir / "creds" / "linear" / "client.json").exists()
    assert server.health()["running"] == 0


def test_callback_header_sink_sets_header(server_factory, mock_token_endpoint):
    server = server_factory(seed_registry(_linear_child()), PUBLIC_URL=PUBLIC, CHILD_START_TIMEOUT="2")
    sup = server.supervisor
    flow = sup.flows.create("linear", "linear", ClientCreds("abc", "shhh"))
    client = server.login()
    resp = client.get(f"/oauth/callback?state={flow.state}&code=c")
    client.close()
    assert resp.status_code == 303 and resp.headers["location"] == "/servers"
    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    spec = reg.get("linear")
    assert spec.headers["Authorization"] == "Bearer ACCESStoken123"
    assert spec.oauth_pending is False
    assert not (server.data_dir / "creds" / "linear").exists()
    server.wait(running=1)


def test_pending_header_child_shows_mark(server_factory):
    server = server_factory(seed_registry(_linear_child()), PUBLIC_URL=PUBLIC, CHILD_START_TIMEOUT="2")
    client = server.login()
    html = client.get("/servers").text
    client.close()
    assert "awaiting authorization" in html
