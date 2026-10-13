"""A revoke between the gate and the write, end to end (bind-actor-to-server-writes, T8 and T10).

The gate admits the request, then the identity store changes inside the first
ASGI `receive` of the handler (or at route entry for a request with no body),
the way `tests/reresolve_race.py` holds a request. Scenarios of
`specs/access-policy/spec.md` (requirements "Server writes check the actor at
write time" and "The write-time right of a server write", and "Write-time actor
check"), `specs/oauth-client/spec.md` ("The OAuth completion checks the actor of
the flow") and `specs/web-ui/spec.md` ("Web routes answer a write-time refusal
with 403"). Model: `WriteByCurrentAdmin`, `NoWriteByDeleted`,
`WriteByCurrentIncarnation`, `FlowOutlivesActorRefused`, `RefusedFlowConsumed`,
`CommittedWriteStays`. Every test asserts that the revoke fired.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from conftest import ADMIN_ACTOR, make_user
from dashboard_site import (  # noqa: F401
    api_headers,
    bearer,
    make_mu_site,
    revisions_on_page,
)
from keyed_stores import tree
from reresolve_race import (
    delete_user,
    demote_alice,
    make_admin_user,
    make_second_admin,
    revoke_during_body,
    revoke_then_capture,
    stores,
)
from test_child_actions import store_spec

from mcpflow.registry import Registry, ServerKey

ALL = ("users.json", "rules.json", "tokens.json", "user_tokens.json",
       "servers.json", "user_servers.json")
TIME = ServerKey(None, "time")
STORE = ServerKey(None, "store")
GMAIL = ServerKey(None, "gmail")
LINEAR = ServerKey(None, "linear")
GH_ALICE = ServerKey("alice", "github")
GH_BOB = ServerKey("bob", "github")
PUBLIC = "https://mcp.example"
NEW_TIME = {"kind": "npm", "package": "@acme/time@1.0.0", "args": ["--changed"]}
NEW_TIME_FORM = {"kind": "npm", "namespace": "time", "package": "@acme/time@1.0.0",
                 "args": "--changed", "enabled": "on"}


def sup_of(site):
    return site.app.state.supervisor


def specs(site) -> list[dict]:
    return [s.model_dump(mode="json") for s in sup_of(site).registry.list()]


def alice_admin(site) -> str:
    """Make `alice` an admin with a session and a token. Return the clear token."""
    token = make_second_admin(site)
    site.login("alice")
    return token


# --- the `/api` writes --------------------------------------------------------


def test_put_api_servers_by_a_revoked_admin_answers_403(make_mu_site):  # noqa: F811
    """Scenario "A revoke before an update refuses it"."""
    site = make_mu_site()
    token = alice_admin(site)
    revoke, after = revoke_then_capture(site, demote_alice(site), ALL)
    fired = revoke_during_body(site.app, "PUT", "/api/servers/{ref}", revoke)
    launches = site.launches()
    resp = site.client.put("/api/servers/time", headers=bearer(token), json=NEW_TIME)
    assert fired, "the revoke never ran: the window was not exercised"
    assert resp.status_code == 403, (resp.status_code, resp.text)
    assert resp.json() == {"error": "the admin role is required"}
    assert stores(site, ALL) == after
    assert sup_of(site).registry.get(TIME).args != ["--changed"]
    assert site.status(TIME) == "running" and site.launches() == launches


def test_post_servers_edit_by_a_revoked_admin_answers_403(make_mu_site):  # noqa: F811
    """Scenario "A demoted admin's server edit answers 403"."""
    site = make_mu_site()
    alice_admin(site)
    revoke, after = revoke_then_capture(site, demote_alice(site), ALL)
    fired = revoke_during_body(site.app, "POST", "/servers/{ref}", revoke)
    launches = site.launches()
    resp = site.request("alice", "POST", "/servers/time", data=NEW_TIME_FORM)
    assert fired
    assert (resp.status_code, resp.text) == (403, "the admin role is required")
    assert stores(site, ALL) == after
    assert site.status(TIME) == "running" and site.launches() == launches


def test_api_remove_and_restart_by_a_revoked_admin_answer_403(make_mu_site):  # noqa: F811
    """Scenarios "A revoke before a remove / a restart refuses it"."""
    site = make_mu_site()
    token = alice_admin(site)
    creds = site.data / "creds" / "time"
    creds.mkdir(parents=True)
    (creds / "token.json").write_text('{"old": true}')
    log = site.data / "logs" / "time.log"
    assert log.exists(), "the running child holds a log"
    launches = site.launches()
    revoke, after = revoke_then_capture(site, demote_alice(site), ALL)
    fired = revoke_during_body(site.app, "DELETE", "/api/servers/{ref}", revoke, at="enter")
    resp = site.client.delete("/api/servers/time", headers=bearer(token))
    assert fired
    assert resp.status_code == 403, (resp.status_code, resp.text)
    assert resp.json() == {"error": "the admin role is required"}
    assert stores(site, ALL) == after
    assert (creds / "token.json").read_text() == '{"old": true}'
    assert log.exists()
    assert TIME in {s.key for s in sup_of(site).registry.list()}
    assert site.status(TIME) == "running"

    # The same admin, restored, then a restart in flight.
    sup_of(site).policy.set_admin(ADMIN_ACTOR, "alice", True)
    token = make_second_admin(site)
    revoke, after = revoke_then_capture(site, demote_alice(site), ALL)
    fired = revoke_during_body(site.app, "POST", "/api/servers/{ref}/restart", revoke, at="enter")
    resp = site.client.post("/api/servers/time/restart", headers=bearer(token))
    assert fired
    assert resp.status_code == 403, (resp.status_code, resp.text)
    assert stores(site, ALL) == after
    assert site.status(TIME) == "running" and site.launches() == launches


def test_a_deleted_admin_restart_answers_403_with_the_unknown_actor_text(make_mu_site):  # noqa: F811
    """Scenario "A deleted actor's server write is refused"."""
    site = make_mu_site()
    token = make_admin_user(site, "carol")
    revoke, after = revoke_then_capture(site, delete_user(site, "carol"), ALL)
    fired = revoke_during_body(site.app, "POST", "/api/servers/{ref}/restart", revoke, at="enter")
    launches = site.launches()
    resp = site.client.post("/api/servers/time/restart", headers=bearer(token))
    assert fired
    assert resp.status_code == 403, (resp.status_code, resp.text)
    assert resp.json() == {"error": "the acting user is unknown"}
    assert stores(site, ALL) == after
    assert site.status(TIME) == "running" and site.launches() == launches


def test_a_still_admin_restarts_over_the_api(make_mu_site):  # noqa: F811
    """Scenario "A still-admin actor writes"."""
    site = make_mu_site()
    token = make_second_admin(site)
    launches = site.launches()
    resp = site.client.post("/api/servers/time/restart", headers=bearer(token))
    assert resp.status_code == 200, (resp.status_code, resp.text)
    site.wait_running(TIME)
    assert site.launches() == launches + 1


def test_a_revoke_during_update_teardown_keeps_the_new_record_over_http(make_mu_site, monkeypatch):  # noqa: F811
    """Scenario "A revoke after the commit does not undo the write"."""
    site = make_mu_site()
    token = alice_admin(site)
    sup = sup_of(site)
    real = sup._teardown
    fired: list[int] = []
    demote = demote_alice(site)

    async def teardown(child):
        if not fired:
            fired.append(1)
            demote()
        await real(child)

    monkeypatch.setattr(sup, "_teardown", teardown)
    launches = site.launches()
    resp = site.client.put("/api/servers/time", headers=bearer(token), json=NEW_TIME)
    assert fired, "the revoke never ran: the teardown window was not exercised"
    assert resp.status_code == 200, (resp.status_code, resp.text)
    assert sup.registry.get(TIME).args == ["--changed"]
    stored = json.loads((site.data / "servers.json").read_text())["servers"]
    assert next(s for s in stored if s["namespace"] == "time")["args"] == ["--changed"]
    site.wait_running(TIME)
    assert site.launches() == launches + 1, "time did not start from the new record"


# --- the web writes -----------------------------------------------------------


@pytest.mark.parametrize("op", ["enable", "disable", "restart", "delete"])
def test_web_server_actions_by_a_revoked_admin_answer_403(make_mu_site, op):  # noqa: F811
    """Scenarios "A demoted admin's server action answers 403" and "A demoted admin
    loses an admin-owned server"."""
    site = make_mu_site()
    alice_admin(site)
    if op == "enable":
        resp = site.client.post("/api/servers/time/disable", headers=api_headers(site))
        assert resp.status_code == 200, resp.text
        assert site.status(TIME) == "stopped"
    wanted = site.status(TIME)
    revoke, after = revoke_then_capture(site, demote_alice(site), ALL)
    fired = revoke_during_body(site.app, "POST", f"/servers/{{ref}}/{op}", revoke, at="enter")
    launches = site.launches()
    resp = site.request("alice", "POST", f"/servers/time/{op}")
    assert fired
    assert (resp.status_code, resp.text) == (403, "the admin role is required")
    assert stores(site, ALL) == after
    assert TIME in {s.key for s in sup_of(site).registry.list()}
    assert site.status(TIME) == wanted and site.launches() == launches


@pytest.mark.parametrize("kind", ["web-root", "web-tool", "api-namespace"])
def test_visibility_writes_by_a_revoked_admin_answer_403(make_mu_site, kind):  # noqa: F811
    """Scenarios "A revoke before a root / namespace / tool mute refuses it"."""
    site = make_mu_site()
    token = alice_admin(site)
    revoke, after = revoke_then_capture(site, demote_alice(site), ALL)
    before_specs = specs(site)
    if kind == "web-root":
        fired = revoke_during_body(site.app, "POST", "/visibility/root", revoke)
        resp = site.request("alice", "POST", "/visibility/root", data={"x": "1"})
    elif kind == "web-tool":
        fired = revoke_during_body(site.app, "POST", "/visibility/namespaces/{ref}/tool", revoke)
        resp = site.request("alice", "POST", "/visibility/namespaces/time/tool",
                            data={"tool": "get_current_time"})
    else:
        fired = revoke_during_body(site.app, "PUT", "/api/visibility/namespaces/{ref}", revoke)
        resp = site.client.put("/api/visibility/namespaces/time", headers=bearer(token),
                               json={"muted": True})
    assert fired
    assert resp.status_code == 403, (resp.status_code, resp.text)
    assert "the admin role is required" in resp.text
    assert stores(site, ALL) == after
    assert specs(site) == before_specs
    assert sup_of(site).root_muted() is False


def test_web_approve_by_a_revoked_admin_answers_403(make_mu_site):  # noqa: F811
    """Scenario "A revoke before an approve refuses it"."""
    site = make_mu_site()
    alice_admin(site)
    edit = site.request("bob", "POST", "/servers/github@bob", data={
        "kind": "npm", "namespace": "github", "package": "@acme/mcp@2.0.0", "enabled": "on"})
    assert edit.status_code == 303, edit.text
    assert sup_of(site).registry.get(GH_BOB).approval == "pending"
    rev = revisions_on_page(site.request("admin", "GET", "/approvals").text)["github@bob"]
    revoke, after = revoke_then_capture(site, demote_alice(site), ALL)
    fired = revoke_during_body(site.app, "POST", "/approvals/{ref}/approve", revoke)
    launches = site.launches()
    resp = site.request("alice", "POST", "/approvals/github@bob/approve", data={"revision": rev})
    assert fired
    assert resp.status_code == 403, (resp.status_code, resp.text)
    assert "the admin role is required" in resp.text
    assert stores(site, ALL) == after
    assert sup_of(site).registry.get(GH_BOB).approval == "pending"
    assert site.status(GH_BOB) == "stopped" and site.launches() == launches


def add_store(data: Path) -> None:
    reg = Registry(data / "servers.json", data / "user_servers.json")
    reg.load()
    reg.add(store_spec(env={"MCPFLOW_CALL_LOG": str(data / "calls.log")}))


def test_a_revoked_admin_action_submit_answers_403(make_mu_site):  # noqa: F811
    """Scenario "A revoke before an action refuses it"."""
    site = make_mu_site(add_store)
    alice_admin(site)
    site.wait_running(STORE)
    revoke, after = revoke_then_capture(site, demote_alice(site), ALL)
    fired = revoke_during_body(site.app, "POST", "/servers/{ref}/actions/{action}", revoke)
    resp = site.request("alice", "POST", "/servers/store/actions/set_writable",
                        data={"name": "s3main"})
    assert fired
    assert (resp.status_code, resp.text) == (403, "the admin role is required")
    calls = site.data / "calls.log"
    assert not calls.exists() or calls.read_text() == "", "the child received a call"
    assert stores(site, ALL) == after


# --- the admin MCP ------------------------------------------------------------


def mcp_call(site, token: str, name: str, arguments: dict) -> dict:
    """One `tools/call` of `/mcp` over a raw Streamable HTTP exchange."""
    base = {**bearer(token), "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json"}

    def rpc(payload: dict, headers: dict):
        resp = site.client.post("/mcp", headers=headers, json=payload)
        assert resp.status_code in (200, 202), (resp.status_code, resp.text)
        if not resp.text:
            return resp, None
        text = resp.text
        if "data:" in text:
            text = next(line[5:] for line in text.splitlines() if line.startswith("data:"))
        return resp, json.loads(text)

    resp, _ = rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-03-26", "capabilities": {},
        "clientInfo": {"name": "t", "version": "1"}}}, base)
    headers = dict(base)
    if resp.headers.get("mcp-session-id"):
        headers["mcp-session-id"] = resp.headers["mcp-session-id"]
    rpc({"jsonrpc": "2.0", "method": "notifications/initialized"}, headers)
    _, out = rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                  "params": {"name": name, "arguments": arguments}}, headers)
    return out


def failed(out: dict) -> bool:
    return bool(out.get("error")) or bool(out.get("result", {}).get("isError"))


@pytest.mark.parametrize("tool", ["mcpflow_update_server", "mcpflow_write_source"])
def test_admin_mcp_writes_check_the_caller(make_mu_site, monkeypatch, tool):  # noqa: F811
    """Scenarios "An admin MCP write checks the caller" and "A revoke before a source
    write refuses it". The wrap revokes after the tool resolved its caller."""
    site = make_mu_site()
    token = make_second_admin(site)
    sup = sup_of(site)
    revoke, after = revoke_then_capture(site, demote_alice(site), ALL)
    fired: list[int] = []
    method = "update" if tool == "mcpflow_update_server" else "write_source"
    real = getattr(sup, method)

    async def delegate(*args):
        fired.append(1)
        revoke()
        return await real(*args)

    monkeypatch.setattr(sup, method, delegate)
    launches = site.launches()
    sources = tree(site.data / "servers")
    if tool == "mcpflow_update_server":
        out = mcp_call(site, token, tool, {"namespace": "time", "spec": NEW_TIME})
    else:
        out = mcp_call(site, token, tool, {"namespace": "time", "files": {"a.py": "x = 1\n"}})
    assert fired, "the revoke never ran: the window was not exercised"
    assert failed(out), out
    assert stores(site, ALL) == after
    assert tree(site.data / "servers") == sources
    assert sup.registry.get(TIME).args != ["--changed"]
    assert site.status(TIME) == "running" and site.launches() == launches


# --- OwnerKeepsOwnKey over HTTP ----------------------------------------------


def test_a_demoted_admin_keeps_an_own_server_over_the_web(make_mu_site):  # noqa: F811
    """Scenario "A demoted admin keeps the rights on an own server"."""
    site = make_mu_site()
    alice_admin(site)
    demote_alice(site)()
    launches = site.launches()
    resp = site.request("alice", "POST", "/servers/github@alice/restart")
    assert resp.status_code in (200, 303), (resp.status_code, resp.text)  # a user is redirected
    site.wait_running(GH_ALICE)
    assert site.launches() == launches + 1


def test_a_demoted_admins_request_in_flight_on_an_own_server_is_refused_then_retried(make_mu_site):  # noqa: F811
    """Scenario "A demoted admin's write in flight on an own server is refused"."""
    site = make_mu_site()
    alice_admin(site)
    revoke, after = revoke_then_capture(site, demote_alice(site), ALL)
    fired = revoke_during_body(site.app, "POST", "/servers/{ref}/restart", revoke, at="enter")
    launches = site.launches()
    resp = site.request("alice", "POST", "/servers/github@alice/restart")
    assert fired
    assert (resp.status_code, resp.text) == (403, "the admin role is required")
    assert stores(site, ALL) == after
    assert site.launches() == launches and site.status(GH_ALICE) == "running"
    retry = site.request("alice", "POST", "/servers/github@alice/restart")
    assert retry.status_code in (200, 303), (retry.status_code, retry.text)
    site.wait_running(GH_ALICE)
    assert site.launches() == launches + 1


def test_a_user_manages_an_own_server(make_mu_site):  # noqa: F811
    """Scenario "A user manages an own server"."""
    site = make_mu_site()
    resp = site.request("bob", "POST", "/servers/github@bob/disable")
    assert resp.status_code in (200, 303), (resp.status_code, resp.text)
    assert sup_of(site).registry.get(GH_BOB).enabled is False
    assert site.status(GH_BOB) == "stopped"


# --- AP-1 over HTTP -----------------------------------------------------------


def test_a_re_used_id_does_not_let_an_old_request_act(make_mu_site):  # noqa: F811
    """Scenario "A re-used id does not let an old request act"."""
    site = make_mu_site()
    policy = sup_of(site).policy
    removed = site.client.delete("/api/servers/github@bob", headers=api_headers(site))
    assert removed.status_code == 204, removed.text  # `bob` owns nothing now
    site.login("bob")

    def reuse() -> None:
        policy.delete_user(ADMIN_ACTOR, "bob")
        make_user(policy, "bob", "pw-bob-new-0123456789")

    revoke, after = revoke_then_capture(site, reuse, ALL)
    fired = revoke_during_body(site.app, "POST", "/tokens", revoke)
    resp = site.request("bob", "POST", "/tokens", data={"name": "t", "scope": "mcp"})
    assert fired
    assert (resp.status_code, resp.text) == (403, "the acting user is unknown")
    assert stores(site, ALL) == after
    new_bob = policy.local_identity().get_user("bob")
    assert new_bob.incarnation == 1
    assert policy.tokens_for(new_bob) == []


def test_an_unrelated_edit_does_not_refuse_a_write(make_mu_site):  # noqa: F811
    """Scenario "An unrelated edit does not refuse a write"."""
    site = make_mu_site()
    token = make_second_admin(site)
    policy = sup_of(site).policy
    policy.create_group(ADMIN_ACTOR, "eng")
    revoke = lambda: policy.change_groups(ADMIN_ACTOR, "alice", add=["eng"])
    fired = revoke_during_body(site.app, "POST", "/api/groups", revoke)
    resp = site.client.post("/api/groups", headers=bearer(token), json={"name": "ops"})
    assert fired
    assert resp.status_code == 201, (resp.status_code, resp.text)
    assert "ops" in policy.local_identity().list_groups()
    assert "eng" in policy.local_identity().get_user("alice").groups


# --- the OAuth callback: the flow outlives its opener (OC-2, WU-1) ---------------


@pytest.fixture
def token_endpoint(monkeypatch):
    """Replace the token endpoint. `hook["before"]` runs when the exchange arrives."""
    hook: dict = {"before": None, "calls": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        hook["calls"] += 1
        if hook["before"] is not None:
            hook["before"]()
        return httpx.Response(200, json={
            "access_token": "ACCESStoken123", "refresh_token": "REFRESHtoken456",
            "scope": "s", "token_type": "Bearer", "expires_in": 3600})

    def factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=15.0)

    monkeypatch.setattr("mcpflow.oauth.http_client", factory)
    return hook


def connect(site, entry: str) -> str:
    """`alice` opens the flow of `entry`. Return its `state`."""
    resp = site.request("alice", "POST", f"/marketplace/{entry}/connect", data={
        "namespace": entry, "client_id": "abc", "client_secret": "shhh"})
    assert resp.status_code == 303, (resp.status_code, resp.text)
    return parse_qs(urlsplit(resp.headers["location"]).query)["state"][0]


def callback(site, state: str):
    """A callback in the session of the bootstrap admin: another admin than the opener."""
    return site.request("admin", "GET", f"/oauth/callback?state={state}&code=the-code")


def drop_alice_servers(site) -> None:
    removed = site.client.delete("/api/servers/github@alice", headers=api_headers(site))
    assert removed.status_code == 204, removed.text  # `alice` owns nothing now


def test_a_callback_after_the_opener_is_deleted_answers_403(make_mu_site, token_endpoint):  # noqa: F811
    """Scenario "A completion after the opener is deleted writes nothing"."""
    site = make_mu_site(PUBLIC_URL=PUBLIC)
    drop_alice_servers(site)
    alice_admin(site)
    state = connect(site, "gmail")
    assert site.status(GMAIL) == "stopped"
    revoke, after = revoke_then_capture(site, delete_user(site, "alice"), ALL)
    token_endpoint["before"] = revoke
    resp = callback(site, state)
    assert token_endpoint["calls"] == 1 and after, "the exchange window was not exercised"
    assert (resp.status_code, resp.text) == (403, "the acting user is unknown")
    assert not (site.data / "creds" / "gmail" / "token.json").exists()
    assert site.status(GMAIL) == "stopped"
    assert sup_of(site).registry.get(GMAIL).enabled is False
    assert stores(site, ALL) == after
    again = callback(site, state)
    assert again.status_code == 400, (again.status_code, again.text)


def test_a_callback_after_the_opener_is_demoted_writes_nothing(make_mu_site, token_endpoint):  # noqa: F811
    """Scenario "A completion after the opener is demoted writes nothing" (header sink)."""
    site = make_mu_site(PUBLIC_URL=PUBLIC)
    alice_admin(site)
    state = connect(site, "linear")
    before = sup_of(site).registry.get(LINEAR)
    assert before.oauth_pending is True and "Authorization" not in before.headers
    revoke, after = revoke_then_capture(site, demote_alice(site), ALL)
    token_endpoint["before"] = revoke
    resp = callback(site, state)
    assert token_endpoint["calls"] == 1 and after
    assert (resp.status_code, resp.text) == (403, "the admin role is required")
    spec = sup_of(site).registry.get(LINEAR)
    assert "Authorization" not in spec.headers
    assert spec.oauth_pending is True
    assert not (site.data / "creds" / "linear" / "refresh.json").exists()
    assert stores(site, ALL) == after
    assert callback(site, state).status_code == 400


def test_a_callback_after_the_openers_id_is_re_used_writes_nothing(make_mu_site, token_endpoint):  # noqa: F811
    """Scenario "A completion after the opener's id is re-used writes nothing"."""
    site = make_mu_site(PUBLIC_URL=PUBLIC)
    drop_alice_servers(site)
    alice_admin(site)
    state = connect(site, "gmail")
    policy = sup_of(site).policy

    def reuse() -> None:
        policy.delete_user(ADMIN_ACTOR, "alice")
        make_user(policy, "alice", "pw-alice-new-0123456789", admin=True)

    revoke, after = revoke_then_capture(site, reuse, ALL)
    token_endpoint["before"] = revoke
    resp = callback(site, state)
    assert token_endpoint["calls"] == 1 and after
    assert (resp.status_code, resp.text) == (403, "the acting user is unknown")
    assert policy.local_identity().get_user("alice").is_admin
    assert not (site.data / "creds" / "gmail" / "token.json").exists()
    assert site.status(GMAIL) == "stopped"


def test_a_current_opener_completes_in_the_session_of_another_admin(make_mu_site, token_endpoint):  # noqa: F811
    """Scenario "A current opener completes the flow"; the flow binds the opener (R-H)."""
    site = make_mu_site(PUBLIC_URL=PUBLIC)
    alice_admin(site)
    state = connect(site, "gmail")
    resp = callback(site, state)
    assert token_endpoint["calls"] == 1
    assert resp.status_code == 303 and resp.headers["location"] == "/servers"
    assert (site.data / "creds" / "gmail" / "token.json").exists()
    assert sup_of(site).registry.get(GMAIL).enabled is True


def test_the_connect_route_stores_the_opener_in_the_flow(make_mu_site, token_endpoint):  # noqa: F811
    """Scenario "A flow holds its opener": the connect and the re-authorize routes."""
    site = make_mu_site(PUBLIC_URL=PUBLIC)
    alice_admin(site)
    state = connect(site, "gmail")
    flow = sup_of(site).flows.peek(state)
    alice = sup_of(site).policy.local_identity().get_user("alice")
    assert flow is not None and flow.actor == alice and flow.actor.is_admin
    assert flow.reauth is False
    # Complete it, then re-authorize as the bootstrap admin: the flow holds that admin.
    assert callback(site, state).status_code == 303
    resp = site.request("admin", "POST", "/servers/gmail/reauthorize", data={
        "client_id": "abc", "client_secret": "shhh"})
    assert resp.status_code == 303, (resp.status_code, resp.text)
    again = parse_qs(urlsplit(resp.headers["location"]).query)["state"][0]
    reflow = sup_of(site).flows.peek(again)
    assert reflow is not None and reflow.reauth is True
    assert reflow.actor == sup_of(site).policy.local_identity().get_user("admin")
