"""Verifier tests for the 2026-09-18 amendment (section 15) of change
`child-actions-page`: codex findings F1, F2 (action-capability trust flag),
F4, and F5.

Every test derives from a spec scenario, not from the implementation:

- `specs/mcp-gateway/spec.md` — "Action-capability trust grant" and the
  amended "Admin tools are visible to admin sessions only" (F1, F2).
- `specs/web-ui/spec.md` — "Actions page" (F4, F5) and "Cache TTL field for an
  action-capable child" (F2 form).

The store child is action-capable (`store_spec()` sets `actions=True`). A
non-capable child uses `fake_child_spec(..., "action")` with the default
`actions=False`. The MCP-surface tests drive the real gateway over Streamable
HTTP with a bearer token, so the filter and the hash authorizer see a real
`AccessToken`. Supervisor-level tests use the in-process `make_supervisor`
fixture so they can await `actions`/`run_action` directly.
"""

from __future__ import annotations

import html
import re

import pytest
from action_browser import action_post, control
from conftest import fake_child_spec, seed_registry
from fastmcp.exceptions import ToolError
from fastmcp.server.providers.addressing import hash_tool
from test_child_actions import (
    PAGE,
    SECRET,
    call,
    cards,
    list_names,
    more_spec,
    password_inputs,
    start,
    store_spec,
)
from test_supervisor import make_supervisor  # noqa: F401 -- async fixture
from test_visibility import admin, call_log, mute, tool_path

from mcpflow.actions import ActionScopeFilter, AuthorizedHashProvider
from mcpflow.registry import Registry, ServerSpec
from mcpflow.supervisor import (
    ActionUnavailable,  # noqa: F401 -- still exported (A4 dead)
)

# The declared hash of the fixture's `hashed` tool (meta uses hash_tool("fake",...)).
HASH = hash_tool("fake", "hashed")


def _custom(ns: str, **extra) -> ServerSpec:
    extra.setdefault("args", ["y"])
    return ServerSpec(namespace=ns, kind="custom", command="x", **extra)


# =============================================================================
# F1: authorize the hashed dispatch path
# =============================================================================


# 15.F1.4 -- scenario "A hash-reachable clause violator is hidden and refused".
def test_f1_4_hash_reachable_violator_hidden_and_refused(server_factory):
    server, h = start(server_factory, store_spec())
    assert "store_hashed" not in list_names(server.base_url, h["mcp"])
    with pytest.raises(ToolError, match="Unknown tool"):
        call(server.base_url, h["mcp"], f"{HASH}_hashed")
    assert call_log(server) == []


# 15.F1.5 -- scenario "An admin runs a hash-reachable tagged tool".
def test_f1_5_admin_runs_hash_reachable_tagged_tool(server_factory):
    server, h = start(server_factory, store_spec())
    assert call(server.base_url, h["admin"], f"{HASH}_hashed") == "hashed"
    assert call_log(server) == ["hashed"]


# 15.F1.6 -- scenario "The hashed path honours a mute".
def test_f1_6_hashed_path_honours_a_mute(server_factory):
    server, h = start(server_factory, store_spec())
    with admin(server) as client:
        mute(client, tool_path("store"), tool="hashed")
    with pytest.raises(ToolError, match="Unknown tool"):
        call(server.base_url, h["admin"], f"{HASH}_hashed")
    assert call_log(server) == []


# =============================================================================
# F2: the action-capability trust grant
# =============================================================================


# 15.F2.9 -- scenario "A tag on a non-capable child is ordinary" + the
# trust-boundary adversarial proof: a tagged tool on a non-capable child lists,
# calls, and is never an action.
def test_f2_9_tag_on_a_non_capable_child_is_ordinary(server_factory):
    # `fake_child_spec(..., "action")` keeps the default actions=False.
    server, h = start(server_factory, fake_child_spec("store", "action"))
    names = set(list_names(server.base_url, h["mcp"]))
    # The tagged tools (and even the hash-reachable one) are ordinary: listed
    # and callable by an mcp session, because the child is not action-capable.
    assert {"store_set_writable", "store_hashed"} <= names
    assert call(server.base_url, h["mcp"], "store_set_writable", {"name": "s"}) == "writable: s"
    # The page seam returns nothing and refuses run_action for the child.
    # A4 F1: run_action returns an ActionRun for every renderable outcome; a
    # non-capable child yields kind "unknown" (no tool of it is an action).
    assert run_sync(server.supervisor.actions("store")) == []
    run = run_sync(server.supervisor.run_action("store", "set_writable", {"name": "x"}))
    assert run.kind == "unknown"


def run_sync(coro):
    """Run a coroutine that returns before any I/O.

    `Supervisor.actions`/`run_action` short-circuit for a non-capable child
    before they open a client, so this never touches the gateway's event loop.
    """
    import asyncio

    return asyncio.new_event_loop().run_until_complete(coro)


# 15.F2.10 -- scenario "A non-capable child keeps its cache TTL".
@pytest.mark.asyncio
async def test_f2_10_non_capable_child_keeps_its_cache_ttl(make_supervisor):  # noqa: F811
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("time", "good", cache_ttl=30))
    await child.task
    assert child.status == "running"
    # The chain is the pre-amendment chain: Namespace(Visibility(ProxyProvider)).
    assert not isinstance(child.provider, AuthorizedHashProvider)
    proxy = child.provider._inner._inner
    assert proxy._cache_ttl == 30.0
    assert ActionScopeFilter not in [type(t) for t in proxy.transforms]


# 15.F2.11 -- scenario "An edit save keeps the grant" (anti-revoke) plus the
# gate's anti-self-grant audit: an update dict cannot flip the flag.
def test_f2_11_update_keeps_the_grant_and_blocks_self_grant(tmp_path):
    reg = Registry(tmp_path / "servers.json")
    reg.load()
    reg.add(_custom("store", actions=True))
    reg.add(_custom("time"))  # actions defaults False
    # Anti-revoke: an edit save that OMITS `actions` keeps the stored grant.
    reg.update(_custom("store", args=["z"]))
    assert reg.get("store").actions is True
    # Anti-self-grant: an update dict that sets actions=True on a non-capable
    # child does NOT flip it; only a create or a catalog connect can.
    reg.update(_custom("time", args=["z"], actions=True))
    assert reg.get("time").actions is False
    # The grant survives a reload.
    again = Registry(tmp_path / "servers.json")
    again.load()
    assert again.get("store").actions is True
    assert again.get("time").actions is False


# 15.F2.12 -- scenario "A stale cache on a non-capable child is safe".
def test_f2_12_stale_cache_on_a_non_capable_child_is_safe(server_factory, tmp_path):
    flag = tmp_path / "retag"
    # Non-capable child with a non-zero cache_ttl. The child re-tags a tool live.
    spec = fake_child_spec("store", "action", cache_ttl=300, env={"MCPFLOW_RETAG": str(flag)})
    server, h = start(server_factory, spec)
    flag.write_text("")  # rotate_keys is now tagged on the child
    # A tag on a non-capable child is never an action, whatever the cache reports.
    assert call(server.base_url, h["mcp"], "store_rotate_keys") == "rotated"
    assert "store_rotate_keys" in list_names(server.base_url, h["mcp"])
    assert call_log(server) == ["rotate_keys"]


# 15.F2.13 -- scenario "A live re-tag closes the mcp path" (by name).
def test_f2_13_live_retag_closes_the_mcp_path_by_name(server_factory, tmp_path):
    flag = tmp_path / "retag"
    spec = fake_child_spec("store", "action", actions=True, env={"MCPFLOW_RETAG": str(flag)})
    server, h = start(server_factory, spec)
    # Before the tag: ordinary, listed and callable by an mcp session.
    assert "store_rotate_keys" in list_names(server.base_url, h["mcp"])
    assert call(server.base_url, h["mcp"], "store_rotate_keys") == "rotated"
    flag.write_text("")  # live re-tag; cache_ttl=0 classifies the live tool
    assert "store_rotate_keys" not in list_names(server.base_url, h["mcp"])
    # Called by name with no intervening tools/list: still refused, no child call.
    with pytest.raises(ToolError, match="Unknown tool"):
        call(server.base_url, h["mcp"], "store_rotate_keys")
    assert call_log(server) == ["rotate_keys"]  # only the before-tag call


# 15.F2.14 -- scenario "A live re-tag closes the mcp path" (the hash address).
def test_f2_14_hash_address_of_a_tagged_tool_is_closed_for_mcp(server_factory):
    # `hashed` is a hash-enabled tagged tool on a capable child. Its old hashed
    # address no longer runs for an mcp session, and it is absent from the list.
    server, h = start(server_factory, store_spec())
    assert "store_hashed" not in list_names(server.base_url, h["mcp"])
    with pytest.raises(ToolError, match="Unknown tool"):
        call(server.base_url, h["mcp"], f"{HASH}_hashed")
    assert call_log(server) == []


# 15.F2.15 -- scenarios "An action-capable child disables the Cache TTL field"
# and "A non-capable child keeps the Cache TTL field editable".
def test_f2_15_cache_ttl_field_disabled_for_capable_enabled_for_non_capable(server_factory):
    server = server_factory(
        seed_registry(
            fake_child_spec("cap", "good", enabled=False, cache_ttl=5, actions=True),
            fake_child_spec("plain", "good", enabled=False, cache_ttl=7),
        )
    )
    client = server.login()
    try:
        cap_body = client.get("/servers/cap").text
        plain_body = client.get("/servers/plain").text
    finally:
        client.close()
    cap_field = re.search(r'<input name="cache_ttl"[^>]*>', cap_body).group(0)
    plain_field = re.search(r'<input name="cache_ttl"[^>]*>', plain_body).group(0)
    # Capable: disabled with the note.
    assert "disabled" in cap_field
    assert "This server classifies actions live; the cache stays off." in cap_body
    # Non-capable: enabled with the stored value, no note.
    assert "disabled" not in plain_field
    assert 'value="7"' in plain_field
    assert "This server classifies actions live" not in plain_body


# =============================================================================
# F4: run one action against one generation
# =============================================================================


# 15.F4.3 -- scenario "A restart between the check and the call does not swap
# the tool". run_action lists and re-checks conformance on its own lease, so a
# name a stale probe offered but that is not a conforming action on the live
# generation is refused, and a real restart binds the call to the new generation.
@pytest.mark.asyncio
async def test_f4_3_run_action_rechecks_on_the_execution_generation(make_supervisor):  # noqa: F811
    sup = make_supervisor()
    child = await sup.add(store_spec())
    await child.task
    # An ordinary tool, a clause violator, and an absent name: each is not a
    # conforming action on the live generation, so run_action refuses before it
    # calls any tool (it raises before `client.call_tool`).
    # A4 F1: run_action returns an ActionRun; a non-conforming name yields kind
    # "unknown" before any call_tool_mcp, so no tool runs.
    for name, args in (("list_stores", {}), ("nested", {"cfg": {}}), ("ghost", {})):
        run = await sup.run_action("store", name, args)
        assert run.kind == "unknown", name
    # A restart supersedes the probed generation; a conforming action still runs
    # on the new generation, never a swapped stale object.
    await sup.restart("store")
    await child.task
    run = await sup.run_action("store", "set_writable", {"name": "s3main"})
    assert run.kind == "ran" and not run.result.is_error


# 15.F4.3 (mute leg) -- run_action re-checks the mute on its own generation and
# raises "muted", calling no tool. This is the second line of defence behind the
# route's pre-call mute check.
@pytest.mark.asyncio
async def test_f4_run_action_refuses_a_mute_and_calls_no_tool(make_supervisor):  # noqa: F811
    sup = make_supervisor()
    child = await sup.add(store_spec())
    await child.task
    sup.set_tool_muted("store", "set_writable", True)
    # A4 F1: prove no tool call by spying the raw call primitive; run_action
    # returns kind "muted" before it reaches call_tool_mcp.
    calls = []
    orig = child.session.client.call_tool_mcp

    async def spy(*a, **k):
        calls.append(a)
        return await orig(*a, **k)

    child.session.client.call_tool_mcp = spy
    run = await sup.run_action("store", "set_writable", {"name": "s3main"})
    assert run.kind == "muted"
    assert calls == []


# 15.F4.4 -- scenario "Unknown action on submit": a POST with an {action} that
# Supervisor.actions did not return answers 404 and calls no tool.
def test_f4_4_unknown_action_segment_is_404_and_calls_no_tool(server_factory, monkeypatch):
    called = []

    async def spy(self, ns, name, arguments, **kwargs):
        called.append((ns, name))

    monkeypatch.setattr("mcpflow.supervisor.Supervisor.run_action", spy)
    server, _h = start(server_factory, store_spec())
    with admin(server) as client:
        for action in ("nope", "list_stores", "hashed", "mcpflow_list_servers"):
            assert action_post(client, f"{PAGE}/{action}").status_code == 404
    assert called == [] and call_log(server) == []


# =============================================================================
# F5: one redaction owner for every surface
# =============================================================================


def _schema_block(card: str) -> str:
    m = re.search(r"<details>\s*<summary[^>]*>schema</summary>(.*?)</details>", card, re.DOTALL)
    assert m, "no schema disclosure in the card"
    return html.unescape(m.group(1))


# 15.F5.5 -- scenario "A configured secret in a result is redacted". A configured
# `env` secret echoed in a result renders as `***`, even when it arrives through
# a non-password field, because the redactor unions child_secrets(ns).
#
# 16.F5.3 -- tightened for Amendment 3 (F5): the refill `values` must ALSO mask
# the secret. `name` is a plain string field, but a configured secret typed into
# it renders `***` on EVERY echo surface, the re-filled control included, not
# only the result block. This is the "every echo surface" guarantee the
# section-15 test previously permitted to leak.
def test_f5_5_configured_secret_in_a_result_is_redacted(server_factory):
    server, _h = start(server_factory, store_spec(env={"API_KEY": SECRET}))
    with admin(server) as client:
        resp = action_post(client, PAGE + "/set_writable", data={"name": SECRET})
    assert resp.status_code == 200, resp.text
    # No echo surface holds the secret: not the result, not the re-filled form.
    assert SECRET not in resp.text
    m = re.search(r'<div class="result">(.*?)</div>', resp.text, re.DOTALL)
    assert m, "no result block"
    result = html.unescape(m.group(1))
    assert "writable: ***" in result
    # The re-filled `name` control shows `***`, not the posted configured secret.
    card = cards(resp.text)["set_writable"]
    name_input = control(card, "name")
    value = re.search(r'value="([^"]*)"', name_input)
    assert value and html.unescape(value.group(1)) == "***"


# 15.F5.5 -- scenario "A secret default in the raw schema is redacted". The
# collapsed raw schema of a password property shows no `default` value.
def test_f5_5_secret_default_in_the_raw_schema_is_redacted(server_factory):
    server, _h = start(server_factory, more_spec())
    with admin(server) as client:
        card = cards(client.get(PAGE).text)["defaulted"]
    # The password control carries no value on render.
    inputs = password_inputs(card)
    assert len(inputs) == 1 and "value=" not in inputs[0]
    # The raw schema disclosure drops the default of the secret property.
    schema = _schema_block(card)
    assert "D3FAULT-SECRET-9" not in card
    assert '"default"' not in schema
