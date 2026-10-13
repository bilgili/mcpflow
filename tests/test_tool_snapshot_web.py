"""Verifier tests for change `dashboard-tool-snapshot`: the tree and its poll.

Scenarios from `specs/web-ui/spec.md` (Tool tree poll), `specs/server-registry/
spec.md` (Snapshot read, callers of `Supervisor.tools`), and
`specs/tool-visibility/spec.md` (A muted action is marked and not submitted).

`server_factory` runs the app in a thread with its own event loop, so a test
here cannot await `session.probe`. It makes a snapshot stale with a patch of
`mcpflow.supervisor.SNAPSHOT_MAX_AGE` (the constant is read at call time, so
the patch reaches the thread) or with `session.probed_at = None`, and it polls
`/tools/tree?poll=1` in a bounded loop.

`probes` (the spy on `Supervisor._probe_child`) is shared with
`test_tool_snapshot.py`. It records the call when the probe is scheduled.

Scenario -> test map:

    The tree polls while a child starts                  test_the_tree_polls_while_a_child_starts_with_the_poll_url
    The tree does not poll when every child is settled   test_the_tree_does_not_poll_when_every_child_is_settled
    The tree polls while a snapshot probe runs           test_the_tree_polls_while_a_snapshot_probe_runs
    A poll answer starts no probe                        test_a_poll_answer_starts_no_probe
    The tree stops polling after the probe               test_the_poll_stops_for_two_children
    The poll shows a dead child as failed                test_the_poll_shows_a_dead_child_as_failed
    The poll route renders the tree collapsed            test_the_poll_route_renders_the_tree_collapsed_with_poll_one
    The parameter grants nothing                         test_poll_one_grants_nothing
    A mute answer shows the mute at once (+ controls)    test_a_control_answer_is_a_probing_render
    callers of Supervisor.tools                          test_the_api_tools_route_reads_the_snapshot_and_can_probe
    the same pair the tool rows use (tool-visibility)    test_the_tree_row_and_the_actions_form_agree_on_a_mute
"""

# ruff: noqa: F401, F811
# The fixtures come from sibling test modules by import, as the other test files
# do; the import then looks unused (F401) and a test parameter shadows it (F811).

from __future__ import annotations

import re
import time

import httpx
import pytest
from conftest import ADMIN_ACTOR, admin_reach, fake_child_spec, seed_registry
from test_admin_mcp import _seed as _seed_tokens
from test_admin_mcp import call_tool
from test_supervisor import make_supervisor
from test_tool_snapshot import probes
from test_user_routes import GH_ALICE, GH_BOB, make_site
from test_visibility import admin, tool_path

from mcpflow import supervisor as supervisor_mod
from mcpflow.registry import ServerKey
from mcpflow.supervisor import Supervisor

POLL_URL = 'hx-get="/tools/tree?poll=1"'


def _root(body: str) -> str:
    """The opening tag of the tree root."""
    return body[body.index('<div id="tools-tree"') :].split(">", 1)[0]


def _polls(body: str) -> bool:
    return POLL_URL in _root(body)


def _settle(client, timeout: float = 15.0) -> str:
    """Poll `/tools/tree?poll=1` until an answer carries no poll. Fail at the
    bound: a tree that never stops polling is the defect this guards."""
    deadline = time.monotonic() + timeout
    body = ""
    while time.monotonic() < deadline:
        body = client.get("/tools/tree?poll=1").text
        if not _polls(body):
            return body
        time.sleep(0.1)
    raise AssertionError("the tree still polled at the bound:\n" + _root(body))


def _row(body: str, name: str) -> str:
    rows = [r for r in body.split("<tr") if f"<code>{name}</code>" in r]
    assert len(rows) == 1, f"{name}: {len(rows)} rows"
    return rows[0]


def _group_status(body: str, ns: str) -> str:
    block = body.split(f'data-ns="{ns}"')[1].split("</summary>")[0]
    return re.search(r'class="status status-(\w+)"', block).group(1)


# --- Tool tree poll (web-ui) -------------------------------------------------


def test_the_tree_polls_while_a_child_starts_with_the_poll_url(server_factory):
    # Scenario: The tree polls while a child starts. D7.
    # A child in mode `hang` stays `starting` for the length of this request.
    server = server_factory(
        seed_registry(fake_child_spec("slow", "hang")), CHILD_START_TIMEOUT="30"
    )
    server.wait(starting=1)
    client = server.login()
    body = client.get("/tools/tree").text
    client.close()
    root = _root(body)
    assert POLL_URL in root
    assert 'hx-trigger="every 3s"' in root
    assert 'hx-target="#tools-tree"' in root
    assert 'hx-swap="outerHTML"' in root
    assert 'hx-sync="this:drop"' in root
    assert 'hx-disinherit="*"' in root


def test_the_tree_does_not_poll_when_every_child_is_settled(server_factory, monkeypatch):
    # Scenario: The tree does not poll when every child is settled.
    # Fresh snapshots: the age is raised so a slow box cannot make one stale.
    monkeypatch.setattr(supervisor_mod, "SNAPSHOT_MAX_AGE", 1e9)
    server = server_factory(
        seed_registry(
            fake_child_spec("alive", "good"),
            fake_child_spec("off", "good", enabled=False),
            fake_child_spec("broken", "fail"),
        )
    )
    server.wait(running=1, failed=1)
    client = server.login()
    body = client.get("/tools/tree").text
    client.close()
    assert _group_status(body, "alive") == "running"
    assert _group_status(body, "off") == "stopped"
    assert _group_status(body, "broken") == "failed"
    root = _root(body)
    assert "hx-get" not in root and "hx-trigger" not in root
    assert 'hx-disinherit="*"' in root


def test_the_tree_polls_while_a_snapshot_probe_runs(server_factory, monkeypatch, tmp_path):
    # Scenario: The tree polls while a snapshot probe runs. D3, D7.
    # Mutation: drop `probing` from the `polling` condition of the template.
    hang = tmp_path / "hang"
    server = server_factory(
        seed_registry(
            fake_child_spec("time", "action", env={"MCPFLOW_HANG_LIST": str(hang)})
        )
    )
    server.wait(running=1)
    monkeypatch.setattr(supervisor_mod, "SNAPSHOT_MAX_AGE", 0.0)  # every snapshot stale
    hang.write_text("")  # the probe of the load hangs
    client = server.login()
    try:
        body = client.get("/tools/tree").text  # returns at once: no wait for the child
        assert "time_list_stores" in body  # the old snapshot rows
        assert _polls(body)
        # The poll keeps going while the probe hangs, and starts no probe.
        assert _polls(client.get("/tools/tree?poll=1").text)
        hang.unlink()
        final = _settle(client)
        assert "time_list_stores" in final
    finally:
        client.close()
        if hang.exists():
            hang.unlink()


def test_a_poll_answer_starts_no_probe(server_factory, probes, monkeypatch, tmp_path):
    # Scenario: A poll answer starts no probe. D7, F1.
    # Mutation: pass `probe=True` for every request in `tools_tree`.
    monkeypatch.setattr(supervisor_mod, "SNAPSHOT_MAX_AGE", 1e9)
    grow = tmp_path / "grow"
    server = server_factory(
        seed_registry(
            fake_child_spec("time", "good"),
            fake_child_spec("weather", "grow", env={"MCPFLOW_GROW": str(grow)}),
        )
    )
    server.wait(running=2)
    sup = server.supervisor
    client = server.login()
    try:
        assert "weather_get_current_time" in client.get("/tools/tree").text
        assert probes == []  # fresh: the load probed nothing
        grow.touch()
        session = sup.get(ServerKey(None, "weather")).session
        session.probed_at = None  # weather went stale after the last load
        body = client.get("/tools/tree?poll=1").text
        assert "weather_get_current_time" in body  # the old rows
        assert "weather_extra" not in body
        assert probes == []
        assert session.probe is None
        assert not _polls(body)
        # Control: the same stale snapshot starts a probe on a probing render.
        client.get("/tools/tree")
        assert len(probes) == 1
        assert "weather_extra" in _settle(client)
    finally:
        client.close()


def test_the_poll_stops_for_two_children(server_factory, probes, monkeypatch, tmp_path):
    # Scenario: The tree stops polling after the probe. D7, F1, A4.
    # Every snapshot is stale at every request (age 0.0), the case that made a
    # probing poll loop for ever with two children.
    # Mutation: let a poll answer probe stale children (the loop then runs to
    # its bound).
    monkeypatch.setattr(supervisor_mod, "SNAPSHOT_MAX_AGE", 0.0)
    grow = tmp_path / "grow"
    server = server_factory(
        seed_registry(
            fake_child_spec("time", "good"),
            fake_child_spec("weather", "grow", env={"MCPFLOW_GROW": str(grow)}),
        )
    )
    server.wait(running=2)
    grow.touch()
    client = server.login()
    try:
        first = client.get("/tools/tree").text  # the one probing render
        assert _polls(first)
        last = _settle(client)
        assert "weather_extra" in last  # the probe of the load listed the new tool
        assert "time_get_current_time" in last
        assert len(probes) == 2  # one per child, from the load; the polls added none
    finally:
        client.close()


def test_the_poll_shows_a_dead_child_as_failed(server_factory, monkeypatch, tmp_path):
    # Scenario: The poll shows a dead child as failed. D4 step 6, D7.
    brk = tmp_path / "brk"
    server = server_factory(
        seed_registry(
            fake_child_spec("time", "action", env={"MCPFLOW_BREAK": str(brk)})
        )
    )
    server.wait(running=1)
    monkeypatch.setattr(supervisor_mod, "SNAPSHOT_MAX_AGE", 0.0)
    brk.write_text("")  # list_tools now fails
    client = server.login()
    try:
        before = client.get("/tools/tree").text  # a probing render starts the probe
        assert _polls(before)
        after = _settle(client)
        assert _group_status(after, "time") == "failed"
        assert not _polls(after)
    finally:
        client.close()


def test_the_poll_route_renders_the_tree_collapsed_with_poll_one(server_factory):
    # Scenario: The poll route renders the tree collapsed.
    server = server_factory(seed_registry(fake_child_spec("time", "two")))
    server.wait(running=1)
    client = server.login()
    resp = client.get("/tools/tree?poll=1")
    client.close()
    assert resp.status_code == 200
    body = resp.text
    assert "<!doctype" not in body.lower()  # the partial only
    assert '<div id="tools-tree"' in body
    groups = re.findall(r'<details[^>]*class="ns-group"[^>]*>', body)
    assert groups  # the child and the built-in group
    assert not any(re.search(r"\sopen\b", g) for g in groups)
    assert "time_convert_time" in body


def test_poll_one_grants_nothing(make_site, probes, monkeypatch):
    # Rule: The parameter grants nothing. D7.
    # A user with a narrower `Reach` gets only the rows of that `Reach`, also
    # with `poll=1`; `poll=0` and `poll=` are probing renders.
    site = make_site()
    monkeypatch.setattr(supervisor_mod, "SNAPSHOT_MAX_AGE", 0.0)
    sup = site.app.state.supervisor

    def idle() -> None:
        deadline = time.monotonic() + 15
        while sup.get(GH_ALICE).session.probe is not None:
            assert time.monotonic() < deadline, "a probe never ended"
            time.sleep(0.05)

    resp = site.request("alice", "GET", "/tools/tree?poll=1")
    assert resp.status_code == 200
    assert GH_ALICE.ref in resp.text
    assert GH_BOB.ref not in resp.text
    assert 'data-ns="time"' not in resp.text  # the admin server is outside her Reach
    assert probes == []  # poll=1 starts no probe
    for query in ("?poll=0", "?poll="):
        idle()
        before = len(probes)
        resp = site.request("alice", "GET", "/tools/tree" + query)
        assert resp.status_code == 200
        assert GH_ALICE.ref in resp.text and GH_BOB.ref not in resp.text
        assert len(probes) == before + 1, query
    # The probes were of her Reach only.
    assert {ref for ref, _ in probes} == {GH_ALICE.ref}
    idle()


def test_a_control_answer_is_a_probing_render(
    server_factory, probes, monkeypatch, tmp_path
):
    # Scenarios: A mute answer shows the mute at once; Tool tree poll (every
    # control answer is a probing render). D3, D7.
    hang = tmp_path / "hang"
    server = server_factory(
        seed_registry(
            fake_child_spec("time", "action", env={"MCPFLOW_HANG_LIST": str(hang)})
        )
    )
    server.wait(running=1)
    monkeypatch.setattr(supervisor_mod, "SNAPSHOT_MAX_AGE", 0.0)  # stale
    hang.write_text("")  # a probe of `time` would hang
    try:
        with admin(server) as client:
            resp = client.post(tool_path("time"), data={"tool": "list_stores"})  # mute
            assert resp.status_code == 200  # answered at once, no wait for the hang
            body = resp.text
            assert "hidden-tool" in _row(body, "time_list_stores")
            assert "hidden-tool" not in _row(body, "time_get_current_time")
            assert len(probes) == 1  # the control answer started the probe
            assert _polls(body)  # and the tree polls while it runs
            hang.unlink()
            _settle(client)
    finally:
        if hang.exists():
            hang.unlink()


def test_the_api_tools_route_reads_the_snapshot_and_can_probe(
    server_factory, probes, monkeypatch, tmp_path
):
    # Scenario: callers of `Supervisor.tools` (Snapshot read). D8.
    # `api.py` and `admin_mcp.py` keep the default `probe=True`.
    hang = tmp_path / "hang"
    holder: dict = {}
    server = server_factory(
        _seed_tokens(
            holder,
            fake_child_spec("time", "action", env={"MCPFLOW_HANG_LIST": str(hang)}),
        )
    )
    server.wait(running=1)
    keywords: list[dict] = []
    real = Supervisor.tools

    async def spy(self, reach, **kw):
        keywords.append(kw)
        return await real(self, reach, **kw)

    monkeypatch.setattr(Supervisor, "tools", spy)
    monkeypatch.setattr(supervisor_mod, "SNAPSHOT_MAX_AGE", 0.0)
    hang.write_text("")
    try:
        resp = httpx.get(
            server.base_url + "/api/tools",
            headers={"Authorization": f"Bearer {holder['admin']}"},
            timeout=5,
        )
        assert resp.status_code == 200  # answered at once, no wait for the hung child
        assert "time_list_stores" in resp.text  # the old snapshot rows
        assert len(probes) == 1
        assert len(keywords) == 1 and keywords[0].get("probe", True) is True
        # The admin MCP tool reads the same way: the default, so it may probe.
        call_tool(server.base_url, holder["admin"], "mcpflow_list_tools", {})
        assert len(keywords) == 2
        assert all(kw.get("probe", True) is True for kw in keywords)
    finally:
        hang.unlink()


@pytest.mark.asyncio
async def test_the_tree_row_and_the_actions_form_agree_on_a_mute(make_supervisor):
    # Rule: the same pair the tool rows use (tool-visibility, A muted action is
    # marked and not submitted). D9.
    sup = make_supervisor()
    child = await sup.add(
        fake_child_spec("store", "action", actions=True), ADMIN_ACTOR
    )
    await child.task
    assert child.status == "running"
    key = ServerKey(None, "store")
    reach = admin_reach(sup)
    rows = [v for v in await sup.tools(reach) if v.namespace == "store"]
    assert rows and all(v.visible for v in rows)
    actions = await sup.actions(key)
    assert actions and not any(a.disabled for a in actions)
    sup.set_namespace_muted(key, True, ADMIN_ACTOR)
    rows = [v for v in await sup.tools(reach) if v.namespace == "store"]
    assert rows and not any(v.visible for v in rows)
    actions = await sup.actions(key)
    assert actions
    assert all(a.disabled and a.reason == "muted" for a in actions)
