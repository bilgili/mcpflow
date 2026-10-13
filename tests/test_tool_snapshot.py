"""Verifier tests for change `dashboard-tool-snapshot`: the snapshot, the render,
the probe, the leases, and the teardown.

Every test derives from a scenario in
`openspec/changes/dashboard-tool-snapshot/specs/**` or from a frozen interface
in that change's `design.md`, never from the implementation. A `custom` child
that runs `fake_mcp_server.py` over stdio stands in for a real child, so the
tests hold real subprocesses, real leases, and real transports.

How the tests observe a probe:

- `probes` is a spy on `Supervisor._probe_child`. It records the call when
  `_schedule_probe` creates the coroutine, so a probe that never starts shows
  as zero calls with no need to yield the loop first.
- `leases` is a spy on `Supervisor._lease`. A read of the child needs a lease,
  so zero lease calls proves that no `list_tools` went to the child.
- A test makes a snapshot stale with `session.probed_at = None`, or with a
  patch of `mcpflow.supervisor.SNAPSHOT_MAX_AGE`.
- A child read hangs with `MCPFLOW_HANG_LIST` or fails with `MCPFLOW_BREAK`.

No task outlives a test: each test awaits the probe it started, or cancels it
and awaits the cancel. `make_supervisor` shuts every supervisor down.

Scenario -> test map:

    SR-A  A start seeds the snapshot                    test_a_start_seeds_the_snapshot
    SR-A  (tool_count stays; start failure seeds none)  test_a_start_failure_seeds_nothing_and_tool_count_stays
    SR-A  The snapshot holds a muted tool               test_the_snapshot_holds_a_muted_tool
    SR-B  A mute answer shows the mute at once          test_a_mute_answer_shows_the_mute_at_once
    SR-A  A new generation starts with its own snapshot test_a_new_generation_starts_with_its_own_snapshot
    SR-B  A slow child does not delay the tree          test_a_slow_child_does_not_delay_the_render
    SR-B  A closing generation contributes no row       test_a_closing_generation_contributes_no_row_and_starts_no_probe
    SR-B  A malformed schema does not fail the render   test_a_malformed_schema_does_not_fail_the_render
    SR-C  A stale render starts one probe               test_two_stale_renders_start_one_probe
    SR-C  A fresh render starts no probe                test_a_fresh_render_starts_no_probe
    SR-C  A render with probe false starts no probe     test_a_render_with_probe_false_starts_no_probe
    SR-C  A probe updates the snapshot                  test_a_probe_updates_the_snapshot
    SR-C  A probe failure marks the child failed        test_a_probe_failure_marks_the_child_failed
    SR-C  A probe of a superseded session reads nothing test_a_probe_of_a_superseded_session_reads_nothing
    SR-F/G A stale probe failure never marks gen g+1    test_a_swallowed_cancel_marks_nothing_on_the_next_generation
    SR-D  A probe is in flight / not / cancelled        test_probing_*
    SR-F  A read takes and releases a lease             test_a_probe_takes_and_releases_a_lease
    SR-G  Teardown cancels a hung snapshot probe        test_teardown_cancels_a_hung_probe_of_a_stdio_child
    SR-G  (cancel not awaited, raises nothing)          test_the_probe_cancel_is_not_awaited_and_raises_nothing
"""

# ruff: noqa: F401, F811
# The fixtures come from sibling test modules by import, as the other test files
# do; the import then looks unused (F401) and a test parameter shadows it (F811).

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import logging
import time
import warnings
from types import SimpleNamespace

import pytest
from conftest import ADMIN_ACTOR, admin_reach, fake_child_spec, run_stale_probe
from mcp.types import Tool
from test_supervisor import make_supervisor
from test_visibility import _seed as _seed_logged
from test_visibility import admin, mute, tool_names, tool_path

from mcpflow import supervisor as supervisor_mod
from mcpflow.registry import ServerKey
from mcpflow.supervisor import ChildSession, Supervisor, _summarize_schema

# --- helpers -----------------------------------------------------------------


async def _wait(pred, timeout: float = 10.0) -> None:
    """Poll `pred` until true. The lease count is the only cross-task state a
    test waits on; a fixed sleep would race a slow box."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("condition never held within the timeout")


async def _start(sup: Supervisor, ns: str = "time", mode: str = "two", **extra):
    child = await sup.add(fake_child_spec(ns, mode, **extra), ADMIN_ACTOR)
    await child.task
    assert child.status == "running"
    return child


async def _cancel(task: asyncio.Task) -> None:
    """Cancel a probe the test started and await the end, so none leaks."""
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)


def _rows(views, ns: str) -> list:
    return [v for v in views if v.namespace == ns]


def _names(views, ns: str) -> list[str]:
    return [v.name for v in _rows(views, ns)]


@pytest.fixture
def probes(monkeypatch):
    """Every `_probe_child` call: `(ref, session)`, recorded at the call."""
    calls: list = []
    real = Supervisor._probe_child

    def spy(self, child, session):
        calls.append((child.spec.key.ref, session))
        return real(self, child, session)

    monkeypatch.setattr(Supervisor, "_probe_child", spy)
    return calls


@pytest.fixture
def leases(monkeypatch):
    """Every `_lease` call: the ref of the child. A read needs one."""
    calls: list = []
    real = Supervisor._lease

    def spy(self, child):
        calls.append(child.spec.key.ref)
        return real(self, child)

    monkeypatch.setattr(Supervisor, "_lease", spy)
    return calls


class _Read:
    """Stands for the leased client of one probe: the read is the test's."""

    def __init__(self, read) -> None:
        self._read = read

    async def list_tools(self):
        return await self._read()


def _patch_first_read(monkeypatch, read) -> list:
    """The first `_lease` after the patch yields a client whose `list_tools`
    runs `read`; the real lease is still taken and released. Later leases are
    untouched, so a restart still starts a real child."""
    calls: list = []
    real = Supervisor._lease

    @contextlib.asynccontextmanager
    async def lease(self, child):
        calls.append(1)
        async with real(self, child) as client:
            yield _Read(read) if len(calls) == 1 else client

    monkeypatch.setattr(Supervisor, "_lease", lease)
    return calls


# --- Tool snapshot of a generation (server-registry) -------------------------


@pytest.mark.asyncio
async def test_a_start_seeds_the_snapshot(make_supervisor, probes):
    # Scenario: A start seeds the snapshot. D2.
    # Mutation: delete the seed lines of `_run_start`.
    sup = make_supervisor()
    child = await _start(sup, "time", "two")
    session = child.session
    assert sorted(t.name for t in session.tools) == ["convert_time", "get_current_time"]
    assert session.probed_at is not None
    views = await sup.tools(admin_reach(sup))
    assert sorted(_names(views, "time")) == ["time_convert_time", "time_get_current_time"]
    assert probes == []  # the first render starts no probe
    assert session.probe is None


@pytest.mark.asyncio
async def test_a_start_failure_seeds_nothing_and_tool_count_stays(
    make_supervisor, tmp_path
):
    # Scenarios: A start seeds the snapshot (failure side); Dashboard probe
    # ignores the cache (tool_count). D2, gate Q2.
    # Mutation: write `child.tool_count` in `_probe_child`.
    sup = make_supervisor()
    bad = await sup.add(fake_child_spec("broken", "fail"), ADMIN_ACTOR)
    await bad.task
    assert bad.status == "failed"
    assert getattr(bad.session, "tools", None) is None
    assert _rows(await sup.tools(admin_reach(sup)), "broken") == []

    grow = tmp_path / "grow"
    child = await _start(sup, "grow", "grow", env={"MCPFLOW_GROW": str(grow)})
    session = child.session
    assert child.tool_count == 1
    grow.touch()  # the child adds `extra`
    await run_stale_probe(sup, admin_reach(sup), session)
    assert "extra" in [t.name for t in session.tools]
    assert child.tool_count == 1  # the count of the start read, not the probe


def test_the_snapshot_holds_a_muted_tool(server_factory):
    # Scenario: The snapshot holds a muted tool. D1, D9.
    # Mutation: filter the muted tool out of the snapshot or of the row builder.
    holder: dict = {}
    server = server_factory(_seed_logged(fake_child_spec("time", "two"), holder=holder))
    server.wait(running=1)
    child = server.supervisor.get(ServerKey(None, "time"))
    session = child.session
    assert "time_convert_time" in tool_names(server.base_url, holder["clear"])
    with admin(server) as client:
        mute(client, tool_path("time"), tool="convert_time")
        body = client.get("/tools/tree?poll=1").text
    # The snapshot is raw: the muted tool stays in it.
    assert "convert_time" in [t.name for t in session.tools]
    # The row stays on the dashboard, marked hidden.
    row = [r for r in body.split("<tr") if "<code>time_convert_time</code>" in r]
    assert len(row) == 1 and "hidden-tool" in row[0]
    # /mcp does not publish it, and its sibling survives.
    names = tool_names(server.base_url, holder["clear"])
    assert "time_convert_time" not in names
    assert "time_get_current_time" in names
    assert child.provider in server.supervisor.table.providers  # not remounted


@pytest.mark.asyncio
async def test_a_mute_answer_shows_the_mute_at_once(make_supervisor, probes):
    # Scenario: A mute answer shows the mute at once.
    # Mutation: filter the muted tool in `_snapshot_views` (the row vanishes),
    # or read the visibility at the seed instead of at the render.
    sup = make_supervisor()
    child = await _start(sup, "time", "two")
    key = ServerKey(None, "time")
    before = {v.tool: v.visible for v in _rows(await sup.tools(admin_reach(sup)), "time")}
    assert before == {"get_current_time": True, "convert_time": True}
    sup.set_tool_muted(key, "convert_time", True, ADMIN_ACTOR)
    after = {v.tool: v.visible for v in _rows(await sup.tools(admin_reach(sup)), "time")}
    assert after == {"get_current_time": True, "convert_time": False}
    assert probes == []  # no probe of the muted child
    assert "convert_time" in [t.name for t in child.session.tools]
    sup.set_tool_muted(key, "convert_time", False, ADMIN_ACTOR)
    assert all(v.visible for v in _rows(await sup.tools(admin_reach(sup)), "time"))


@pytest.mark.asyncio
async def test_a_new_generation_starts_with_its_own_snapshot(make_supervisor):
    # Scenario: A new generation starts with its own snapshot. SR-E, D1.
    sup = make_supervisor()
    child = await _start(sup, "time", "two")
    session1 = child.session
    tools1 = session1.tools
    await sup.restart(ServerKey(None, "time"), ADMIN_ACTOR)
    await child.task
    session2 = child.session
    assert session2 is not session1
    assert session2.generation > session1.generation
    assert session1.state == "closed"
    assert session2.state == "open"
    assert session2.tools is not tools1
    assert sorted(t.name for t in session2.tools) == ["convert_time", "get_current_time"]
    assert session2.probed_at is not None
    assert session2.probed_at >= session1.probed_at


# --- Snapshot read (server-registry) -----------------------------------------


@pytest.mark.asyncio
async def test_a_slow_child_does_not_delay_the_render(make_supervisor, tmp_path):
    # Scenario: A slow child does not delay the tree. D3.
    # Mutation: restore `asyncio.gather` over the probes in `tools`.
    sup = make_supervisor()
    hang = tmp_path / "hang"
    child = await _start(
        sup, "slow", "action", env={"MCPFLOW_HANG_LIST": str(hang)}
    )
    reach = admin_reach(sup)
    session = child.session
    old = _names(await sup.tools(reach), "slow")
    assert old
    hang.write_text("")  # the next list never returns
    session.probed_at = None
    try:
        views = await asyncio.wait_for(sup.tools(reach), 2)
        assert _names(views, "slow") == old
        probe = session.probe
        assert probe is not None and not probe.done()
        assert sup.probing(reach) is True
    finally:
        probe = session.probe
        if probe is not None:
            await _cancel(probe)
        hang.unlink()
    await _wait(lambda: session.leases == 0)


@pytest.mark.asyncio
async def test_a_closing_generation_contributes_no_row_and_starts_no_probe(
    make_supervisor, probes
):
    # Scenario: A closing generation contributes no row. D3 step 2.
    # Mutation: drop the check `session.state != "open"` in `tools`.
    sup = make_supervisor()
    child = await _start(sup, "time", "two")
    reach = admin_reach(sup)
    session = child.session
    session.state = "closing"  # a teardown holds the generation; status stays running
    session.probed_at = None
    try:
        views = await sup.tools(reach)
        assert _rows(views, "time") == []
        assert probes == []
        assert session.probe is None
        assert sup.probing(reach) is False
        assert child.status == "running"
    finally:
        session.state = "open"


def test_summarize_schema_is_total():
    # Scenario: A malformed schema does not fail the render (unit side). D11.
    assert _summarize_schema(None) == ""
    assert _summarize_schema({}) == ""
    assert _summarize_schema({"properties": []}) == ""
    assert "any" in _summarize_schema({"properties": {"flag": True}})
    assert _summarize_schema({"properties": {"tz": {"type": "string"}}}) == "tz: string"


@pytest.mark.asyncio
async def test_a_malformed_schema_does_not_fail_the_render(make_supervisor):
    # Scenario: A malformed schema does not fail the render. D11, F2.
    # Mutation: read `tool.inputSchema` in `_snapshot_views`.
    sup = make_supervisor()
    child = await _start(sup, "odd", "good")
    session = child.session
    session.tools = [
        Tool(name="list_props", description="d1", input_schema={"properties": []}),
        Tool(
            name="bool_prop",
            description="d2",
            input_schema={"type": "object", "properties": {"flag": True}},
        ),
        Tool(
            name="well_formed",
            description="d3",
            input_schema={"type": "object", "properties": {"tz": {"type": "string"}}},
        ),
        # A bare object that has the field `input_schema` and nothing else:
        # only a builder that reads `tool.input_schema` can summarise it. (With
        # FastMCP loaded, `Tool.inputSchema` is a deprecated alias that still
        # answers, so a real `Tool` alone cannot tell the two reads apart.)
        SimpleNamespace(
            name="duck",
            description=None,
            input_schema={"type": "object", "properties": {"n": {"type": "integer"}}},
        ),
    ]
    with warnings.catch_warnings():
        # The deprecated alias warns; the render must not touch it.
        warnings.filterwarnings("error", message=".*inputSchema.*")
        views = _rows(await sup.tools(admin_reach(sup)), "odd")
    assert [v.name for v in views] == [
        "odd_list_props",
        "odd_bool_prop",
        "odd_well_formed",
        "odd_duck",
    ]
    by_name = {v.tool: v for v in views}
    assert by_name["list_props"].schema_summary == ""
    assert "any" in by_name["bool_prop"].schema_summary
    # A well-formed Tool gives a summary: the builder reads `input_schema`.
    assert by_name["well_formed"].schema_summary == "tz: string"
    assert by_name["duck"].schema_summary == "n: integer"
    assert by_name["duck"].description == ""
    assert child.status == "running"


# --- Snapshot probe (server-registry) ----------------------------------------


@pytest.mark.asyncio
async def test_two_stale_renders_start_one_probe(make_supervisor, probes, tmp_path):
    # Scenario: A stale render starts one probe. D5.
    # Mutation: drop `session.probe is None or session.probe.done()` in
    # `_schedule_probe`.
    sup = make_supervisor()
    hang = tmp_path / "hang"
    child = await _start(sup, "time", "action", env={"MCPFLOW_HANG_LIST": str(hang)})
    reach = admin_reach(sup)
    session = child.session
    old = _names(await sup.tools(reach), "time")
    hang.write_text("")
    session.probed_at = None
    first = await sup.tools(reach)
    second = await sup.tools(reach)  # the probe has not ended
    assert _names(first, "time") == old
    assert _names(second, "time") == old
    assert len(probes) == 1
    task = session.probe
    assert task is not None and not task.done()
    hang.unlink()
    await asyncio.wait_for(task, 15)
    assert session.probe is None
    assert len(probes) == 1


@pytest.mark.asyncio
async def test_a_fresh_render_starts_no_probe(make_supervisor, probes, leases, monkeypatch):
    # Scenario: A fresh render starts no probe. D3, SR-C age rule.
    # Mutation: invert the stale test in `tools`.
    assert supervisor_mod.SNAPSHOT_MAX_AGE == 10.0
    sup = make_supervisor()
    child = await _start(sup, "time", "two")
    reach = admin_reach(sup)
    session = child.session
    for _ in range(3):
        await sup.tools(reach)
    assert probes == [] and leases == []
    assert session.leases == 0 and session.probe is None
    # Just under the age: still fresh.
    session.probed_at = time.monotonic() - (supervisor_mod.SNAPSHOT_MAX_AGE - 3)
    await sup.tools(reach)
    assert probes == []
    # Over the age: stale, one probe.
    session.probed_at = time.monotonic() - (supervisor_mod.SNAPSHOT_MAX_AGE + 1)
    await sup.tools(reach)
    assert len(probes) == 1
    await asyncio.wait_for(session.probe, 15)
    assert time.monotonic() - session.probed_at < supervisor_mod.SNAPSHOT_MAX_AGE
    # The age is read at call time: a patched constant makes the next render stale.
    monkeypatch.setattr(supervisor_mod, "SNAPSHOT_MAX_AGE", 0.0)
    await sup.tools(reach)
    assert len(probes) == 2
    await asyncio.wait_for(session.probe, 15)


@pytest.mark.asyncio
async def test_a_render_with_probe_false_starts_no_probe(
    make_supervisor, probes, leases
):
    # Scenario: A render with probe false starts no probe. D7, F1, F8.
    # Mutation: ignore the keyword `probe` in `tools`.
    sup = make_supervisor()
    child = await _start(sup, "time", "two")
    reach = admin_reach(sup)
    session = child.session
    old = _names(await sup.tools(reach), "time")
    session.probed_at = None
    views = await sup.tools(reach, probe=False)
    assert _names(views, "time") == old
    assert probes == []
    assert leases == []  # the child received no list_tools
    assert session.probe is None
    assert session.probed_at is None  # a render with probe false stamps nothing


@pytest.mark.asyncio
async def test_a_probe_updates_the_snapshot(make_supervisor, tmp_path):
    # Scenario: A probe updates the snapshot. D4 step 4, D9.
    sup = make_supervisor()
    grow = tmp_path / "grow"
    child = await _start(sup, "grow", "grow", env={"MCPFLOW_GROW": str(grow)})
    reach = admin_reach(sup)
    session = child.session
    assert _names(await sup.tools(reach), "grow") == ["grow_get_current_time"]
    providers = list(sup.table.providers)
    provider = child.provider
    stamp = session.probed_at
    grow.touch()
    await run_stale_probe(sup, reach, session)
    assert "extra" in [t.name for t in session.tools]
    assert session.probed_at is not None and session.probed_at > stamp
    assert session.probe is None
    # Display-only: the probe success remounts and restatuses nothing.
    assert child.status == "running"
    assert child.provider is provider
    assert len(sup.table.providers) == len(providers)
    assert all(a is b for a, b in zip(sup.table.providers, providers, strict=True))
    assert sorted(_names(await sup.tools(reach), "grow")) == [
        "grow_extra",
        "grow_get_current_time",
    ]


@pytest.mark.asyncio
async def test_a_probe_failure_marks_the_child_failed(make_supervisor, tmp_path):
    # Scenario: A probe failure marks the child failed. D4 step 6, gate Q3.
    # Mutation: write the snapshot (tools or probed_at) in the failure path.
    sup = make_supervisor()
    brk = tmp_path / "brk"
    child = await _start(sup, "time", "action", env={"MCPFLOW_BREAK": str(brk)})
    reach = admin_reach(sup)
    session = child.session
    tools_before = session.tools
    stamp_before = session.probed_at = time.monotonic() - 60  # stale, known value
    assert sup.table.providers
    brk.write_text("")  # list_tools now raises
    await sup.tools(reach)
    await asyncio.wait_for(session.probe, 15)
    assert child.status == "failed"
    assert child.last_error
    assert sup.table.providers == []
    # The failure path writes no snapshot and no stamp.
    assert session.tools is tools_before
    assert session.probed_at == stamp_before
    assert session.probe is None
    # The failed child contributes no row.
    assert _rows(await sup.tools(reach), "time") == []


@pytest.mark.asyncio
async def test_a_probe_failure_scrubs_the_secrets(make_supervisor, monkeypatch):
    # Scenario: A probe failure marks the child failed ("scrubbed message").
    # The secret set is captured before the first await (D4 step 1).
    secret = "ZZ-snapshot-secret-0001"
    sup = make_supervisor()
    child = await _start(sup, "time", "two", env={"MCP_API_KEY": secret})

    async def read():
        raise RuntimeError(f"auth rejected for {secret}")

    _patch_first_read(monkeypatch, read)
    session = child.session
    await run_stale_probe(sup, admin_reach(sup), session)
    assert child.status == "failed"
    assert secret not in (child.last_error or "")
    assert "auth rejected" in child.last_error


@pytest.mark.asyncio
async def test_a_probe_of_a_superseded_session_reads_nothing(
    make_supervisor, probes, leases
):
    # Scenario: A probe of a superseded session reads nothing. D4 step 2, F3.
    # Mutation: drop step 2 of `_probe_child` (the lease then lands on the new
    # session).
    sup = make_supervisor()
    child = await _start(sup, "time", "two")
    session1 = child.session
    session1.probed_at = None
    tools1 = session1.tools
    session2 = ChildSession(
        namespace="time",
        generation=session1.generation + 1,
        transport=session1.transport,
        client=None,
        state="open",
    )
    task = asyncio.create_task(sup._probe_child(child, session1))
    child.session = session2  # before the task takes its first step
    try:
        await asyncio.wait_for(task, 10)
    finally:
        child.session = session1  # the real child must still be torn down
    assert task.exception() is None
    assert session1.probed_at is not None  # the stamp of the old generation only
    assert session1.tools is tools1
    assert leases == []  # no lease, so no request reached the child
    assert session1.leases == 0 and session2.leases == 0
    assert session2.tools is None and session2.probed_at is None
    assert session2.probe is None
    assert child.status == "running" and child.last_error is None


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["raise", "return"])
async def test_a_swallowed_cancel_marks_nothing_on_the_next_generation(
    make_supervisor, monkeypatch, outcome
):
    # SR-F ("A stale probe failure never marks the next generation") and SR-G:
    # FastMCP can swallow the teardown cancel of a dead child (design F3), so
    # the probe of generation 1 outlives the restart and ends after generation
    # 2 is `running`. The read below swallows the cancel, then waits for the
    # test, then raises (a failure) or returns (a stale list).
    # Mutation 1: drop the identity check in the failure path.
    # Mutation 2: write `child.session.tools` in step 4 (outcome "return").
    monkeypatch.setattr(supervisor_mod, "LEASE_DRAIN_TIMEOUT", 0.3)
    sup = make_supervisor()
    child = await _start(sup, "time", "two")
    session1 = child.session
    entered, proceed = asyncio.Event(), asyncio.Event()
    stale = [Tool(name="stale_g1", input_schema={"type": "object"})]

    async def read():
        entered.set()
        while not proceed.is_set():
            try:
                await proceed.wait()
            except asyncio.CancelledError:
                continue  # swallowed, as FastMCP does for a dead child
        if outcome == "raise":
            raise RuntimeError("session closed")
        return stale

    _patch_first_read(monkeypatch, read)
    session1.probed_at = None
    await sup.tools(admin_reach(sup))
    probe = session1.probe
    assert probe is not None
    await asyncio.wait_for(entered.wait(), 10)
    # The restart cancels the probe in `_teardown`; the read swallows it, so
    # the drain runs to its (patched) bound and generation 2 starts.
    await asyncio.wait_for(sup.restart(ServerKey(None, "time"), ADMIN_ACTOR), 30)
    await child.task
    session2 = child.session
    assert session2 is not session1 and child.status == "running"
    tools2 = list(session2.tools)
    stamp2 = session2.probed_at
    assert not probe.done()
    proceed.set()
    await asyncio.wait_for(probe, 15)
    assert probe.exception() is None
    # The late end of the probe of generation 1 touched nothing of generation 2.
    assert child.status == "running"
    assert child.last_error is None
    assert child.session is session2
    assert session2.tools == tools2
    assert "stale_g1" not in [t.name for t in session2.tools]
    assert session2.probed_at == stamp2
    assert child.provider in sup.table.providers


# --- Probe in flight (server-registry) ---------------------------------------


@pytest.mark.asyncio
async def test_probing_is_true_while_a_probe_is_live(make_supervisor, tmp_path):
    # Scenario: A probe is in flight.
    sup = make_supervisor()
    hang = tmp_path / "hang"
    child = await _start(sup, "time", "action", env={"MCPFLOW_HANG_LIST": str(hang)})
    reach = admin_reach(sup)
    session = child.session
    hang.write_text("")
    session.probed_at = None
    try:
        await sup.tools(reach)
        assert not session.probe.done()
        assert sup.probing(reach) is True
        # A Reach that holds no key of the child gives False.
        empty = dataclasses.replace(reach, keys=())
        assert sup.probing(empty) is False
    finally:
        await _cancel(session.probe)
        hang.unlink()
    await _wait(lambda: session.leases == 0)


@pytest.mark.asyncio
async def test_probing_is_false_with_no_probe_and_after_a_probe_ends(make_supervisor):
    # Scenario: No probe is in flight.
    sup = make_supervisor()
    child = await _start(sup, "time", "two")
    reach = admin_reach(sup)
    session = child.session
    assert sup.probing(reach) is False
    await run_stale_probe(sup, reach, session)
    assert sup.probing(reach) is False


@pytest.mark.asyncio
async def test_probing_is_false_for_a_closing_generation_with_a_cancelled_probe(
    make_supervisor, tmp_path
):
    # Scenario: A cancelled probe of a closing generation is not in flight.
    # The state of `_teardown` right after its detach block: `closing`, the
    # probe cancelled, the status still `running`.
    # Mutation: drop `session.state == "open"` from `probing`.
    sup = make_supervisor()
    hang = tmp_path / "hang"
    child = await _start(sup, "time", "action", env={"MCPFLOW_HANG_LIST": str(hang)})
    reach = admin_reach(sup)
    session = child.session
    hang.write_text("")
    session.probed_at = None
    await sup.tools(reach)
    probe = session.probe
    assert sup.probing(reach) is True
    session.state = "closing"
    probe.cancel()  # the cancel is requested, the task has not ended yet
    try:
        assert child.status == "running"
        assert sup.probing(reach) is False
    finally:
        await asyncio.gather(probe, return_exceptions=True)
        session.state = "open"
        hang.unlink()
    await _wait(lambda: session.leases == 0)


@pytest.mark.asyncio
async def test_a_done_probe_task_is_no_probe_and_the_next_stale_render_replaces_it(
    make_supervisor, probes
):
    # SR-D / SR-C: the readers of `session.probe` treat a done task as no probe.
    # Mutation: drop `.done()` from `probing` or from `_schedule_probe`.
    sup = make_supervisor()
    child = await _start(sup, "time", "two")
    reach = admin_reach(sup)
    session = child.session
    done = asyncio.create_task(asyncio.sleep(0))
    await done
    session.probe = done
    assert sup.probing(reach) is False
    session.probed_at = None
    await sup.tools(reach)
    assert len(probes) == 1
    assert session.probe is not done and not session.probe.done()
    await asyncio.wait_for(session.probe, 15)


# --- Transport leases and teardown (server-registry) -------------------------


@pytest.mark.asyncio
async def test_a_probe_takes_and_releases_a_lease(make_supervisor, tmp_path):
    # Scenario: A read takes and releases a lease (the snapshot probe).
    sup = make_supervisor()
    hang = tmp_path / "hang"
    child = await _start(sup, "time", "action", env={"MCPFLOW_HANG_LIST": str(hang)})
    session = child.session
    assert session.leases == 0
    hang.write_text("")  # hold the read
    session.probed_at = None
    await sup.tools(admin_reach(sup))
    task = session.probe
    await _wait(lambda: session.leases == 1)
    assert not task.done()
    hang.unlink()  # release the read
    await asyncio.wait_for(task, 15)
    assert session.leases == 0


@pytest.mark.asyncio
async def test_teardown_cancels_a_hung_probe_of_a_stdio_child(
    make_supervisor, tmp_path, caplog
):
    # Scenario: Teardown cancels a hung snapshot probe. D6, F4.
    # Mutation: delete the `session.probe.cancel()` line in `_teardown`.
    sup = make_supervisor()
    hang = tmp_path / "hang"
    child = await _start(sup, "slow", "action", env={"MCPFLOW_HANG_LIST": str(hang)})
    session = child.session
    hang.write_text("")
    session.probed_at = None
    await sup.tools(admin_reach(sup))
    task = session.probe
    await _wait(lambda: session.leases == 1)
    caplog.set_level(logging.WARNING, logger="mcpflow.supervisor")
    # Under half the drain bound: the cancel ends the lease, the bound does not.
    await asyncio.wait_for(
        sup.disable(ServerKey(None, "slow"), ADMIN_ACTOR),
        supervisor_mod.LEASE_DRAIN_TIMEOUT / 2,
    )
    assert task.cancelled()
    assert session.leases == 0
    assert child.status == "stopped"
    assert session.state == "closed"
    drain = [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING and "lease drain timed out" in r.getMessage()
    ]
    assert drain == []


@pytest.mark.asyncio
async def test_the_probe_cancel_is_not_awaited_and_raises_nothing(
    make_supervisor, leases
):
    # Scenarios: Teardown cancels a hung snapshot probe (no await, no raise),
    # A cancelled probe of a closing generation is not in flight. D4 (last
    # paragraph), D6, F5.
    sup = make_supervisor()
    child = await _start(sup, "time", "two")
    reach = admin_reach(sup)
    session = child.session
    session.probed_at = None
    await sup.tools(reach)  # creates the probe task; it has not taken a step
    task = session.probe
    assert task is not None and not task.done()
    assert leases == []  # the first step has not run
    await sup.disable(ServerKey(None, "time"), ADMIN_ACTOR)  # raises nothing
    # Cancelled before its first step: the coroutine never ran, so its
    # `finally` never cleared `session.probe`. The done task stays.
    assert task.cancelled()
    assert leases == []
    assert session.probe is task and task.done()
    assert child.status == "stopped"
    assert session.state == "closed"
    assert sup.probing(reach) is False
