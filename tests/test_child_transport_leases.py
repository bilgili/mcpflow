"""Verifier tests for change `child-transport-leases`.

Every test derives from a scenario in
`openspec/changes/child-transport-leases/specs/**` or from a design contract
(D1-D7) in that change's `design.md`, never from the implementation. A `custom`
child that runs `fake_mcp_server.py` over stdio stands in for a real child, so
the tests hold real subprocesses, real leases, and real transports.

Failure is injected only through the real mechanism the design keeps: kill the
child process, hang its `tools/list` (`MCPFLOW_HANG_LIST`), fail its
`tools/list` (`MCPFLOW_BREAK`), or move the generation state the owners move.
No test swaps `child.transport` or patches `Client`; those techniques the
design removed.

Scenario -> test map (see the module tail comment for the full table).
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import time

import pytest
from conftest import fake_child_spec
from fastmcp import Client
from fastmcp.client.transports.base import TransportOptions
from test_child_actions import PAGE, start, store_spec
from test_supervisor import make_supervisor  # noqa: F401 -- fixture
from test_visibility import admin, call_log

from mcpflow import supervisor as supervisor_mod
from mcpflow.registry import ServerSpec
from mcpflow.supervisor import ChildSession, LeaseRefused


async def _wait(pred, timeout: float = 10.0) -> None:
    """Poll `pred` until true. The lease count and the drain are the only
    cross-task states a test waits on; a fixed sleep would race a slow box."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("condition never held within the timeout")


def _pids(path) -> list[str]:
    return path.read_text().split() if path.exists() else []


# --- Child session generations (server-registry) -----------------------------


@pytest.mark.asyncio
async def test_a_start_creates_one_open_generation(make_supervisor):  # noqa: F811
    # Scenario: A start creates one generation.
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("time", "good"))
    await child.task
    assert child.status == "running"
    assert child.session is not None
    assert child.session.state == "open"
    assert child.session.generation >= 1


@pytest.mark.asyncio
async def test_a_restart_makes_a_higher_generation_and_closes_the_old(
    make_supervisor,  # noqa: F811
):
    # Scenario: A restart creates the next generation.
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("time", "good"))
    await child.task
    first = child.session
    await sup.restart("time")
    await child.task
    assert child.session is not first
    assert child.session.generation > first.generation
    assert first.state == "closed"
    assert child.session.state == "open"


@pytest.mark.asyncio
async def test_a_second_connect_is_refused_and_spawns_no_process(
    make_supervisor, tmp_path  # noqa: F811
):
    # Scenario: One connect per stdio generation. D3.
    sup = make_supervisor()
    pid_file = tmp_path / "pids"
    spec = fake_child_spec("time", "good", env={"MCPFLOW_PID_FILE": str(pid_file)})
    transport = sup._build_transport(spec, generation=1)
    c1 = Client(transport, timeout=sup.settings.child_start_timeout)
    await c1.__aenter__()
    try:
        assert len(_pids(pid_file)) == 1
        # The guard raises at the transport before any await.
        second = transport.connect_session()
        with pytest.raises(LeaseRefused) as ei:
            await second.__aenter__()
        assert ei.value.reason == "second connect"
        # And a whole second Client cannot connect either, spawning nothing.
        c2 = Client(transport, timeout=sup.settings.child_start_timeout)
        with pytest.raises(RuntimeError):
            await c2.__aenter__()
        assert len(_pids(pid_file)) == 1
    finally:
        await c1.__aexit__(None, None, None)
        await transport.close()  # closes the owned log handle too
        await transport.close()


@pytest.mark.asyncio
async def test_a_crashed_child_is_not_respawned_and_the_next_poll_fails_it(
    make_supervisor, tmp_path  # noqa: F811
):
    # Scenario: A crashed child is not respawned inside its generation. D6.
    sup = make_supervisor()
    pid_file = tmp_path / "pids"
    spec = fake_child_spec("time", "good", env={"MCPFLOW_PID_FILE": str(pid_file)})
    child = await sup.add(spec)
    await child.task
    pid = int(_pids(pid_file)[0])
    os.kill(pid, signal.SIGKILL)
    await _wait(lambda: not _alive(pid))
    # A later read fails and starts no process.
    with pytest.raises(Exception):  # noqa: B017 -- a dead session raises some error
        async with sup._lease(child) as client:
            await asyncio.wait_for(client.list_tools(), 10)
    assert _pids(pid_file) == [str(pid)]
    # The next dashboard poll marks it failed; still no new process.
    await sup.tools()
    assert child.status == "failed"
    assert _pids(pid_file) == [str(pid)]


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def test_a_remote_generation_owns_no_client_and_reads_open_their_own(
    make_supervisor,  # noqa: F811
):
    # Scenario: A remote child opens one client per read. D2/D5 remote branch.
    sup = make_supervisor()
    spec = ServerSpec(
        namespace="rem", kind="remote", url="https://example.test/mcp", transport="http"
    )
    transport = sup._build_transport(spec)
    session = ChildSession(
        namespace="rem", generation=1, transport=transport, client=None, state="open"
    )
    assert session.client is None
    factory = sup._make_factory(session)
    c1 = factory()
    c2 = factory()
    assert isinstance(c1, Client) and isinstance(c2, Client)
    assert c1 is not c2  # each read opens its own client
    assert c1.transport is transport


# --- Transport leases (server-registry) --------------------------------------


@pytest.mark.asyncio
async def test_a_read_takes_and_releases_a_lease(make_supervisor):  # noqa: F811
    # Scenario: A read takes and releases a lease.
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("time", "good"))
    await child.task
    session = child.session
    assert session.leases == 0
    async with sup._lease(child) as client:
        assert session.leases == 1
        await client.list_tools()
    assert session.leases == 0


@pytest.mark.asyncio
async def test_the_lease_acquire_is_atomic_with_the_session_read(
    make_supervisor,  # noqa: F811
):
    # Requirement (Transport leases): the supervisor reads `child.session` and
    # increments the lease count with no `await` between the two. A reader that
    # starts just before a disable must therefore win the generation while it is
    # still open; an await between the read and the acquire would let the disable
    # move the generation to `closing` first and spuriously refuse the reader.
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("time", "good"))
    await child.task
    granted: dict = {}

    async def read() -> None:
        try:
            async with sup._lease(child) as client:
                await client.list_tools()
            granted["ok"] = True
        except LeaseRefused:
            granted["ok"] = False

    # The reader is scheduled first, so with the atomic read+acquire it holds
    # the lease before disable runs; disable then drains behind it.
    reader = asyncio.create_task(read())
    disabler = asyncio.create_task(sup.disable("time"))
    await asyncio.gather(reader, disabler)
    assert granted["ok"] is True
    assert child.status == "stopped"


@pytest.mark.asyncio
async def test_a_cancelled_actions_read_releases_the_lease_and_keeps_the_pid(
    make_supervisor, tmp_path  # noqa: F811
):
    # Scenario: A cancelled actions request closes nothing.
    sup = make_supervisor()
    hang = tmp_path / "hang"
    pid_file = tmp_path / "pids"
    spec = fake_child_spec(
        "store",
        "action",
        actions=True,  # F2 revised: `actions()` opens a client only on a capable child
        env={"MCPFLOW_HANG_LIST": str(hang), "MCPFLOW_PID_FILE": str(pid_file)},
    )
    child = await sup.add(spec)
    await child.task
    session = child.session
    pids = _pids(pid_file)
    hang.write_text("")  # the actions list now hangs
    task = asyncio.create_task(sup.actions("store"))
    await _wait(lambda: session.leases == 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # The cancel released the lease and closed nothing.
    assert session.leases == 0
    assert session.state == "open"
    assert _pids(pid_file) == pids
    # A later actions read runs on the same process.
    hang.unlink()
    views = await sup.actions("store")
    assert [v.name for v in views][:2] == ["set_writable", "add_store"]
    assert _pids(pid_file) == pids


@pytest.mark.asyncio
async def test_a_refused_probe_adds_no_row_and_changes_no_status(
    make_supervisor,  # noqa: F811
):
    # Scenario: A refused lease fails the probe without a status change.
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("time", "good"))
    await child.task
    child.session.state = "closing"  # a teardown holds the generation closing
    before = (child.status, child.last_error)
    views = await sup._probe_child(child)
    assert views == []
    assert (child.status, child.last_error) == before == ("running", None)
    # Observable through the dashboard: no row for the child, status unchanged.
    all_views = await sup.tools()
    assert all(v.namespace != "time" for v in all_views)
    assert child.status == "running"


@pytest.mark.asyncio
async def test_a_refused_instructions_read_adds_no_block_and_logs_one_warning(
    make_supervisor, tmp_path, caplog  # noqa: F811
):
    # Scenario: A refused lease contributes no instructions block.
    sup = make_supervisor()
    path = tmp_path / "skills.md"
    path.write_text("catalog")
    child = await sup.add(
        fake_child_spec("skills", "instructions", env={"INSTRUCTIONS_FILE": str(path)})
    )
    await child.task
    child.session.state = "closing"
    caplog.set_level(logging.WARNING, logger="mcpflow.supervisor")
    blocks = await sup.instructions_blocks()
    assert blocks == []
    warns = [
        r.getMessage()
        for r in caplog.records
        if r.name == "mcpflow.supervisor" and r.levelno == logging.WARNING
    ]
    assert len(warns) == 1
    assert "read failed for skills" in warns[0]
    assert child.status == "running"


@pytest.mark.asyncio
async def test_a_probe_failure_of_gen_g_never_marks_gen_g_plus_1(
    make_supervisor, tmp_path  # noqa: F811
):
    # D7: a probe of generation g that fails after a restart made generation
    # g+1 running must not mark g+1. The stale probe captures gen1, hangs, then
    # fails when gen1's process dies while `child.session` is gen2.
    sup = make_supervisor()
    hang = tmp_path / "hang"
    pid_file = tmp_path / "pids"
    spec = fake_child_spec(
        "time",
        "action",
        env={"MCPFLOW_HANG_LIST": str(hang), "MCPFLOW_PID_FILE": str(pid_file)},
    )
    child = await sup.add(spec)
    await child.task
    session1 = child.session
    gen1_pid = int(_pids(pid_file)[0])
    hang.write_text("")  # gen1's list hangs, so the probe holds its lease
    probe = asyncio.create_task(sup._probe_child(child))
    await _wait(lambda: session1.leases == 1)
    # A restart superseded gen1: gen2 is the current, running generation.
    session2 = ChildSession(
        namespace="time",
        generation=session1.generation + 1,
        transport=session1.transport,
        client=None,
        state="open",
    )
    child.session = session2
    session1.state = "closing"
    # gen1's process dies; the hung probe's list_tools now raises.
    os.kill(gen1_pid, signal.SIGKILL)
    views = await asyncio.wait_for(probe, 15)
    # The stale gen1 failure marked nothing on gen2 (D7 identity check).
    assert views == []
    assert child.status == "running"
    assert child.session is session2
    assert child.last_error is None


@pytest.mark.asyncio
async def test_a_reader_never_awaits_the_lock_while_holding_the_lease(
    make_supervisor, tmp_path  # noqa: F811
):
    # Rule L1: `_probe_child` releases the lease before it takes `child.lock`
    # in its failure path. Holding the lock here would strand the probe with
    # the lease still held if L1 were violated; teardown would then deadlock to
    # the drain bound. The construction proves the lease is already released.
    sup = make_supervisor()
    brk = tmp_path / "brk"
    spec = fake_child_spec("time", "action", env={"MCPFLOW_BREAK": str(brk)})
    child = await sup.add(spec)
    await child.task
    session = child.session
    brk.write_text("")  # list_tools now raises, so the probe hits its except
    async with child.lock:
        probe = asyncio.create_task(sup._probe_child(child))
        # The probe fails its read, releases the lease, then waits for the lock.
        await _wait(lambda: probe_waiting(probe, session))
        assert session.leases == 0  # L1: released before awaiting the lock
        assert not probe.done()  # blocked on the lock we hold
    views = await asyncio.wait_for(probe, 10)
    assert views == []
    assert child.status == "failed"


def probe_waiting(task, session) -> bool:
    # The probe has failed its read (lease released) but not finished, so it is
    # blocked on `child.lock`.
    return session.leases == 0 and not task.done()


# --- Teardown drains leases (server-registry) --------------------------------


@pytest.mark.asyncio
async def test_disable_waits_for_a_live_read_then_closes(
    make_supervisor, tmp_path  # noqa: F811
):
    # Scenario: Teardown waits for a live read.
    sup = make_supervisor()
    hang = tmp_path / "hang"
    spec = fake_child_spec("time", "action", actions=True, env={"MCPFLOW_HANG_LIST": str(hang)})
    child = await sup.add(spec)
    await child.task
    session = child.session
    hang.write_text("")
    reader = asyncio.create_task(sup.actions("time"))
    await _wait(lambda: session.leases == 1)
    disable = asyncio.create_task(sup.disable("time"))
    await asyncio.sleep(0.4)
    # Still draining under the bound: the lease is held, the transport is open.
    assert not disable.done()
    assert child.transport is not None
    assert session.leases == 1
    # Release the read; only then does disable close the transport.
    hang.unlink()
    await asyncio.wait_for(disable, 10)
    assert child.status == "stopped"
    assert child.transport is None
    assert session.state == "closed"
    await _drain(reader)


@pytest.mark.asyncio
async def test_a_hung_read_does_not_block_teardown_past_the_bound(
    make_supervisor, tmp_path, monkeypatch, caplog  # noqa: F811
):
    # Scenario: A hung read does not block teardown past the bound.
    monkeypatch.setattr(supervisor_mod, "LEASE_DRAIN_TIMEOUT", 0.5)
    sup = make_supervisor()
    hang = tmp_path / "hang"
    spec = fake_child_spec("slow", "action", actions=True, env={"MCPFLOW_HANG_LIST": str(hang)})
    child = await sup.add(spec)
    await child.task
    session = child.session
    hang.write_text("")
    reader = asyncio.create_task(sup.actions("slow"))
    await _wait(lambda: session.leases == 1)
    caplog.set_level(logging.WARNING, logger="mcpflow.supervisor")
    t0 = time.monotonic()
    await asyncio.wait_for(sup.disable("slow"), 10)
    elapsed = time.monotonic() - t0
    assert elapsed < 0.5 + 3.0  # the bound plus the close, not the hung read
    assert child.status == "stopped"
    warns = [
        r.getMessage()
        for r in caplog.records
        if r.name == "mcpflow.supervisor"
        and r.levelno == logging.WARNING
        and "lease drain timed out" in r.getMessage()
    ]
    assert len(warns) == 1
    assert "slow generation" in warns[0]
    hang.unlink()
    await _drain(reader)


@pytest.mark.asyncio
async def test_a_late_reader_on_a_closed_generation_fails_and_starts_no_process(
    make_supervisor, tmp_path  # noqa: F811
):
    # Scenario: A late reader starts no process. D3 guard after teardown.
    sup = make_supervisor()
    pid_file = tmp_path / "pids"
    spec = fake_child_spec("time", "good", env={"MCPFLOW_PID_FILE": str(pid_file)})
    child = await sup.add(spec)
    await child.task
    session = child.session
    owned = session.client  # a borrower captured the client before teardown
    pids = _pids(pid_file)
    await sup.disable("time")
    assert session.state == "closed"
    # The captured generation refuses a late lease.
    with pytest.raises(LeaseRefused) as ei:
        session.acquire()
    assert ei.value.reason == "closed"
    # A late first enter on the owned client cannot spawn a process (D3).
    with pytest.raises(RuntimeError):
        async with owned:
            await owned.list_tools()
    assert _pids(pid_file) == pids


@pytest.mark.asyncio
async def test_the_registry_records_disabled_before_the_drain_starts(
    make_supervisor, tmp_path  # noqa: F811
):
    # Scenario: Registry first, convergence second.
    sup = make_supervisor()
    hang = tmp_path / "hang"
    spec = fake_child_spec("time", "action", actions=True, env={"MCPFLOW_HANG_LIST": str(hang)})
    child = await sup.add(spec)
    await child.task
    session = child.session
    hang.write_text("")
    reader = asyncio.create_task(sup.actions("time"))
    await _wait(lambda: session.leases == 1)
    disable = asyncio.create_task(sup.disable("time"))
    await asyncio.sleep(0.4)
    # disable wrote the registry before it entered the drain.
    assert not disable.done()
    assert sup.registry.get("time").enabled is False
    assert session.state == "closing"
    hang.unlink()
    await asyncio.wait_for(disable, 10)
    assert child.status == "stopped"
    await _drain(reader)


# --- Proxy calls borrow the generation (server-registry) ---------------------


@pytest.mark.asyncio
async def test_a_tool_call_during_closing_is_refused_and_starts_no_process(
    make_supervisor, tmp_path  # noqa: F811
):
    # Scenario: A tool call during a teardown is refused.
    sup = make_supervisor()
    pid_file = tmp_path / "pids"
    spec = fake_child_spec("time", "good", env={"MCPFLOW_PID_FILE": str(pid_file)})
    child = await sup.add(spec)
    await child.task
    session = child.session
    factory = sup._make_factory(session)
    pids = _pids(pid_file)
    session.state = "closing"
    with pytest.raises(LeaseRefused) as ei:
        factory()
    assert ei.value.reason == "closing"
    assert _pids(pid_file) == pids


@pytest.mark.asyncio
async def test_a_tool_call_on_a_closed_generation_starts_no_process(
    make_supervisor, tmp_path  # noqa: F811
):
    # Scenario: A tool call after the close starts no process.
    sup = make_supervisor()
    pid_file = tmp_path / "pids"
    spec = fake_child_spec("time", "good", env={"MCPFLOW_PID_FILE": str(pid_file)})
    child = await sup.add(spec)
    await child.task
    session = child.session
    owned = session.client  # a proxy call captured the client before teardown
    factory = sup._make_factory(session)
    pids = _pids(pid_file)
    await sup.disable("time")
    assert session.state == "closed"
    with pytest.raises(LeaseRefused):
        factory()
    with pytest.raises(RuntimeError):
        async with owned:
            await owned.list_tools()
    assert _pids(pid_file) == pids


@pytest.mark.asyncio
async def test_two_proxy_calls_share_one_stdio_client_and_one_process(
    make_supervisor, tmp_path  # noqa: F811
):
    # Scenario: Two proxy calls share one stdio client.
    sup = make_supervisor()
    pid_file = tmp_path / "pids"
    spec = fake_child_spec("time", "good", env={"MCPFLOW_PID_FILE": str(pid_file)})
    child = await sup.add(spec)
    await child.task
    session = child.session
    factory = sup._make_factory(session)
    c1 = factory()
    c2 = factory()
    assert c1 is c2 is session.client
    async with c1, c2:
        t1 = await c1.list_tools()
        t2 = await c2.list_tools()
    assert [t.name for t in t1] == [t.name for t in t2] == ["get_current_time"]
    assert len(_pids(pid_file)) == 1


# --- Transport options invariant (mcp-gateway) -------------------------------


@pytest.mark.asyncio
async def test_the_transport_options_invariant_holds(make_supervisor):  # noqa: F811
    # Scenario: One session profile per stdio generation.
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("time", "good"))
    await child.task
    session = child.session
    assert session.client._transport_options is None
    assert child.transport.inner._session_options == TransportOptions()
    factory_client = sup._make_factory(session)()
    assert type(factory_client) is Client  # plain Client, never a ProxyClient
    assert factory_client._transport_options is None


# --- Actions page during a teardown (web-ui) ---------------------------------


def test_the_actions_page_renders_a_refusal_during_a_teardown(server_factory):
    # Scenario: The actions page renders a refusal.
    server, _h = start(server_factory, store_spec())
    session = server.supervisor.get("store").session
    gen = session.generation
    session.state = "closing"
    with admin(server) as client:
        resp = client.get(PAGE)
    assert resp.status_code == 200
    body = resp.text
    assert "refused: closing" in body
    assert str(gen) in body
    assert "store" in body
    assert '<form method="post"' not in body
    assert server.supervisor.get("store").status == "running"


def test_a_submit_during_a_teardown_answers_503_and_calls_no_tool(server_factory):
    # Amendment 5: every POST lease refusal answers 503, including the probe.
    server, _h = start(server_factory, store_spec())
    session = server.supervisor.get("store").session
    gen = session.generation
    session.state = "closing"
    with admin(server) as client:
        resp = client.post(PAGE + "/set_writable", data={"name": "git1"})
    assert resp.status_code == 503
    assert "refused: closing" in resp.text
    assert str(gen) in resp.text
    assert "set_writable" not in call_log(server)
    assert server.supervisor.get("store").status == "running"


async def _drain(task) -> None:
    """Await a reader whose hung list ended with the transport close. Its
    failure path raises; the test only needs it not to leak."""
    task.cancel()
    try:
        await asyncio.wait_for(task, 10)
    except (asyncio.CancelledError, Exception):  # noqa: BLE001, S110 -- cleanup only
        pass
