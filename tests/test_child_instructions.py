"""The gateway carries each child's live `instructions://self` into a session.

Scenarios from `openspec/changes/child-instructions/specs/**`. The children run
the fake server in modes `instructions`, `slowres`, and `bigres`; a real MCP
client over `/mcp` reads the `initialize` result. The gate tests and the bound
placement test drive the supervisor in process, because they need to hold a
child in a state or a lock the HTTP surface cannot.
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path

import pytest
from conftest import fake_child_spec
from test_supervisor import make_supervisor  # noqa: F401 -- fixture
from test_visibility import ROOT, _seed, admin, call, mute, ns_path

from mcpflow.instructions import (
    INSTRUCTIONS_BLOCK_CAP,
    TRUNCATION_MARKER,
    render_instructions,
)
from mcpflow.supervisor import INSTRUCTIONS_READ_TIMEOUT

SRC = Path(__file__).parent.parent / "src" / "mcpflow"


def _client(base: str, token: str, **kw):
    from fastmcp import Client
    from fastmcp.client.transports import StreamableHttpTransport

    transport = StreamableHttpTransport(
        base + "/mcp", headers={"Authorization": f"Bearer {token}"}
    )
    return Client(transport, **kw)


def initialize(base: str, token: str) -> str | None:
    """The `instructions` of a fresh session's `initialize` result."""

    async def run():
        async with _client(base, token, mode="legacy") as c:
            return c.initialize_result.instructions

    return asyncio.run(run())


def discover(base: str, token: str) -> str | None:
    """The `instructions` of a fresh session's `server/discover` result."""

    async def run():
        # The default mode negotiates through `server/discover`; an
        # `initialize_result` would mean the client fell back to `initialize`.
        async with _client(base, token) as c:
            assert c.initialize_result is None
            return c.instructions

    return asyncio.run(run())


def text_child(tmp_path: Path, namespace: str, body: str, **extra):
    path = tmp_path / f"{namespace}.md"
    path.write_text(body)
    spec = fake_child_spec(
        namespace, "instructions", env={"INSTRUCTIONS_FILE": str(path)}, **extra
    )
    return spec, path


def _start(server_factory, *specs, running: int):
    holder: dict = {}
    server = server_factory(_seed(*specs, holder=holder))
    counts = server.wait(running=running)
    assert counts["running"] == running, counts
    return server, server.base_url, holder["clear"]


def _warnings(caplog, logger: str, namespace: str) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == logger
        and r.levelno == logging.WARNING
        and f" {namespace}" in r.getMessage()
    ]


# --- C-1: blocks, order, a child without the resource --------------------------


def test_two_children_render_two_blocks_in_registry_order(server_factory, tmp_path):
    a, _ = text_child(tmp_path, "a", "alpha\n")
    b, _ = text_child(tmp_path, "b", "beta")
    _server, base, token = _start(server_factory, a, b, running=2)

    assert initialize(base, token) == "## a\nalpha\n\n## b\nbeta"


def test_child_without_the_resource_contributes_no_block(
    server_factory, tmp_path, caplog
):
    caplog.set_level(logging.WARNING, logger="mcpflow.supervisor")
    skills, _ = text_child(tmp_path, "skills", "catalog")
    _server, base, token = _start(
        server_factory, fake_child_spec("time", "good"), skills, running=2
    )

    text = initialize(base, token)

    assert text == "## skills\ncatalog"
    assert len(_warnings(caplog, "mcpflow.supervisor", "time")) == 1


# --- C-2: the status gate -------------------------------------------------------


@pytest.mark.asyncio
async def test_only_a_running_child_contributes(make_supervisor, tmp_path):  # noqa: F811
    spec, _ = text_child(tmp_path, "skills", "catalog")
    sup = make_supervisor(spec)
    await sup.startup()
    child = sup.get("skills")
    await child.task
    assert await sup.instructions_blocks() == [("skills", "catalog")]

    # The gate is the owner's; hold the child in each non-running state.
    for status in ("starting", "failed"):
        child.status = status
        assert await sup.instructions_blocks() == []
    child.status = "running"

    await sup.disable("skills")
    assert child.status == "stopped"
    assert await sup.instructions_blocks() == []


# --- C-3: mutes -----------------------------------------------------------------


def test_namespace_mute_and_root_mute_remove_blocks(server_factory, tmp_path):
    skills, _ = text_child(tmp_path, "skills", "catalog")
    docs, _ = text_child(tmp_path, "docs", "manual")
    server, base, token = _start(server_factory, skills, docs, running=2)
    assert initialize(base, token) == "## skills\ncatalog\n\n## docs\nmanual"

    with admin(server) as client:
        mute(client, ns_path("skills"))
        assert initialize(base, token) == "## docs\nmanual"
        mute(client, ROOT)
        assert initialize(base, token) is None


# --- C-4: failures --------------------------------------------------------------


def test_raising_read_keeps_the_child_running(server_factory, caplog):
    caplog.set_level(logging.WARNING, logger="mcpflow.supervisor")
    server, base, token = _start(
        server_factory, fake_child_spec("bad", "good"), running=1
    )
    child = server.supervisor.get("bad")
    before = child.last_error

    assert initialize(base, token) is None

    assert child.status == "running"
    assert child.last_error == before
    assert child.provider in server.supervisor.table.providers
    assert len(_warnings(caplog, "mcpflow.supervisor", "bad")) == 1


def test_hanging_read_adds_at_most_the_bound(server_factory, tmp_path, caplog):
    caplog.set_level(logging.WARNING, logger="mcpflow.supervisor")
    skills, _ = text_child(tmp_path, "skills", "catalog")
    server, base, token = _start(
        server_factory, fake_child_spec("slow", "slowres"), skills, running=2
    )

    t0 = time.monotonic()
    text = initialize(base, token)
    elapsed = time.monotonic() - t0

    # The other children still contribute.
    assert text == "## skills\ncatalog"
    assert elapsed < INSTRUCTIONS_READ_TIMEOUT + 3.0
    assert server.supervisor.get("slow").status == "running"
    assert _warnings(caplog, "mcpflow.supervisor", "slow") == [
        "instructions://self read timed out for slow after 2.0s"
    ]


def test_hanging_read_keeps_the_child_session(server_factory, tmp_path):
    pid_file = tmp_path / "slow.pid"
    spec = fake_child_spec("slow", "slowres", env={"MCPFLOW_PID_FILE": str(pid_file)})
    _server, base, token = _start(server_factory, spec, running=1)
    pids = pid_file.read_text().split()
    assert len(pids) == 1

    assert initialize(base, token) is None
    assert call(base, token, "slow_get_current_time", {}) == "2026-01-01T00:00:00Z"

    # The same subprocess served the call: no respawn.
    assert pid_file.read_text().split() == pids
    # A later initialize still works against the same child.
    assert initialize(base, token) is None
    assert pid_file.read_text().split() == pids


@pytest.mark.asyncio
async def test_a_cancelled_borrowed_read_keeps_the_shared_transport(
    make_supervisor, tmp_path  # noqa: F811
):
    """D2 replaced the fresh-client-per-read with a borrowed owned client, so
    the old "bound never covers the enter" proof no longer applies. The
    underlying guarantee stays: a caller cancel of a borrowed read must not
    close the shared transport or kill the child. Prove it against the owned
    client. The `slowres` resource read hangs, so the cancel lands mid-flight."""
    pid_file = tmp_path / "skills.pid"
    spec = fake_child_spec(
        "skills", "slowres", env={"MCPFLOW_PID_FILE": str(pid_file)}
    )
    sup = make_supervisor(spec)
    await sup.startup()
    child = sup.get("skills")
    await child.task
    pids = pid_file.read_text().split()
    assert len(pids) == 1
    session = child.session

    # A borrowed read in flight, then cancelled (the client disconnected).
    read = asyncio.create_task(sup._read_instructions(child))
    for _ in range(400):
        await asyncio.sleep(0.01)
        if session.leases == 1:
            break
    assert session.leases == 1
    read.cancel()
    with pytest.raises(asyncio.CancelledError):
        await read

    # The cancel released the lease and closed nothing: same generation, same
    # process, and the owned client still serves a later read.
    assert session.leases == 0
    assert child.session is session and session.state == "open"
    assert pid_file.read_text().split() == pids
    views = await sup._probe_child(child)
    assert any(v.tool == "get_current_time" for v in views)
    assert pid_file.read_text().split() == pids


# --- C-5: discover parity -------------------------------------------------------


def test_discover_matches_initialize(server_factory, tmp_path):
    skills, _ = text_child(tmp_path, "skills", "catalog")
    _server, base, token = _start(server_factory, skills, running=1)

    first = initialize(base, token)
    assert first == "## skills\ncatalog"
    assert discover(base, token) == first


# --- C-6: live text -------------------------------------------------------------


def test_next_initialize_carries_new_text(server_factory, tmp_path):
    skills, path = text_child(tmp_path, "skills", "v1")
    _server, base, token = _start(server_factory, skills, running=1)
    assert initialize(base, token) == "## skills\nv1"

    path.write_text("v2")

    assert initialize(base, token) == "## skills\nv2"


# --- C-7: null ------------------------------------------------------------------


def test_no_contributing_child_renders_null(server_factory):
    _server, base, token = _start(
        server_factory, fake_child_spec("time", "good"), running=1
    )

    assert initialize(base, token) is None


# --- C-8: generic contract ------------------------------------------------------


def test_no_source_file_names_a_skill():
    offenders = [
        str(p.relative_to(SRC))
        for p in SRC.rglob("*")
        if p.is_file()
        and "__pycache__" not in p.parts
        and not (p.suffix == ".json" and p.is_relative_to(SRC / "catalog"))
        and "skill" in p.read_text(errors="ignore").lower()
    ]
    assert offenders == []


# --- C-9: cap -------------------------------------------------------------------


def test_large_block_is_truncated(server_factory, caplog):
    caplog.set_level(logging.WARNING, logger="mcpflow.instructions")
    _server, base, token = _start(
        server_factory, fake_child_spec("big", "bigres"), running=1
    )

    text = initialize(base, token)

    header, body = text.split("\n", 1)
    assert header == "## big"
    kept, marker = body.rsplit("\n", 1)
    assert marker == TRUNCATION_MARKER
    assert len(kept.encode()) <= INSTRUCTIONS_BLOCK_CAP
    assert _warnings(caplog, "mcpflow.instructions", "big") == [
        "instructions block for big truncated at 16384 bytes"
    ]


def test_block_within_the_cap_is_unchanged(server_factory, tmp_path):
    body = "s" * 100
    skills, _ = text_child(tmp_path, "skills", body)
    _server, base, token = _start(server_factory, skills, running=1)

    assert initialize(base, token) == "## skills\n" + body


# --- C-10: transport options invariant ------------------------------------------


@pytest.mark.asyncio
async def test_both_clients_share_one_session_profile(make_supervisor, tmp_path):  # noqa: F811
    from fastmcp.client.transports.base import TransportOptions

    spec, _ = text_child(tmp_path, "skills", "catalog")
    sup = make_supervisor(spec)
    await sup.startup()
    child = sup.get("skills")
    await child.task

    proxy_client = sup._make_factory(child.session)()
    # The factory returns the one client the generation owns, so a proxy call
    # and a direct read share one session.
    assert proxy_client is child.session.client
    async with proxy_client:
        # The supervisor's read borrows the same owned client while the
        # factory's reference is held.
        assert await sup.instructions_blocks() == [("skills", "catalog")]
        assert proxy_client._transport_options is None
        # `_session_options` lives on the inner StdioTransport now.
        assert child.transport.inner._session_options == TransportOptions()

    from fastmcp import Client

    direct = Client(child.transport, timeout=sup.settings.child_start_timeout)
    assert direct._transport_options is None
    assert type(proxy_client) is Client


# --- render_instructions --------------------------------------------------------


def test_render_joins_own_and_blocks():
    assert render_instructions(None, []) is None
    assert render_instructions("", []) is None
    assert render_instructions("own", []) == "own"
    assert render_instructions(None, [("a", "alpha \n")]) == "## a\nalpha"
    assert (
        render_instructions("own", [("a", "alpha"), ("b", "beta")])
        == "own\n\n## a\nalpha\n\n## b\nbeta"
    )


def test_render_cut_lands_on_a_character_boundary():
    # Each "é" is two bytes; one leading ASCII byte puts the cap mid-character.
    text = "x" + "é" * INSTRUCTIONS_BLOCK_CAP
    out = render_instructions(None, [("a", text)])
    kept = out.split("\n")[1]
    assert out.endswith("\n" + TRUNCATION_MARKER)
    assert kept == "x" + "é" * ((INSTRUCTIONS_BLOCK_CAP - 1) // 2)
    assert len(kept.encode()) <= INSTRUCTIONS_BLOCK_CAP
