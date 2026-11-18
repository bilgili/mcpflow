"""Verifier tests for the usage store (usage-stats group 7).

Each test derives from a scenario of `specs/usage-stats/spec.md` or
`specs/web-ui/spec.md`, the frozen interfaces of `design.md`, and the race
steps of `specs/tla/usage_stats.tla` and `usage_forget.tla`. The private
names `_pending`, `_forget`, `_write`, and `_flush` are the names D6 gives.
A held write blocks in its worker thread on a `threading.Event`; every test
releases it in `finally`, so no thread outlives a test.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sqlite3
import threading
import time
from datetime import UTC, date, datetime, timedelta
from datetime import time as dtime
from types import SimpleNamespace

import pytest
from conftest import ADMIN_ACTOR, make_user

from mcpflow import usage
from mcpflow.auth import TokenStore, hash_password
from mcpflow.identity import LocalIdentityProvider, write_admin_password_file
from mcpflow.policy import AccessPolicy, RuleStore
from mcpflow.registry import Registry, ServerSpec
from mcpflow.usage import Counts, UsageRange, UsageStore

pytestmark = pytest.mark.asyncio

LOGGER = "mcpflow.usage"
TOOL = "get_current_time"


# --- helpers -------------------------------------------------------------


def make_world(tmp_path, *servers: str):
    """An `AccessPolicy` over admin-owned `servers`, with the store under test
    as its `usage` argument (frozen: `AccessPolicy.__init__(..., usage)`).
    Mirrors `conftest.make_policy`, but the test holds the store."""
    write_admin_password_file(tmp_path, hash_password("secret", iterations=1000))
    identity = LocalIdentityProvider(tmp_path / "users.json")
    identity.load()
    tokens = TokenStore(tmp_path / "tokens.json", tmp_path / "user_tokens.json")
    tokens.load()
    rules = RuleStore(tmp_path / "rules.json")
    rules.load()
    reg = Registry(tmp_path / "servers.json", tmp_path / "user_servers.json")
    reg.load()
    for ns in servers:
        reg.add(ServerSpec(namespace=ns, kind="npm", package="p@1.0.0"))
    store = UsageStore(tmp_path / "usage.sqlite3")
    policy = AccessPolicy(identity, rules, tokens, reg, store)
    return SimpleNamespace(policy=policy, store=store, path=tmp_path / "usage.sqlite3")


def grant_group(w, group: str, server: str) -> None:
    w.policy.add_rule(
        ADMIN_ACTOR, subject_kind="group", subject=group, level="server",
        server=server, tool=None, effect="allow",
    )


def world_with_eng(tmp_path, *servers: str):
    """`servers` granted to the group `eng`. A group rule survives
    `delete_user`, so a re-created member reaches the same servers and a read
    of `0` proves the forget, not a lost grant."""
    w = make_world(tmp_path, *servers)
    w.policy.create_group(ADMIN_ACTOR, "eng")
    for s in servers:
        grant_group(w, "eng", s)
    return w


def recreate(w, uid: str):
    w.policy.delete_user(ADMIN_ACTOR, uid)
    return make_user(w.policy, uid, groups=["eng"])


def today_range() -> UsageRange:
    today = datetime.now(UTC).astimezone().date()  # a local date (D9)
    return UsageRange(start=today - timedelta(days=1), end=today, bucket="day")


async def calls_of(store, reach, ref="time", tool=TOOL) -> int:
    totals = await store.totals(today_range(), reach)
    return totals.by_tool.get((ref, tool), Counts()).calls


def admin(w):
    return w.policy.keys_for(ADMIN_ACTOR, "dashboard")


def rows(path) -> list[tuple]:
    con = sqlite3.connect(path)
    try:
        return con.execute(
            "SELECT hour, server, tool, user, calls, errors, total_ms FROM usage"
        ).fetchall()
    finally:
        con.close()


def table_calls(path, user: str | None = None) -> int:
    return sum(r[4] for r in rows(path) if user is None or r[3] == user)


def pending_calls(store, user: str | None = None) -> int:
    return sum(v[0] for k, v in store._pending.items() if user is None or k[3] == user)


def logs(caplog, level: int) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == LOGGER and r.levelno == level]


async def wait(ev: threading.Event, what: str) -> None:
    assert await asyncio.to_thread(ev.wait, 5), f"timed out waiting for {what}"


def hold_write(store, monkeypatch, *, commit_first: bool = False, fail: bool = False):
    """Patch `store._write` so its FIRST call blocks in the worker thread
    until `h.release` is set. `commit_first` runs the real write before the
    block (the batch is committed, the flusher has not resumed). `fail`
    raises after the block in place of the write. Later calls run the real
    write."""
    real = store._write
    h = SimpleNamespace(
        entered=threading.Event(), release=threading.Event(),
        done=threading.Event(), used=False,
    )

    def write(batch, forget):
        if h.used:
            return real(batch, forget)
        h.used = True
        try:
            if commit_first:
                real(batch, forget)
            h.entered.set()
            assert h.release.wait(10), "held write never released"
            if fail:
                raise OSError("held write fails")
            if not commit_first:
                real(batch, forget)
        finally:
            h.done.set()

    monkeypatch.setattr(store, "_write", write)
    return h


def fail_writes(store, monkeypatch, n: int = 1):
    """The next `n` calls of `_write` raise; later ones run the real write."""
    real = store._write
    left = [n]

    def write(batch, forget):
        if left[0] > 0:
            left[0] -= 1
            raise OSError("disk says no")
        return real(batch, forget)

    monkeypatch.setattr(store, "_write", write)


def hold_query(store, monkeypatch, *, after: bool):
    """Patch `store._query` (the read's worker-thread query) to block until
    `h.go`: before the real query when `after` is false, after it otherwise."""
    real = store._query
    h = SimpleNamespace(entered=threading.Event(), go=threading.Event())

    def query(*a, **kw):
        res = real(*a, **kw) if after else None
        h.entered.set()
        assert h.go.wait(10), "held query never released"
        return res if after else real(*a, **kw)

    monkeypatch.setattr(store, "_query", query)
    return h


# --- Usage store (7.1, 7.2) ----------------------------------------------


async def test_calls_of_one_hour_share_one_row(tmp_path):
    """Spec `Usage store`, "Calls of one hour share one row".
    Mutation: insert per call, or drop the ON CONFLICT add -> fails."""
    store = UsageStore(tmp_path / "usage.sqlite3")
    await store.start()
    try:
        before = int(time.time()) // 3600
        store.record("time", TOOL, "alice", ok=True, ms=10)
        store.record("time", TOOL, "alice", ok=False, ms=20)
        store.record("time", TOOL, "alice", ok=True, ms=30)
        after = int(time.time()) // 3600
        await store._flush(final=False)
        (row,) = rows(tmp_path / "usage.sqlite3")
        hour, server, tool, user, calls, errors, total_ms = row
        assert before <= hour <= after  # the UTC hour of the call end
        assert (server, tool, user) == ("time", TOOL, "alice")
        assert (calls, errors, total_ms) == (3, 1, 60)
        assert store._pending == {}
    finally:
        await store.stop()


async def test_old_rows_are_deleted(tmp_path):
    """Spec `Usage store`, "Old rows are deleted"; schema mark and WAL (D5).
    Mutation: drop the retention DELETE -> fails."""
    path = tmp_path / "usage.sqlite3"
    store = UsageStore(path)
    await store.start()
    try:
        now_hour = int(time.time()) // 3600
        old = now_hour - 401 * 24
        kept = now_hour - 399 * 24
        con = sqlite3.connect(path)
        with con:
            con.execute("INSERT INTO usage VALUES (?, 'time', ?, 'alice', 5, 0, 50)", (old, TOOL))
            con.execute("INSERT INTO usage VALUES (?, 'time', ?, 'alice', 7, 0, 70)", (kept, TOOL))
        con.close()
        store.record("time", TOOL, "alice", ok=True, ms=1)
        await store._flush(final=False)
        hours = {r[0]: r[4] for r in rows(path)}
        assert old not in hours
        assert hours[kept] == 7
        assert sum(hours.values()) == 8
        con = sqlite3.connect(path)
        try:
            assert con.execute("PRAGMA user_version").fetchone()[0] == 1
            assert con.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        finally:
            con.close()
    finally:
        await store.stop()


# --- Usage flush (7.3 to 7.6) --------------------------------------------


async def test_a_failed_write_is_retried(tmp_path, monkeypatch, caplog):
    """Spec `Usage flush`, "A failed write is retried" (D6 step 3).
    Mutation: drop the merge of step 3 -> fails."""
    path = tmp_path / "usage.sqlite3"
    store = UsageStore(path)
    await store.start()
    try:
        store.record("time", TOOL, "alice", ok=True, ms=5)
        store.record("time", TOOL, "alice", ok=False, ms=5)
        fail_writes(store, monkeypatch, 1)
        caplog.set_level(logging.WARNING, logger=LOGGER)
        with contextlib.suppress(Exception):
            await store._flush(final=False)
        assert pending_calls(store) == 2
        (counts,) = store._pending.values()
        assert list(counts) == [2, 1, 10]
        assert len(logs(caplog, logging.WARNING)) == 1
        assert rows(path) == []
        await store._flush(final=False)
        assert table_calls(path) == 2
        assert store._pending == {}
    finally:
        await store.stop()


async def test_no_call_is_counted_twice(tmp_path, monkeypatch):
    """Spec `Usage flush`, "No call is counted twice"; `Usage read`
    ("SHALL NOT add the batch of a running write").
    The write commits and holds before the flusher resumes, while a recorder
    task runs into the swap.
    Mutation: split the swap with `await asyncio.sleep(0)` -> the recorder's
    calls are lost. Mutation: add the running batch to the read -> the read
    exceeds the ended calls."""
    w = make_world(tmp_path, "time")
    store, path = w.store, w.path
    await store.start()
    h = hold_write(store, monkeypatch, commit_first=True)
    try:
        ended = 0
        for _ in range(3):
            store.record("time", TOOL, "", ok=True, ms=1)
            ended += 1

        async def recorder():
            for _ in range(5):
                store.record("time", TOOL, "", ok=True, ms=1)
                await asyncio.sleep(0)

        flush = asyncio.create_task(store._flush(final=False))
        rec = asyncio.create_task(recorder())
        await rec
        ended += 5
        await wait(h.entered, "the write to commit")
        # Committed, the flusher not resumed: every call is in the table or
        # in `_pending`, and a read stays within the ended calls.
        assert table_calls(path) + pending_calls(store) == ended
        seen = await calls_of(store, admin(w))
        assert seen <= ended
        h.release.set()
        await flush
        assert table_calls(path) + pending_calls(store) == ended
        await store._flush(final=False)
        assert table_calls(path) == ended
        assert await calls_of(store, admin(w)) == ended
    finally:
        h.release.set()
        await store.stop()


async def test_a_read_during_a_flush_does_not_overcount(tmp_path, monkeypatch):
    """Spec `Usage read`, "A read during a flush does not overcount": the
    read queries SQLite first, then adds `_pending` (D8).
    The read is held in its worker thread before the query; a whole flush
    commits the batch meanwhile.
    Mutation: add `_pending` before the query -> the read returns 6 of 3."""
    w = make_world(tmp_path, "time")
    store = w.store
    await store.start()
    h = hold_query(store, monkeypatch, after=False)
    try:
        for _ in range(3):
            store.record("time", TOOL, "", ok=True, ms=1)
        read = asyncio.create_task(store.totals(today_range(), admin(w)))
        await wait(h.entered, "the read query")
        await store._flush(final=False)
        h.go.set()
        totals = await read
        assert totals.by_tool[("time", TOOL)].calls <= 3
        assert totals.by_server["time"].calls <= 3
    finally:
        h.go.set()
        await store.stop()


async def test_a_cancelled_write_merges_nothing(tmp_path, monkeypatch):
    """Spec `Usage flush` ("Only an `Exception` SHALL put a batch back; a
    cancel SHALL NOT"), D6, model `usage_stats_cancelmerge.cfg`.
    Mutation: merge on `BaseException` -> the batch is in `_pending` and in
    the table."""
    path = tmp_path / "usage.sqlite3"
    store = UsageStore(path)
    await store.start()
    h = hold_write(store, monkeypatch)
    try:
        store.record("time", TOOL, "alice", ok=True, ms=1)
        store.record("time", TOOL, "alice", ok=True, ms=1)
        flush = asyncio.create_task(store._flush(final=False))
        await wait(h.entered, "the held write")
        flush.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await flush
        assert store._pending == {}
        h.release.set()
        await wait(h.done, "the worker thread")
        # The thread ran on and committed; nothing is counted twice.
        assert table_calls(path) + pending_calls(store) == 2
        assert store._pending == {}
    finally:
        h.release.set()
        await store.stop()


async def test_the_flusher_survives_a_fault(tmp_path, monkeypatch):
    """Spec `Usage flush` ("The flusher task SHALL NOT end before the stop,
    whatever an iteration raises"), D6.
    Mutation: drop the `except Exception` of the flusher loop -> fails."""
    monkeypatch.setattr(usage, "FLUSH_INTERVAL", 0.05)
    path = tmp_path / "usage.sqlite3"
    store = UsageStore(path)
    real = store._flush
    raised = []

    async def flaky(*a, **kw):
        if not raised:
            raised.append(True)
            raise RuntimeError("an iteration fault outside _write")
        return await real(*a, **kw)

    monkeypatch.setattr(store, "_flush", flaky)
    await store.start()
    try:
        store.record("time", TOOL, "alice", ok=True, ms=1)
        for _ in range(100):
            if raised and rows(path):
                break
            await asyncio.sleep(0.05)
        assert raised, "the flusher never ran an iteration"
        assert table_calls(path) == 1, "the flusher stopped flushing after a fault"
        assert not store._task.done()
    finally:
        await store.stop()


# --- Usage store lifecycle (7.7) -----------------------------------------


async def test_a_clean_stop_keeps_every_call(tmp_path):
    """Spec `Usage store lifecycle`, "A clean shutdown keeps every call".
    Mutation: `stop` does not await the flusher task -> fails."""
    path = tmp_path / "usage.sqlite3"
    store = UsageStore(path)
    await store.start()
    for i in range(4):
        store.record("time", TOOL, "alice", ok=i != 0, ms=3)
    store.record("gitlab", "list_commits", "bob", ok=True, ms=3)
    await store.stop()
    assert table_calls(path) == 5
    assert table_calls(path, "alice") == 4
    assert store._pending == {}


async def test_a_record_after_stop_is_dropped(tmp_path, caplog):
    """Spec `Usage store lifecycle` ("A record on a closed store SHALL drop
    the call and log it at debug level")."""
    path = tmp_path / "usage.sqlite3"
    store = UsageStore(path)
    await store.start()
    await store.stop()
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    store.record("time", TOOL, "alice", ok=True, ms=1)
    assert store._pending == {}
    assert rows(path) == []
    assert logs(caplog, logging.DEBUG)


async def test_a_failed_final_write_logs_the_dropped_calls(tmp_path, monkeypatch, caplog):
    """Spec `Usage store lifecycle` ("A final write that fails SHALL log a
    warning with the number of calls it drops"); D7 `StoppedAccounted`:
    after the stop `_pending` is empty."""
    path = tmp_path / "usage.sqlite3"
    store = UsageStore(path)
    await store.start()
    for _ in range(3):
        store.record("time", TOOL, "alice", ok=True, ms=1)
    fail_writes(store, monkeypatch, 1)
    caplog.set_level(logging.WARNING, logger=LOGGER)
    await store.stop()
    (warning,) = logs(caplog, logging.WARNING)
    assert "3" in warning.getMessage()
    assert store._pending == {}
    assert rows(path) == []


# --- Usage visibility (7.8) ----------------------------------------------


async def _visibility_world(tmp_path):
    w = make_world(tmp_path, "time", "weather")
    w.policy.create_group(ADMIN_ACTOR, "eng")
    grant_group(w, "eng", "time")  # `weather` is outside the users' Reach
    w.alice = make_user(w.policy, "alice", groups=["eng"])
    w.bob = make_user(w.policy, "bob", groups=["eng"])
    await w.store.start()
    return w


async def test_a_user_sees_only_their_own_calls(tmp_path):
    """Spec `Usage visibility`, "A user sees only their own calls"; D12.
    A call under `''` and a server outside the Reach stay hidden. Checked on
    both read sources: `_pending`, then the table."""
    w = await _visibility_world(tmp_path)
    store = w.store
    try:
        store.record("time", TOOL, "alice", ok=True, ms=1)
        store.record("time", TOOL, "bob", ok=True, ms=1)
        store.record("time", TOOL, "", ok=True, ms=1)
        store.record("weather", "forecast", "alice", ok=True, ms=1)
        reach = w.policy.keys_for(w.alice, "dashboard")
        assert [k.ref for k in reach.keys] == ["time"]
        for _ in ("pending", "table"):
            totals = await store.totals(today_range(), reach)
            assert totals.by_tool[("time", TOOL)].calls == 1
            assert totals.by_server["time"].calls == 1
            assert ("weather", "forecast") not in totals.by_tool
            assert "weather" not in totals.by_server
            series = await store.series(today_range(), reach)
            assert sum(series.by_server["time"]) == 1
            assert "weather" not in series.by_server
            await store._flush(final=False)
    finally:
        await store.stop()


async def test_an_admin_sees_every_call(tmp_path):
    """Spec `Usage visibility`, "An admin sees every call"; D12: every user,
    `''`, and every server reference in the table, a deleted one included."""
    w = await _visibility_world(tmp_path)
    store = w.store
    try:
        store.record("time", TOOL, "alice", ok=True, ms=1)
        store.record("time", TOOL, "bob", ok=True, ms=1)
        assert await calls_of(store, admin(w)) == 2
        store.record("time", TOOL, "", ok=True, ms=1)
        store.record("gone", "old_tool", "alice", ok=False, ms=1)  # no such server
        for _ in ("pending", "table"):
            totals = await store.totals(today_range(), admin(w))
            assert totals.by_tool[("time", TOOL)].calls == 3
            assert totals.by_tool[("gone", "old_tool")] == Counts(calls=1, errors=1)
            assert totals.by_server["gone"].calls == 1
            series = await store.series(today_range(), admin(w))
            assert sum(series.by_server["time"]) == 3
            await store._flush(final=False)
    finally:
        await store.stop()


# --- A re-created user starts clean (7.9 to 7.13) ------------------------


async def test_a_recreated_user_sees_no_old_calls(tmp_path, monkeypatch):
    """Spec `A re-created user starts clean`, "A re-created user sees no old
    calls"; D14. 25 old calls are in the table and 25 in `_pending`.
    Mutation: drop step 1 of `forget_user` -> the `_pending` 25 show.
    Mutation: drop the read skip -> the table 25 show.
    Mutation: clear `_forget` at the swap, not after the commit -> the table
    25 show during the held write."""
    w = world_with_eng(tmp_path, "time")
    store = w.store
    make_user(w.policy, "alice", groups=["eng"])
    await store.start()
    try:
        for _ in range(25):
            store.record("time", TOOL, "alice", ok=True, ms=1)
        await store._flush(final=False)
        assert table_calls(w.path, "alice") == 25
        for _ in range(25):
            store.record("time", TOOL, "alice", ok=True, ms=1)

        alice = recreate(w, "alice")
        reach = w.policy.keys_for(alice, "dashboard")
        assert [k.ref for k in reach.keys] == ["time"]
        assert await calls_of(store, reach) == 0
        totals = await store.totals(today_range(), reach)
        assert totals.by_server.get("time", Counts()).calls == 0

        h2 = hold_write(store, monkeypatch)  # hold the write of the forget
        try:
            flush = asyncio.create_task(store._flush(final=False))
            await wait(h2.entered, "the held forget write")
            assert await calls_of(store, reach) == 0
            h2.release.set()
            await flush
        finally:
            h2.release.set()
        assert await calls_of(store, reach) == 0
        assert table_calls(w.path, "alice") == 0
    finally:
        await store.stop()


async def test_the_new_holder_keeps_its_calls(tmp_path):
    """Spec `A re-created user starts clean`, "The new holder keeps its
    calls"; D14 (move before the upsert).
    Mutation: run the upsert before the move in `_write` -> alice reads 0."""
    w = world_with_eng(tmp_path, "time")
    store = w.store
    make_user(w.policy, "alice", groups=["eng"])
    await store.start()
    try:
        for _ in range(50):
            store.record("time", TOOL, "alice", ok=True, ms=1)
        await store._flush(final=False)
        alice = recreate(w, "alice")
        store.record("time", TOOL, "alice", ok=True, ms=1)
        store.record("time", TOOL, "alice", ok=True, ms=1)
        await store._flush(final=False)
        reach = w.policy.keys_for(alice, "dashboard")
        assert await calls_of(store, reach) == 2
        assert table_calls(w.path, "alice") == 2
        assert table_calls(w.path, "") == 50
        assert await calls_of(store, admin(w)) == 52
    finally:
        await store.stop()


async def test_a_failed_write_keeps_the_new_holders_calls(tmp_path, monkeypatch):
    """Spec `A re-created user starts clean`, "A failed write keeps the new
    holder's calls"; D6 step 3 (gate R2-F1); "A failed write SHALL put its
    forget set back" (`usage_forget_gate_dropforget.cfg`).
    Mutation: decide the merge with the batch's own forget set -> the key
    goes to `''`. Mutation: drop the forget set on failure -> the old 50
    stay under alice."""
    w = world_with_eng(tmp_path, "time")
    store = w.store
    make_user(w.policy, "alice", groups=["eng"])
    await store.start()
    try:
        for _ in range(50):
            store.record("time", TOOL, "alice", ok=True, ms=1)
        await store._flush(final=False)
        alice = recreate(w, "alice")
        store.record("time", TOOL, "alice", ok=True, ms=1)
        fail_writes(store, monkeypatch, 1)
        with contextlib.suppress(Exception):
            await store._flush(final=False)
        assert pending_calls(store, "alice") == 1
        assert pending_calls(store, "") == 0
        await store._flush(final=False)
        assert store._pending == {}
        assert table_calls(w.path, "alice") == 1
        assert table_calls(w.path, "") == 50
        assert await calls_of(store, w.policy.keys_for(alice, "dashboard")) == 1
    finally:
        await store.stop()


async def test_a_forget_during_a_failed_write_moves_the_key(tmp_path, monkeypatch):
    """Spec `A re-created user starts clean` ("it SHALL move a key to the
    empty user only for a forget that ran after the swap of that batch").
    A delete during the held write that then fails sends alice's key to
    `''` on the merge, and the new alice never sees it."""
    w = world_with_eng(tmp_path, "time")
    store = w.store
    make_user(w.policy, "alice", groups=["eng"])
    await store.start()
    h = hold_write(store, monkeypatch, fail=True)
    try:
        store.record("time", TOOL, "alice", ok=True, ms=1)
        flush = asyncio.create_task(store._flush(final=False))
        await wait(h.entered, "the held write")
        alice = recreate(w, "alice")
        h.release.set()
        with contextlib.suppress(Exception):
            await flush
        assert pending_calls(store, "alice") == 0
        assert pending_calls(store, "") == 1
        assert await calls_of(store, w.policy.keys_for(alice, "dashboard")) == 0
        await store._flush(final=False)
        assert table_calls(w.path, "alice") == 0
        assert table_calls(w.path, "") == 1
    finally:
        h.release.set()
        await store.stop()


async def test_the_admin_keeps_the_old_calls(tmp_path):
    """Spec `A re-created user starts clean`, "The admin keeps the old
    calls"; D14: the moved counts stay visible to an admin under `''`."""
    w = world_with_eng(tmp_path, "time")
    store = w.store
    make_user(w.policy, "alice", groups=["eng"])
    await store.start()
    try:
        for _ in range(30):
            store.record("time", TOOL, "alice", ok=True, ms=1)
        await store._flush(final=False)
        for _ in range(20):
            store.record("time", TOOL, "alice", ok=True, ms=1)
        w.policy.delete_user(ADMIN_ACTOR, "alice")
        assert await calls_of(store, admin(w)) == 50
        await store._flush(final=False)
        assert await calls_of(store, admin(w)) == 50
        assert table_calls(w.path, "") == 50
        assert table_calls(w.path, "alice") == 0
    finally:
        await store.stop()


async def test_the_read_decides_the_skip_before_the_query(tmp_path, monkeypatch):
    """Spec `A re-created user starts clean` ("decided before the read
    queries the table"); model `usage_forget_gate_decidelate.cfg`: the new
    alice's read starts while the forget is queued, queries the table with
    the old rows still under alice, then the forget commits and clears
    before the read ends.
    Mutation: take the skip decision after the query -> the read holds the
    old 50."""
    w = world_with_eng(tmp_path, "time")
    store = w.store
    make_user(w.policy, "alice", groups=["eng"])
    await store.start()
    try:
        for _ in range(50):
            store.record("time", TOOL, "alice", ok=True, ms=1)
        await store._flush(final=False)
        alice = recreate(w, "alice")
        reach = w.policy.keys_for(alice, "dashboard")
        h = hold_query(store, monkeypatch, after=True)
        try:
            read = asyncio.create_task(store.totals(today_range(), reach))
            # A read that decided to skip may run no query at all.
            for _ in range(500):
                if h.entered.is_set() or read.done():
                    break
                await asyncio.sleep(0.01)
            assert h.entered.is_set() or read.done(), "the read neither queried nor ended"
            if h.entered.is_set():
                await store._flush(final=False)  # the forget commits and clears
                assert table_calls(w.path, "alice") == 0
            h.go.set()
            totals = await read
        finally:
            h.go.set()
        assert totals.by_tool.get(("time", TOOL), Counts()).calls == 0
        assert totals.by_server.get("time", Counts()).calls == 0
    finally:
        await store.stop()


# --- Usage faults (7.14) -------------------------------------------------


async def test_a_broken_file_does_not_stop_start(tmp_path, caplog):
    """Spec `Usage faults`, "A broken database file"; D15: `start` never
    raises, logs one error, and a read is degraded with `_pending` only."""
    w = make_world(tmp_path, "time")
    w.path.mkdir()
    store = w.store
    caplog.set_level(logging.WARNING, logger=LOGGER)
    await store.start()
    try:
        assert len(logs(caplog, logging.ERROR)) == 1
        assert store._task is not None and not store._task.done()
        store.record("time", TOOL, "alice", ok=True, ms=1)
        store.record("time", TOOL, "alice", ok=True, ms=1)
        reach = admin(w)
        totals = await store.totals(today_range(), reach)
        assert totals.degraded is True
        assert totals.by_tool[("time", TOOL)].calls == 2
        series = await store.series(today_range(), reach)
        assert series.degraded is True
        assert sum(series.by_server["time"]) == 2
    finally:
        await store.stop()


async def test_a_newer_schema_is_never_written(tmp_path, caplog):
    """Spec `Usage faults`, "A newer schema"; D15: one error, no write,
    every record dropped, no counts."""
    path = tmp_path / "usage.sqlite3"
    con = sqlite3.connect(path)
    with con:
        con.execute("CREATE TABLE future (x INTEGER)")
        con.execute("INSERT INTO future VALUES (1)")
    con.execute("PRAGMA user_version = 2")
    con.close()
    before = path.read_bytes()
    w = make_world(tmp_path, "time")
    store = w.store
    caplog.set_level(logging.WARNING, logger=LOGGER)
    await store.start()
    try:
        assert len(logs(caplog, logging.ERROR)) == 1
        make_user(w.policy, "alice")
        store.record("time", TOOL, "alice", ok=True, ms=1)
        store.forget_user("alice")
        assert store._pending == {}
        totals = await store.totals(today_range(), admin(w))
        assert totals.by_tool == {} and totals.by_server == {}
        series = await store.series(today_range(), admin(w))
        assert all(sum(v) == 0 for v in series.by_server.values())
    finally:
        await store.stop()
    assert path.read_bytes() == before
    assert not (tmp_path / "usage.sqlite3-wal").exists() or (
        (tmp_path / "usage.sqlite3-wal").stat().st_size == 0
    )


async def test_a_newer_schema_after_start_disables_the_store(tmp_path, caplog):
    """D15 after `start`: the flush finds `user_version` 2, logs one error,
    drops the batch, and the store writes nothing more."""
    w = make_world(tmp_path, "time")
    store = w.store
    await store.start()
    try:
        con = sqlite3.connect(tmp_path / "usage.sqlite3")
        con.execute("PRAGMA user_version = 2")
        con.close()
        caplog.set_level(logging.WARNING, logger=LOGGER)
        store.record("time", TOOL, "admin", ok=True, ms=1)
        await store._flush(final=False)
        assert len(logs(caplog, logging.ERROR)) == 1
        assert store._pending == {}
        store.record("time", TOOL, "admin", ok=True, ms=1)
        assert store._pending == {}
    finally:
        await store.stop()
    assert not logs(caplog, logging.WARNING)


async def test_a_read_without_a_table_is_degraded(tmp_path, caplog):
    """Spec `Usage faults` ("a read that ... finds no table, SHALL return the
    counts in memory only, mark its result degraded, and log one warning");
    D15: an unstarted store creates no file."""
    w = make_world(tmp_path, "time")
    path, store = w.path, w.store
    store.record("time", TOOL, "alice", ok=True, ms=1)
    caplog.set_level(logging.WARNING, logger=LOGGER)
    reach = admin(w)
    totals = await store.totals(today_range(), reach)
    assert totals.degraded is True
    assert totals.by_tool == {("time", TOOL): Counts(calls=1, errors=0)}
    assert len(logs(caplog, logging.WARNING)) == 1
    assert not path.exists()


async def test_a_write_heals_a_missing_schema(tmp_path):
    """Spec `Usage faults` ("A write SHALL create a missing schema in its own
    transaction"); D15."""
    path = tmp_path / "usage.sqlite3"
    store = UsageStore(path)
    await store.start()
    try:
        con = sqlite3.connect(path)
        with con:
            con.execute("DROP TABLE usage")
        con.close()
        store.record("time", TOOL, "alice", ok=True, ms=4)
        await store._flush(final=False)
        assert [r[1:] for r in rows(path)] == [("time", TOOL, "alice", 1, 0, 4)]
        assert store._pending == {}
    finally:
        await store.stop()


# --- Series buckets (7.15) -----------------------------------------------


def _local_noon_hour(d: date) -> int:
    return int(datetime.combine(d, dtime(12)).timestamp()) // 3600


async def test_series_buckets(tmp_path):
    """Spec `Usage range resolution` ("A week bucket SHALL start on Monday,
    and a month bucket SHALL be a calendar month"), `Usage chart`; D9: the
    first and the last bucket clip to the range."""
    w = make_world(tmp_path, "time", "weather")
    store = w.store
    await store.start()
    try:
        data = {
            date(2026, 9, 29): 100,  # before the range
            date(2026, 9, 30): 1,  # Wednesday, the range start
            date(2026, 10, 4): 2,  # Sunday
            date(2026, 10, 5): 4,  # Monday
            date(2026, 10, 31): 8,
            date(2026, 11, 4): 16,  # Wednesday, the range end
            date(2026, 11, 5): 100,  # after the range
        }
        con = sqlite3.connect(w.path)
        with con:
            for d, n in data.items():
                con.execute(
                    "INSERT INTO usage VALUES (?, 'time', ?, 'alice', ?, 0, 0)",
                    (_local_noon_hour(d), TOOL, n),
                )
            con.execute(
                "INSERT INTO usage VALUES (?, 'weather', 'forecast', 'bob', 3, 0, 0)",
                (_local_noon_hour(date(2026, 10, 5)),),
            )
        con.close()
        start, end = date(2026, 9, 30), date(2026, 11, 4)

        def rng(bucket):
            return UsageRange(start=start, end=end, bucket=bucket)

        day = await store.series(rng("day"), admin(w))
        assert day.degraded is False
        assert day.buckets[0] == start and day.buckets[-1] == end
        assert len(day.buckets) == (end - start).days + 1
        assert list(day.buckets) == [start + timedelta(days=i) for i in range(36)]
        by_day = dict(zip(day.buckets, day.by_server["time"], strict=True))
        assert by_day[date(2026, 10, 4)] == 2 and by_day[date(2026, 10, 5)] == 4
        assert sum(day.by_server["time"]) == 31
        assert sum(day.by_server["weather"]) == 3

        week = await store.series(rng("week"), admin(w))
        assert week.buckets == (
            date(2026, 9, 30),  # clipped: the Monday is 2026-09-28
            date(2026, 10, 5), date(2026, 10, 12), date(2026, 10, 19),
            date(2026, 10, 26), date(2026, 11, 2),
        )
        assert week.by_server["time"] == (3, 4, 0, 0, 8, 16)
        assert week.by_server["weather"] == (0, 3, 0, 0, 0, 0)

        month = await store.series(rng("month"), admin(w))
        assert month.buckets == (date(2026, 9, 30), date(2026, 10, 1), date(2026, 11, 1))
        assert month.by_server["time"] == (1, 14, 16)
        assert month.by_server["weather"] == (0, 3, 0)
    finally:
        await store.stop()
