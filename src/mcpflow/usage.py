"""Tool-call usage statistics (change `usage-stats`).

Owners (design D13): `attribute` writes the per-call holder; the provider
that returns the tool calls it (`CallerRouter._named` for a child tool,
`UsageAttribution` for a built-in one). `UsageMiddleware` owns the timer,
the outcome, the user, and the record. `UsageStore` owns the in-memory
batch, the flush, the schema, the retention, the forget queue, and the
reads.

The step order of `record`, `forget_user`, `_flush`, `stop`, and the reads
is the order that `specs/tla/usage_stats.tla` and
`specs/tla/usage_forget.tla` check. Do not reorder it.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import time
from collections.abc import Mapping
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from datetime import time as dtime
from typing import TYPE_CHECKING, Any, Literal

from fastmcp.exceptions import NotFoundError
from fastmcp.server.middleware import Middleware
from fastmcp.server.transforms import GetToolNext, Transform, VersionSpec
from fastmcp.tools.base import InputRequiredToolResult, ToolResult

from .registry import RESERVED_NAMESPACE

if TYPE_CHECKING:
    from pathlib import Path

    from fastmcp.tools.base import Tool

    from .identity import User
    from .policy import AccessPolicy, Reach

logger = logging.getLogger(__name__)

FLUSH_INTERVAL = 30.0      # seconds between flushes
RETENTION_DAYS = 400       # rows older than this are deleted at flush
MAX_RANGE_DAYS = 400       # the widest range a read accepts
DEFAULT_RANGE_DAYS = 30
TOP_SERVERS = 7
SCHEMA_VERSION = 1

Bucket = Literal["day", "week", "month"]

# (hour, server, tool, user) -> [calls, errors, total_ms]
Key = tuple[int, str, str, str]


# --- attribution (D1, D2) ---------------------------------------------------


@dataclass
class Attribution:
    ref: str | None = None
    tool: str | None = None


CALL_ATTRIBUTION: ContextVar[Attribution | None] = ContextVar(
    "mcpflow_call_attribution", default=None
)


def attribute(ref: str, tool: str) -> None:
    """Write the call's holder. A no-op outside a `tools/call`: only
    `UsageMiddleware` sets a holder, so a list or a test writes nothing."""
    holder = CALL_ATTRIBUTION.get()
    if holder is not None:
        holder.ref = ref
        holder.tool = tool


# --- read results -----------------------------------------------------------


@dataclass(frozen=True)
class Counts:
    calls: int = 0
    errors: int = 0


@dataclass(frozen=True)
class UsageRange:
    start: date      # inclusive, local
    end: date        # inclusive, local
    bucket: Bucket


@dataclass(frozen=True)
class Totals:
    by_tool: dict[tuple[str, str], Counts]       # (ref, tool) -> counts
    by_server: dict[str, Counts]                 # ref -> counts
    degraded: bool


@dataclass(frozen=True)
class Series:
    buckets: tuple[date, ...]                    # first day of each bucket
    by_server: dict[str, tuple[int, ...]]        # ref -> calls per bucket
    degraded: bool


# --- the store (D5 to D8, D14, D15) -----------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS usage (
    hour     INTEGER NOT NULL,
    server   TEXT    NOT NULL,
    tool     TEXT    NOT NULL,
    user     TEXT    NOT NULL,
    calls    INTEGER NOT NULL,
    errors   INTEGER NOT NULL,
    total_ms INTEGER NOT NULL,
    PRIMARY KEY (hour, server, tool, user)
) WITHOUT ROWID
"""
_ADD = (
    " ON CONFLICT (hour, server, tool, user) DO UPDATE SET"
    " calls = calls + excluded.calls,"
    " errors = errors + excluded.errors,"
    " total_ms = total_ms + excluded.total_ms"
)
_UPSERT = "INSERT INTO usage VALUES (?, ?, ?, ?, ?, ?, ?)" + _ADD
# The WHERE clause is required: it ends the SELECT, so SQLite parses the
# ON CONFLICT as the upsert clause and not as a join constraint.
_MOVE = (
    "INSERT INTO usage SELECT hour, server, tool, '', calls, errors, total_ms"
    " FROM usage WHERE user = ?" + _ADD
)


class _NewerSchema(Exception):
    """The file has a `user_version` this gateway does not know (D15)."""


def _scope(reach: Reach) -> tuple[str, frozenset[str]] | None:
    """D12: `None` reads every row (admin); else `(user id, server refs)`."""
    if reach.user.is_admin:
        return None
    return reach.user.id, frozenset(k.ref for k in reach.keys)


def _hours(rng: UsageRange) -> tuple[int, int]:
    """The UTC hours of the local days of `rng`: `[start, end)`."""

    def hour(d: date) -> int:
        return int(datetime.combine(d, dtime.min).timestamp()) // 3600

    return hour(rng.start), hour(rng.end + timedelta(days=1))


def _bucket_start(day: date, rng: UsageRange) -> date:
    if rng.bucket == "week":
        first = day - timedelta(days=day.weekday())
    elif rng.bucket == "month":
        first = day.replace(day=1)
    else:
        return day
    return max(first, rng.start)


class UsageStore:
    def __init__(self, path: Path) -> None:
        # No file I/O here: `start` opens the file.
        self._path = path
        self._pending: dict[Key, list[int]] = {}
        self._forget: set[str] = set()
        self._inflight_forget: set[str] = set()
        self._closed = False
        self._disabled = False
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    def _add(self, key: Key, counts: list[int]) -> None:
        acc = self._pending.setdefault(key, [0, 0, 0])
        for i, n in enumerate(counts):
            acc[i] += n

    # --- writers on the event loop (synchronous: never await) -----------

    def record(self, ref: str, tool: str, user: str, *, ok: bool, ms: int) -> None:
        if self._closed:
            logger.debug("usage store closed; dropped call of %s %s", ref, tool)
            return
        if self._disabled:
            return
        hour = int(time.time()) // 3600
        self._add((hour, ref, tool, user), [1, 0 if ok else 1, ms])

    def forget_user(self, user_id: str) -> None:
        # D14. Step 1 then step 2, with no await (usage_forget_nopending.cfg).
        # An empty id would move the '' rows onto themselves and delete them.
        if self._disabled or not user_id:
            return
        for key in [k for k in self._pending if k[3] == user_id]:
            self._add((key[0], key[1], key[2], ""), self._pending.pop(key))
        self._forget.add(user_id)

    # --- the flush (D6) -------------------------------------------------

    @staticmethod
    def _check_version(con: sqlite3.Connection) -> int:
        version = con.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, SCHEMA_VERSION):
            raise _NewerSchema(f"user_version {version}")
        return version

    def _write(self, batch: dict[Key, list[int]], forget: set[str]) -> None:
        """One transaction in a worker thread: schema, move, upsert, retention
        (usage_forget_upsertfirst.cfg rejects the upsert before the move)."""
        now_hour = int(time.time()) // 3600
        con = sqlite3.connect(self._path, isolation_level=None)
        try:
            # The journal-mode switch rewrites the file header, so refuse a
            # newer file before it too; the check in the transaction stays.
            self._check_version(con)
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("BEGIN IMMEDIATE")
            try:
                version = self._check_version(con)
                con.execute(_SCHEMA)
                if version == 0:
                    con.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                for uid in forget:
                    con.execute(_MOVE, (uid,))
                    con.execute("DELETE FROM usage WHERE user = ?", (uid,))
                con.executemany(_UPSERT, [(*k, *v) for k, v in batch.items()])
                con.execute(
                    "DELETE FROM usage WHERE hour < ?",
                    (now_hour - RETENTION_DAYS * 24,),
                )
                con.execute("COMMIT")
            except Exception:
                if con.in_transaction:
                    con.execute("ROLLBACK")
                raise
        finally:
            con.close()

    async def _flush(self, *, final: bool) -> None:
        if self._disabled:
            return
        # Step 1, the swap: no await between the read and the reset
        # (usage_stats_gate_splitswap.cfg).
        batch, forget = self._pending, self._forget
        self._pending, self._forget = {}, set()
        self._inflight_forget = forget
        if not batch and not forget:
            self._inflight_forget = set()
            return
        try:
            await asyncio.to_thread(self._write, batch, forget)
        except _NewerSchema as exc:
            # D15: a newer schema appeared after `start`. Disable the store and
            # drop the batch; a retry would only fail again every interval.
            logger.error("usage: %s has a newer schema (%s); statistics disabled", self._path, exc)
            self._disabled = True
            self._pending, self._forget = {}, set()
            self._inflight_forget = set()
            return
        except Exception:
            # Exception only: a cancel merges nothing (usage_stats_cancelmerge.cfg).
            if final:
                logger.warning(
                    "usage: final write failed; dropped %d calls",
                    sum(v[0] for v in batch.values()),
                    exc_info=True,
                )
            else:
                # Step 3: only a forget that ran after the swap sends a key to
                # '' (usage_forget_gate_mergeany.cfg); then the batch's own
                # forget set goes back (usage_forget_gate_dropforget.cfg).
                after = set(self._forget)
                for (hour, server, tool, user), counts in batch.items():
                    self._add((hour, server, tool, "" if user in after else user), counts)
                self._forget |= forget
                logger.warning("usage: write failed; retrying next interval", exc_info=True)
            self._inflight_forget = set()
            return
        # Step 4: the forget committed, so the read skip ends here, not at the
        # swap (usage_forget_clearatswap.cfg).
        self._inflight_forget = set()

    async def _run(self) -> None:
        # The loop never ends before the stop, whatever an iteration raises.
        while True:
            try:
                await asyncio.wait_for(self._stop.wait(), FLUSH_INTERVAL)
            except TimeoutError:
                pass
            final = self._stop.is_set()
            try:
                await self._flush(final=final)
            except Exception:
                logger.exception("usage: flush failed")
            if final:
                return

    # --- lifecycle (D7, D15) --------------------------------------------

    async def start(self) -> None:
        """Open the file and create the schema. Never raises."""
        try:
            await asyncio.to_thread(self._write, {}, set())
        except _NewerSchema as exc:
            logger.error("usage: %s has a newer schema (%s); statistics disabled", self._path, exc)
            self._disabled = True
        except Exception:
            # The store stays enabled: a later `_write` can heal the file.
            logger.exception("usage: cannot open %s", self._path)
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        # Closed before any await (usage_stats_gate_stopnoawait.cfg needs the
        # await of the task below).
        self._closed = True
        self._stop.set()
        if self._task is not None:
            await self._task

    # --- reads (D8, D12, D14, D15) --------------------------------------

    def _query(
        self, by_day: bool, lo: int, hi: int, scope: tuple[str, frozenset[str]] | None
    ) -> list[tuple[str, Any, int, int]]:
        group = "date(hour * 3600, 'unixepoch', 'localtime')" if by_day else "tool"
        sql = f"SELECT server, {group}, SUM(calls), SUM(errors) FROM usage WHERE hour >= ? AND hour < ?"
        params: list[Any] = [lo, hi]
        if scope is not None:
            uid, refs = scope
            sql += f" AND user = ? AND server IN ({', '.join('?' * len(refs))})"
            params += [uid, *refs]
        sql += " GROUP BY 1, 2"
        # mode=rw: a read never creates the file.
        con = sqlite3.connect(self._path.absolute().as_uri() + "?mode=rw", uri=True)
        try:
            rows = con.execute(sql, params).fetchall()
        finally:
            con.close()
        if by_day:
            return [(s, date.fromisoformat(d), c, e) for s, d, c, e in rows]
        return rows

    async def _read(
        self, rng: UsageRange, reach: Reach, *, by_day: bool
    ) -> tuple[dict[tuple[str, Any], list[int]], bool]:
        """SQLite first, then `_pending` (usage_stats_pendingfirst.cfg); never
        the running batch (usage_stats_readinflight.cfg)."""
        if self._disabled:
            return {}, True
        scope = _scope(reach)
        lo, hi = _hours(rng)
        out: dict[tuple[str, Any], list[int]] = {}

        def add(server: str, k: Any, calls: int, errors: int) -> None:
            acc = out.setdefault((server, k), [0, 0])
            acc[0] += calls
            acc[1] += errors

        # Step 1: decide the skip before the query (usage_forget_gate_decidelate.cfg).
        skip = scope is not None and (
            not scope[1] or scope[0] in self._forget or scope[0] in self._inflight_forget
        )
        degraded = False
        if not skip:
            try:
                # Step 2.
                rows = await asyncio.to_thread(self._query, by_day, lo, hi, scope)
            except Exception:
                logger.warning("usage: read of %s failed", self._path, exc_info=True)
                rows, degraded = [], True
            for row in rows:
                add(*row)
        # Step 3: `_pending` after the await, with no await in this loop.
        for (hour, server, tool, user), (calls, errors, _ms) in self._pending.items():
            if not lo <= hour < hi:
                continue
            if scope is not None and (user != scope[0] or server not in scope[1]):
                continue
            add(server, datetime.fromtimestamp(hour * 3600, UTC).astimezone().date() if by_day else tool, calls, errors)
        return out, degraded

    async def totals(self, rng: UsageRange, reach: Reach) -> Totals:
        rows, degraded = await self._read(rng, reach, by_day=False)
        by_tool = {key: Counts(c, e) for key, (c, e) in rows.items()}
        per_ref: dict[str, list[int]] = {}
        for (ref, _tool), (c, e) in rows.items():
            acc = per_ref.setdefault(ref, [0, 0])
            acc[0] += c
            acc[1] += e
        by_server = {ref: Counts(c, e) for ref, (c, e) in per_ref.items()}
        return Totals(by_tool, by_server, degraded)

    async def series(self, rng: UsageRange, reach: Reach) -> Series:
        rows, degraded = await self._read(rng, reach, by_day=True)
        days = (rng.start + timedelta(days=n) for n in range((rng.end - rng.start).days + 1))
        buckets = tuple(dict.fromkeys(_bucket_start(d, rng) for d in days))
        index = {b: i for i, b in enumerate(buckets)}
        per_ref: dict[str, list[int]] = {}
        for (ref, day), (calls, _errors) in rows.items():
            # A half-hour time zone can put one hour outside the range: clip it.
            day = min(max(day, rng.start), rng.end)
            per_ref.setdefault(ref, [0] * len(buckets))[index[_bucket_start(day, rng)]] += calls
        return Series(buckets, {ref: tuple(v) for ref, v in per_ref.items()}, degraded)


# --- the built-in chain and the gateway middleware (D1 to D4) ----------------


class UsageAttribution(Transform):
    """Attribute a built-in tool. `register_builtin` puts it inside
    `Namespace(RESERVED_NAMESPACE)`, so `name` is the bare tool name, and
    outside `ScopeFilter`, so a non-admin session gets `None` here."""

    async def get_tool(
        self, name: str, call_next: GetToolNext, *, version: VersionSpec | None = None
    ) -> Tool | None:
        tool = await call_next(name, version=version)
        if tool is not None:
            attribute(RESERVED_NAMESPACE, name)
        return tool


class UsageMiddleware(Middleware):
    """Time each `tools/call` and record it once it ends (D3)."""

    def __init__(self, store: UsageStore, policy: AccessPolicy) -> None:
        self._store = store
        self._policy = policy

    async def on_call_tool(self, context: Any, call_next: Any) -> Any:
        user = self._policy.current_user()  # the snapshot, before the call (D4)
        holder = Attribution()
        token = CALL_ATTRIBUTION.set(holder)
        t0 = time.monotonic()
        try:
            try:
                result = await call_next(context)
            except NotFoundError:
                raise  # no tool resolved
            except Exception:
                self._record(holder, user, t0, ok=False)
                raise
            # A BaseException (a cancel) did not end the call: no record.
            if isinstance(result, InputRequiredToolResult):
                return result  # the round that ends the call records it
            self._record(
                holder, user, t0,
                ok=not (isinstance(result, ToolResult) and result.is_error),
            )
            return result
        finally:
            CALL_ATTRIBUTION.reset(token)

    def _record(self, holder: Attribution, user: User | None, t0: float, *, ok: bool) -> None:
        # `is_current` and `record` in one synchronous step
        # (usage_forget_gate_norecordcheck.cfg).
        if holder.ref is None or holder.tool is None:
            return
        uid = user.id if user is not None and self._policy.is_current(user) else ""
        ms = int((time.monotonic() - t0) * 1000)
        self._store.record(holder.ref, holder.tool, uid, ok=ok, ms=ms)


# --- range and chart (D9, D10) ------------------------------------------------


_BUCKETS = ("day", "week", "month")


def parse_range(params: Mapping[str, str], today: date) -> UsageRange:
    """The one owner of the parse, the defaults, and the limits (D9).

    The steps run in this order; the range grants nothing."""

    def day(name: str) -> date | None:
        try:
            return date.fromisoformat(params[name])
        except (KeyError, ValueError):
            return None

    # Step 1: each field alone.
    end = day("to") or today
    start = day("from")
    bucket = params.get("bucket")
    if bucket not in _BUCKETS:
        bucket = "day"
    # Step 2.
    end = min(end, today)
    # Step 3.
    default = end - timedelta(days=DEFAULT_RANGE_DAYS - 1)
    if start is None or start > end or (end - start).days + 1 > MAX_RANGE_DAYS:
        start = default
    return UsageRange(start, end, bucket)  # type: ignore[arg-type]


_VIEW_W, _VIEW_H = 960, 200
_PAD_L, _PAD_B, _PAD_T = 36, 22, 6
OTHER = "other"


@dataclass(frozen=True)
class Bar:
    x: float
    y: float
    width: float
    height: float
    slot: int          # color slot: the rank of the series; `other` is last
    label: str         # the series name
    day: date          # first day of the bucket
    calls: int


@dataclass(frozen=True)
class Tick:
    y: float
    value: int


@dataclass(frozen=True)
class XLabel:
    x: float
    day: date


@dataclass(frozen=True)
class LegendRow:
    label: str
    slot: int
    calls: int


@dataclass(frozen=True)
class ChartView:
    width: int
    height: int
    plot_left: int
    bars: tuple[Bar, ...]
    ticks: tuple[Tick, ...]
    xlabels: tuple[XLabel, ...]
    legend: tuple[LegendRow, ...]
    degraded: bool
    empty: bool


def _nice_max(peak: int) -> int:
    """The smallest 4 * (1, 2, 5) * 10^k at or above `peak`: four even ticks."""
    step = 1
    while True:
        for m in (1, 2, 5):
            if 4 * m * step >= peak:
                return 4 * m * step
        step *= 10


def chart_view(series: Series, *, top: int = TOP_SERVERS) -> ChartView:
    """Pure: the stacked bars, ticks, and legend of `series` (D10)."""
    n = len(series.buckets)
    totals = {ref: sum(v) for ref, v in series.by_server.items()}
    ranked = sorted((r for r in totals if totals[r] > 0), key=lambda r: (-totals[r], r))
    rows: list[tuple[str, tuple[int, ...]]] = [(r, series.by_server[r]) for r in ranked[:top]]
    rest = ranked[top:]
    if rest:
        rows.append((OTHER, tuple(sum(series.by_server[r][i] for r in rest) for i in range(n))))
    if not rows:
        return ChartView(_VIEW_W, _VIEW_H, _PAD_L, (), (), (), (), series.degraded, True)

    plot_h = _VIEW_H - _PAD_B - _PAD_T
    peak = max(sum(v[i] for _, v in rows) for i in range(n))
    top_value = _nice_max(peak)
    slot_w = (_VIEW_W - _PAD_L) / n
    bar_w = min(22.0, max(slot_w - 4, 1.0))
    bars: list[Bar] = []
    xlabels: list[XLabel] = []
    every = max(1, -(-n // 6))
    for i, b in enumerate(series.buckets):
        x = _PAD_L + i * slot_w + (slot_w - bar_w) / 2
        acc = 0.0
        for k, (label, calls) in enumerate(rows):
            if not calls[i]:
                continue
            h = plot_h * calls[i] / top_value
            slot = top if label == OTHER else k
            bars.append(Bar(
                round(x, 1), round(_VIEW_H - _PAD_B - acc - h, 1),
                round(bar_w, 1), round(max(h - 1, 0.5), 1), slot, label, b, calls[i],
            ))
            acc += h
        if i % every == 0:
            xlabels.append(XLabel(round(x + bar_w / 2, 1), b))
    ticks = tuple(
        Tick(round(_VIEW_H - _PAD_B - plot_h * t / 4, 1), top_value * t // 4) for t in range(5)
    )
    legend = tuple(
        LegendRow(label, top if label == OTHER else k, sum(calls))
        for k, (label, calls) in enumerate(rows)
    )
    return ChartView(
        _VIEW_W, _VIEW_H, _PAD_L, tuple(bars), ticks, tuple(xlabels), legend,
        series.degraded, False,
    )
