"""The web layer of usage-stats: range, bar, chart, tree header and column.

Scenarios from `specs/web-ui/spec.md` (Usage bar, Usage range resolution,
Usage chart, Usage in the tool tree, Tool tree poll) and
`specs/usage-stats/spec.md` (Usage visibility, Usage faults).
"""

from __future__ import annotations

import contextlib
import re
import sqlite3
import time
from datetime import date, datetime
from datetime import time as dtime
from types import SimpleNamespace
from unittest import mock

import httpx
import pytest
from conftest import ADMIN_ACTOR, fake_child_spec, make_settings, make_user

from mcpflow import usage as usage_mod
from mcpflow.auth import TokenStore, sign_session
from mcpflow.usage import Series, UsageStore, chart_view, parse_range

TODAY = date(2026, 11, 16)
RANGE = "from=2026-11-01&to=2026-11-07&bucket=day"
IN_RANGE = date(2026, 11, 3)
OUT_OF_RANGE = date(2026, 11, 10)
ALICE_PW = "pw-alice-0123456789"


def rec(store, day, ref, tool, user="admin", *, ok=True, n=1):
    """Record `n` calls at local noon of `day` (the store stamps `time.time()`)."""
    ts = int(datetime.combine(day, dtime(12)).timestamp())
    with mock.patch.object(usage_mod, "time", SimpleNamespace(time=lambda: ts)):
        for _ in range(n):
            store.record(ref, tool, user, ok=ok, ms=5)


def text(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()


def header(body: str, ns: str) -> str:
    """The text of the `<summary>` of group `ns`."""
    for m in re.finditer(r"<summary[^>]*>(.*?)</summary>", body, re.DOTALL):
        t = text(m.group(1))
        if t.split(" ")[0] == ns or f" {ns} " in f" {t} ":
            return t
    raise AssertionError(f"no header for {ns}")


def row(body: str, tool: str) -> str:
    for m in re.finditer(r"<tr[^>]*>(.*?)</tr>", body, re.DOTALL):
        if tool in m.group(1):
            return m.group(1)
    raise AssertionError(f"no row for {tool}")


@contextlib.asynccontextmanager
async def env(tmp_path, children=(), *, alice_on=None, store_start=False):
    from starlette.applications import Starlette
    from starlette.middleware import Middleware

    from mcpflow.auth import SessionGate
    from mcpflow.identity import LocalIdentityProvider
    from mcpflow.oauth import CredStore, PendingFlows
    from mcpflow.policy import AccessPolicy, RuleStore
    from mcpflow.registry import Registry
    from mcpflow.supervisor import Supervisor
    from mcpflow.web import USER_ROUTES, build_routes

    d = tmp_path / "d"
    d.mkdir(exist_ok=True)
    (d / "logs").mkdir()
    reg = Registry(d / "servers.json", d / "user_servers.json")
    reg.load()
    settings = make_settings(d)
    store = UsageStore(d / "usage.sqlite3")
    identity = LocalIdentityProvider(d / "users.json")
    identity.load()
    tokens = TokenStore(d / "tokens.json", d / "user_tokens.json")
    tokens.load()
    rules = RuleStore(d / "rules.json")
    rules.load()
    policy = AccessPolicy(identity, rules, tokens, reg, store)
    sup = Supervisor(reg, settings, CredStore(d), PendingFlows(), policy)
    tasks = [(await sup.add(fake_child_spec(ns, "good"), ADMIN_ACTOR)).task for ns in children]
    for t in tasks:
        if t is not None:
            await t
    if alice_on is not None:
        make_user(policy, "alice", ALICE_PW)
        for ns in alice_on:
            policy.add_rule(ADMIN_ACTOR, subject_kind="user", subject="alice",
                            level="server", server=ns, tool=None, effect="allow")
    if store_start:
        await store.start()
    routes = build_routes(sup, tokens, settings, sup.creds, sup.flows, identity, store)
    app = Starlette(routes=routes, middleware=[Middleware(
        SessionGate, secret=settings.secret_key, identity=identity,
        public_prefixes=("/login", "/static/"), user_routes=USER_ROUTES)])
    cookie = sign_session(settings.secret_key, "admin", identity.session_binding("admin"), int(time.time()) + 3600)

    def client(cookies=None):
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://test",
                                 cookies={"mcpflow_session": cookie} if cookies is None else cookies)

    async def alice():
        c = client({})
        r = await c.post("/login", data={"user": "alice", "password": ALICE_PW, "next": "/"})
        assert r.status_code == 303, r.text
        return c

    try:
        yield SimpleNamespace(store=store, client=client, alice=alice, d=d, sup=sup)
    finally:
        await sup.shutdown()
        if store_start:
            await store.stop()


# --- 9.1 / 9.2 range -----------------------------------------------------------


def test_parse_range():
    default = (date(2026, 10, 18), date(2026, 11, 16))

    def span(p):
        r = parse_range(p, TODAY)
        return r.start, r.end

    assert span({"from": "yesterday"}) == default
    assert span({"from": "2026-11-20", "to": "2026-11-25"}) == default
    assert span({}) == default
    # 401 days resets `from`; 400 days keeps it.
    assert span({"from": "2025-10-12", "to": "2026-11-16"}) == default  # 401 days
    assert span({"from": "2025-10-13", "to": "2026-11-16"}) == (date(2025, 10, 13), TODAY)  # 400
    # `from` after `to` keeps `to`.
    assert span({"from": "2026-11-10", "to": "2026-11-05"}) == (date(2026, 10, 7), date(2026, 11, 5))
    assert parse_range({"bucket": "year"}, TODAY).bucket == "day"
    assert parse_range({"bucket": "week"}, TODAY).bucket == "week"


@pytest.mark.asyncio
async def test_the_range_source(tmp_path):
    async with env(tmp_path, ["time"]) as e:
        rec(e.store, IN_RANGE, "time", "get_current_time", n=2)
        rec(e.store, OUT_OF_RANGE, "time", "get_current_time", n=5)
        hdr = {"HX-Current-URL": f"http://test/?{RANGE}"}
        other = {"HX-Current-URL": "http://test/?from=2026-11-09&to=2026-11-11"}
        async with e.client() as c:
            # No range field in the query: the header decides.
            assert "2 calls" in header((await c.get("/tools/tree", headers=hdr)).text, "time")
            # The query wins over the header.
            r = await c.get("/tools/tree?from=2026-11-09&to=2026-11-11", headers=hdr)
            assert "5 calls" in header(r.text, "time")
            r = await c.get(f"/tools/tree?{RANGE}", headers=other)
            assert "2 calls" in header(r.text, "time")
            # `poll=1` alone is not a range field.
            r = await c.get("/tools/tree?poll=1", headers=hdr)
            assert "2 calls" in header(r.text, "time")


# --- 9.3 / 9.4 / 9.5 -----------------------------------------------------------


@pytest.mark.asyncio
async def test_the_tree_keeps_the_page_range(tmp_path):
    async with env(tmp_path, ["time"]) as e:
        rec(e.store, IN_RANGE, "time", "get_current_time", n=2)
        rec(e.store, OUT_OF_RANGE, "time", "get_current_time", n=7)
        async with e.client() as c:
            r = await c.post("/visibility/namespaces/time/tool",
                             data={"tool": "get_current_time"},  # no `visible`: muted
                             headers={"HX-Request": "true",
                                      "HX-Current-URL": f"http://test/?{RANGE}"})
        assert r.status_code == 200
        assert "2 calls" in header(r.text, "time")
        assert "9 calls" not in r.text and "7" not in text(row(r.text, "get_current_time"))


@pytest.mark.asyncio
async def test_the_poll_keeps_the_page_range(tmp_path):
    async with env(tmp_path, ["time"]) as e:
        rec(e.store, IN_RANGE, "time", "get_current_time", n=3)
        rec(e.store, OUT_OF_RANGE, "time", "get_current_time", n=4)
        async with e.client() as c:
            r = await c.get("/tools/tree?poll=1", headers={
                "HX-Current-URL": "http://test/?from=2026-11-01&to=2026-11-07&bucket=week"})
        assert "3 calls" in header(r.text, "time")
        root = r.text[r.text.index('<div id="tools-tree"'):].split(">", 1)[0]
        assert "from=" not in root and "bucket=" not in root


@pytest.mark.asyncio
async def test_the_noscript_link_carries_the_range(tmp_path):
    async with env(tmp_path) as e, e.client() as c:
        body = (await c.get("/?from=2026-11-01&to=2026-11-07&bucket=week")).text
    link = re.search(r"<noscript>.*?href=\"([^\"]*/tools/tree[^\"]*)\"", body, re.DOTALL)
    assert link, body
    href = link.group(1).replace("&amp;", "&")
    assert "from=2026-11-01" in href and "to=2026-11-07" in href and "bucket=week" in href


# --- 9.6 bar -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_usage_bar(tmp_path):
    async with env(tmp_path) as e:
        for d in (date(2026, 11, 2), date(2026, 11, 9), date(2026, 11, 10)):  # Mondays, a Tuesday
            rec(e.store, d, "time", "get_current_time")
        async with e.client() as c:
            body = (await c.get("/?from=2026-11-02&to=2026-11-15&bucket=week")).text
    form = re.search(r"<form[^>]*method=\"get\"[^>]*>.*?</form>", body, re.DOTALL | re.IGNORECASE)
    assert form
    f = form.group(0)
    assert 'action="/"' in f
    assert re.search(r'<input[^>]*type="date"[^>]*name="from"|<input[^>]*name="from"[^>]*type="date"', f)
    assert re.search(r'<input[^>]*type="date"[^>]*name="to"|<input[^>]*name="to"[^>]*type="date"', f)
    assert "2026-11-02" in f and "2026-11-15" in f
    # One radio group carries the bucket, so every submit (Apply, or Enter in
    # a date field) sends the checked value.
    radios = re.findall(r"<label>\s*<input[^>]*type=\"radio\"[^>]*>.*?</label>", f, re.DOTALL)
    assert [text(r) for r in radios] == ["Daily", "Weekly", "Monthly"]
    assert all('name="bucket"' in r for r in radios)
    assert [re.search(r'value="(\w+)"', r).group(1) for r in radios] == ["day", "week", "month"]
    assert [text(r) for r in radios if re.search(r"\bchecked\b", r)] == ["Weekly"]
    # A bucket change submits at once; a click on a date field opens its picker.
    assert all("requestSubmit()" in r for r in radios)
    dates = re.findall(r'<input[^>]*type="date"[^>]*>', f)
    assert len(dates) == 2 and all("showPicker" in d for d in dates)
    # The `from` field carries no `max`: a typed later range must submit.
    assert all("max=" not in d for d in dates)
    # Exactly one submit button, and it names no field.
    buttons = re.findall(r"<button[^>]*>.*?</button>", f, re.DOTALL)
    assert [text(b) for b in buttons] == ["Apply"]
    assert "name=" not in buttons[0]
    # One bar column per week: two weeks in the range, two bars (one series).
    assert len(re.findall(r"<rect[^>]*>\s*<title>", body)) == 2


# --- 9.7 chart -----------------------------------------------------------------


def test_more_than_seven_servers_view():
    buckets = (date(2026, 11, 1),)
    series = Series(buckets, {f"s{i}": (i,) for i in range(1, 10)}, False)
    view = chart_view(series)
    labels = [r.label for r in view.legend]
    assert len(labels) == 8 and labels[-1] == "other"
    assert labels[:7] == [f"s{i}" for i in range(9, 2, -1)]
    assert [r.calls for r in view.legend][-1] == 1 + 2  # the two smallest fold


@pytest.mark.asyncio
async def test_more_than_seven_servers_page(tmp_path):
    async with env(tmp_path) as e:
        for i in range(1, 10):
            rec(e.store, IN_RANGE, f"srv{i}", "t", n=i)
        async with e.client() as c:
            body = (await c.get(f"/?{RANGE}")).text
    svg = re.search(r"<svg.*?</svg>", body, re.DOTALL).group(0)
    assert 'role="img"' in svg and re.search(r'aria-label="[^"]+"', svg)
    rects = re.findall(r"<rect[^>]*>.*?</rect>", svg, re.DOTALL)
    assert rects and all("<title>" in r for r in rects)
    # Seven named series and `other`: nine servers, two are folded.
    assert "other" in text(body)
    for i in range(3, 10):
        assert f"srv{i}" in svg
    assert "srv1" not in svg and "srv2" not in svg
    assert "9 calls" in text(body) and "3 calls" in text(body)  # srv9 total; other = 1 + 2


# --- 9.8 empty and degraded -----------------------------------------------------


@pytest.mark.asyncio
async def test_an_empty_range_and_a_degraded_read(tmp_path):
    async with env(tmp_path, ["time"]) as e, e.client() as c:
        empty = (await c.get(f"/?{RANGE}")).text
        tree = (await c.get(f"/tools/tree?{RANGE}")).text
    assert "No calls in this range." in empty
    assert "<svg" not in empty
    assert "<svg" not in tree and "No calls in this range." not in tree


@pytest.mark.asyncio
async def test_a_degraded_read(tmp_path):
    # The store is not started and has no file: every read fails and degrades.
    async with env(tmp_path, ["time"]) as e, e.client() as c:
        page = await c.get(f"/?{RANGE}")
        tree = await c.get(f"/tools/tree?{RANGE}")
    assert page.status_code == 200 and tree.status_code == 200
    assert "Usage is not available." in page.text
    assert "<svg" not in tree.text


# --- 9.9 / 9.10 header and column -------------------------------------------------


@pytest.mark.asyncio
async def test_header_and_column(tmp_path):
    async with env(tmp_path, ["gitlab", "weather"]) as e:
        rec(e.store, IN_RANGE, "gitlab", "get_current_time", n=854)
        rec(e.store, IN_RANGE, "gitlab", "get_current_time", ok=False, n=12)
        rec(e.store, IN_RANGE, "gitlab", "other_tool", n=2546)
        async with e.client() as c:
            body = (await c.get(f"/tools/tree?{RANGE}")).text
            muted = await c.post(
                "/visibility/namespaces/gitlab/tool", data={"tool": "get_current_time"},
                headers={"HX-Current-URL": f"http://test/?{RANGE}"})
    assert header(body, "gitlab").endswith("3,412 calls")
    cell = text(row(body, "gitlab_get_current_time"))
    assert "866" in cell and "12 errors" in cell
    # A tool with no calls shows 0.
    assert re.search(r"(^| )0( |$)", text(row(body, "weather_get_current_time")).replace("Usage", ""))
    assert "<th>Usage</th>" in body or ">Usage<" in body
    # A muted tool shows its calls.
    assert "866" in text(row(muted.text, "gitlab_get_current_time"))


@pytest.mark.asyncio
async def test_one_call(tmp_path):
    async with env(tmp_path, ["time"]) as e:
        rec(e.store, IN_RANGE, "time", "get_current_time")
        async with e.client() as c:
            one = (await c.get(f"/tools/tree?{RANGE}")).text
        rec(e.store, IN_RANGE, "time", "get_current_time", ok=False)
        async with e.client() as c:
            err = (await c.get(f"/tools/tree?{RANGE}")).text
    assert header(one, "time").endswith("1 call")
    assert "error" not in text(row(one, "get_current_time"))
    assert re.search(r"\b1 error\b", text(row(err, "get_current_time")))
    assert not re.search(r"\b1 errors\b", err)


# --- 9.11 visibility ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_forged_header_grants_nothing(tmp_path):
    async with env(tmp_path, ["time", "gitlab"], alice_on=["time"]) as e:
        rec(e.store, IN_RANGE, "time", "get_current_time", "alice", n=2)
        rec(e.store, IN_RANGE, "time", "get_current_time", "bob", n=5)
        rec(e.store, IN_RANGE, "time", "get_current_time", "admin", n=7)
        rec(e.store, IN_RANGE, "gitlab", "get_current_time", "alice", n=9)
        forged = {"HX-Current-URL": f"http://test/?{RANGE}&user=bob&all=1"}
        a = await e.alice()
        try:
            tree = (await a.get("/tools/tree", headers=forged)).text
            page = (await a.get(f"/?{RANGE}&user=bob")).text
        finally:
            await a.aclose()
        async with e.client() as c:
            admin = (await c.get(f"/tools/tree?{RANGE}")).text
    assert header(tree, "time").endswith("2 calls")
    assert "gitlab" not in tree
    assert "9 calls" not in text(page)
    assert header(admin, "time").endswith("14 calls")
    assert header(admin, "gitlab").endswith("9 calls")


# --- 9.12 newer schema ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_newer_schema_renders_no_counts(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    con = sqlite3.connect(d / "usage.sqlite3")
    con.execute("PRAGMA user_version = 2")
    con.commit()
    con.close()
    async with env(tmp_path, ["time"], store_start=True) as e:
        rec(e.store, IN_RANGE, "time", "get_current_time", n=3)
        async with e.client() as c:
            page = await c.get(f"/?{RANGE}")
            tree = await c.get(f"/tools/tree?{RANGE}")
        await e.store.stop()
    assert page.status_code == 200 and tree.status_code == 200
    assert "<svg" not in page.text
    assert header(tree.text, "time").endswith("0 calls")
    con = sqlite3.connect(d / "usage.sqlite3")
    assert con.execute("PRAGMA user_version").fetchone()[0] == 2
    assert con.execute("SELECT count(*) FROM sqlite_master WHERE name='usage'").fetchone()[0] == 0
    con.close()


# --- usage-bar-native-pickers: Stylesheet version ------------------------------

@pytest.mark.asyncio
async def test_the_stylesheet_url_carries_its_digest(tmp_path):
    import hashlib
    from pathlib import Path

    import mcpflow

    style = Path(mcpflow.__file__).parent / "static" / "style.css"
    want = f'href="/static/style.css?v={hashlib.sha256(style.read_bytes()).hexdigest()[:12]}"'
    async with env(tmp_path) as e:
        async with e.client() as c:
            page = (await c.get("/")).text
        async with e.client({}) as c:
            login = (await c.get("/login")).text
            setup = (await c.get("/login/setup")).text
    assert want in page
    assert want in login
    assert want in setup
