"""Header sink token refresh for a public client (header-sink-token-refresh).

Scenarios from `specs/oauth-client/spec.md` (Credential store, Provider
registry, Header sink, Public client, Header sink token refresh).

The token endpoint is an `httpx.MockTransport` behind `mcpflow.oauth.http_client`.
The refresh task's clock and sleep are `mcpflow.supervisor._now` / `_sleep`; a
`FakeTime` records each delay and blocks until the test releases it, so no test
waits on a real timer. The D8 pin test runs a real FastMCP HTTP server.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import stat
import threading
import time
from pathlib import Path
from urllib.parse import parse_qsl

import httpx
import pytest
import pytest_asyncio
import uvicorn
from conftest import make_settings

from mcpflow import oauth as oauth_mod
from mcpflow.oauth import (
    ClientCreds,
    CredStore,
    HeaderSpec,
    PendingFlows,
    ProviderRegistry,
    check_token_response,
    refresh_state,
)
from mcpflow.registry import Registry, ServerSpec
from mcpflow.supervisor import Supervisor

TOKEN_URL = "https://webapi.moomoo.com/oauth2/token"
HEADER = HeaderSpec("Authorization", "Bearer", TOKEN_URL)
CLIENT = ClientCreds("moomoo-client", "")
T0 = 1_000_000.0
PROVIDERS = Path(oauth_mod.__file__).parent / "catalog" / "providers"


class FakeTime:
    """`_now` returns `now`; `_sleep` records the delay and blocks until
    `release` grants it."""

    def __init__(self) -> None:
        self.now = T0
        self.sleeps: list[float] = []
        self._budget = 0
        self._event = asyncio.Event()

    def clock(self) -> float:
        return self.now

    async def sleep(self, delay: float) -> None:
        self.sleeps.append(delay)
        while self._budget == 0:
            self._event.clear()
            await self._event.wait()
        self._budget -= 1

    def release(self, n: int = 1) -> None:
        self._budget += n
        self._event.set()


class FakeEndpoint:
    """Scripted token endpoint. Each entry of `script` is a status + json, or
    the string "raise" for a transport error. `gate`, when set, holds every
    response until the test sets it."""

    def __init__(self) -> None:
        self.script: list = []
        self.bodies: list[dict] = []
        self.gate: asyncio.Event | None = None
        self.arrived = asyncio.Event()

    async def handler(self, request: httpx.Request) -> httpx.Response:
        self.bodies.append(dict(parse_qsl(request.content.decode())))
        self.arrived.set()
        if self.gate is not None:
            await self.gate.wait()
        step = self.script.pop(0)
        if step == "raise":
            raise httpx.ConnectError("boom", request=request)
        status, payload = step
        return httpx.Response(status, json=payload)


@pytest.fixture
def fake_time(monkeypatch):
    ft = FakeTime()
    monkeypatch.setattr("mcpflow.supervisor._now", ft.clock)
    monkeypatch.setattr("mcpflow.supervisor._sleep", ft.sleep)
    return ft


@pytest.fixture
def endpoint(monkeypatch):
    ep = FakeEndpoint()

    def factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(ep.handler), timeout=15.0)

    monkeypatch.setattr("mcpflow.oauth.http_client", factory)
    return ep


@pytest_asyncio.fixture
async def make_sup(tmp_path):
    created: list[Supervisor] = []

    def _make(*specs: ServerSpec, data_dir=None) -> Supervisor:
        data_dir = data_dir or tmp_path / f"sup{len(created)}"
        data_dir.mkdir(exist_ok=True)
        reg = Registry(data_dir / "servers.json")
        reg.load()
        for spec in specs:
            if spec.namespace not in {s.namespace for s in reg.list()}:
                reg.add(spec)
        sup = Supervisor(reg, make_settings(data_dir), CredStore(data_dir), PendingFlows())
        created.append(sup)
        return sup

    yield _make
    for sup in created:
        await sup.shutdown()


def _moomoo(**over) -> ServerSpec:
    fields = {
        "namespace": "moomoo",
        "kind": "remote",
        # A closed port: a start fails fast and reaches no network.
        "url": "http://127.0.0.1:9/mcp",
        "transport": "http",
        "catalog": "moomoo",
        "enabled": False,
        "oauth_pending": True,
    }
    fields.update(over)
    return ServerSpec(**fields)


def _tokens(n: int, *, refresh: bool = True, expires_in=7200) -> dict:
    out = {"access_token": f"ACCESS{n}xyz", "token_type": "Bearer"}
    if refresh:
        out["refresh_token"] = f"REFRESH{n}xyz"
    if expires_in is not None:
        out["expires_in"] = expires_in
    return out


def _state(sup: Supervisor, n: int, expires_at: float | None = T0 + 7200) -> None:
    """Write refresh.json for grant `n` directly."""
    state = {
        "client_id": CLIENT.client_id,
        "token_url": TOKEN_URL,
        "access_token": f"ACCESS{n}xyz",
        "refresh_token": f"REFRESH{n}xyz",
        "header_name": "Authorization",
        "header_scheme": "Bearer",
    }
    if expires_at is not None:
        state["expires_at"] = int(expires_at)
    sup.creds.write_refresh("moomoo", state)


async def _until(pred, rounds: int = 2000) -> None:
    for _ in range(rounds):
        if pred():
            return
        await asyncio.sleep(0)
    raise AssertionError("condition not reached")


def _header(sup: Supervisor) -> str | None:
    return sup.registry.get("moomoo").headers.get("Authorization")


async def _connect(sup: Supervisor, tokens: dict, reauth: bool = False) -> bool:
    flow = sup.flows.create("moomoo", "moomoo", CLIENT, reauth=reauth)
    return await sup.finish_oauth(flow, None, tokens, reauth=reauth, header=HEADER)


async def _connected(make_sup, fake_time, enabled: bool = False) -> Supervisor:
    """A connected, disabled `moomoo` with grant 1 in refresh.json."""
    sup = make_sup(_moomoo())
    assert await _connect(sup, _tokens(1))
    if not enabled:
        await sup.disable("moomoo")
    await _until(lambda: len(fake_time.sleeps) == 1)
    return sup


# --- Provider registry and public client --------------------------------------


def _provider_file(directory, name, data):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{name}.json").write_text(json.dumps(data))


def test_public_client_without_pkce_is_rejected(tmp_path):
    local = tmp_path / "providers"
    _provider_file(local, "bad", {
        "id": "bad", "name": "Bad",
        "authorize_url": "https://x.example/a", "token_url": "https://x.example/t",
        "pkce": False, "public_client": True,
    })
    reg = ProviderRegistry.load(tmp_path / "none", local)
    assert reg.get("bad") is None
    assert len(reg.skipped) == 1 and "public_client" in reg.skipped[0][1]


def test_builtin_providers_public_client_flags():
    reg = ProviderRegistry.load(PROVIDERS, None)
    assert reg.get("google").public_client is False
    moomoo = reg.get("moomoo")
    assert moomoo.public_client is True and moomoo.pkce is True
    assert moomoo.authorize_url == "https://webapi.moomoo.com/oauth2/authorize/confirm"
    assert moomoo.token_url == TOKEN_URL
    assert moomoo.scope_separator == " "
    assert "POST https://webapi.moomoo.com/oauth2/register" in moomoo.help


def _flow(secret: str):
    return PendingFlows().create("ns", "e", ClientCreds("cid", secret))


def test_token_request_omits_the_empty_secret():
    reg = ProviderRegistry.load(PROVIDERS, None)
    _url, body = oauth_mod.token_request(reg.get("moomoo"), "https://r", "c", _flow(""))
    assert set(body) == {"grant_type", "code", "redirect_uri", "client_id", "code_verifier"}


def test_confidential_client_still_sends_its_secret():
    reg = ProviderRegistry.load(PROVIDERS, None)
    _url, body = oauth_mod.token_request(reg.get("google"), "https://r", "c", _flow("s3"))
    assert body["client_secret"] == "s3"


# --- Credential store: refresh.json -------------------------------------------


def test_refresh_file_is_private_and_round_trips(tmp_path):
    store = CredStore(tmp_path)
    state = refresh_state("cid", TOKEN_URL, HEADER, _tokens(1))
    store.write_refresh("moomoo", state)
    path = store.refresh_path("moomoo")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert store.read_refresh("moomoo") == state
    assert abs(state["expires_at"] - (time.time() + 7200)) < 5


def test_refresh_file_is_not_a_token_file(tmp_path):
    store = CredStore(tmp_path)
    store.write_refresh("moomoo", refresh_state("cid", TOKEN_URL, HEADER, _tokens(1)))
    assert store.has_token("moomoo") is False
    assert store.awaiting("moomoo") is False


def test_read_refresh_absent_and_http_rejected(tmp_path):
    store = CredStore(tmp_path)
    assert store.read_refresh("moomoo") is None
    store.write_refresh("moomoo", refresh_state("cid", "http://x.example/t", HEADER, _tokens(1)))
    with pytest.raises(ValueError, match="https"):
        store.read_refresh("moomoo")
    store.remove_refresh("moomoo")
    store.remove_refresh("moomoo")  # absent is fine
    assert store.read_refresh("moomoo") is None


def test_write_private_fsyncs_file_and_directory(tmp_path, monkeypatch):
    synced: list[int] = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (synced.append(fd), real(fd)))
    CredStore(tmp_path).write_refresh("moomoo", {"a": "b"})
    assert len(synced) == 2


def test_refresh_state_keeps_the_prior_refresh_token_and_optional_expiry():
    state = refresh_state("cid", TOKEN_URL, HEADER, _tokens(2, refresh=False, expires_in=None), "OLD")
    assert state["refresh_token"] == "OLD" and "expires_at" not in state


def test_public_header_sink_checks_expires_in():
    check_token_response(None, _tokens(1, expires_in="later"))  # confidential: passes
    with pytest.raises(oauth_mod.OAuthTokenError):
        check_token_response(None, _tokens(1, expires_in="later"), refresh=True)


# --- finish_oauth for a public client header sink ------------------------------


@pytest.mark.asyncio
async def test_public_client_callback_writes_the_refresh_file(make_sup, fake_time):
    sup = make_sup(_moomoo())
    assert await _connect(sup, _tokens(1))
    path = sup.creds.refresh_path("moomoo")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    state = json.loads(path.read_text())
    assert {"client_id", "token_url", "access_token", "refresh_token", "expires_at"} <= set(state)
    assert state["access_token"] == "ACCESS1xyz" and state["refresh_token"] == "REFRESH1xyz"
    assert not sup.creds.paths("moomoo").client.exists()
    assert not sup.creds.paths("moomoo").token.exists()
    assert _header(sup) == "Bearer ACCESS1xyz"
    assert "moomoo" in sup._refresh_tasks
    assert sup.get("moomoo").grant == 1


@pytest.mark.asyncio
async def test_no_refresh_token_means_no_file(make_sup, fake_time):
    sup = make_sup(_moomoo())
    assert await _connect(sup, _tokens(1, refresh=False))
    assert not sup.creds.refresh_path("moomoo").exists()
    assert "moomoo" not in sup._refresh_tasks
    assert _header(sup) == "Bearer ACCESS1xyz"


@pytest.mark.asyncio
async def test_reauth_without_refresh_token_deletes_the_refresh_file(make_sup, fake_time):
    sup = await _connected(make_sup, fake_time)
    old_task = sup._refresh_tasks["moomoo"]
    assert await _connect(sup, _tokens(2, refresh=False), reauth=True)
    assert not sup.creds.refresh_path("moomoo").exists()
    assert _header(sup) == "Bearer ACCESS2xyz"
    await asyncio.sleep(0)
    assert old_task.cancelled() or old_task.done()
    assert "moomoo" not in sup._refresh_tasks


@pytest.mark.asyncio
async def test_confidential_header_sink_writes_no_file(make_sup, fake_time):
    sup = make_sup(_moomoo())
    flow = sup.flows.create("moomoo", "moomoo", ClientCreds("c", "s"))
    assert await sup.finish_oauth(flow, None, _tokens(1), header=HeaderSpec("Authorization", "Bearer"))
    assert not (sup.creds.root / "moomoo").exists()
    assert not sup._refresh_tasks


# --- The refresh task ----------------------------------------------------------


@pytest.mark.asyncio
async def test_schedule_margin_is_a_tenth_of_the_lifetime(make_sup, fake_time, endpoint):
    sup = make_sup(_moomoo(oauth_pending=False))
    _state(sup, 1, expires_at=T0 + 7200)
    await sup.startup()
    await _until(lambda: fake_time.sleeps)
    assert fake_time.sleeps == [7200 - 720]


@pytest.mark.asyncio
async def test_schedule_margin_is_at_least_a_minute(make_sup, fake_time, endpoint):
    sup = make_sup(_moomoo(oauth_pending=False))
    _state(sup, 1, expires_at=T0 + 300)
    await sup.startup()
    await _until(lambda: fake_time.sleeps)
    assert fake_time.sleeps == [240]


@pytest.mark.asyncio
async def test_past_expiry_fires_at_once(make_sup, fake_time, endpoint):
    sup = make_sup(_moomoo(oauth_pending=False))
    _state(sup, 1, expires_at=T0 - 100)
    await sup.startup()
    await _until(lambda: fake_time.sleeps)
    assert fake_time.sleeps == [0.0]


@pytest.mark.asyncio
async def test_no_expiry_schedules_no_refresh(make_sup, fake_time, endpoint):
    sup = make_sup(_moomoo(oauth_pending=False))
    _state(sup, 1, expires_at=None)
    await sup.startup()
    await _until(lambda: "moomoo" not in sup._refresh_tasks)
    assert fake_time.sleeps == [] and endpoint.bodies == []


@pytest.mark.asyncio
async def test_refresh_renews_the_header_without_a_restart(make_sup, fake_time, endpoint):
    sup = await _connected(make_sup, fake_time)
    child = sup.get("moomoo")
    endpoint.script.append((200, _tokens(2)))
    fake_time.release()
    await _until(lambda: _header(sup) == "Bearer ACCESS2xyz")
    body = endpoint.bodies[0]
    assert body == {
        "grant_type": "refresh_token", "refresh_token": "REFRESH1xyz",
        "client_id": CLIENT.client_id,
    }
    state = sup.creds.read_refresh("moomoo")
    assert state["access_token"] == "ACCESS2xyz" and state["refresh_token"] == "REFRESH2xyz"
    assert state["expires_at"] >= int(time.time()) + 7200 - 5
    # No restart: the same child, still stopped, no start task.
    assert sup.get("moomoo") is child and child.status == "stopped" and child.task is None


@pytest.mark.asyncio
async def test_refresh_without_refresh_token_keeps_the_stored_one(make_sup, fake_time, endpoint):
    sup = await _connected(make_sup, fake_time)
    endpoint.script.append((200, _tokens(2, refresh=False)))
    fake_time.release()
    await _until(lambda: _header(sup) == "Bearer ACCESS2xyz")
    assert sup.creds.read_refresh("moomoo")["refresh_token"] == "REFRESH1xyz"


@pytest.mark.asyncio
async def test_a_disabled_child_keeps_its_grant_alive(make_sup, fake_time, endpoint):
    sup = await _connected(make_sup, fake_time, enabled=True)
    await sup.disable("moomoo")  # disable leaves the task
    assert "moomoo" in sup._refresh_tasks
    endpoint.script.append((200, _tokens(2)))
    fake_time.release()
    await _until(lambda: _header(sup) == "Bearer ACCESS2xyz")
    assert sup.creds.read_refresh("moomoo")["access_token"] == "ACCESS2xyz"
    child = sup.get("moomoo")
    assert child.status == "stopped" and child.task is None and child.transport is None
    # Enable then starts the child with the refreshed header.
    seen: list[str] = []

    async def fake_start(ns):
        seen.append(sup.get(ns).spec.headers["Authorization"])

    sup._run_start = fake_start
    await sup.enable("moomoo")
    await _until(lambda: seen)
    assert seen == ["Bearer ACCESS2xyz"]


@pytest.mark.asyncio
async def test_a_rejected_refresh_stops_the_task(make_sup, fake_time, endpoint):
    sup = await _connected(make_sup, fake_time)
    before = sup.creds.refresh_path("moomoo").read_text()
    endpoint.script.append((400, {"error": "invalid_grant"}))
    fake_time.release()
    await _until(lambda: "moomoo" not in sup._refresh_tasks)
    assert sup.get("moomoo").last_error == "refresh rejected (400 invalid_grant); re-authorize"
    assert sup.creds.refresh_path("moomoo").read_text() == before
    assert _header(sup) == "Bearer ACCESS1xyz"


@pytest.mark.asyncio
async def test_a_rejected_refresh_filters_the_error_word(make_sup, fake_time, endpoint):
    sup = await _connected(make_sup, fake_time)
    endpoint.script.append((403, {"error": "no <b>way</b>"}))
    fake_time.release()
    await _until(lambda: "moomoo" not in sup._refresh_tasks)
    assert sup.get("moomoo").last_error == "refresh rejected (403 nobwayb); re-authorize"


@pytest.mark.asyncio
async def test_an_echoed_refresh_token_stays_out_of_last_error(make_sup, fake_time, endpoint):
    # LOW-2: a provider that echoes the refresh token in `error`, and a word
    # past the 64-character cap. The scrub runs before the cut.
    sup = await _connected(make_sup, fake_time)
    endpoint.script.append((400, {"error": "x" * 60 + "REFRESH1xyz" + "y" * 100}))
    fake_time.release()
    await _until(lambda: "moomoo" not in sup._refresh_tasks)
    err = sup.get("moomoo").last_error
    assert "REFRESH1" not in err and "RESH1xyz" not in err
    word = err.removeprefix("refresh rejected (400 ").removesuffix("); re-authorize")
    assert len(word) == 64 and word.startswith("x" * 60)


@pytest.mark.asyncio
async def test_a_transport_error_retries(make_sup, fake_time, endpoint):
    sup = await _connected(make_sup, fake_time)
    before = sup.creds.refresh_path("moomoo").read_text()
    endpoint.script.extend(["raise", (200, _tokens(2))])
    fake_time.release()
    await _until(lambda: len(fake_time.sleeps) == 2)
    assert fake_time.sleeps[1] == 30
    # Nothing written between the failure and the retry.
    assert sup.creds.refresh_path("moomoo").read_text() == before
    assert _header(sup) == "Bearer ACCESS1xyz"
    fake_time.release()
    await _until(lambda: _header(sup) == "Bearer ACCESS2xyz")
    assert len(endpoint.bodies) == 2


@pytest.mark.asyncio
async def test_rate_limiting_retries_with_backoff_to_the_cap(make_sup, fake_time, endpoint):
    sup = await _connected(make_sup, fake_time)
    fake_time.now = T0 + 10**6  # long past the expiry: retries continue
    endpoint.script.extend([(429, {}), (503, {}), (408, {}), (500, {}), (502, {}), (504, {})])
    fake_time.release(6)
    await _until(lambda: len(fake_time.sleeps) == 7)
    assert fake_time.sleeps[1:] == [30, 60, 120, 240, 300, 300]
    assert "moomoo" in sup._refresh_tasks
    assert not (sup.get("moomoo").last_error or "").startswith("refresh rejected")


@pytest.mark.asyncio
async def test_a_reauthorization_during_the_refresh_wins(make_sup, fake_time, endpoint):
    sup = await _connected(make_sup, fake_time)
    endpoint.gate = asyncio.Event()
    endpoint.script.append((200, _tokens(9)))
    fake_time.release()
    await endpoint.arrived.wait()
    assert await _connect(sup, _tokens(2), reauth=True)
    endpoint.gate.set()
    for _ in range(50):
        await asyncio.sleep(0)
    assert sup.creds.read_refresh("moomoo")["access_token"] == "ACCESS2xyz"
    assert _header(sup) == "Bearer ACCESS2xyz"


@pytest.mark.asyncio
async def test_a_stale_grant_is_discarded_even_when_the_response_arrives(
    make_sup, fake_time, endpoint
):
    # I1 on its own: the response reaches the apply, but the grant moved.
    sup = await _connected(make_sup, fake_time)
    child = sup.get("moomoo")
    endpoint.script.append((200, _tokens(9)))
    await child.lock.acquire()
    fake_time.release()
    await _until(lambda: endpoint.bodies)
    for _ in range(20):
        await asyncio.sleep(0)
    child.grant += 1
    child.lock.release()
    await _until(lambda: "moomoo" not in sup._refresh_tasks)
    assert sup.creds.read_refresh("moomoo")["access_token"] == "ACCESS1xyz"
    assert _header(sup) == "Bearer ACCESS1xyz"


@pytest.mark.asyncio
async def test_a_remove_during_the_refresh_writes_nothing(make_sup, fake_time, endpoint):
    sup = await _connected(make_sup, fake_time)
    task = sup._refresh_tasks["moomoo"]
    endpoint.gate = asyncio.Event()
    endpoint.script.append((200, _tokens(9)))
    fake_time.release()
    await endpoint.arrived.wait()
    await sup.remove("moomoo")
    assert "moomoo" not in sup._refresh_tasks
    endpoint.gate.set()
    for _ in range(50):
        await asyncio.sleep(0)
    assert not (sup.creds.root / "moomoo").exists()
    assert "moomoo" not in [s.namespace for s in sup.registry.list()]


@pytest.mark.asyncio
async def test_a_remove_and_readd_during_the_refresh_writes_nothing(make_sup, fake_time, endpoint):
    sup = await _connected(make_sup, fake_time)
    old = sup.get("moomoo")
    grant = old.grant
    state = sup.creds.read_refresh("moomoo")
    # A refresh round of the old grant that `remove` cannot cancel: it is not
    # the table's task, so only the grant and identity guard stands in its way.
    endpoint.gate = asyncio.Event()
    endpoint.script.append((200, _tokens(9)))
    round_ = asyncio.create_task(sup._refresh_once("moomoo", old, grant, state))
    await endpoint.arrived.wait()
    # The real remove, then the real add and connect.
    await sup.remove("moomoo")
    new = await sup.add(_moomoo())
    assert await _connect(sup, _tokens(2))
    assert new is sup.get("moomoo") and new is not old
    # The new counter equals the captured one: identity alone must reject.
    assert new.grant == grant
    endpoint.gate.set()
    assert await round_ is None
    assert sup.creds.read_refresh("moomoo")["access_token"] == "ACCESS2xyz"
    assert _header(sup) == "Bearer ACCESS2xyz"


@pytest.mark.asyncio
async def test_remove_bumps_the_grant_and_cancels_the_task(make_sup, fake_time):
    sup = await _connected(make_sup, fake_time)
    child = sup.get("moomoo")
    task = sup._refresh_tasks["moomoo"]
    grant = child.grant
    await sup.remove("moomoo")
    await asyncio.sleep(0)
    assert child.grant == grant + 1 and task.cancelled()
    assert not sup._refresh_tasks


@pytest.mark.asyncio
async def test_a_replaced_task_does_not_drop_its_successor(make_sup, fake_time):
    sup = await _connected(make_sup, fake_time)
    old = sup._refresh_tasks["moomoo"]
    assert await _connect(sup, _tokens(2), reauth=True)
    new = sup._refresh_tasks["moomoo"]
    for _ in range(20):
        await asyncio.sleep(0)
    assert old.done() and sup._refresh_tasks.get("moomoo") is new


@pytest.mark.asyncio
async def test_tokens_stay_out_of_the_log(make_sup, fake_time, endpoint, caplog):
    caplog.set_level(logging.DEBUG)
    sup = await _connected(make_sup, fake_time)
    endpoint.script.append((200, _tokens(2)))
    fake_time.release()
    await _until(lambda: _header(sup) == "Bearer ACCESS2xyz")
    for secret in ("ACCESS1xyz", "REFRESH1xyz", "ACCESS2xyz", "REFRESH2xyz"):
        assert secret not in caplog.text


# --- startup and shutdown ------------------------------------------------------


@pytest.mark.asyncio
async def test_startup_repairs_a_header_after_a_crash_between_the_writes(
    make_sup, fake_time, endpoint, tmp_path
):
    # The apply wrote grant 2 to the file; the header still holds grant 1.
    data_dir = tmp_path / "crash"
    sup = make_sup(_moomoo(oauth_pending=False, headers={"Authorization": "Bearer ACCESS1xyz"}), data_dir=data_dir)
    _state(sup, 2)
    await sup.startup()
    assert _header(sup) == "Bearer ACCESS2xyz"
    assert sup.get("moomoo").spec.headers["Authorization"] == "Bearer ACCESS2xyz"
    reg = Registry(data_dir / "servers.json")
    reg.load()
    assert reg.get("moomoo").headers["Authorization"] == "Bearer ACCESS2xyz"
    await _until(lambda: fake_time.sleeps)
    assert endpoint.bodies == []
    assert "moomoo" in sup._refresh_tasks


@pytest.mark.asyncio
async def test_startup_sets_the_header_before_the_child_starts(make_sup, fake_time, monkeypatch):
    sup = make_sup(_moomoo(oauth_pending=False, enabled=True, headers={"Authorization": "Bearer ACCESS1xyz"}))
    _state(sup, 2)
    seen: list[str] = []

    async def fake_start(ns):
        seen.append(sup.get(ns).spec.headers["Authorization"])

    monkeypatch.setattr(sup, "_run_start", fake_start)
    await sup.startup()
    await _until(lambda: seen)
    assert seen == ["Bearer ACCESS2xyz"]


@pytest.mark.asyncio
async def test_startup_drops_an_orphan_credential_directory(make_sup, fake_time):
    sup = make_sup()
    _state(sup, 1)
    assert (sup.creds.root / "moomoo").exists()
    await sup.startup()
    assert not (sup.creds.root / "moomoo").exists()
    assert not sup._refresh_tasks


@pytest.mark.asyncio
async def test_shutdown_cancels_every_task(make_sup, fake_time):
    sup = await _connected(make_sup, fake_time)
    task = sup._refresh_tasks["moomoo"]
    await sup.shutdown()
    assert task.cancelled() and not sup._refresh_tasks


# --- D8 pin: the live transport carries the new header --------------------------


def _serve_fake_remote(transport: str = "http"):
    """A FastMCP HTTP server whose tool echoes the request's Authorization."""
    from fastmcp import FastMCP
    from fastmcp.server.dependencies import get_http_headers

    mcp = FastMCP("fake-remote")

    @mcp.tool
    def whoami() -> str:
        return get_http_headers(include_all=True).get("authorization", "")

    server = uvicorn.Server(
        uvicorn.Config(mcp.http_app(path="/mcp", transport=transport), host="127.0.0.1", port=0,
                       log_level="error", lifespan="on")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    t0 = time.time()
    while not server.started:
        if time.time() - t0 > 20:
            raise RuntimeError("fake remote did not start")
        time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    return server, thread, f"http://127.0.0.1:{port}/mcp"


async def _whoami(sup: Supervisor) -> str:
    async with sup._lease(sup.get("moomoo")) as client:
        result = await client.call_tool("whoami", {})
    return result.content[0].text


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ["http", "sse"])
async def test_the_next_call_after_a_refresh_sends_the_new_header(
    make_sup, fake_time, endpoint, transport
):
    server, thread, url = _serve_fake_remote(transport)
    try:
        sup = make_sup(_moomoo(url=url, transport=transport))
        assert await _connect(sup, _tokens(1))  # connect enables and starts
        child = sup.get("moomoo")
        for _ in range(400):
            if child.status == "running":
                break
            await asyncio.sleep(0.05)
        assert child.status == "running", child.last_error
        assert await _whoami(sup) == "Bearer ACCESS1xyz"
        transport, session = child.transport, child.session
        endpoint.script.append((200, _tokens(2)))
        fake_time.release()
        await _until(lambda: _header(sup) == "Bearer ACCESS2xyz")
        # No restart: the same generation serves the next call.
        assert child.transport is transport and child.session is session
        assert child.status == "running"
        assert await _whoami(sup) == "Bearer ACCESS2xyz"
    finally:
        server.should_exit = True
        thread.join(timeout=10)


# --- Review fixes -------------------------------------------------------------


async def _wait_running(child) -> None:
    for _ in range(400):
        if child.status == "running":
            return
        await asyncio.sleep(0.05)
    raise AssertionError(child.last_error)


@pytest.mark.asyncio
async def test_a_very_short_lifetime_does_not_refresh_in_a_loop(make_sup, fake_time, endpoint):
    # MED-1: `expires_in` 0 would schedule a sleep of 0 after every refresh.
    fake_time.now = time.time()
    sup = make_sup(_moomoo(oauth_pending=False))
    _state(sup, 1, expires_at=fake_time.now - 100)
    await sup.startup()
    await _until(lambda: fake_time.sleeps)
    assert fake_time.sleeps == [0.0]  # the first round may fire at once
    endpoint.script.extend([(200, _tokens(2, expires_in=0)), (200, _tokens(3, expires_in=-5))])
    fake_time.release()
    await _until(lambda: len(fake_time.sleeps) == 2)
    assert fake_time.sleeps[1] == 30
    fake_time.release()
    await _until(lambda: len(fake_time.sleeps) == 3)
    assert fake_time.sleeps[2] == 30
    assert len(endpoint.bodies) == 2


@pytest.mark.asyncio
async def test_a_provider_turned_confidential_deletes_the_refresh_file(make_sup, fake_time):
    # MED-2: a re-authorization whose provider is now confidential passes no
    # refresh token URL. The old grant's file must not outlive it.
    sup = await _connected(make_sup, fake_time)
    old_task = sup._refresh_tasks["moomoo"]
    flow = sup.flows.create("moomoo", "moomoo", ClientCreds("c", "s"), reauth=True)
    assert await sup.finish_oauth(
        flow, None, _tokens(2), reauth=True, header=HeaderSpec("Authorization", "Bearer")
    )
    await asyncio.sleep(0)
    assert not sup.creds.refresh_path("moomoo").exists()
    assert "moomoo" not in sup._refresh_tasks and old_task.done()
    assert _header(sup) == "Bearer ACCESS2xyz"


@pytest.mark.asyncio
async def test_an_unexpected_error_keeps_the_task_alive(make_sup, fake_time, endpoint, monkeypatch):
    # MED-3: a disk error on the apply retries with the backoff.
    sup = await _connected(make_sup, fake_time)
    real = sup.creds.write_refresh
    calls = {"n": 0}

    def flaky(ns, state):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("disk full at /secret/REFRESH2xyz")
        real(ns, state)

    monkeypatch.setattr(sup.creds, "write_refresh", flaky)
    endpoint.script.extend([(200, _tokens(2)), (200, _tokens(3))])
    fake_time.release()
    await _until(lambda: len(fake_time.sleeps) == 2)
    assert fake_time.sleeps[1] == 30
    assert sup.get("moomoo").last_error == "refresh failed (OSError); retrying"
    assert "moomoo" in sup._refresh_tasks
    fake_time.release()
    await _until(lambda: _header(sup) == "Bearer ACCESS3xyz")


@pytest.mark.asyncio
async def test_an_invalid_token_url_keeps_the_task_alive(make_sup, fake_time, monkeypatch):
    # MED-3: httpx.InvalidURL is not an httpx.HTTPError.
    sup = await _connected(make_sup, fake_time)

    def bad_client():
        raise httpx.InvalidURL("bad https://x/?refresh_token=REFRESH1xyz")

    monkeypatch.setattr("mcpflow.oauth.http_client", bad_client)
    fake_time.release(2)
    await _until(lambda: len(fake_time.sleeps) == 3)
    assert fake_time.sleeps[1:] == [30, 60]
    assert sup.get("moomoo").last_error == "refresh failed (InvalidURL); retrying"
    assert "moomoo" in sup._refresh_tasks


@pytest.mark.asyncio
async def test_a_corrupt_expiry_retries_and_heals(make_sup, fake_time, endpoint):
    # MED-3: a non-numeric `expires_at` in the file.
    sup = make_sup(_moomoo(oauth_pending=False))
    _state(sup, 1, expires_at=None)
    state = sup.creds.read_refresh("moomoo")
    sup.creds.write_refresh("moomoo", {**state, "expires_at": "soon"})
    await sup.startup()
    await _until(lambda: fake_time.sleeps)
    assert fake_time.sleeps == [30]
    assert sup.get("moomoo").last_error == "refresh failed (TypeError); retrying"
    endpoint.script.append((200, _tokens(2)))
    fake_time.release()
    await _until(lambda: _header(sup) == "Bearer ACCESS2xyz")
    assert isinstance(sup.creds.read_refresh("moomoo")["expires_at"], int)


@pytest.mark.asyncio
async def test_a_rejection_survives_a_successful_start(make_sup, fake_time, endpoint):
    # MED-4: a restart before the expiry must not hide "re-authorize".
    server, thread, url = _serve_fake_remote()
    try:
        sup = make_sup(_moomoo(url=url))
        assert await _connect(sup, _tokens(1))
        child = sup.get("moomoo")
        await _wait_running(child)
        endpoint.script.append((400, {"error": "invalid_grant"}))
        fake_time.release()
        await _until(lambda: "moomoo" not in sup._refresh_tasks)
        msg = "refresh rejected (400 invalid_grant); re-authorize"
        assert child.last_error == msg
        await sup.restart("moomoo")
        await _wait_running(child)
        assert child.last_error == msg and child.refresh_rejected == msg
        # Only a re-authorization clears it.
        assert await _connect(sup, _tokens(2), reauth=True)
        assert child.refresh_rejected is None
        await _wait_running(child)
        assert child.last_error is None
    finally:
        server.should_exit = True
        thread.join(timeout=10)


@pytest.mark.asyncio
async def test_a_failing_reauth_write_leaves_no_old_task(make_sup, fake_time, monkeypatch):
    # LOW-1: the grant bump and the cancel come before any write.
    sup = await _connected(make_sup, fake_time)
    child = sup.get("moomoo")
    grant = child.grant
    old_task = sup._refresh_tasks["moomoo"]

    def boom(ns, state):
        raise OSError("disk full")

    monkeypatch.setattr(sup.creds, "write_refresh", boom)
    with pytest.raises(OSError):
        await _connect(sup, _tokens(2), reauth=True)
    await asyncio.sleep(0)
    assert child.grant == grant + 1
    assert old_task.cancelled() and "moomoo" not in sup._refresh_tasks


def test_record_error_masks_a_remembered_log_secret(make_sup):
    # LOW-4: a token rotated mid-operation is in `_LOG_SECRETS`, not in the
    # captured secret set.
    from mcpflow.supervisor import remember_log_secrets

    sup = make_sup(_moomoo())
    remember_log_secrets(["ROTATEDtoken999"])
    sup._record_error(sup.get("moomoo"), "bad ROTATEDtoken999", [])
    assert "ROTATEDtoken999" not in sup.get("moomoo").last_error


def test_write_private_removes_the_tmp_on_failure(tmp_path, monkeypatch):
    # LOW-6
    store = CredStore(tmp_path)

    def boom(fd):
        raise OSError("fsync failed")

    monkeypatch.setattr(os, "fsync", boom)
    with pytest.raises(OSError):
        store.write_refresh("moomoo", {"a": "b"})
    assert list((tmp_path / "creds" / "moomoo").iterdir()) == []


def test_public_header_sink_checks_refresh_token():
    # LOW-6: absent is fine; present must be a non-empty string.
    check_token_response(None, _tokens(1, refresh=False), refresh=True)
    for bad in (12345, "", ["x"]):
        with pytest.raises(oauth_mod.OAuthTokenError):
            check_token_response(None, {**_tokens(1), "refresh_token": bad}, refresh=True)
