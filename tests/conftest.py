"""Shared fixtures for the verifier suite.

The fixtures derive from the frozen interfaces in `design.md`, not from the
implementation. A `custom` child that speaks MCP over stdio stands in for a
real `uvx`/`npx` child, so no test needs the network.
"""

from __future__ import annotations

import asyncio
import os
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
import uvicorn

from mcpflow.auth import hash_password
from mcpflow.config import Settings, load_settings
from mcpflow.identity import ADMINS_GROUP, BOOTSTRAP_ADMIN_ID, User
from mcpflow.registry import Registry, ServerSpec

FAKE_SERVER = str(Path(__file__).parent / "fake_mcp_server.py")


def pytest_configure(config) -> None:
    # Informational only: a `slow` test runs in the normal suite.
    config.addinivalue_line("markers", "slow: a slow test; it still runs by default")

# The bootstrap admin as an actor, for a test that calls an owner directly.
# Production code passes the user of the request; only tests build one.
ADMIN_ACTOR = User(
    id=BOOTSTRAP_ADMIN_ID,
    name=BOOTSTRAP_ADMIN_ID,
    groups=frozenset({ADMINS_GROUP}),
    provider="local",
)


def make_user(
    owner, uid: str, password: str = "pw-for-tests", *, iterations: int = 1000, **kw
) -> User:
    """Create an ACTIVE local user that signs in with `password`.

    `owner` is a `LocalIdentityProvider` or an `AccessPolicy` (the policy
    path creates the user as `ADMIN_ACTOR`). The helper redeems the setup
    code the way the setup page does: `check_setup_code`, then
    `replace_credential` with a hash of `iterations` rounds (the production
    default is 600000; a test of the verify cost passes it). `kw` is `name`,
    `admin`, `groups`.
    """
    if hasattr(owner, "local_identity"):
        local = owner.local_identity()
        _, code = owner.create_user(ADMIN_ACTOR, uid, **kw)
    else:
        local = owner
        _, code = local._create_user(uid, **kw)
    state = local.check_setup_code(uid, code)
    assert state is not None, f"fresh setup code for {uid} must verify"
    assert local.replace_credential(uid, state, hash_password(password, iterations=iterations))
    user = local.get_user(uid)
    assert user is not None
    return user


def fake_child_spec(
    namespace: str, mode: str = "good", mode_arg: str | None = None, **extra
) -> ServerSpec:
    """A `custom` child that runs the fake stdio MCP server in `mode`."""
    args = [FAKE_SERVER, mode]
    if mode_arg is not None:
        args.append(mode_arg)
    return ServerSpec(
        namespace=namespace,
        kind="custom",
        command=sys.executable,
        args=args,
        **extra,
    )


def make_settings(data_dir: Path, password: str = "secret", **overrides) -> Settings:
    over = {"DATA_DIR": str(data_dir), "ADMIN_PASSWORD": password}
    over.update(overrides)
    return load_settings(over)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return make_settings(tmp_path)


class LiveServer:
    """A real gateway app served by uvicorn on an ephemeral port."""

    def __init__(self, base_url: str, password: str, data_dir: Path, app=None) -> None:
        self.base_url = base_url
        self.password = password
        self.data_dir = data_dir
        self.app = app

    @property
    def supervisor(self):
        return self.app.state.supervisor

    def get(self, path: str, **kw) -> httpx.Response:
        return httpx.get(self.base_url + path, **kw)

    def post(self, path: str, **kw) -> httpx.Response:
        return httpx.post(self.base_url + path, **kw)

    def health(self) -> dict:
        return self.get("/health").json()["children"]

    def wait(self, *, running: int | None = None, failed: int | None = None,
             starting: int | None = None, timeout: float = 40.0) -> dict:
        deadline = time.time() + timeout
        counts = self.health()
        while time.time() < deadline:
            counts = self.health()
            if running is not None and counts["running"] < running or failed is not None and counts["failed"] < failed or starting is not None and counts["starting"] != starting:
                pass
            else:
                return counts
            time.sleep(0.15)
        return counts

    def login(self, password: str | None = None) -> httpx.Client:
        client = httpx.Client(base_url=self.base_url, follow_redirects=False)
        resp = client.post(
            "/login",
            data={"password": password or self.password, "next": "/"},
        )
        assert resp.status_code == 303, resp.text
        assert client.cookies.get("mcpflow_session")
        return client


@pytest.fixture
def server_factory(tmp_path: Path):
    """Return a `start(seed=None, ...)` callable that runs a gateway app.

    `seed(data_dir)` prepares `servers.json` / `tokens.json` before the app is
    built. Each started server is stopped at teardown.
    """
    started: list[tuple[uvicorn.Server, threading.Thread]] = []
    counter = {"n": 0}

    def start(
        seed: Callable[[Path], object] | None = None,
        *,
        password: str = "secret",
        **override,
    ) -> LiveServer:
        counter["n"] += 1
        data_dir = tmp_path / f"srv{counter['n']}"
        data_dir.mkdir()
        (data_dir / "logs").mkdir()
        if seed is not None:
            seed(data_dir)

        from mcpflow.gateway import build_app

        settings = make_settings(data_dir, password=password, **override)
        app = build_app(settings)
        config = uvicorn.Config(
            app, host="127.0.0.1", port=0, log_level="error", lifespan="on"
        )
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        t0 = time.time()
        while not server.started:
            if time.time() - t0 > 20:
                raise RuntimeError("server did not start")
            time.sleep(0.05)
        port = server.servers[0].sockets[0].getsockname()[1]
        started.append((server, thread))
        return LiveServer(f"http://127.0.0.1:{port}", password, data_dir, app)

    yield start

    for server, thread in started:
        server.should_exit = True
        thread.join(timeout=15)


def seed_registry(*specs: ServerSpec) -> Callable[[Path], None]:
    def _seed(data_dir: Path) -> None:
        reg = Registry(data_dir / "servers.json", data_dir / "user_servers.json")
        reg.load()
        for spec in specs:
            reg.add(spec)

    return _seed


def make_policy(data_dir: Path, registry: Registry):
    """An `AccessPolicy` over `registry` with the bootstrap `admin` only.

    For a test that builds a `Supervisor` by hand. The stores live in
    `data_dir`, beside the registry files.
    """
    from mcpflow.auth import TokenStore, hash_password
    from mcpflow.identity import LocalIdentityProvider
    from mcpflow.policy import AccessPolicy, RuleStore

    identity = LocalIdentityProvider(
        data_dir / "users.json", hash_password("secret", iterations=1000)
    )
    identity.load()
    tokens = TokenStore(data_dir / "tokens.json", data_dir / "user_tokens.json")
    tokens.load()
    rules = RuleStore(data_dir / "rules.json")
    rules.load()
    return AccessPolicy(identity, rules, tokens, registry)


def admin_reach(sup, surface: str = "dashboard"):
    """The `Reach` of the bootstrap admin on `surface`, for a hand-built
    supervisor. `tools` and `instructions_blocks` require one."""
    return sup.policy.keys_for(ADMIN_ACTOR, surface)


async def run_stale_probe(sup, reach, session) -> None:
    """Make the snapshot of `session` stale, render once, and await the probe
    that render started, with a 15 s bound (dashboard-tool-snapshot D3/D4).

    The render pass has no await after `_schedule_probe`, so the task is still
    in `session.probe` when `tools` returns."""
    session.probed_at = None
    await sup.tools(reach)
    task = session.probe
    assert task is not None, "the stale render started no probe"
    await asyncio.wait_for(task, 15)


@pytest.fixture
def users_writes(monkeypatch):
    """Count the writes of `users.json`: each `os.replace` onto it.

    `{"n": <count>}`; a test resets `n` to 0 after its setup. The count rests
    on the write contract (temporary file plus `os.replace`), not on a
    private name.
    """
    log = {"n": 0}
    real = os.replace

    def replace(src, dst, *a, **k):
        if Path(dst).name == "users.json":
            log["n"] += 1
        return real(src, dst, *a, **k)

    monkeypatch.setattr(os, "replace", replace)
    return log
