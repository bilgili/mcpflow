"""Shared fixtures for the verifier suite.

The fixtures derive from the frozen interfaces in `design.md`, not from the
implementation. A `custom` child that speaks MCP over stdio stands in for a
real `uvx`/`npx` child, so no test needs the network.
"""

from __future__ import annotations

import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
import uvicorn

from mcpflow.config import Settings, load_settings
from mcpflow.registry import Registry, ServerSpec

FAKE_SERVER = str(Path(__file__).parent / "fake_mcp_server.py")


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
        reg = Registry(data_dir / "servers.json")
        reg.load()
        for spec in specs:
            reg.add(spec)

    return _seed
