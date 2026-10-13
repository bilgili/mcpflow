"""A live gateway for the 10D router tests (multi-user-access).

The fixture of the 10D preamble: users `alice`, `bob`, `carol` (non-admin),
`root` (admin), and the bootstrap `admin`; admin-owned `time` and `github`;
user-owned `github@alice` and `github@bob`. Every child runs
`tests/fake_router_child.py`.

A user-owned server may not be `custom` (D7b), so a user-owned child is a
`remote` server that points at the fake child served over HTTP. The fixture
seeds it through the frozen `Registry` interface: `add` with the owner, then
`set_approved_revision(key, revision(spec))`. The supervisor then starts it
through its normal startup and start gate.

The gateway runs in a thread on an event loop that the test owns, so a test can
run a coroutine on the live supervisor, router, or gateway (`Live.run`). The
`build_app` wiring is not changed: the test only wraps two constructors in the
`mcpflow.gateway` namespace to keep a handle on the live identity provider and
the live gateway object.
"""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pytest
import uvicorn
from conftest import make_settings, make_user

from mcpflow.auth import TokenStore, hash_password
from mcpflow.identity import LocalIdentityProvider
from mcpflow.registry import Registry, ServerKey, ServerSpec, revision

CHILD = str(Path(__file__).parent / "fake_router_child.py")
USERS = {"alice": False, "bob": False, "carol": False, "root": True}
GROUPS = ("eng", "interns", "ops")


@dataclass
class Child:
    """One child of the fixture. `ref` is `ns` or `ns@owner`."""

    ref: str
    app: str
    tools: tuple[str, ...]
    extra: dict = field(default_factory=dict)
    instructions: str | None = None
    # Extra command-line arguments of `fake_router_child.py`.
    args: tuple[str, ...] = ()

    @property
    def key(self) -> ServerKey:
        return ServerKey.parse(self.ref)


MAIN = (
    Child("time", "time", ("get_current_time", "convert_time"),
          {"cache_ttl": 300}, "TIME-INSTR-MARK"),
    Child("github", "gh", ("x", "create_issue", "shared_only")),
    Child("github@alice", "gh", ("x", "alice_only"), {"cache_ttl": 0},
          "ALICE-INSTR-MARK"),
    Child("github@bob", "gh", ("x", "bob_only")),
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_port(port: int, proc: subprocess.Popen, timeout: float = 30) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"fake child exited with {proc.returncode}")
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise RuntimeError("fake child did not listen")


def _env(child: Child, log: Path) -> dict[str, str]:
    # No `CHILD_ID` here: every `env` value of a spec is a secret the process
    # log masks until exit (redact-process-log), and a reference such as
    # `time` would then mask that word in every later test's log. The id
    # travels as `--id`, which is not a secret.
    env = {"MCPFLOW_CALL_LOG": str(log)}
    if child.instructions:
        env["INSTRUCTIONS"] = f"{child.instructions} of {child.ref}"
    return env


def _seed(data_dir: Path, children, procs: list) -> dict[str, str]:
    """Seed users, groups, tokens, and the registry. Return the clear tokens."""
    ident = LocalIdentityProvider(
        data_dir / "users.json", hash_password("secret", iterations=1000)
    )
    ident.load()
    for group in GROUPS:
        ident._create_group(group)
    for uid, is_admin in USERS.items():
        make_user(ident, uid, f"pw-{uid}-0123456789", admin=is_admin)
    store = TokenStore(data_dir / "tokens.json", data_dir / "user_tokens.json")
    store.load()
    tokens = {}
    for uid, scope in (("alice", "mcp"), ("bob", "mcp"), ("carol", "mcp"),
                       ("root", "admin"), ("admin", "admin")):
        _rec, tokens[uid] = store.create(f"{uid}-token", scope, uid)
    reg = Registry(data_dir / "servers.json", data_dir / "user_servers.json")
    reg.load()
    for child in children:
        key = child.key
        log = data_dir / f"calls-{child.ref}.log"
        env = _env(child, log)
        if key.owner is None:
            reg.add(ServerSpec(namespace=key.namespace, kind="custom",
                               command=sys.executable,
                               args=[CHILD, child.app, ",".join(child.tools),
                                     "--id", child.ref, *child.args],
                               env=env, **child.extra))
            continue
        port = _free_port()
        proc = subprocess.Popen(
            [sys.executable, CHILD, child.app, ",".join(child.tools),
             "--id", child.ref, *child.args, "--http", str(port)],
            env={**_base_env(), **env},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        procs.append(proc)
        _wait_port(port, proc)
        reg.add(ServerSpec(namespace=key.namespace, kind="remote",
                           url=f"http://127.0.0.1:{port}/mcp", owner=key.owner,
                           **child.extra))
        reg.set_approved_revision(key, revision(reg.get(key)))
    return tokens


def _base_env() -> dict[str, str]:
    return dict(os.environ)


class Live:
    """A running gateway plus handles on its live owners."""

    def __init__(self, data_dir, app, gateway, identity, tokens, children):
        self.data_dir = data_dir
        self.app = app
        self.gateway = gateway
        self.identity = identity
        self.tokens = tokens
        self.children = {c.ref: c for c in children}
        self.rules: list = []
        self.base_url = ""
        self.loop: asyncio.AbstractEventLoop | None = None

    @property
    def policy(self):
        return self.app.state.policy

    @property
    def supervisor(self):
        return self.app.state.supervisor

    def user(self, uid: str):
        return self.identity.get_user(uid)

    def run(self, coro, timeout: float = 60):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def log(self, ref: str) -> list[str]:
        path = self.data_dir / f"calls-{ref}.log"
        return path.read_text().split() if path.exists() else []

    def calls(self, ref: str) -> list[str]:
        return [x for x in self.log(ref) if x.startswith("call:")]

    def clear_logs(self) -> None:
        for ref in self.children:
            (self.data_dir / f"calls-{ref}.log").write_text("")

    def grant(self, kind, subject, level, effect, server=None, tool=None):
        rule = self.policy.add_rule(
            self.user("admin"), subject_kind=kind, subject=subject, level=level,
            server=server, tool=tool, effect=effect)
        self.rules.append(rule.id)
        return rule

    def revoke(self, rule) -> None:
        self.policy.remove_rule(self.user("admin"), rule.id)
        self.rules.remove(rule.id)

    def reset(self) -> None:
        for rule_id in list(self.rules):
            self.policy.remove_rule(self.user("admin"), rule_id)
        self.rules.clear()
        for uid, is_admin in USERS.items():
            if not is_admin:
                self.identity.set_groups(uid, ())
        self.clear_logs()

    def health(self) -> dict:
        return httpx.get(self.base_url + "/health").json()["children"]

    # --- MCP client helpers (a fresh session each, on the test thread) -------

    def client(self, uid: str):
        from fastmcp import Client
        from fastmcp.client.transports import StreamableHttpTransport

        return Client(StreamableHttpTransport(
            self.base_url + "/mcp",
            headers={"Authorization": f"Bearer {self.tokens[uid]}"}))

    def names(self, uid: str) -> set[str]:
        async def go():
            async with self.client(uid) as c:
                return {t.name for t in await c.list_tools()}
        return asyncio.run(go())

    def call(self, uid: str, name: str, args: dict | None = None):
        async def go():
            async with self.client(uid) as c:
                return (await c.call_tool(name, args or {})).data
        return asyncio.run(go())


def start_live(data_dir: Path, children=MAIN) -> tuple[Live, callable]:
    """Start the gateway. Return the `Live` handle and its stop function."""
    import mcpflow.gateway as gw

    (data_dir / "logs").mkdir(exist_ok=True)
    procs: list[subprocess.Popen] = []
    tokens = _seed(data_dir, children, procs)
    captured: dict = {}

    class _Identity(gw.LocalIdentityProvider):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            captured["identity"] = self
            self.resolved: list = []

        def resolve(self, token):
            self.resolved.append(getattr(token, "subject", None))
            return super().resolve(token)

    class _Gateway(gw.FastMCP):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            captured.setdefault("gateway", self)

    mp = pytest.MonkeyPatch()
    mp.setattr(gw, "LocalIdentityProvider", _Identity)
    mp.setattr(gw, "FastMCP", _Gateway)
    try:
        app = gw.build_app(make_settings(data_dir))
    finally:
        mp.undo()
    live = Live(data_dir, app, captured["gateway"], captured["identity"],
                tokens, children)
    server = uvicorn.Server(uvicorn.Config(
        app, host="127.0.0.1", port=0, log_level="error", lifespan="on"))
    loop = asyncio.new_event_loop()
    live.loop = loop
    thread = threading.Thread(
        target=lambda: loop.run_until_complete(server.serve()), daemon=True)
    thread.start()
    t0 = time.time()
    while not server.started:
        if time.time() - t0 > 30 or not thread.is_alive():
            raise RuntimeError("gateway did not start")
        time.sleep(0.05)
    live.base_url = f"http://127.0.0.1:{server.servers[0].sockets[0].getsockname()[1]}"
    deadline = time.time() + 60
    while live.health()["running"] < len(children) and time.time() < deadline:
        time.sleep(0.2)
    assert live.health()["running"] == len(children), live.health()

    def stop() -> None:
        server.should_exit = True
        thread.join(timeout=20)
        loop.close()
        for proc in procs:
            proc.terminate()
            proc.wait(timeout=10)

    return live, stop
