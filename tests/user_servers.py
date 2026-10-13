"""Shared helpers for the 10F tests (multi-user-access, section 6).

Derived from the frozen interfaces in `design.md` (`Supervisor.add(spec,
actor)`, `Supervisor.approve(key, revision, actor)`,
`Supervisor.update(key, spec, actor)`, `Registry.set_approved_revision`,
`AccessPolicy`, `RuleStore`), not from the
implementation.

A user-owned `npm` child runs the real start path (`npx -y <package>`). A fake
`npx` on `PATH` stands in for the network: it appends one line to a call log,
then runs `tests/fake_mcp_server.py`. So a test sees whether a process ran.
A user-owned `remote` child points at `Listener`, a TCP server that counts
every connection, so a test sees whether mcpflow sent any request.
"""

from __future__ import annotations

import asyncio
import os
import stat
import sys
import time
from pathlib import Path

from conftest import FAKE_SERVER, make_settings, make_user

from mcpflow.auth import TokenStore, hash_password
from mcpflow.identity import ADMINS_GROUP, LocalIdentityProvider, User
from mcpflow.oauth import CredStore, PendingFlows
from mcpflow.policy import AccessPolicy, RuleStore
from mcpflow.registry import Registry, ServerKey, ServerSpec
from mcpflow.supervisor import Supervisor


def _user(uid: str, admin: bool = False) -> User:
    return User(id=uid, name=uid,
                groups=frozenset({ADMINS_GROUP}) if admin else frozenset(),
                provider="local")


ADMIN = _user("admin", admin=True)
ALICE = _user("alice")
BOB = _user("bob")
GH_ALICE = ServerKey("alice", "github")


class Env:
    """One data dir with a registry, a rule store, a policy, and a supervisor."""

    def __init__(self, data_dir: Path) -> None:
        data_dir.mkdir(parents=True, exist_ok=True)
        (data_dir / "logs").mkdir(exist_ok=True)
        self.dir = data_dir
        self.reg = Registry(data_dir / "servers.json", data_dir / "user_servers.json")
        self.reg.load()
        ident = LocalIdentityProvider(data_dir / "users.json",
                                      hash_password("secret", iterations=1000))
        ident.load()
        for uid in ("alice", "bob"):
            if ident.get_user(uid) is None:
                make_user(ident, uid, f"pw-{uid}-0123456789")
        tokens = TokenStore(data_dir / "tokens.json", data_dir / "user_tokens.json")
        tokens.load()
        self.rules = RuleStore(data_dir / "rules.json")
        self.rules.load()
        self.policy = AccessPolicy(ident, self.rules, tokens, self.reg)
        self.sup = Supervisor(self.reg, make_settings(data_dir), CredStore(data_dir),
                              PendingFlows(), self.policy)

    def stored(self, key: ServerKey = GH_ALICE) -> ServerSpec:
        return self.reg.get(key)

    async def close(self) -> None:
        for child in list(self.sup._children.values()):
            if child.task is not None and not child.task.done():
                child.task.cancel()
                await asyncio.gather(child.task, return_exceptions=True)
        await self.sup.shutdown()


def fake_npx(bin_dir: Path, mode: str = "good") -> Path:
    """Write a fake `npx` into `bin_dir`. Return the path of its call log.

    In mode `slow` the fake server waits for `<bin_dir>/release`.
    """
    bin_dir.mkdir(parents=True, exist_ok=True)
    log = bin_dir / "npx-calls.log"
    script = bin_dir / "npx"
    script.write_text(
        "#!/bin/sh\n"
        f'echo "$@" >> "{log}"\n'
        f'MCPFLOW_RELEASE="{bin_dir / "release"}" exec "{sys.executable}" '
        f'"{FAKE_SERVER}" {mode}\n'
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return log


def npm_spec(namespace: str = "github", package: str = "@acme/mcp@1.2.3",
             **extra) -> ServerSpec:
    return ServerSpec(namespace=namespace, kind="npm", package=package, **extra)


async def wait_status(sup: Supervisor, key: ServerKey, want: set[str],
                      timeout: float = 30.0) -> str:
    deadline = time.monotonic() + timeout
    status = sup.get(key).status
    while time.monotonic() < deadline:
        status = sup.get(key).status
        if status in want:
            return status
        await asyncio.sleep(0.05)
    raise AssertionError(f"{key.ref} stayed {status}, wanted {want}")


class Listener:
    """A TCP server on 127.0.0.1 that counts connections and closes them."""

    def __init__(self) -> None:
        self.connections = 0
        self.server: asyncio.AbstractServer | None = None

    async def __aenter__(self) -> Listener:
        async def on_conn(reader, writer):
            self.connections += 1
            writer.close()

        self.server = await asyncio.start_server(on_conn, "127.0.0.1", 0)
        return self

    @property
    def url(self) -> str:
        port = self.server.sockets[0].getsockname()[1]
        return f"http://127.0.0.1:{port}/mcp"

    async def __aexit__(self, *exc) -> None:
        self.server.close()
        await self.server.wait_closed()


def path_with(bin_dir: Path) -> str:
    return f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"
