"""Shared helpers for the 10E keyed-store tests (multi-user-access).

Guarded invariant: `OpTouchesOnlyOwnPaths` in
`specs/tla/multi_user_access_lifecycle.tla` (negative config
`multi_user_access_lifecycle_nskeyed.cfg`): an operation on one key touches
only the paths of that key.

A user add through `Supervisor.add` lands in section 6.1, so a user-owned
record is seeded through the frozen `Registry` interface: `add` with the
owner, then `set_approved_revision(key, revision(spec))`. A user-owned
server may not be `custom` (D7b), so it is a `remote` server. Its URL points
at a closed port: a start attempt fails, and no test needs the network.
"""

from __future__ import annotations

import asyncio
import os
import stat
from pathlib import Path

from conftest import make_policy, make_settings, make_user

from mcpflow.identity import User
from mcpflow.oauth import CredStore, PendingFlows
from mcpflow.registry import Registry, ServerKey, ServerSpec, revision
from mcpflow.supervisor import Supervisor

ALICE = User(id="alice", name="alice", groups=frozenset(), provider="local")
BOB = User(id="bob", name="bob", groups=frozenset(), provider="local")

# References that must never name a path: traversal, absolute, encoded,
# a dot owner, a second `@`, and a trailing newline.
BAD_REFS = ["../tokens", "github@../x", "github@alice/x", "/abs", "%2f",
            "github@.", "github@a@b", "github\n", "github@alice\n",
            "github@../..", "Bad"]

TOKENS = {"access_token": "a", "refresh_token": "r", "scope": "s",
          "token_type": "Bearer", "expires_in": 3600}


def user_spec(namespace: str, owner: str, **extra) -> ServerSpec:
    return ServerSpec(namespace=namespace, kind="remote",
                      url="http://127.0.0.1:9/mcp", owner=owner, **extra)


def seed_user(reg: Registry, spec: ServerSpec, *, approve: bool = True) -> ServerKey:
    reg.add(spec)
    key = ServerKey(spec.owner, spec.namespace)
    if approve:
        reg.set_approved_revision(key, revision(reg.get(key)))
    return key


def register_actors(sup: Supervisor, *actors: User) -> None:
    """Register each actor in the identity store of `sup`, if absent.

    `Supervisor.add` re-reads its actor at write time (reresolve-actor-at-write),
    so a snapshot built outside the store is refused. The constants keep their
    id and role: the check reads only those two.
    """
    local = sup.policy.local_identity()
    for actor in actors:
        if local.get_user(actor.id) is None:
            make_user(local, actor.id)


def build(data_dir: Path, *specs: ServerSpec) -> Supervisor:
    """A hand-built supervisor over `data_dir`. A spec with an owner is
    seeded as an approved user record."""
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "logs").mkdir(exist_ok=True)
    reg = Registry(data_dir / "servers.json", data_dir / "user_servers.json")
    reg.load()
    for spec in specs:
        if spec.owner is None:
            reg.add(spec)
        else:
            seed_user(reg, spec)
    sup = Supervisor(reg, make_settings(data_dir), CredStore(data_dir),
                     PendingFlows(), make_policy(data_dir, reg))
    register_actors(sup, ALICE, BOB)
    return sup


def tree(root: Path) -> dict[str, tuple]:
    """Every path under `root` with its type, mode, and content or target."""
    out: dict[str, tuple] = {}
    if not root.exists() and not root.is_symlink():
        return out
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            p = Path(dirpath) / name
            st = os.lstat(p)
            rel = str(p.relative_to(root))
            if stat.S_ISLNK(st.st_mode):
                out[rel] = ("link", os.readlink(p))
            elif stat.S_ISDIR(st.st_mode):
                out[rel] = ("dir", stat.S_IMODE(st.st_mode))
            else:
                out[rel] = ("file", stat.S_IMODE(st.st_mode), p.read_bytes())
    return out


async def user_add(sup: Supervisor, spec: ServerSpec, actor: User = ALICE, **kw):
    """`Supervisor.add` by a non-admin actor. Since section 6.1 a
    `PermissionError` here is a regression and must fail, never skip."""
    register_actors(sup, actor)
    return await sup.add(spec, actor, **kw)


async def drain(sup: Supervisor) -> None:
    for child in list(sup._children.values()):
        if child.task is not None and not child.task.done():
            await asyncio.gather(child.task, return_exceptions=True)
    await sup.shutdown()
