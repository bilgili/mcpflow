"""Hold one request between the gate and the write (reresolve-actor-at-write).

The gate middleware has already admitted the request when the wrapped route
runs. `revoke_during_body` changes the identity store at that point, so the
handler writes with a snapshot that the store no longer backs. No thread is
needed: the revoke runs inside the first ASGI `receive` call, which is the
moment a slow body read ends (design T6). A route that reads no body never
calls `receive`; `at="enter"` runs the revoke when the route is entered, which
is the same window (after the gate, before the owner call).
"""

from __future__ import annotations

from collections.abc import Callable

from conftest import ADMIN_ACTOR
from starlette.routing import Mount, Route


def _find(routes, method: str, path: str, prefix: str = ""):
    for r in routes:
        if isinstance(r, Mount):
            hit = _find(getattr(r, "routes", None) or [], method, path, prefix + r.path)
            if hit is not None:
                return hit
        elif isinstance(r, Route) and prefix + r.path == path and method in (r.methods or ()):
            return r
    return None


def revoke_during_body(app, method: str, path: str, revoke: Callable[[], object],
                       *, at: str = "receive") -> list[int]:
    """Wrap the route `method path` so `revoke()` runs once between gate and
    handler. Return a list that gets one entry per revoke, for the test to
    assert that the window was really exercised."""
    route = _find(app.router.routes, method, path)
    assert route is not None, f"no route {method} {path}"
    assert at in ("receive", "enter")
    inner = route.app
    fired: list[int] = []

    def fire() -> None:
        if not fired:
            fired.append(1)
            revoke()

    async def held(scope, receive, send):
        if at == "enter":
            fire()
            await inner(scope, receive, send)
            return

        async def late_receive():
            fire()
            return await receive()

        await inner(scope, late_receive, send)

    route.app = held
    return fired


def make_second_admin(site) -> str:
    """Make `alice` an admin. Return the clear text of an admin token of hers."""
    policy = site.app.state.supervisor.policy
    policy.set_admin(ADMIN_ACTOR, "alice", True)
    _record, clear = policy.mint_token(ADMIN_ACTOR, "ops", "admin", "alice")
    return clear


def demote_alice(site) -> Callable[[], object]:
    policy = site.app.state.supervisor.policy
    return lambda: policy.set_admin(ADMIN_ACTOR, "alice", False)


def delete_user(site, uid: str) -> Callable[[], object]:
    policy = site.app.state.supervisor.policy
    return lambda: policy.delete_user(ADMIN_ACTOR, uid)


def stores(site, names) -> dict[str, bytes | None]:
    """The bytes of the named files of the data dir; a missing file reads None."""
    return {n: (site.data / n).read_bytes() if (site.data / n).exists() else None
            for n in names}


def revoke_then_capture(site, revoke: Callable[[], object], names) -> tuple[Callable[[], None], dict]:
    """A `revoke` that also records the files right after it ran.

    The revoke itself writes the stores (a demotion rewrites `users.json`). The
    refused write must change nothing beyond that, so a test compares the files
    after the request with the captured ones."""
    captured: dict = {}

    def run() -> None:
        revoke()
        captured.update(stores(site, names))

    return run, captured


def make_admin_user(site, uid: str) -> str:
    """Create an active admin `uid` that owns nothing. Return a clear admin token."""
    from conftest import make_user
    policy = site.app.state.supervisor.policy
    make_user(policy, uid, admin=True)
    _record, clear = policy.mint_token(ADMIN_ACTOR, "ops", "admin", uid)
    return clear
