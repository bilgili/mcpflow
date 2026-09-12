"""`Supervisor.remove` saves the removal before it tears the child down.

`remove` spans two owners: the registry holds the persisted state, the
supervisor holds the live state. If it tore the child down first and the
write then failed, the provider would already be unpublished and the
transport handle dropped while `servers.json` still listed the child and its
status still read `running` - a state nothing in the system can repair.

The tests drive removal through `/servers/{ns}/delete`, so the operation runs
on the gateway's own event loop, where the per-child lock lives.

Scenarios from `specs/server-registry/spec.md`, requirement "Registry
operations".
"""

from __future__ import annotations

import asyncio
import contextlib
import threading

import pytest
from conftest import fake_child_spec

from mcpflow.auth import TokenStore
from mcpflow.registry import Registry, RegistryError, ServerSpec


def _seed(*specs: ServerSpec, holder: dict):
    def seed(data_dir):
        reg = Registry(data_dir / "servers.json")
        reg.load()
        for spec in specs:
            reg.add(spec)
        store = TokenStore(data_dir / "tokens.json")
        store.load()
        _record, clear = store.create("test")
        holder["clear"] = clear

    return seed


def tool_names(base: str, token: str) -> list[str]:
    async def run():
        from fastmcp import Client
        from fastmcp.client.transports import StreamableHttpTransport

        transport = StreamableHttpTransport(
            base + "/mcp", headers={"Authorization": f"Bearer {token}"}
        )
        async with Client(transport) as c:
            return sorted(t.name for t in await c.list_tools())

    return asyncio.run(run())


@contextlib.contextmanager
def admin(server):
    client = server.login()
    try:
        yield client
    finally:
        client.close()


@pytest.fixture
def running_server(server_factory):
    holder: dict = {}
    server = server_factory(_seed(fake_child_spec("time", "two"), holder=holder))
    server.wait(running=1)
    server.token = holder["clear"]
    return server


def break_writes(server, monkeypatch):
    def boom(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(server.supervisor.registry, "_write", boom)


def _still_registered(sup) -> bool:
    return any(s.namespace == "time" for s in sup.registry.list())


def delete(client, ns: str):
    return client.post(f"/servers/{ns}/delete")


def test_a_failed_write_leaves_the_child_in_the_registry(running_server, monkeypatch):
    break_writes(running_server, monkeypatch)
    with admin(running_server) as client:
        assert delete(client, "time").status_code >= 500

    assert running_server.supervisor.registry.get("time").namespace == "time"
    fresh = Registry(running_server.data_dir / "servers.json")
    fresh.load()
    assert fresh.get("time").namespace == "time"


def test_a_failed_write_leaves_the_child_running_with_its_provider(
    running_server, monkeypatch
):
    sup = running_server.supervisor
    provider = sup.get("time").provider
    assert provider in sup.table.providers

    break_writes(running_server, monkeypatch)
    with admin(running_server) as client:
        assert delete(client, "time").status_code >= 500

    child = sup.get("time")
    assert child.status == "running"
    assert child.provider is provider
    assert provider in sup.table.providers
    assert child.transport is not None


def test_a_failed_write_leaves_the_tools_published(running_server, monkeypatch):
    """The live gate must still agree with the registry."""
    before = tool_names(running_server.base_url, running_server.token)
    assert "time_get_current_time" in before

    break_writes(running_server, monkeypatch)
    with admin(running_server) as client:
        assert delete(client, "time").status_code >= 500

    assert tool_names(running_server.base_url, running_server.token) == before


def test_a_successful_remove_requests_close_and_forgets(running_server):
    """The success path is unchanged by the reorder."""
    sup = running_server.supervisor
    provider = sup.get("time").provider

    with admin(running_server) as client:
        assert delete(client, "time").status_code in (200, 303)

    assert provider not in sup.table.providers
    with pytest.raises(KeyError):
        sup.get("time")
    fresh = Registry(running_server.data_dir / "servers.json")
    fresh.load()
    with pytest.raises(KeyError):
        fresh.get("time")
    assert tool_names(running_server.base_url, running_server.token) == []


def test_teardown_swallows_a_failing_transport_close(running_server):
    """No ordinary error may stop a saved removal part-way. A close that
    raises must still leave the provider gone and the child dropped.

    Note what this does NOT prove: the close failed, so the subprocess may
    well still be running. `remove` asks the child to stop and forgets it."""
    sup = running_server.supervisor

    class Exploding:
        async def close(self):
            raise RuntimeError("close blew up")

    child = sup.get("time")
    child.transport = Exploding()

    with admin(running_server) as client:
        assert delete(client, "time").status_code in (200, 303)

    # The removal completed despite the raising close.
    with pytest.raises(KeyError):
        sup.get("time")
    fresh = Registry(running_server.data_dir / "servers.json")
    fresh.load()
    with pytest.raises(KeyError):
        fresh.get("time")


def test_teardown_swallows_a_cancellation_during_close(running_server):
    """`CancelledError` derives from `BaseException`, so a handler that
    caught only `Exception` would let a cancellation delivered during the
    close escape `_teardown` - stranding a child the registry has already
    forgotten. The contract must hold for that case too."""
    sup = running_server.supervisor

    class Cancelling:
        async def close(self):
            raise asyncio.CancelledError

    sup.get("time").transport = Cancelling()

    with admin(running_server) as client:
        assert delete(client, "time").status_code in (200, 303)

    with pytest.raises(KeyError):
        sup.get("time")
    fresh = Registry(running_server.data_dir / "servers.json")
    fresh.load()
    with pytest.raises(KeyError):
        fresh.get("time")


def test_a_concurrent_add_under_the_same_namespace_is_refused(running_server):
    """A removal reserves its namespace until its teardown returns.

    This test previously asserted the opposite: the add during the teardown
    succeeded and the resuming `remove` left the replacement alone. Two
    cleanup guards existed only to survive that window, and a child that
    rewrites its own token file needed a third. The window was the cause, so
    `remove` now holds the namespace and `add` refuses it. Persist-first is
    unchanged; the registry entry still goes before the teardown, and the
    reservation is in memory over the gap.

    The test blocks the teardown with a gated transport close and drives both
    operations through the real routes, so both run on the gateway's loop.
    """
    sup = running_server.supervisor
    gate = threading.Event()
    entered = threading.Event()

    class Gated:
        async def close(self):
            entered.set()
            while not gate.is_set():
                await asyncio.sleep(0.01)

    sup.get("time").transport = Gated()

    outcome: dict = {}

    def do_delete():
        with admin(running_server) as client:
            outcome["status"] = delete(client, "time").status_code

    remover = threading.Thread(target=do_delete, daemon=True)
    remover.start()

    # Wait for the teardown itself, not merely for the registry write. A
    # `remove` that failed early would also clear the registry, and the rest
    # of the test would then pass without ever exercising the interleaving.
    assert entered.wait(timeout=20), "remove never reached the teardown"
    assert not _still_registered(sup)

    with admin(running_server) as client:
        resp = client.post(
            "/servers",
            data={
                "namespace": "time",
                "kind": "custom",
                "command": "true",
                "args": "",
                "description": "replacement",
            },
        )
        # Refused while the removal holds the namespace. The form re-renders
        # with the reason rather than redirecting.
        assert resp.status_code != 303, resp.text
        assert "being removed" in resp.text

    # Nothing was registered under the reserved namespace.
    with pytest.raises(KeyError):
        sup.get("time")
    assert not _still_registered(sup)

    gate.set()
    remover.join(timeout=20)
    assert not remover.is_alive()
    # The removal itself must have succeeded, not merely got out of the way.
    assert outcome.get("status") in (200, 303), outcome

    # Once the removal returned, the namespace is free again.
    with admin(running_server) as client:
        resp = client.post(
            "/servers",
            data={
                "namespace": "time",
                "kind": "custom",
                "command": "true",
                "args": "",
                "description": "replacement",
            },
        )
        assert resp.status_code == 303, resp.text
    assert sup.registry.get("time").description == "replacement"


def test_a_queued_remove_cannot_delete_a_later_generation(tmp_path):
    """A mutator resolves its child before it awaits that child's lock, so a
    queued waiter can hold a generation that a completed remove already
    dropped. Its lock is then uncontended, and without an identity re-check
    it would wake and delete the replacement's registry and `_children`
    entries while tearing down its own stale object.

    No gateway is needed: the guard is about identity, not about processes,
    so the children here never start.
    """
    from conftest import make_settings

    from mcpflow.supervisor import Supervisor, _new_child

    reg = Registry(tmp_path / "servers.json")
    reg.load()
    reg.add(fake_child_spec("time", "good", enabled=False))
    from mcpflow.oauth import CredStore, PendingFlows

    sup = Supervisor(reg, make_settings(tmp_path), CredStore(tmp_path), PendingFlows())
    stale = sup.get("time")

    async def scenario():
        # Hold the stale child's lock so a second remove queues behind it.
        await stale.lock.acquire()
        queued = asyncio.create_task(sup.remove("time"))
        await asyncio.sleep(0)  # let it reach the lock
        await asyncio.sleep(0)

        # The real removal completes and an add installs a replacement, both
        # while the queued operation still holds the stale child object.
        del sup._children["time"]
        sup.registry.remove("time")
        replacement_spec = fake_child_spec(
            "time", "good", enabled=False, description="replacement"
        )
        sup.registry.add(replacement_spec)
        replacement = _new_child(replacement_spec)
        sup._children["time"] = replacement

        stale.lock.release()
        try:
            await queued
        except RegistryError as exc:
            return "refused", replacement, str(exc)
        return "completed", replacement, ""

    outcome, replacement, message = asyncio.run(scenario())

    # The queued remove must refuse rather than delete the replacement.
    assert outcome == "refused", "the queued remove acted on a dead generation"
    assert "changed while the operation waited" in message
    assert sup.get("time") is replacement
    assert sup.registry.get("time").description == "replacement"


def test_remove_drops_creds_before_teardown(tmp_path):
    """`remove` deletes the credential directory and the open flow in the same
    window as the registry write, before the first `await`. A callback that
    arrives during the (here, blocked) teardown already finds nothing."""
    from conftest import make_settings

    from mcpflow.oauth import ClientCreds, CredStore, PendingFlows
    from mcpflow.supervisor import Supervisor

    reg = Registry(tmp_path / "servers.json")
    reg.load()
    reg.add(fake_child_spec("gmail", "good", enabled=False))
    sup = Supervisor(reg, make_settings(tmp_path), CredStore(tmp_path), PendingFlows())
    sup.creds.write_client("gmail", "google-client", ClientCreds("a", "1"))
    sup.creds.write_token("gmail", "google-auth-library", {
        "access_token": "a", "refresh_token": "r", "scope": "s",
        "token_type": "Bearer", "expires_in": 3600,
    })
    flow = sup.flows.create("gmail", "gmail", ClientCreds("a", "1"))
    creds_dir = sup.creds.root / "gmail"
    assert creds_dir.exists()

    async def scenario():
        entered = asyncio.Event()
        released = asyncio.Event()

        async def blocked_teardown(_child):
            entered.set()
            await released.wait()

        sup._teardown = blocked_teardown
        task = asyncio.create_task(sup.remove("gmail"))
        await entered.wait()
        # The teardown is still blocked, yet the creds and the flow are gone.
        assert not creds_dir.exists()
        assert sup.flows.pop(flow.state) is None
        released.set()
        await task

    asyncio.run(scenario())
    assert "gmail" not in [s.namespace for s in sup.registry.list()]


def _oauth_sup(tmp_path, namespace="gmail"):
    """A supervisor holding one disabled OAuth child with both credential
    files on disk."""
    from conftest import make_settings

    from mcpflow.oauth import ClientCreds, CredStore, PendingFlows
    from mcpflow.supervisor import Supervisor

    reg = Registry(tmp_path / "servers.json")
    reg.load()
    reg.add(fake_child_spec(namespace, "good", enabled=False))
    sup = Supervisor(reg, make_settings(tmp_path), CredStore(tmp_path), PendingFlows())
    sup.creds.write_client(namespace, "google-client", ClientCreds("a", "1"))
    sup.creds.write_token(namespace, "google-auth-library", {
        "access_token": "a", "refresh_token": "r", "scope": "s",
        "token_type": "Bearer", "expires_in": 3600,
    })
    return sup


def test_remove_deletes_creds_again_after_the_teardown(tmp_path):
    """A child that refreshes its own access token rewrites its token file.

    The first delete runs before the teardown, while that process is still
    alive, so the child can recreate `token.json` afterwards and
    `rmtree(ignore_errors=True)` reports nothing. The second delete, after the
    teardown returns, is what leaves no live refresh token on the host.

    Scenario: `specs/oauth-client/spec.md`, "A deleted child leaves no
    credential behind".
    """
    sup = _oauth_sup(tmp_path)
    creds_dir = sup.creds.root / "gmail"
    token = sup.creds.paths("gmail").token

    async def scenario():
        async def child_writes_during_teardown(_child):
            # Stand in for the child's refresh listener renaming its tmp file
            # back over the token path after the first delete.
            creds_dir.mkdir(parents=True, exist_ok=True)
            token.write_text('{"access_token": "a", "refresh_token": "r"}')

        sup._teardown = child_writes_during_teardown
        await sup.remove("gmail")

    asyncio.run(scenario())
    assert not token.exists()
    assert not creds_dir.exists()


def test_add_purges_residue_of_an_interrupted_removal(tmp_path):
    """A restart inside the teardown await forgets the in-memory reservation,
    so the second delete never runs and a token file can outlive its child.

    Nothing sweeps the credential root at startup, so `add` is what drops the
    residue: reaching past `registry.add` proves the namespace was free.

    Scenario: `specs/oauth-client/spec.md`, "A removal interrupted by a
    restart leaves no usable credential".
    """
    from conftest import make_settings

    from mcpflow.oauth import CredStore, PendingFlows
    from mcpflow.supervisor import Supervisor

    sup = _oauth_sup(tmp_path)
    token = sup.creds.paths("gmail").token
    # Simulate the interrupted removal: the registry entry is gone, the token
    # the child wrote is not, and a fresh process starts with no reservation.
    sup.registry.remove("gmail")
    assert token.exists()
    fresh = Supervisor(
        sup.registry, make_settings(tmp_path), CredStore(tmp_path), PendingFlows()
    )
    assert fresh.creds.paths("gmail").token.exists()  # residue survived

    asyncio.run(fresh.add(fake_child_spec("gmail", "good", enabled=False)))

    assert not fresh.creds.paths("gmail").token.exists()
    assert not fresh.creds.has_client("gmail")


def test_a_duplicate_add_keeps_the_live_childs_credential(tmp_path):
    """The purge sits after `registry.add`, never before it.

    Before it, a duplicate `add` would delete a live child's credential and
    only then raise on the duplicate check. `gate_neg_purge_position.cfg`
    states this formally as `LiveChildKeepsCredential`.

    Scenario: `specs/oauth-client/spec.md`, "A duplicate add keeps the live
    child's credential".
    """
    sup = _oauth_sup(tmp_path)
    paths = sup.creds.paths("gmail")
    assert paths.client.exists() and paths.token.exists()

    with pytest.raises(RegistryError, match="already exists"):
        asyncio.run(sup.add(fake_child_spec("gmail", "good", enabled=False)))

    assert paths.client.exists()
    assert paths.token.exists()


def test_a_failed_client_write_leaves_a_removable_child(tmp_path):
    """`add` writes the client file last, after both stores agree.

    The write is the only fallible step in `add`. A disk error between the
    registry write and the child install would stand the namespace up in one
    store and not the other: `remove` reads `_children` and would raise
    `KeyError`, while a retry would hit the duplicate in the registry. The
    namespace would be stranded until the gateway restarted.

    Writing after the install keeps the documented recovery working: delete
    the child and connect again.
    """
    from conftest import make_settings

    from mcpflow.oauth import ClientCreds, CredStore, PendingFlows
    from mcpflow.supervisor import Supervisor

    reg = Registry(tmp_path / "servers.json")
    reg.load()
    sup = Supervisor(reg, make_settings(tmp_path), CredStore(tmp_path), PendingFlows())

    def boom(*_a, **_kw):
        raise PermissionError("read-only filesystem")

    sup.creds.write_client = boom

    with pytest.raises(PermissionError):
        asyncio.run(
            sup.add(
                fake_child_spec("gmail", "good", enabled=False),
                "google-client",
                ClientCreds("id", "secret"),
            )
        )

    # Both stores agree, so the child is removable and the operator can retry.
    assert "gmail" in [s.namespace for s in sup.registry.list()]
    assert "gmail" in sup._children
    asyncio.run(sup.remove("gmail"))
    assert "gmail" not in [s.namespace for s in sup.registry.list()]
    assert "gmail" not in sup._children


def test_a_failed_reauth_write_leaves_a_restartable_child(tmp_path):
    """`finish_oauth` marks the child stopped once its teardown returns.

    The teardown drops the provider and the transport, so `running` is no
    longer true. If a credential write then raises, the status must already
    say `stopped`, or the child reports `running`, serves nothing, and cannot
    be repaired: `enable` is a no-op on a child that is not `stopped`.
    """
    from conftest import make_settings

    from mcpflow.oauth import ClientCreds, CredStore, PendingFlows
    from mcpflow.supervisor import Supervisor

    reg = Registry(tmp_path / "servers.json")
    reg.load()
    reg.add(fake_child_spec("gmail", "good", enabled=True))
    sup = Supervisor(reg, make_settings(tmp_path), CredStore(tmp_path), PendingFlows())
    child = sup._children["gmail"]
    child.status = "running"

    def boom(*_a, **_kw):
        raise OSError("no space left on device")

    sup.creds.write_token = boom
    flow = sup.flows.create("gmail", "gmail", ClientCreds("a", "1"), reauth=True)

    with pytest.raises(OSError):
        asyncio.run(
            sup.finish_oauth(
                flow,
                "google-auth-library",
                {"access_token": "a", "refresh_token": "r", "expires_in": 3600},
                reauth=True,
            )
        )

    # Truthful and recoverable: the child is down and says so.
    assert child.status == "stopped"
    assert child.transport is None
    assert child.provider is None


def test_connect_writes_the_client_file_through_add(tmp_path):
    """`Supervisor.add` owns the register-then-write pair, so no module
    outside the supervisor calls `CredStore.write_client`.

    Scenario: `specs/oauth-client/spec.md`, "The connect path writes through
    the supervisor".
    """
    from conftest import make_settings

    from mcpflow.oauth import ClientCreds, CredStore, PendingFlows
    from mcpflow.supervisor import Supervisor

    reg = Registry(tmp_path / "servers.json")
    reg.load()
    sup = Supervisor(reg, make_settings(tmp_path), CredStore(tmp_path), PendingFlows())

    asyncio.run(
        sup.add(
            fake_child_spec("gmail", "good", enabled=False),
            "google-client",
            ClientCreds("id", "secret"),
        )
    )

    assert sup.creds.has_client("gmail")
    assert not sup.creds.has_token("gmail")
    assert sup.creds.awaiting("gmail")  # client written, token still pending
