"""Inline source servers: the ownership rule, the directory lifecycle, and the
`write_source` tool.

Scenarios from `specs/server-registry/spec.md` (Source ownership, Source
directory lifecycle) and `specs/inline-source-servers/spec.md` (Write source
tool). The lifecycle tests inject a fake transport so no test needs a real
`uvx --from` build (which would need the network); the uvx/npx command mapping
itself is covered in `test_supervisor.py` under git-source-packages.
"""

from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio
from conftest import fake_child_spec, make_settings
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

from mcpflow.auth import TokenStore
from mcpflow.oauth import CredStore, PendingFlows
from mcpflow.registry import Registry, RegistryError, ServerSpec
from mcpflow.supervisor import Supervisor


@pytest_asyncio.fixture
async def make_supervisor(tmp_path):
    created: list[Supervisor] = []
    counter = {"n": 0}

    def _make(*specs: ServerSpec, **over) -> Supervisor:
        counter["n"] += 1
        data_dir = tmp_path / f"sup{counter['n']}"
        data_dir.mkdir()
        reg = Registry(data_dir / "servers.json")
        reg.load()
        for spec in specs:
            reg.add(spec)
        sup = Supervisor(
            reg, make_settings(data_dir, **over), CredStore(data_dir), PendingFlows()
        )
        created.append(sup)
        return sup

    yield _make
    for sup in created:
        await sup.shutdown()


def _py(namespace: str, source: str, **over) -> ServerSpec:
    return ServerSpec(
        namespace=namespace, kind="python", package="p", source=source,
        enabled=False, **over,
    )


class _FakeTransport:
    """A transport stand-in whose async close runs a check callback."""

    def __init__(self, on_close) -> None:
        self._on_close = on_close
        self.closed = False

    async def close(self) -> None:
        self._on_close()
        self.closed = True


# --- Source ownership (5.9, 8.1) ---------------------------------------------


@pytest.mark.asyncio
async def test_add_source_of_other_namespace_rejected(make_supervisor):
    sup = make_supervisor()
    other_dir = sup.sources.write("other", {"main.py": "x"})
    with pytest.raises(RegistryError) as exc:
        await sup.add(_py("mine", str(other_dir)))
    assert "other" in str(exc.value)
    # The registry file was not written.
    assert not (sup.settings.data_dir / "servers.json").exists()


@pytest.mark.asyncio
async def test_update_source_of_other_namespace_rejected(make_supervisor):
    sup = make_supervisor()
    own = sup.sources.write("mine", {"main.py": "x"})
    other = sup.sources.write("other", {"main.py": "y"})
    await sup.add(_py("mine", str(own)))
    before = (sup.settings.data_dir / "servers.json").read_text()
    with pytest.raises(RegistryError) as exc:
        await sup.update(_py("mine", str(other)))
    assert "other" in str(exc.value)
    assert (sup.settings.data_dir / "servers.json").read_text() == before


@pytest.mark.asyncio
async def test_add_source_equal_to_root_rejected(make_supervisor):
    sup = make_supervisor()
    with pytest.raises(RegistryError) as exc:
        await sup.add(_py("mine", str(sup.sources.root)))
    assert "is inside DATA_DIR/servers" in str(exc.value)


@pytest.mark.asyncio
async def test_add_own_source_ok(make_supervisor):
    sup = make_supervisor()
    own = sup.sources.write("mine", {"main.py": "x"})
    child = await sup.add(_py("mine", str(own)))
    assert child.spec.namespace == "mine"


# --- Source directory lifecycle (5.13, 5.14, 5.15, 5.16) ---------------------


@pytest.mark.asyncio
async def test_remove_deletes_directory_after_teardown(make_supervisor):
    sup = make_supervisor()
    own = sup.sources.write("mine", {"main.py": "x"})
    child = await sup.add(_py("mine", str(own)))
    # Promote to a running child with a transport whose close asserts the
    # directory is still present when it runs (delete must come after close).
    seen = {}
    child.status = "running"
    child.transport = _FakeTransport(lambda: seen.update(present=own.exists()))
    await sup.remove("mine")
    assert seen["present"] is True  # dir was present during close
    assert not own.exists()  # deleted after teardown


@pytest.mark.asyncio
async def test_namespace_cannot_be_reclaimed_during_teardown(make_supervisor):
    """The reservation makes the old reclaim window unreachable.

    This test used to assert the opposite: an add during the teardown
    reclaimed the namespace and the removal then skipped its delete. A child
    that rewrites its own token file made that window unsafe, so `remove` now
    holds the namespace until its teardown returns. The delete no longer needs
    a child-table guard, because there can be no replacement to protect.
    """
    sup = make_supervisor()
    own = sup.sources.write("mine", {"main.py": "x"})
    child = await sup.add(_py("mine", str(own)))
    child.status = "running"

    held: list[bool] = []
    child.transport = _FakeTransport(lambda: held.append("mine" in sup._removing))

    await sup.remove("mine")

    assert held == [True]  # reserved while the teardown ran
    assert not own.exists()  # deleted, because nothing could reclaim it
    assert "mine" not in sup._removing  # released when the removal returned


@pytest.mark.asyncio
async def test_add_refuses_a_namespace_under_removal(make_supervisor):
    sup = make_supervisor()
    own = sup.sources.write("mine", {"main.py": "x"})
    await sup.add(_py("mine", str(own)))
    sup._removing.add("mine")

    # The reservation is checked before `registry.add`, so the reason names the
    # removal rather than the duplicate namespace.
    with pytest.raises(RegistryError, match="being removed"):
        await sup.add(_py("mine", str(own)))


@pytest.mark.asyncio
async def test_update_to_git_source_keeps_directory(make_supervisor):
    sup = make_supervisor()
    own = sup.sources.write("mine", {"main.py": "x"})
    await sup.add(_py("mine", str(own)))
    await sup.update(
        ServerSpec(
            namespace="mine", kind="python", package="p",
            source="git+https://host/o/r", enabled=False,
        )
    )
    assert own.exists()


@pytest.mark.asyncio
async def test_disable_keeps_directory(make_supervisor):
    sup = make_supervisor()
    own = sup.sources.write("mine", {"main.py": "x"})
    await sup.add(_py("mine", str(own)))
    await sup.disable("mine")
    assert own.exists()


@pytest.mark.asyncio
async def test_remove_git_source_deletes_nothing(make_supervisor):
    sup = make_supervisor()
    # A directory exists under the store, but the child runs from a git source.
    stray = sup.sources.write("mine", {"main.py": "x"})
    await sup.add(
        ServerSpec(
            namespace="mine", kind="python", package="p",
            source="git+https://host/o/r", enabled=False,
        )
    )
    await sup.remove("mine")
    # owns() is false for a git source, so the store directory is left intact.
    assert stray.exists()


@pytest.mark.asyncio
async def test_remove_propagates_store_oserror(make_supervisor):
    sup = make_supervisor()
    own = sup.sources.write("mine", {"main.py": "x"})
    await sup.add(_py("mine", str(own)))

    def boom(namespace):
        raise OSError("disk gone")

    sup.sources.remove = boom
    with pytest.raises(OSError):
        await sup.remove("mine")
    # The registry no longer lists the child; a retry answers KeyError (404).
    assert "mine" not in [c.spec.namespace for c in sup.children()]
    with pytest.raises(KeyError):
        await sup.remove("mine")


# --- write_source restart semantics (5.11, 5.12) -----------------------------


@pytest.mark.asyncio
async def test_write_source_restarts_running_child(make_supervisor):
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("time", "good"))
    await child.task
    assert child.status == "running"
    result = await sup.write_source("time", {"main.py": "x"})
    assert result.restarted is True
    assert result.files == 1
    await sup._children["time"].task
    assert sup._children["time"].status == "running"


@pytest.mark.asyncio
async def test_write_source_restarts_failed_child(make_supervisor):
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("broken", "fail"))
    await child.task
    assert child.status == "failed"
    result = await sup.write_source("broken", {"main.py": "x"})
    assert result.restarted is True


@pytest.mark.asyncio
async def test_write_source_does_not_restart_stopped_or_missing(make_supervisor):
    sup = make_supervisor()
    stopped = await sup.add(fake_child_spec("time", "good", enabled=False))
    assert stopped.status == "stopped"
    r1 = await sup.write_source("time", {"main.py": "x"})
    assert r1.restarted is False
    assert sup._children["time"].task is None
    # A namespace with no child gets an orphan directory.
    r2 = await sup.write_source("ghost", {"main.py": "x"})
    assert r2.restarted is False
    assert sup.sources.path_for("ghost").exists()


@pytest.mark.asyncio
async def test_write_source_does_not_restart_starting_child(make_supervisor):
    # A child that hangs at startup stays `starting`; a write must not bounce it.
    sup = make_supervisor(CHILD_START_TIMEOUT="30")
    child = await sup.add(fake_child_spec("slow", "hang"))
    assert child.status == "starting"
    result = await sup.write_source("slow", {"main.py": "x"})
    assert result.restarted is False


# --- write_source over the admin MCP tool (5.10, 5.17) -----------------------


def _seed(holder: dict, *specs: ServerSpec):
    def seed(data_dir):
        reg = Registry(data_dir / "servers.json")
        reg.load()
        for spec in specs:
            reg.add(spec)
        store = TokenStore(data_dir / "tokens.json")
        store.load()
        _a, admin = store.create("admin", "admin")
        holder["admin"] = admin

    return seed


def _call(base: str, token: str, name: str, args: dict):
    async def run():
        transport = StreamableHttpTransport(
            base + "/mcp", headers={"Authorization": f"Bearer {token}"}
        )
        async with Client(transport) as c:
            return (await c.call_tool(name, args)).data

    return asyncio.run(run())


def _list(base: str, token: str) -> list[str]:
    async def run():
        transport = StreamableHttpTransport(
            base + "/mcp", headers={"Authorization": f"Bearer {token}"}
        )
        async with Client(transport) as c:
            return [t.name for t in await c.list_tools()]

    return asyncio.run(run())


def test_write_source_tool_success_returns_five_keys(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder))
    data = _call(
        server.base_url, holder["admin"], "mcpflow_write_source",
        {"namespace": "app", "files": {"main.py": "print(1)"}},
    )
    assert set(data) == {"namespace", "path", "files", "bytes", "restarted"}
    assert data["namespace"] == "app"
    assert data["files"] == 1
    assert data["restarted"] is False
    assert (server.data_dir / "servers" / "app" / "main.py").read_text() == "print(1)"


def test_write_source_tool_bad_key_is_toolerror(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder))
    with pytest.raises(Exception) as exc:
        _call(
            server.base_url, holder["admin"], "mcpflow_write_source",
            {"namespace": "app", "files": {"../escape.py": "x"}},
        )
    assert "../escape.py" in str(exc.value)


def test_write_then_add_custom_child_tools_appear(server_factory):
    # The agent round-trip: write the source files, register a child that runs
    # from the written directory, then its tools appear on /mcp. A custom child
    # runs the file through the system python so the test needs no uvx build.
    import sys
    from pathlib import Path

    holder: dict = {}
    server = server_factory(_seed(holder), CHILD_START_TIMEOUT="30")
    fake = Path(__file__).parent / "fake_mcp_server.py"
    server_code = fake.read_text()
    written = _call(
        server.base_url, holder["admin"], "mcpflow_write_source",
        {"namespace": "inline", "files": {"srv.py": server_code}},
    )
    srv_path = str(Path(written["path"]) / "srv.py")
    _call(
        server.base_url, holder["admin"], "mcpflow_add_server",
        {"spec": {
            "namespace": "inline", "kind": "custom",
            "command": sys.executable, "args": [srv_path, "good"],
        }},
    )
    server.wait(running=1)
    tools = _list(server.base_url, holder["admin"])
    assert any(t.startswith("inline_") for t in tools)
