"""Child lifecycle, transports, and the mount table.

Scenarios from `specs/mcp-gateway/spec.md` (Child kinds, Child environment
variables) and `specs/server-registry/spec.md` (Child lifecycle, Registry
operations, Failure isolation, Mount table ownership, Child log tail).

A `custom` child that speaks MCP over stdio stands in for a real child.
"""

from __future__ import annotations

import asyncio
import sys
import time

import pytest
import pytest_asyncio
from conftest import fake_child_spec, make_settings
from fastmcp.client.transports import StdioTransport, StreamableHttpTransport

from mcpflow.oauth import ClientCreds, CredStore, HeaderSpec, PendingFlows
from mcpflow.registry import Registry, RegistryError, ServerSpec
from mcpflow.supervisor import SingleConnectTransport, Supervisor

_CREDS = ClientCreds("abc", "secret")
_TOKENS = {
    "access_token": "a", "refresh_token": "r", "scope": "s",
    "token_type": "Bearer", "expires_in": 3600,
}


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
        settings = make_settings(data_dir, **over)
        sup = Supervisor(reg, settings, CredStore(data_dir), PendingFlows())
        created.append(sup)
        return sup

    yield _make

    for sup in created:
        await sup.shutdown()


# --- Child kinds and environment (12.6) --------------------------------------


def test_python_child_command(make_supervisor):
    sup = make_supervisor()
    spec = ServerSpec(
        namespace="time",
        kind="python",
        package="mcp-server-time",
        args=["--local-timezone", "UTC"],
    )
    transport = sup._build_transport(spec)
    # The stdio transport is now wrapped so it admits one connect per
    # generation; the command/args live on the wrapped `.inner` StdioTransport.
    assert isinstance(transport, SingleConnectTransport)
    assert isinstance(transport.inner, StdioTransport)
    assert transport.inner.command == "uvx"
    assert transport.inner.args == ["mcp-server-time", "--local-timezone", "UTC"]
    transport.log.close()  # the transport owns the log handle; nothing connected


def test_npm_child_command(make_supervisor):
    sup = make_supervisor()
    spec = ServerSpec(
        namespace="fs",
        kind="npm",
        package="@modelcontextprotocol/server-filesystem",
        args=["/data"],
    )
    transport = sup._build_transport(spec)
    assert isinstance(transport, SingleConnectTransport)
    assert isinstance(transport.inner, StdioTransport)
    assert transport.inner.command == "npx"
    assert transport.inner.args == [
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/data",
    ]
    transport.log.close()


def test_python_child_command_with_source():
    """`registry.build_command` owns this, not the supervisor.

    `Supervisor._build_command` is gone: the marketplace detail needs the same
    answer, and two copies of it disagreed as soon as a source existed.
    """
    from mcpflow.registry import build_command

    command, args = build_command(
        kind="python",
        package="my-tool",
        args=["--flag"],
        command=None,
        source="git+https://host/o/r",
    )
    assert command == "uvx"
    assert args == ["--from", "git+https://host/o/r", "my-tool", "--flag"]


def test_npm_child_command_with_source():
    from mcpflow.registry import build_command

    command, args = build_command(
        kind="npm",
        package="bin",
        args=["/data"],
        command=None,
        source="github:o/r",
    )
    assert command == "npx"
    assert args == ["-y", "--package=github:o/r", "bin", "/data"]


def test_build_command_refuses_a_remote_kind():
    """A remote child has a URL and a transport, not an argument list.

    Both callers branch on `remote` before they arrive, so this is a
    programmer guard rather than an admin-facing fault, and a plain
    `ValueError` no caller maps.
    """
    from mcpflow.registry import build_command

    with pytest.raises(ValueError, match="remote"):
        build_command(
            kind="remote", package=None, args=[], command=None, source=None
        )


def test_the_supervisor_starts_a_child_from_the_raw_source(make_supervisor):
    """The detail page redacts; the supervisor must not.

    A redacted source does not install, so the transport the supervisor builds
    has to carry the credential the admin gave.
    """
    sup = make_supervisor()
    spec = ServerSpec(
        namespace="tool",
        kind="python",
        package="my-tool",
        source="git+https://oauth2:TOKEN@host/o/r",
    )
    transport = sup._build_transport(spec)
    assert "git+https://oauth2:TOKEN@host/o/r" in transport.inner.args
    transport.log.close()


@pytest.mark.asyncio
async def test_failed_source_start_does_not_leak_token(make_supervisor):
    # A credential source pointing at a closed loopback port fails fast. The
    # gateway must not put the raw token into last_error; uvx redacts its own
    # output and our code never injects the raw source.
    sup = make_supervisor(CHILD_START_TIMEOUT="15")
    token = "SEKRETTOKEN123"
    spec = ServerSpec(
        namespace="tool",
        kind="python",
        package="my-tool",
        source=f"git+https://oauth2:{token}@127.0.0.1:9/o/r",
    )
    child = await sup.add(spec)
    await child.task
    assert child.status == "failed"
    assert child.last_error is not None
    assert token not in child.last_error


def test_remote_child_proxy(make_supervisor):
    sup = make_supervisor()
    spec = ServerSpec(
        namespace="rem", kind="remote", url="https://example.test/mcp", transport="http"
    )
    transport = sup._build_transport(spec)
    # A remote child is an HTTP proxy and spawns no subprocess.
    assert isinstance(transport, StreamableHttpTransport)
    assert not isinstance(transport, StdioTransport)
    assert transport.url == "https://example.test/mcp"


def test_secret_reaches_the_child(make_supervisor, monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    sup = make_supervisor()
    spec = ServerSpec(
        namespace="k", kind="python", package="pkg", env={"API_KEY": "abc"}
    )
    transport = sup._build_transport(spec)
    assert transport.inner.env["API_KEY"] == "abc"
    assert transport.inner.env["PATH"] == "/usr/bin:/bin"
    transport.log.close()


def test_gateway_secrets_do_not_reach_the_child(make_supervisor, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "pw")
    monkeypatch.setenv(
        "ADMIN_PASSWORD_HASH", "pbkdf2_sha256$1$" + "a" * 16 + "$" + "b" * 64
    )
    monkeypatch.setenv("SECRET_KEY", "deadbeef")
    monkeypatch.setenv("UV_PUBLISH_TOKEN", "tok")
    sup = make_supervisor()
    spec = ServerSpec(namespace="k", kind="python", package="pkg")
    transport = sup._build_transport(spec)
    for name in (
        "ADMIN_PASSWORD",
        "ADMIN_PASSWORD_HASH",
        "SECRET_KEY",
        "UV_PUBLISH_TOKEN",
    ):
        assert name not in transport.inner.env
    transport.log.close()


# --- Child lifecycle probes (12.7) -------------------------------------------


@pytest.mark.asyncio
async def test_probe_success(make_supervisor):
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("time", "good"))
    await child.task
    assert child.status == "running"
    assert child.tool_count == 1


@pytest.mark.asyncio
async def test_probe_failure(make_supervisor):
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("broken", "fail"))
    await child.task
    assert child.status == "failed"
    assert child.last_error


@pytest.mark.asyncio
async def test_probe_timeout(make_supervisor):
    sup = make_supervisor(CHILD_START_TIMEOUT="2")
    child = await sup.add(fake_child_spec("slow", "hang"))
    await child.task
    assert child.status == "failed"
    assert "timed out" in child.last_error


@pytest.mark.asyncio
async def test_log_tail_after_failure(make_supervisor):
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("broken", "fail"))
    await child.task
    deadline = time.time() + 5
    tail = ""
    while time.time() < deadline:
        tail = sup.log_tail("broken")
        if "child boom" in tail:
            break
        await asyncio.sleep(0.1)
    assert "child boom" in tail


# --- Redacted diagnostic secrets ---------------------------------------------


def test_scrub_secrets_masks_skips_short_and_prefers_longest():
    from mcpflow.supervisor import scrub_secrets

    # A configured value is masked; a value under the length floor is not, so
    # ordinary log text with a "1" or "on" survives.
    text = "token=xoxb-super-secret-value debug=1 host=127.0.0.1"
    out = scrub_secrets(text, ["xoxb-super-secret-value", "1"])
    assert "xoxb-super-secret-value" not in out
    assert "token=•••" in out
    assert "debug=1" in out
    assert "127.0.0.1" in out

    # A value that contains a shorter value masks whole, no readable fragment.
    assert scrub_secrets("value=abcdefgh", ["abcdefgh", "abcd"]) == "value=•••"

    # Empty text and an empty secret set are returned unchanged.
    assert scrub_secrets("", ["secretvalue"]) == ""
    assert scrub_secrets("plain text", []) == "plain text"


def test_scrub_secrets_overlapping_values_leave_no_fragment():
    from mcpflow.supervisor import scrub_secrets

    # Two secrets overlap in the text. A naive one-at-a-time replace would
    # strand the "ab" of the first after masking the second. The span merge
    # masks the whole overlapping run.
    out = scrub_secrets("x=abcdefg", ["abcd", "cdefg"])
    assert out == "x=•••"
    assert "ab" not in out.replace("x=", "")


@pytest.mark.asyncio
async def test_log_tail_scrubs_configured_env_secret(make_supervisor):
    secret = "xoxb-super-secret-value"
    spec = fake_child_spec("slack", env={"SLACK_BOT_TOKEN": secret}, enabled=False)
    child = await sup_add_disabled(make_supervisor, spec)
    sup = child["sup"]
    path = sup._log_path("slack")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"token={secret}\nlistening on 127.0.0.1\n")

    tail = sup.log_tail("slack")
    assert secret not in tail
    assert "token=•••" in tail
    # A non-secret line is untouched.
    assert "127.0.0.1" in tail


@pytest.mark.asyncio
async def test_last_error_scrubs_configured_header_value(make_supervisor):
    secret = "abc-super-secret-value"
    spec = fake_child_spec(
        "remote", headers={"Authorization": f"Bearer {secret}"}, enabled=False
    )
    child = await sup_add_disabled(make_supervisor, spec)
    sup, obj = child["sup"], child["child"]
    text = f"connect failed: sent header Bearer {secret}"
    sup._record_error(obj, text, sup._secrets_of(obj.spec))
    assert obj.last_error is not None
    assert secret not in obj.last_error
    assert "•••" in obj.last_error


@pytest.mark.asyncio
async def test_last_error_scrubs_bare_token_without_scheme(make_supervisor):
    # A header stores `Bearer <token>`, but a child error can echo the token
    # alone. The scheme-aware secret set masks it even without `Bearer `.
    secret = "abc-super-secret-value"
    spec = fake_child_spec(
        "remote", headers={"Authorization": f"Bearer {secret}"}, enabled=False
    )
    child = await sup_add_disabled(make_supervisor, spec)
    sup, obj = child["sup"], child["child"]
    sup._record_error(obj, f"invalid token {secret}", sup._secrets_of(obj.spec))
    assert secret not in obj.last_error
    assert obj.last_error == "invalid token •••"


@pytest.mark.asyncio
async def test_last_error_scrubs_source_credential(make_supervisor):
    # uvx/npx echo a failing source into stderr, which reaches last_error. The
    # token in the source URL must mask, while the host and path stay readable
    # so the failure is still diagnosable.
    token = "super-secret-token-value"
    spec = ServerSpec(
        namespace="drive",
        kind="python",
        package="my-tool",
        source=f"git+https://oauth2:{token}@host/o/r",
        enabled=False,
    )
    child = await sup_add_disabled(make_supervisor, spec)
    sup, obj = child["sup"], child["child"]
    text = f"could not read from git+https://oauth2:{token}@host/o/r"
    sup._record_error(obj, text, sup._secrets_of(obj.spec))
    assert obj.last_error is not None
    assert token not in obj.last_error
    assert "host/o/r" in obj.last_error  # host and path stay readable


@pytest.mark.asyncio
async def test_update_that_changes_secret_discards_stale_disabled_log(make_supervisor):
    # A disabled child keeps its log across an edit. When the edit rotates a
    # secret, the retained log holds the old secret, which the current-config
    # scrub can no longer mask. `update` discards the log in that case.
    old = "old-secret-value-xyz"
    spec = fake_child_spec("svc", env={"API_KEY": old}, enabled=False)
    child = await sup_add_disabled(make_supervisor, spec)
    sup = child["sup"]
    path = sup._log_path("svc")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"boom with {old}\n")

    new_spec = fake_child_spec("svc", env={"API_KEY": "new-secret-value-xyz"}, enabled=False)
    await sup.update(new_spec)

    # The stale log is gone, so the old secret cannot be read back.
    assert old not in sup.log_tail("svc")


@pytest.mark.asyncio
async def test_update_to_enabled_remote_discards_stale_log(make_supervisor):
    # Codex round 5 (redact-registry-secrets): a remote transport never
    # truncates the log, so an ENABLED switch from local to remote kept the old
    # output, and the new-config scrub could not mask the old env secret.
    old = "old-secret-value-xyz"
    spec = fake_child_spec("svc", env={"API_KEY": old}, enabled=False)
    child = await sup_add_disabled(make_supervisor, spec)
    sup = child["sup"]
    path = sup._log_path("svc")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"boom with {old}\n")

    remote = ServerSpec(namespace="svc", kind="remote", url="http://127.0.0.1:9/mcp")
    await sup.update(remote)

    assert old not in sup.log_tail("svc")


@pytest.mark.asyncio
async def test_remove_then_readd_does_not_expose_the_old_log(make_supervisor):
    # Codex round 6 (redact-registry-secrets): `remove` kept logs/<ns>.log, so a
    # new child under the same namespace read the old output through
    # `log_tail`, scrubbed with its own (different) secret set.
    old = "old-secret-value-xyz"
    spec = fake_child_spec("svc", env={"API_KEY": old}, enabled=False)
    child = await sup_add_disabled(make_supervisor, spec)
    sup = child["sup"]
    path = sup._log_path("svc")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"boom with {old}\n")

    await sup.remove("svc")
    await sup.add(fake_child_spec("svc", enabled=False))

    assert old not in sup.log_tail("svc")


@pytest.mark.asyncio
async def test_mute_during_update_teardown_does_not_expose_the_old_log(
    make_supervisor, monkeypatch
):
    # Codex round 6 (redact-registry-secrets), deferred to stale-log-discard-
    # order: `set_namespace_muted` replaces `child.spec` from the registry
    # without the child lock. During the teardown await of an update, the
    # registry already holds the new secret set, so a mute there made
    # `log_tail` scrub the retained old log with the new set only.
    old = "old-secret-value-xyz"
    spec = fake_child_spec("svc", env={"API_KEY": old}, enabled=False)
    child = await sup_add_disabled(make_supervisor, spec)
    sup = child["sup"]
    path = sup._log_path("svc")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"boom with {old}\n")

    paused, release = asyncio.Event(), asyncio.Event()
    real_teardown = sup._teardown

    async def slow_teardown(c):
        paused.set()
        await release.wait()
        await real_teardown(c)

    monkeypatch.setattr(sup, "_teardown", slow_teardown)
    new_spec = fake_child_spec("svc", env={"API_KEY": "new-secret-value-xyz"}, enabled=False)
    task = asyncio.create_task(sup.update(new_spec))
    await paused.wait()

    sup.set_namespace_muted("svc", True)
    assert old not in sup.log_tail("svc")
    sup.set_tool_muted("svc", "echo", True)
    assert old not in sup.log_tail("svc")

    release.set()
    await task
    assert old not in sup.log_tail("svc")


@pytest.mark.asyncio
async def test_update_during_start_does_not_let_the_old_child_recreate_the_log(
    make_supervisor,
):
    # Design gate F1 (stale-log-discard-order): fastmcp opens a `Path` log by
    # name in its own connect task, which `child.task.cancel()` does not
    # cancel. An update that lands between the first step of `_run_start` and
    # that open would unlink the log, and the open would then recreate it for
    # a process that runs with the old env. The supervisor opens the log
    # itself in the start step, so the unlink is final.
    old = "old-secret-value-xyz"
    script = (
        "import os, sys, time; "
        "sys.stderr.write(os.environ['API_KEY'] + '\\n'); sys.stderr.flush(); "
        "time.sleep(30)"
    )
    spec = ServerSpec(
        namespace="svc",
        kind="custom",
        command=sys.executable,
        args=["-c", script],
        env={"API_KEY": old},
    )
    new = spec.model_copy(
        update={"env": {"API_KEY": "new-secret-value-xyz"}, "enabled": False}
    )
    # The window is a few event-loop iterations wide and its exact position
    # depends on fastmcp internals (a `Path` log recreated the file at 3 and 4
    # yields on fastmcp 4.0.2), so sweep the update across the start.
    for yields in range(8):
        sup = make_supervisor()
        await sup.add(spec)
        for _ in range(yields):
            await asyncio.sleep(0)
        path = sup._log_path("svc")
        await sup.update(new)
        await asyncio.sleep(0.3)  # give a stray open or a late write the chance

        assert not path.exists(), f"recreated after {yields} yields"
        assert old not in sup.log_tail("svc")


def _log_gone_at_write(sup, path):
    """Record, at each registry write, whether the log still exists.

    A crash right after the write leaves the file as the registry of the
    restart, so the old log must already be gone when the write happens.
    """
    seen: list[bool] = []
    real_write = sup.registry._write

    def spy(*args, **kwargs):
        seen.append(path.exists())
        return real_write(*args, **kwargs)

    sup.registry._write = spy
    return seen


@pytest.mark.asyncio
async def test_update_discards_the_log_before_it_persists(make_supervisor):
    # Codex gate (stale-log-discard-order): a crash between the registry
    # write and the log delete left the new record beside the old log; the
    # restart then scrubbed that log with the new secret set only.
    old = "old-secret-value-xyz"
    spec = fake_child_spec("svc", env={"API_KEY": old}, enabled=False)
    sup = (await sup_add_disabled(make_supervisor, spec))["sup"]
    path = sup._log_path("svc")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"boom with {old}\n")
    seen = _log_gone_at_write(sup, path)

    await sup.update(fake_child_spec("svc", env={"API_KEY": "new-secret-value-xyz"}, enabled=False))

    assert seen == [False]


@pytest.mark.asyncio
async def test_update_keeps_the_old_record_when_the_log_delete_fails(
    make_supervisor, monkeypatch
):
    # Codex gate: with the delete after the write, an `OSError` from the
    # unlink aborted `update` with the new record persisted and the old log
    # kept, and the next mute exposed the old secret. The delete now runs
    # first, so its failure persists nothing.
    import pathlib

    old = "old-secret-value-xyz"
    spec = fake_child_spec("svc", env={"API_KEY": old}, enabled=False)
    sup = (await sup_add_disabled(make_supervisor, spec))["sup"]
    path = sup._log_path("svc")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"boom with {old}\n")
    real_unlink = pathlib.Path.unlink

    def refuse(self, missing_ok=False):
        if self == path:
            raise PermissionError(13, "Permission denied", str(self))
        return real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(pathlib.Path, "unlink", refuse)
    with pytest.raises(PermissionError):
        await sup.update(
            fake_child_spec("svc", env={"API_KEY": "new-secret-value-xyz"}, enabled=False)
        )

    assert sup.registry.get("svc").env == {"API_KEY": old}
    sup.set_namespace_muted("svc", True)
    assert old not in sup.log_tail("svc")


@pytest.mark.asyncio
async def test_add_discards_a_residue_log_before_it_persists(make_supervisor):
    old = "old-secret-value-xyz"
    sup = make_supervisor()
    path = sup._log_path("svc")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"boom with {old}\n")
    seen = _log_gone_at_write(sup, path)

    await sup.add(fake_child_spec("svc", enabled=False))

    assert seen == [False]


@pytest.mark.asyncio
async def test_duplicate_add_keeps_the_live_log(make_supervisor):
    spec = fake_child_spec("svc", enabled=False)
    sup = (await sup_add_disabled(make_supervisor, spec))["sup"]
    path = sup._log_path("svc")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("live output\n")

    with pytest.raises(RegistryError):
        await sup.add(spec)

    assert path.read_text() == "live output\n"


@pytest.mark.asyncio
async def test_add_discards_a_residue_log(make_supervisor):
    # A log under a namespace the registry does not list is residue: a remove
    # that a restart interrupted, or a remove from before the log delete. The
    # new child cannot scrub it (its secret set is different), so `add`
    # discards it, next to the credential residue purge.
    old = "old-secret-value-xyz"
    sup = make_supervisor()
    path = sup._log_path("svc")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"boom with {old}\n")

    await sup.add(fake_child_spec("svc", enabled=False))

    assert old not in sup.log_tail("svc")
    assert not path.exists()


@pytest.mark.asyncio
async def test_log_tail_with_no_secrets_is_unchanged(make_supervisor):
    spec = fake_child_spec("time", enabled=False)
    child = await sup_add_disabled(make_supervisor, spec)
    sup = child["sup"]
    path = sup._log_path("time")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("ready\n")
    assert "ready" in sup.log_tail("time")


async def sup_add_disabled(make_supervisor, spec):
    """Register a disabled child so it lands in `_children` without spawning."""
    sup = make_supervisor()
    obj = await sup.add(spec)
    return {"sup": sup, "child": obj}


# --- Registry operations (12.8) ----------------------------------------------


@pytest.mark.asyncio
async def test_add_enabled_child_starts_it(make_supervisor):
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("time", "good"))
    assert child.status == "starting"
    assert "time" in [s.namespace for s in sup.registry.list()]
    await child.task


@pytest.mark.asyncio
async def test_add_disabled_child(make_supervisor):
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("time", "good", enabled=False))
    assert child.status == "stopped"
    assert "time" in [s.namespace for s in sup.registry.list()]


@pytest.mark.asyncio
async def test_update_restarts_a_running_child(make_supervisor):
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("time", "good"))
    await child.task
    assert child.status == "running"
    new = ServerSpec(
        namespace="time",
        kind="custom",
        command=child.spec.command,
        args=[*child.spec.args, "--flag-ignored"],
    )
    updated = await sup.update(new)
    assert updated.status == "starting"
    assert sup.registry.get("time").args[-1] == "--flag-ignored"
    await updated.task


@pytest.mark.asyncio
async def test_remove_requests_close_and_forgets(make_supervisor):
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("time", "good"))
    await child.task
    assert child.status == "running"
    await sup.remove("time")
    assert "time" not in [s.namespace for s in sup.registry.list()]
    with pytest.raises(KeyError):
        sup.get("time")
    assert sup.table.providers == []


@pytest.mark.asyncio
async def test_remove_during_start(make_supervisor):
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("time", "good"))
    assert child.status == "starting"
    # Remove before the probe finishes.
    await sup.remove("time")
    assert "time" not in [s.namespace for s in sup.registry.list()]
    with pytest.raises(KeyError):
        sup.get("time")


# --- Child lifecycle transitions (12.9) --------------------------------------


@pytest.mark.asyncio
async def test_restart_from_failed(make_supervisor):
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("broken", "fail"))
    await child.task
    assert child.status == "failed"
    await sup.restart("broken")
    assert child.status == "starting"
    await child.task
    assert child.status in ("running", "failed")


@pytest.mark.asyncio
async def test_enable_sets_starting(make_supervisor):
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("time", "good", enabled=False))
    assert child.status == "stopped"
    await sup.enable("time")
    assert child.status == "starting"
    await child.task


@pytest.mark.asyncio
async def test_enable_of_a_running_child_is_a_noop(make_supervisor):
    # Regression: enable had no status guard, so a second enable ran
    # `_run_start` again over the live child, overwriting `child.transport`
    # and appending a duplicate provider. The old transport and its
    # subprocess leaked. enable is now idempotent: a non-`stopped` child is
    # left untouched.
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("time", "good"))
    await child.task
    assert child.status == "running"
    transport = child.transport
    provider = child.provider
    provider_count = len(sup.table.providers)

    await sup.enable("time")

    assert child.status == "running"
    assert child.task is None  # no second start task
    assert child.transport is transport  # same handle, nothing leaked
    assert child.provider is provider
    assert len(sup.table.providers) == provider_count  # no duplicate provider


@pytest.mark.asyncio
async def test_restart_of_a_disabled_child(make_supervisor):
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("time", "good", enabled=False))
    assert child.status == "stopped"
    with pytest.raises(RegistryError):
        await sup.restart("time")
    assert child.status == "stopped"


# --- Failure isolation and mount table (12.10) -------------------------------


@pytest.mark.asyncio
async def test_one_of_two_children_fails(make_supervisor, tmp_path):
    brk = tmp_path / "a_break"
    sup = make_supervisor()
    # Child `a` runs the real transport; while `brk` exists its `tools/list`
    # raises, so the probe fails through the owned client (no transport swap:
    # the read borrows `session.client`, not `child.transport`).
    a = await sup.add(fake_child_spec("a", "action", env={"MCPFLOW_BREAK": str(brk)}))
    b = await sup.add(fake_child_spec("b", "good"))
    # Capture the task refs before awaiting: a finished start clears child.task
    # to None (the in-flight task, else None).
    a_task, b_task = a.task, b.task
    await a_task
    await b_task
    assert a.status == "running" and b.status == "running"
    assert len(sup.table.providers) == 2
    # Child a's connection breaks: any list_tools on it now raises.
    brk.write_text("")
    views = await sup.tools()
    assert a.status == "failed"
    assert b.status == "running"
    # The gateway keeps serving b's tools.
    assert any(v.namespace == "b" for v in views)
    assert all(v.namespace != "a" for v in views)
    assert len(sup.table.providers) == 1


@pytest.mark.asyncio
async def test_provider_added_after_probe(make_supervisor):
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("time", "good"))
    await child.task
    assert child.status == "running"
    assert child.provider is not None
    assert len(sup.table.providers) == 1


@pytest.mark.asyncio
async def test_provider_removed_on_stop(make_supervisor):
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("time", "good"))
    await child.task
    assert len(sup.table.providers) == 1
    await sup.disable("time")
    assert child.status == "stopped"
    assert sup.table.providers == []
    assert child.transport is None


def test_read_tail_matches_whole_file_read(tmp_path):
    """P2 backward reader must match the naive whole-file tail, incl. edges."""
    from mcpflow.supervisor import _read_tail

    p = tmp_path / "big.log"
    # 500 lines, last one without a trailing newline (edge case).
    body = "".join(f"line {i}\n" for i in range(499)) + "line 499"
    p.write_text(body)

    def naive(n):
        return "".join(p.read_text(errors="replace").splitlines(keepends=True)[-n:])

    for n in (1, 10, 100, 499, 500, 1000):
        assert _read_tail(p, n) == naive(n), f"mismatch at n={n}"
    assert _read_tail(p, 0) == ""


class _RaisingTransport:
    """A transport whose close raises. `exc` is the class to raise."""

    def __init__(self, exc):
        self._exc = exc

    async def close(self):
        raise self._exc()


class _Boom(BaseException):
    """A `BaseException` that is neither `Exception` nor `CancelledError`."""


async def _raise_boom(*_args):
    raise _Boom


@pytest.mark.asyncio
@pytest.mark.parametrize("where", ["task", "drain", "client_exit", "client_exit_early"])
async def test_teardown_releases_everything_when_a_base_exception_escapes(
    make_supervisor, where
):
    """teardown-release-on-base-exception: a `BaseException` raised before the
    close still propagates, but only after the teardown unpublished the
    provider, exited the owned client, closed the transport (and the log
    handle it owns), and closed the generation. Before, it escaped with the
    transport, the process, and the log handle still held."""
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("time", "good"))
    await child.task
    assert child.status == "running"
    transport, session, provider = child.transport, child.session, child.provider
    client = session.client
    real_exit = type(client).__aexit__
    exited: list[bool] = []

    async def spy_exit(*args):
        exited.append(True)
        if where == "client_exit":
            await real_exit(client, None, None, None)  # stop the session task
            raise _Boom
        if where == "client_exit_early":
            raise _Boom  # before the exit released anything (codex round 3)
        return await real_exit(client, *args)

    client.__aexit__ = spy_exit
    if where == "task":
        child.task = asyncio.create_task(_raise_boom())
        await asyncio.sleep(0)  # let it raise; a cancel before its first step would win
    elif where == "drain":
        # One lease held: the drain is waiting when it raises, so the close
        # runs with the lease still held, before the bound (design gate F1).
        session.acquire()
        session.idle.wait = _raise_boom

    with pytest.raises(_Boom):
        await sup._teardown(child)

    assert provider not in sup.table.providers
    assert exited == [True]  # the owned client exited on every path (gate F2)
    assert child.transport is None
    assert transport.log.closed
    assert session.state == "closed"
    assert child.session is None
    assert child.task is None
    if where == "client_exit_early":
        # The transport close ran anyway; now run the skipped exit so the
        # owned client's session task stops before the fixture's loop closes.
        del client.__aexit__
        await client.__aexit__(None, None, None)


@pytest.mark.asyncio
@pytest.mark.parametrize("exc", [RuntimeError, asyncio.CancelledError])
async def test_disable_completes_when_close_raises_ordinary_or_cancelled(
    make_supervisor, exc
):
    """`_teardown` swallows `Exception` and `CancelledError`, so `disable`
    reaches its status assignment and the handle is dropped regardless."""
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("time", "good"))
    await child.task
    child.transport.log.close()  # the stub below drops the real transport
    child.transport = _RaisingTransport(exc)

    await sup.disable("time")

    assert child.status == "stopped"
    assert sup.table.providers == []
    assert child.transport is None
    assert sup.registry.get("time").enabled is False


@pytest.mark.asyncio
async def test_disable_leaves_the_handle_when_close_raises_baseexception(
    make_supervisor,
):
    """Another `BaseException` escapes `_teardown` before it clears the
    handle, so `disable` never reaches its status assignment: the transport
    stays installed and the status stays `running`. The registry write has
    already landed, because `disable` persists before it tears down."""

    class Boom(BaseException):
        pass

    sup = make_supervisor()
    child = await sup.add(fake_child_spec("time", "good"))
    await child.task
    child.transport.log.close()  # the stub below drops the real transport
    child.transport = _RaisingTransport(Boom)

    with pytest.raises(Boom):
        await sup.disable("time")

    assert child.status == "running"
    assert child.transport is not None
    # The provider is released before the close, so it is already gone.
    assert sup.table.providers == []
    assert sup.registry.get("time").enabled is False

    # Drop the raising transport, or the fixture's shutdown re-raises it.
    child.transport = None


# --- OAuth: enable needs a token, remove cleans creds (oauth-connect 5.2/5.3)


@pytest.mark.asyncio
async def test_enable_refuses_awaiting(make_supervisor):
    sup = make_supervisor(fake_child_spec("gmail", "good", enabled=False))
    sup.creds.write_client("gmail", "google-client", _CREDS)
    with pytest.raises(RegistryError) as exc:
        await sup.enable("gmail")
    assert "gmail" in str(exc.value) and "awaits authorization" in str(exc.value)
    assert sup.get("gmail").status == "stopped"


@pytest.mark.asyncio
async def test_update_refuses_awaiting(make_supervisor):
    sup = make_supervisor(fake_child_spec("gmail", "good", enabled=False))
    sup.creds.write_client("gmail", "google-client", _CREDS)
    spec = fake_child_spec("gmail", "good", enabled=True)
    with pytest.raises(RegistryError) as exc:
        await sup.update(spec)
    assert "awaits authorization" in str(exc.value)
    assert sup.registry.get("gmail").enabled is False


@pytest.mark.asyncio
async def test_add_refuses_awaiting(make_supervisor):
    sup = make_supervisor()
    sup.creds.write_client("gmail", "google-client", _CREDS)
    with pytest.raises(RegistryError) as exc:
        await sup.add(fake_child_spec("gmail", "good", enabled=True))
    assert "awaits authorization" in str(exc.value)


@pytest.mark.asyncio
async def test_enable_after_token_exists(make_supervisor):
    sup = make_supervisor(fake_child_spec("gmail", "good", enabled=False))
    sup.creds.write_client("gmail", "google-client", _CREDS)
    sup.creds.write_token("gmail", "google-auth-library", _TOKENS)
    await sup.enable("gmail")
    child = sup.get("gmail")
    if child.task is not None:
        await child.task
    assert child.status == "running"


@pytest.mark.asyncio
async def test_remove_deletes_creds_and_flow(make_supervisor):
    sup = make_supervisor(fake_child_spec("gmail", "good", enabled=False))
    sup.creds.write_client("gmail", "google-client", _CREDS)
    sup.creds.write_token("gmail", "google-auth-library", _TOKENS)
    flow = sup.flows.create("gmail", "gmail", _CREDS)
    assert (sup.creds.root / "gmail").exists()
    await sup.remove("gmail")
    assert not (sup.creds.root / "gmail").exists()
    assert sup.flows.pop(flow.state) is None


@pytest.mark.asyncio
async def test_remove_without_creds_ok(make_supervisor):
    sup = make_supervisor(fake_child_spec("gmail", "good", enabled=False))
    await sup.remove("gmail")  # no creds, no error
    assert "gmail" not in [s.namespace for s in sup.registry.list()]


@pytest.mark.asyncio
async def test_finish_oauth_success(make_supervisor):
    sup = make_supervisor(fake_child_spec("gmail", "good", enabled=False))
    sup.creds.write_client("gmail", "google-client", _CREDS)
    flow = sup.flows.create("gmail", "gmail", _CREDS)
    ok = await sup.finish_oauth(flow, "google-auth-library", _TOKENS)
    assert ok is True
    assert sup.creds.has_token("gmail")
    assert sup.flows.pop(flow.state) is None  # consumed
    child = sup.get("gmail")
    if child.task is not None:
        await child.task
    assert child.status == "running"


@pytest.mark.asyncio
async def test_finish_oauth_rejects_when_removed(make_supervisor):
    # A delete during the token exchange: finish_oauth must write nothing.
    sup = make_supervisor(fake_child_spec("gmail", "good", enabled=False))
    sup.creds.write_client("gmail", "google-client", _CREDS)
    flow = sup.flows.create("gmail", "gmail", _CREDS)
    await sup.remove("gmail")  # discards the flow, removes creds
    ok = await sup.finish_oauth(flow, "google-auth-library", _TOKENS)
    assert ok is False
    assert not (sup.creds.root / "gmail").exists()
    assert "gmail" not in [s.namespace for s in sup.registry.list()]


_NEW_TOKENS = {
    "access_token": "new-access", "refresh_token": "new-refresh", "scope": "s",
    "token_type": "Bearer", "expires_in": 3600,
}


async def _connected_running(sup):
    """An enabled, running, authorized `gmail` child."""
    child = await sup.add(fake_child_spec("gmail", "good", enabled=True, catalog="gmail"))
    if child.task is not None:
        await child.task
    sup.creds.write_client("gmail", "google-client", ClientCreds("old-id", "old-secret"))
    sup.creds.write_token("gmail", "google-auth-library", _TOKENS)
    return child


@pytest.mark.asyncio
async def test_finish_oauth_reauth_writes_client_and_token(make_supervisor):
    import json

    sup = make_supervisor()
    await _connected_running(sup)
    flow = sup.flows.create("gmail", "gmail", ClientCreds("new-id", "new-secret"), reauth=True)
    ok = await sup.finish_oauth(
        flow, "google-auth-library", _NEW_TOKENS,
        client_fmt="google-client", reauth=True,
    )
    assert ok is True
    client_on_disk = json.loads(sup.creds.paths("gmail").client.read_text())
    assert client_on_disk["web"]["client_id"] == "new-id"
    token_on_disk = json.loads(sup.creds.paths("gmail").token.read_text())
    assert token_on_disk["access_token"] == "new-access"


@pytest.mark.asyncio
async def test_finish_oauth_reauth_restarts(make_supervisor):
    sup = make_supervisor()
    await _connected_running(sup)
    flow = sup.flows.create("gmail", "gmail", ClientCreds("new-id", "new-secret"), reauth=True)
    ok = await sup.finish_oauth(
        flow, "google-auth-library", _NEW_TOKENS,
        client_fmt="google-client", reauth=True,
    )
    assert ok is True
    child = sup.get("gmail")
    if child.task is not None:
        await child.task
    assert child.status == "running"
    assert sup.flows.pop(flow.state) is None  # consumed


@pytest.mark.asyncio
async def test_finish_oauth_reauth_honors_disable(make_supervisor):
    import json

    sup = make_supervisor()
    await _connected_running(sup)
    await sup.disable("gmail")  # a disable during the flow
    flow = sup.flows.create("gmail", "gmail", ClientCreds("new-id", "new-secret"), reauth=True)
    ok = await sup.finish_oauth(
        flow, "google-auth-library", _NEW_TOKENS,
        client_fmt="google-client", reauth=True,
    )
    assert ok is True
    # The new token is written, but the child stays stopped: the disable wins.
    token_on_disk = json.loads(sup.creds.paths("gmail").token.read_text())
    assert token_on_disk["access_token"] == "new-access"
    assert sup.get("gmail").status == "stopped"
    assert sup.registry.get("gmail").enabled is False


# --- header sink (remote-oauth) ----------------------------------------------


def _header_child(**over):
    return fake_child_spec(
        "linear", "good", enabled=False, catalog="linear", oauth_pending=True, **over
    )


@pytest.mark.asyncio
async def test_finish_oauth_header_sink(make_supervisor):
    sup = make_supervisor(_header_child())
    flow = sup.flows.create("linear", "linear", _CREDS)
    ok = await sup.finish_oauth(
        flow, None, {"access_token": "tok-xyz"}, header=HeaderSpec("Authorization", "Bearer")
    )
    assert ok is True
    spec = sup.registry.get("linear")
    assert spec.headers["Authorization"] == "Bearer tok-xyz"
    assert spec.oauth_pending is False
    # The header token has the same exposure as a hand-typed header: scrubbed
    # from diagnostics by scrub_secrets (a headers value, plus the token after
    # the Bearer scheme).
    from mcpflow.supervisor import scrub_secrets

    secrets = sup._secrets_of(spec)
    assert "tok-xyz" not in scrub_secrets("child error: token tok-xyz", secrets)
    child = sup.get("linear")
    if child.task is not None:
        await child.task
    assert child.status == "running"


@pytest.mark.asyncio
async def test_enable_refuses_header_pending(make_supervisor):
    sup = make_supervisor(_header_child())
    with pytest.raises(RegistryError) as exc:
        await sup.enable("linear")
    assert "awaits authorization" in str(exc.value)
    assert sup.get("linear").status == "stopped"


@pytest.mark.asyncio
async def test_update_preserves_oauth_pending(make_supervisor):
    # An edit that omits oauth_pending must neither clear it nor enable the
    # pending header child (the flag is registry-owned).
    sup = make_supervisor(_header_child())
    enabling = fake_child_spec("linear", "good", enabled=True, catalog="linear")
    with pytest.raises(RegistryError) as exc:
        await sup.update(enabling)
    assert "awaits authorization" in str(exc.value)
    assert sup.registry.get("linear").oauth_pending is True
    # A benign disabled edit is applied but still preserves the flag.
    benign = fake_child_spec("linear", "good", enabled=False, catalog="linear")
    await sup.update(benign)
    assert sup.registry.get("linear").oauth_pending is True


@pytest.mark.asyncio
async def test_finish_oauth_header_atomic_with_remove(make_supervisor):
    # A delete during the exchange: finish_oauth writes no header for a gone
    # namespace (the pop under the child lock returns None).
    sup = make_supervisor(_header_child())
    flow = sup.flows.create("linear", "linear", _CREDS)
    await sup.remove("linear")
    ok = await sup.finish_oauth(
        flow, None, {"access_token": "x"}, header=HeaderSpec("Authorization", "Bearer")
    )
    assert ok is False
    assert "linear" not in [s.namespace for s in sup.registry.list()]


# --- Child catalog freshness (child-catalog-freshness) -----------------------


def _proxy_cache_ttl(child) -> float:
    # Reads the private `ProxyProvider._cache_ttl` of FastMCP 4.0.x, under the
    # visibility and namespace wrappers. A FastMCP upgrade that renames either
    # attribute breaks this helper only; the `grow` tests in test_gateway.py
    # stay the behavioral proof.
    return child.provider._inner._inner._cache_ttl


@pytest.mark.asyncio
async def test_provider_takes_the_gateway_default(make_supervisor):
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("time", "good"))
    await child.task
    assert child.status == "running"
    assert _proxy_cache_ttl(child) == 300.0


@pytest.mark.asyncio
async def test_provider_takes_the_configured_gateway_default(make_supervisor):
    sup = make_supervisor(CHILD_CACHE_TTL="2")
    child = await sup.add(fake_child_spec("time", "good"))
    await child.task
    assert child.status == "running"
    assert _proxy_cache_ttl(child) == 2.0


@pytest.mark.asyncio
async def test_provider_takes_the_per_child_override(make_supervisor):
    sup = make_supervisor()
    child = await sup.add(fake_child_spec("skills", "good", cache_ttl=0))
    await child.task
    assert child.status == "running"
    assert _proxy_cache_ttl(child) == 0.0
