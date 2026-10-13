"""10F: ownership, approval, and the start gate (multi-user-access, section 6).

Scenarios from `specs/server-registry/spec.md` (Owner assignment at add,
Approval binds a revision, Approval gate, Ownership of a server). Guarded TLA+
invariants (`specs/tla/multi_user_access.tla`,
`specs/tla/multi_user_access_lifecycle.tla`):

- `PendingNeverRunning`: a pending server has no process and no transport.
- `PendingNeverReachable`: no reach of any user includes a pending server.
- `PublishedImpliesApproved`: a mounted provider belongs to an approved server.
- `RunningSpecWasReviewed`: the running spec is the revision the admin read; a
  stale approval raises `RevisionConflict` and changes nothing.
- `ApprovalCoversCurrentSpec`: an approved record has no un-reviewed edit.
- `ApprovedEventuallyRuns`: an approval that stands reaches `running`.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from conftest import ADMIN_ACTOR, fake_child_spec
from dashboard_site import groups_on_page, make_mu_site  # noqa: F401
from user_servers import (
    ADMIN,
    ALICE,
    BOB,
    GH_ALICE,
    Env,
    Listener,
    fake_npx,
    npm_spec,
    path_with,
    wait_status,
)

from mcpflow.api import child_json
from mcpflow.policy import GrantRule
from mcpflow.registry import (
    SECRET_MASK,
    Registry,
    RegistryError,
    ServerKey,
    ServerSpec,
    redact_spec,
    revision,
)
from mcpflow.supervisor import RevisionConflict

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def env(tmp_path):
    e = Env(tmp_path / "data")
    yield e
    await e.close()


@pytest.fixture
def npx(tmp_path, monkeypatch):
    log = fake_npx(tmp_path / "bin")
    monkeypatch.setenv("PATH", path_with(tmp_path / "bin"))
    return log


@pytest.fixture
def slow_npx(tmp_path, monkeypatch):
    log = fake_npx(tmp_path / "bin", mode="slow")
    monkeypatch.setenv("PATH", path_with(tmp_path / "bin"))
    return log


def _mounted(env: Env, key: ServerKey) -> bool:
    """True when the supervisor routes a provider for `key` to the admin."""
    reach = env.policy.keys_for(ADMIN, "dashboard")
    return any(k == key for k, _p in env.sup.routed(reach))


async def _approved_running(env: Env, spec: ServerSpec) -> None:
    await env.sup.add(spec, ALICE)
    await env.sup.approve(GH_ALICE, revision(env.stored()), ADMIN_ACTOR)
    await wait_status(env.sup, GH_ALICE, {"running"})


# --- Owner assignment at add -------------------------------------------------


async def test_a_user_adds_a_server(env, npx):
    """`alice` adds a body that claims `actions`, a catalog, owner `bob`, and an
    approval. Guards `PendingNeverRunning` and the registry-owned fields."""
    body = npm_spec(package="x@1.0.0", actions=True, catalog="evil",
                    owner="bob", approved_revision="f" * 64)
    await env.sup.add(body, ALICE)
    stored = env.stored()
    assert stored.owner == "alice"
    assert stored.approved_revision is None
    assert stored.actions is False
    assert stored.catalog is None
    assert stored.approval == "pending"
    assert {s.key for s in env.reg.list()} == {GH_ALICE}
    assert env.sup.get(GH_ALICE).status == "stopped"
    recs = json.loads((env.dir / "user_servers.json").read_text())
    assert "bob" not in json.dumps(recs)
    assert not npx.exists()


async def test_an_admin_adds_a_server(env):
    """An admin add is admin-owned and approved by construction."""
    await env.sup.add(fake_child_spec("time"), ADMIN)
    stored = env.reg.get(ServerKey(None, "time"))
    assert stored.owner is None
    assert stored.approval == "approved"
    on_disk = json.loads((env.dir / "servers.json").read_text())
    assert "time" in json.dumps(on_disk)
    assert env.sup.get(ServerKey(None, "time")).status in {"starting", "running"}
    await wait_status(env.sup, ServerKey(None, "time"), {"running"})


async def test_a_new_server_inherits_no_rule(env):
    """A stale allow for `bob` on `github@alice` is dropped by the re-add."""
    # The residue of a removed server: `add_rule` refuses an unknown server,
    # so the rule enters through the frozen `RuleStore.add`.
    env.rules.add(GrantRule(id="stale", subject_kind="user", subject="bob",
                            level="server", server="github@alice", tool=None,
                            effect="allow", created_at=datetime.now(UTC)))
    assert any(r.server == "github@alice" for r in env.rules.list())
    await env.sup.add(npm_spec(), ALICE)
    assert not any(r.server == "github@alice" for r in env.rules.list())
    text = (env.dir / "rules.json").read_text()
    assert "github@alice" not in text


async def test_a_duplicate_add_keeps_the_rules_of_the_live_server(env):
    """Design D8b: the purge runs only after the key proves free."""
    await env.sup.add(npm_spec(), ALICE)
    rule = env.policy.add_rule(ADMIN, subject_kind="user", subject="bob",
                               level="server", server="github@alice", tool=None,
                               effect="allow")
    with pytest.raises(RegistryError):
        await env.sup.add(npm_spec(), ALICE)
    assert rule.id in {r.id for r in env.rules.list()}
    assert rule.id in (env.dir / "rules.json").read_text()


# --- Approval binds a revision -----------------------------------------------


async def test_approval_starts_the_server(env, npx):
    """AC-5. Guards `ApprovedEventuallyRuns` and `PublishedImpliesApproved`."""
    await env.sup.add(npm_spec(), ALICE)
    assert not _mounted(env, GH_ALICE)
    await env.sup.approve(GH_ALICE, revision(env.stored()), ADMIN_ACTOR)
    assert env.stored().approval == "approved"
    assert env.sup.get(GH_ALICE).status == "starting"
    await wait_status(env.sup, GH_ALICE, {"running"})
    assert _mounted(env, GH_ALICE)
    assert npx.read_text().split() == ["-y", "@acme/mcp@1.2.3"]


async def test_a_stale_approval_is_refused(env, npx):
    """F1. Guards `RunningSpecWasReviewed`: approve with R1 after an `args`
    edit raises `RevisionConflict` and changes nothing."""
    await env.sup.add(npm_spec(), ALICE)
    r1 = revision(env.stored())
    await env.sup.update(GH_ALICE, npm_spec(args=["--evil"]), ADMIN_ACTOR)
    before = (env.dir / "user_servers.json").read_bytes()
    with pytest.raises(RevisionConflict):
        await env.sup.approve(GH_ALICE, r1, ADMIN_ACTOR)
    assert (env.dir / "user_servers.json").read_bytes() == before
    assert env.stored().approved_revision is None
    assert env.stored().approval == "pending"
    child = env.sup.get(GH_ALICE)
    assert child.status == "stopped"
    assert child.transport is None and child.provider is None
    await asyncio.sleep(0.5)
    assert not npx.exists(), "a stale approval started a process"
    # The current revision is approved and runs (the review saw `--evil`).
    await env.sup.approve(GH_ALICE, revision(env.stored()), ADMIN_ACTOR)
    await wait_status(env.sup, GH_ALICE, {"running"})
    assert "--evil" in npx.read_text()


@pytest.mark.parametrize("edit", [
    {"args": ["--x"]},
    {"package": "@acme/mcp@1.2.4"},
    {"env": {"API_KEY": "k"}},
])
async def test_an_owner_edit_needs_a_new_approval(env, npx, edit):
    """Guards `ApprovalCoversCurrentSpec` and `PendingNeverRunning`."""
    await _approved_running(env, npm_spec())
    await env.sup.update(GH_ALICE, npm_spec(**edit), ADMIN_ACTOR)
    assert env.stored().approval == "pending"
    child = env.sup.get(GH_ALICE)
    assert child.status == "stopped"
    assert child.provider is None and child.transport is None
    assert not _mounted(env, GH_ALICE)
    await asyncio.sleep(0.5)
    assert env.sup.get(GH_ALICE).status == "stopped"
    assert len(npx.read_text().splitlines()) == 1


async def test_a_description_edit_keeps_the_approval(env, npx):
    await _approved_running(env, npm_spec())
    approved = env.stored().approved_revision
    await env.sup.update(GH_ALICE, npm_spec(description="new text"), ADMIN_ACTOR)
    assert env.stored().approval == "approved"
    assert env.stored().approved_revision == approved
    assert env.stored().description == "new text"
    await wait_status(env.sup, GH_ALICE, {"running"})
    # The child restarted: the fake npx ran a second time.
    assert len(npx.read_text().splitlines()) == 2


async def test_a_mute_keeps_the_approval(env, npx):
    await _approved_running(env, npm_spec())
    approved = env.stored().approved_revision
    env.sup.set_tool_muted(GH_ALICE, "get_current_time", True, ADMIN_ACTOR)
    env.sup.set_namespace_muted(GH_ALICE, True, ADMIN_ACTOR)
    assert env.stored().approval == "approved"
    assert env.stored().approved_revision == approved
    await asyncio.sleep(0.3)
    assert env.sup.get(GH_ALICE).status == "running"
    assert len(npx.read_text().splitlines()) == 1



# --- Masked echo (redact-registry-secrets x approval) ------------------------


async def test_a_masked_echo_keeps_the_approval(env, npx):
    """A client reads the masked record and PUTs it back unchanged. The
    write-back restores the stored secrets BEFORE the revision is read, so the
    round trip keeps the approval, restarts the server, and stores no mask.
    Guards `ApprovalCoversCurrentSpec` against the write-back rule."""
    await _approved_running(env, npm_spec(env={"API_KEY": "sk-live-secret-1"}))
    stored = env.stored()
    shown = child_json(env.sup.get(GH_ALICE))
    assert shown["env"] == {"API_KEY": SECRET_MASK}
    assert "sk-live-secret-1" not in str(shown)
    # The revision a client reads is the stored one, never the masked form's.
    assert shown["revision"] == revision(stored)
    await env.sup.update(GH_ALICE, redact_spec(stored), ADMIN_ACTOR)
    after = env.stored()
    assert after.env == {"API_KEY": "sk-live-secret-1"}
    assert revision(after) == revision(stored)
    assert after.approved_revision == stored.approved_revision
    assert after.approval == "approved"
    await wait_status(env.sup, GH_ALICE, {"running"})
    assert len(npx.read_text().splitlines()) == 2


async def test_a_masked_echo_keeps_the_revision_of_a_remote_server(tmp_path):
    """The same property at the registry, over every masked field of a
    remote server: url user information, a url query value, and a header."""
    reg = Registry(tmp_path / "servers.json", tmp_path / "user_servers.json")
    reg.load()
    key = ServerKey("alice", "quiver")
    reg.add(ServerSpec(
        namespace="quiver", owner="alice", kind="remote",
        url="https://u:pw-secret-1@api.example.com/mcp?token=tok-secret-2",
        headers={"Authorization": "Bearer hdr-secret-3"},
    ))
    stored = reg.get(key)
    reg.set_approved_revision(key, revision(stored))
    stored = reg.get(key)
    masked = redact_spec(stored)
    for secret in ("pw-secret-1", "tok-secret-2", "hdr-secret-3"):
        assert secret not in masked.model_dump_json()
    reg.update(masked.model_copy(update={"approved_revision": None}))
    after = reg.get(key)
    assert after.url == stored.url and after.headers == stored.headers
    assert revision(after) == revision(stored)
    assert after.approval == "approved"
    on_disk = (tmp_path / "user_servers.json").read_text()
    assert SECRET_MASK not in on_disk



async def test_a_secret_edit_discards_the_own_log_before_the_write(env):
    """stale-log-discard-order in the key model: an edit that changes the
    secret set discards `logs/<ref>.log` BEFORE `user_servers.json` is
    written, and never touches the log of the same namespace under another
    owner."""
    await env.sup.add(npm_spec(env={"API_KEY": "old-secret-value-xyz"},
                               enabled=False), ALICE)
    own = env.sup._log_path(GH_ALICE)
    other = env.sup._log_path(ServerKey(None, "github"))
    assert own.name == "github@alice.log" and other.name == "github.log"
    own.write_text("boom with old-secret-value-xyz\n")
    other.write_text("admin output\n")
    seen: list[bool] = []
    real = env.reg._write_user

    def spy(specs):
        seen.append(own.exists())
        real(specs)

    env.reg._write_user = spy
    await env.sup.update(GH_ALICE, npm_spec(env={"API_KEY": "new-secret-value-xyz"},
                                            enabled=False), ADMIN_ACTOR)
    assert seen == [False]
    assert other.read_text() == "admin output\n"


# --- Approval gate -----------------------------------------------------------


async def test_a_user_npm_server_waits_for_approval(env, npx):
    """AC-5. Guards `PendingNeverRunning` and `PendingNeverReachable`."""
    await env.sup.add(npm_spec(), ALICE)
    assert env.stored().approval == "pending"
    child = env.sup.get(GH_ALICE)
    assert child.status == "stopped"
    assert child.transport is None and child.provider is None
    assert child.task is None or child.task.done()
    await asyncio.sleep(0.5)
    assert not npx.exists(), "a pending npm server ran a process"
    for user in (ADMIN, ALICE, BOB):
        for surface in ("mcp", "dashboard"):
            routed = env.sup.routed(env.policy.keys_for(user, surface))
            assert GH_ALICE not in {k for k, _p in routed}


async def test_a_pending_remote_server_makes_no_request(env):
    """AC-5b. A pending `remote` server has no transport: zero connections
    reach its URL until the admin approves it. Guards `PendingNeverRunning`."""
    async with Listener() as fake:
        spec = ServerSpec(namespace="github", kind="remote", url=fake.url)
        await env.sup.add(spec, ALICE)
        with pytest.raises(RegistryError):
            await env.sup.enable(GH_ALICE, ADMIN_ACTOR)
        with pytest.raises(RegistryError):
            await env.sup.restart(GH_ALICE, ADMIN_ACTOR)
        for user in (ADMIN, ALICE):
            await env.sup.tools(env.policy.keys_for(user, "mcp"))
            await env.sup.tools(env.policy.keys_for(user, "dashboard"))
        await asyncio.sleep(0.5)
        assert fake.connections == 0
        assert env.sup.get(GH_ALICE).status == "stopped"
        # Control: the approval opens the first connection.
        await env.sup.approve(GH_ALICE, revision(env.stored()), ADMIN_ACTOR)
        for _ in range(200):
            if fake.connections:
                break
            await asyncio.sleep(0.05)
        assert fake.connections > 0


async def test_an_edit_during_the_start_cancels_it(env, slow_npx, tmp_path):
    """F7b, through the real start path (`approve` -> `_begin_start`).
    Guards `PublishedImpliesApproved`: the start of the old revision never
    mounts a provider after the edit, even when its process becomes ready."""
    await env.sup.add(npm_spec(), ALICE)
    await env.sup.approve(GH_ALICE, revision(env.stored()), ADMIN_ACTOR)
    for _ in range(200):  # the process is up and blocked on its release file
        if slow_npx.exists():
            break
        await asyncio.sleep(0.05)
    assert slow_npx.exists()
    assert env.sup.get(GH_ALICE).status == "starting"
    await env.sup.update(GH_ALICE, npm_spec(args=["--evil"]), ADMIN_ACTOR)
    child = env.sup.get(GH_ALICE)
    assert child.status == "stopped"
    assert child.task is None or child.task.done()
    assert child.provider is None
    assert not _mounted(env, GH_ALICE)
    assert env.stored().approval == "pending"
    (tmp_path / "bin" / "release").write_text("go")
    await asyncio.sleep(1.5)
    child = env.sup.get(GH_ALICE)
    assert child.status == "stopped"
    assert child.provider is None
    assert not _mounted(env, GH_ALICE)


async def test_enable_of_a_pending_server_is_refused(env, npx):
    await env.sup.add(npm_spec(enabled=False), ALICE)
    with pytest.raises(RegistryError, match="awaits approval"):
        await env.sup.enable(GH_ALICE, ADMIN_ACTOR)
    assert env.sup.get(GH_ALICE).status == "stopped"
    await asyncio.sleep(0.3)
    assert not npx.exists()


async def test_restart_of_a_stopped_pending_child_raises(env, npx):
    await env.sup.add(npm_spec(), ALICE)
    with pytest.raises(RegistryError, match="github@alice awaits approval"):
        await env.sup.restart(GH_ALICE, ADMIN_ACTOR)
    assert env.sup.get(GH_ALICE).status == "stopped"
    assert not npx.exists()


async def test_a_restart_keeps_pending_servers_down(tmp_path, npx):
    """A fresh process reads `user_servers.json` with pending, enabled
    `github@alice`; `startup` leaves it stopped. Guards `PendingNeverRunning`."""
    data = tmp_path / "data"
    first = Env(data)
    await first.sup.add(npm_spec(), ALICE)
    await first.sup.add(fake_child_spec("time"), ADMIN)
    await first.close()
    assert first.stored().enabled is True
    env = Env(data)
    try:
        await env.sup.startup()
        await wait_status(env.sup, ServerKey(None, "time"), {"running"})
        assert env.sup.get(GH_ALICE).status == "stopped"
        await asyncio.sleep(0.3)
        assert not npx.exists()
    finally:
        await env.close()


# --- Ownership of a server (AC-6) --------------------------------------------


async def test_a_non_owner_cannot_manage_a_server(env, npx):
    """AC-6, policy part (3.12): only the owner and an admin manage."""
    await env.sup.add(npm_spec(), ALICE)
    assert env.policy.can_manage(ALICE, GH_ALICE)
    assert env.policy.can_manage(ADMIN, GH_ALICE)
    assert not env.policy.can_manage(BOB, GH_ALICE)
    assert not env.policy.can_manage(BOB, ServerKey(None, "github"))


def test_a_non_owner_cannot_manage_a_server_over_http(make_mu_site):
    """AC-6, HTTP part (7.2): `bob` gets 404 on every action of `github@alice`
    and the child is untouched."""
    site = make_mu_site()
    before = site.launches()
    for method, path in (("GET", "/servers/github@alice"),
                         ("POST", "/servers/github@alice/restart"),
                         ("POST", "/servers/github@alice/disable"),
                         ("POST", "/servers/github@alice/delete")):
        assert site.request("bob", method, path).status_code == 404, (method, path)
    assert site.status(GH_ALICE) == "running"
    assert site.launches() == before


async def test_a_non_owner_does_not_see_the_server_in_lists(env, npx):
    """AC-6, Reach part (3.10, 4.6): `bob` has no rule for `github@alice`."""
    await _approved_running(env, npm_spec())
    for surface in ("mcp", "dashboard"):
        reach = env.policy.keys_for(BOB, surface)
        assert GH_ALICE not in reach.keys
        assert GH_ALICE not in {k for k, _p in env.sup.routed(reach)}
        assert "github@alice" not in {t.ref for t in await env.sup.tools(reach)}
    admin = env.policy.keys_for(ADMIN, "dashboard")
    assert "github@alice" in {t.ref for t in await env.sup.tools(admin)}


def test_a_non_owner_does_not_see_the_server_on_the_page(make_mu_site):
    """AC-6, page part (7.4): the `/` page of `bob` lists no `github@alice`."""
    site = make_mu_site()
    page = site.request("bob", "GET", "/tools/tree")
    assert page.status_code == 200
    assert groups_on_page(page.text) == ["github@bob"]
    assert "github@alice" not in page.text


async def test_an_owner_cannot_grant_trust_to_a_server(env):
    """10.24b: `actions`, `catalog`, `owner`, and `approved_revision` are
    registry-owned; an owner update cannot set them."""
    await env.sup.add(npm_spec(enabled=False), ALICE)
    assert env.stored().actions is False
    await env.sup.approve(GH_ALICE, revision(env.stored()), ADMIN_ACTOR)
    approved = env.stored().approved_revision
    await env.sup.update(GH_ALICE, npm_spec(
        enabled=False, actions=True, catalog="x", owner="bob",
        approved_revision="f" * 64), ADMIN_ACTOR)
    stored = env.stored()
    assert stored.actions is False
    assert stored.catalog is None
    assert stored.owner == "alice"
    assert stored.approved_revision == approved
    assert stored.approval == "approved"
    assert {s.key for s in env.reg.list()} == {GH_ALICE}

