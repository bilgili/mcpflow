"""bound-user-writes: per-user caps and the approval memo.

Scenarios from `openspec/changes/bound-user-writes/specs/` (server-registry:
Per-user server limit, The approval read computes the revision once for each
stored record; auth: Per-user token limit; mcp-gateway: Per-user limit
settings) and the frozen interfaces in `design.md` ("Design gate", round 4).
The expectations come from the spec text, not from the implementation.

Guarded TLA+ properties (`specs/tla/bound_user_writes.tla`): `ServerCapStep`,
`TokenCapStep`, `ApprovalExact`. `MemoFresh` is no longer a design invariant
(round 3: a snapshot keys the memo, so no hook drops it). Guarded negative
configs of the model: `_noservercap` (5.1), `_notokencap` /
`_adminmintsforuser` (5.2), `_copykeepsmemo` / `_assignkeepsmemo` (5.4),
`_unkeyedmemo` (5.6: a pair reused with no compare of the values),
`_aliasedsnapshot` (5.6: a snapshot that shares a container with the record),
`_untypedsnapshot` (5.6: a pair kept for an out-of-type value).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import ADMIN_ACTOR, make_user
from dashboard_site import make_mu_site  # noqa: F401

from mcpflow import registry
from mcpflow.auth import DEFAULT_MAX_USER_TOKENS, TokenStore, hash_password
from mcpflow.config import ConfigError, load_settings
from mcpflow.identity import LocalIdentityProvider
from mcpflow.policy import AccessPolicy, RuleStore
from mcpflow.registry import (
    DEFAULT_MAX_USER_SERVERS,
    REVISION_FIELDS,
    SECRET_MASK,
    Registry,
    RegistryError,
    ServerKey,
    ServerSpec,
    redact_spec,
    revision,
)

SHA = "0123456789abcdef0123456789abcdef01234567"


# --- helpers ------------------------------------------------------------------


def _remote(ns: str, owner: str | None = "alice", **extra) -> ServerSpec:
    """A user-owned `remote` spec passes the pin rule with no version."""
    return ServerSpec(namespace=ns, kind="remote", url="http://127.0.0.1:9/mcp",
                      owner=owner, **extra)


def _registry(tmp_path: Path, cap: int | None = None) -> Registry:
    kw = {} if cap is None else {"max_user_servers": cap}
    reg = Registry(tmp_path / "servers.json", tmp_path / "user_servers.json", **kw)
    reg.load()
    return reg


def _bytes(tmp_path: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in sorted(tmp_path.glob("*.json"))}


def _world(tmp_path: Path, *, servers: int | None = None, tokens: int | None = None):
    ident = LocalIdentityProvider(
        tmp_path / "users.json", hash_password("pw", iterations=1000)
    )
    ident.load()
    for uid in ("alice", "bob"):
        make_user(ident, uid, "pw")
    tkw = {} if tokens is None else {"max_user_tokens": tokens}
    store = TokenStore(tmp_path / "tokens.json", tmp_path / "user_tokens.json", **tkw)
    store.load()
    reg = _registry(tmp_path, servers)
    rules = RuleStore(tmp_path / "rules.json")
    rules.load()
    return SimpleNamespace(
        policy=AccessPolicy(ident, rules, store, reg), tokens=store, reg=reg,
        root=ident.get_user("admin"), alice=ident.get_user("alice"),
        bob=ident.get_user("bob"),
    )


def test_default_constants():
    assert DEFAULT_MAX_USER_SERVERS == 20
    assert DEFAULT_MAX_USER_TOKENS == 10


# --- 5.1 server limit ---------------------------------------------------------


def test_a_user_at_the_server_limit_is_refused_and_no_file_changes(tmp_path):
    reg = _registry(tmp_path, 2)
    reg.add(_remote("one"))
    reg.add(_remote("two"))
    before = _bytes(tmp_path)
    with pytest.raises(RegistryError) as exc:
        reg.add(_remote("three"))
    assert isinstance(exc.value, ValueError)  # the one error map answers 400
    text = str(exc.value)
    assert text.startswith("limit:")
    assert "MAX_USER_SERVERS" in text and "2" in text
    assert _bytes(tmp_path) == before
    assert [s.namespace for s in reg.list()] == ["one", "two"]


def test_the_server_default_cap_is_20(tmp_path):
    reg = _registry(tmp_path)  # no keyword: the default applies
    for i in range(20):
        reg.add(_remote(f"s{i}"))
    with pytest.raises(RegistryError, match=r"^limit: .*MAX_USER_SERVERS.*20"):
        reg.add(_remote("extra"))


def test_the_server_limit_counts_each_owner_separately(tmp_path):
    reg = _registry(tmp_path, 1)
    reg.add(_remote("github", "alice"))
    reg.add(_remote("github", "bob"))  # bob owns none, so he adds
    assert {s.key for s in reg.list()} == {
        ServerKey("alice", "github"), ServerKey("bob", "github")}
    with pytest.raises(RegistryError, match="^limit:"):
        reg.add(_remote("other", "bob"))


def test_an_admin_write_is_exempt_from_the_server_limit(tmp_path):
    reg = _registry(tmp_path, 0)
    reg.add(ServerSpec(namespace="time", kind="npm", package="@acme/time@1.0.0"))
    assert "time" in (tmp_path / "servers.json").read_text()
    # An admin-owned record is not counted against a user either way.
    with pytest.raises(RegistryError, match="^limit:"):
        reg.add(_remote("mine"))


def test_a_removal_frees_a_server_place(tmp_path):
    reg = _registry(tmp_path, 1)
    reg.add(_remote("github"))
    with pytest.raises(RegistryError, match="^limit:"):
        reg.add(_remote("other"))
    reg.remove(ServerKey("alice", "github"))
    reg.add(_remote("other"))
    assert [s.namespace for s in reg.list()] == ["other"]


def test_a_user_servers_file_above_the_limit_loads(tmp_path):
    seed = _registry(tmp_path, 10)
    for ns in ("a1", "b1", "c1"):
        seed.add(_remote(ns, "alice"))
    reg = _registry(tmp_path, 1)  # `load` ran in the helper and did not raise
    assert {s.namespace for s in reg.list()} == {"a1", "b1", "c1"}
    before = _bytes(tmp_path)
    with pytest.raises(RegistryError, match="^limit:"):
        reg.add(_remote("d1", "alice"))
    assert _bytes(tmp_path) == before
    reg.add(_remote("d1", "bob"))  # another owner is not blocked


def test_a_duplicate_key_at_the_limit_reports_already_exists(tmp_path):
    reg = _registry(tmp_path, 1)
    reg.add(_remote("github"))
    with pytest.raises(RegistryError) as exc:
        reg.add(_remote("github"))
    assert "already exists" in str(exc.value)
    assert not str(exc.value).startswith("limit:")


@pytest.mark.parametrize("bad", [
    # unpinned npm: the pin rule would refuse it
    lambda: ServerSpec(namespace="loose", kind="npm", package="p", owner="alice"),
    # a prefix conflict with the stored "one": the prefix rule would refuse it
    lambda: _remote("one_two"),
], ids=["unpinned", "prefix"])
def test_the_limit_is_checked_before_the_pin_and_prefix_rules(tmp_path, bad):
    reg = _registry(tmp_path, 1)
    reg.add(_remote("one"))
    with pytest.raises(RegistryError) as exc:
        reg.add(bad())
    assert str(exc.value).startswith("limit:")


# --- 5.2 token limit ----------------------------------------------------------


def test_a_user_at_the_token_limit_is_refused_and_no_file_changes(tmp_path):
    w = _world(tmp_path, tokens=2)
    w.policy.mint_token(w.alice, "a", "mcp")
    w.policy.mint_token(w.alice, "b", "mcp")
    before = _bytes(tmp_path)
    with pytest.raises(ValueError) as exc:
        w.policy.mint_token(w.alice, "c", "mcp")
    assert not isinstance(exc.value, PermissionError)
    text = str(exc.value)
    assert text.startswith("limit:") and "MAX_USER_TOKENS" in text and "2" in text
    assert _bytes(tmp_path) == before
    assert len(w.tokens.list_for("alice")) == 2


def test_the_token_limit_counts_each_user_separately(tmp_path):
    w = _world(tmp_path, tokens=1)
    w.policy.mint_token(w.alice, "a", "mcp")
    w.policy.mint_token(w.bob, "b", "mcp")
    with pytest.raises(ValueError, match="^limit:"):
        w.policy.mint_token(w.bob, "b2", "mcp")


def test_an_admin_actor_is_exempt_for_itself_and_for_a_user(tmp_path):
    w = _world(tmp_path, tokens=0)
    own, _ = w.policy.mint_token(w.root, "own", "mcp")
    other, _ = w.policy.mint_token(w.root, "for-alice", "mcp", "alice")
    assert own.user_id == "admin" and other.user_id == "alice"
    # The cap is by actor: alice herself holds a token and still cannot mint.
    with pytest.raises(ValueError, match="^limit:"):
        w.policy.mint_token(w.alice, "mine", "mcp")
    # An admin mints for a user who is already over the cap.
    w.policy.mint_token(w.root, "again", "mcp", "alice")
    assert len(w.tokens.list_for("alice")) == 2


def test_a_revoke_frees_a_token_place(tmp_path):
    w = _world(tmp_path, tokens=1)
    rec, _ = w.policy.mint_token(w.alice, "a", "mcp")
    with pytest.raises(ValueError, match="^limit:"):
        w.policy.mint_token(w.alice, "b", "mcp")
    w.policy.revoke_token(w.alice, rec.id)
    again, _ = w.policy.mint_token(w.alice, "b", "mcp")
    assert [r.id for r in w.tokens.list_for("alice")] == [again.id]


def test_token_store_create_caps_by_default_and_exempt_skips_the_cap(tmp_path):
    store = TokenStore(tmp_path / "tokens.json", tmp_path / "user_tokens.json",
                       max_user_tokens=1)
    store.load()
    store.create("a", "mcp", "alice")
    before = _bytes(tmp_path)
    with pytest.raises(ValueError, match="^limit:.*MAX_USER_TOKENS.*1"):
        store.create("b", "mcp", "alice")  # `exempt` defaults to False
    assert _bytes(tmp_path) == before
    store.create("c", "mcp", "alice", exempt=True)
    assert len(store.list_for("alice")) == 2


def test_the_token_default_cap_is_10(tmp_path):
    store = TokenStore(tmp_path / "tokens.json", tmp_path / "user_tokens.json")
    store.load()
    for i in range(10):
        store.create(f"t{i}", "mcp", "alice")
    with pytest.raises(ValueError, match="^limit:.*MAX_USER_TOKENS.*10"):
        store.create("extra", "mcp", "alice")


def test_a_token_file_above_the_limit_loads(tmp_path):
    seed = TokenStore(tmp_path / "tokens.json", tmp_path / "user_tokens.json",
                      max_user_tokens=10)
    seed.load()
    for i in range(3):
        seed.create(f"t{i}", "mcp", "alice")
    store = TokenStore(tmp_path / "tokens.json", tmp_path / "user_tokens.json",
                       max_user_tokens=1)
    store.load()  # no refusal
    assert len(store.list_for("alice")) == 3
    with pytest.raises(ValueError, match="^limit:"):
        store.create("next", "mcp", "alice")


def _token_bytes(site) -> dict[str, bytes]:
    return {n: (site.data / n).read_bytes() for n in ("tokens.json", "user_tokens.json")
            if (site.data / n).exists()}


def test_the_dashboard_answers_400_for_a_user_at_the_token_limit(make_mu_site):
    """`seed` gives `alice` one token, so `MAX_USER_TOKENS=1` puts her at it."""
    site = make_mu_site(MAX_USER_TOKENS="1")
    before = _token_bytes(site)
    resp = site.request("alice", "POST", "/tokens", data={"name": "second"})
    assert resp.status_code == 400
    assert resp.text.startswith("limit:") and "MAX_USER_TOKENS" in resp.text
    assert "1" in resp.text
    assert _token_bytes(site) == before


def test_the_dashboard_and_api_admin_mint_past_the_token_limit(make_mu_site):
    """The `/api` gate refuses a non-admin user (401), so a 400 on `/api` has no
    caller; what `/api` shows is the admin exemption."""
    site = make_mu_site(MAX_USER_TOKENS="0")
    for form in ({"name": "own"}, {"name": "for-alice", "user": "alice"}):
        assert site.request("admin", "POST", "/tokens", data=form).status_code == 200
    h = {"Authorization": f"Bearer {site.admin_token}"}
    for body in ({"name": "own2"}, {"name": "for-alice2", "user_id": "alice"}):
        assert site.client.post("/api/tokens", headers=h, json=body).status_code == 201
    # alice is still capped at zero.
    assert site.request("alice", "POST", "/tokens", data={"name": "x"}).status_code == 400


# --- 5.3 settings -------------------------------------------------------------


def _load(tmp_path, monkeypatch, **env):
    monkeypatch.delenv("MAX_USER_SERVERS", raising=False)
    monkeypatch.delenv("MAX_USER_TOKENS", raising=False)
    return load_settings({"DATA_DIR": str(tmp_path), "ADMIN_PASSWORD": "pw", **env})


def test_the_limit_settings_default_to_20_and_10(tmp_path, monkeypatch):
    s = _load(tmp_path, monkeypatch)
    assert (s.max_user_servers, s.max_user_tokens) == (20, 10)


def test_the_limit_settings_read_integers(tmp_path, monkeypatch):
    s = _load(tmp_path, monkeypatch, MAX_USER_SERVERS="0", MAX_USER_TOKENS="7")
    assert (s.max_user_servers, s.max_user_tokens) == (0, 7)


@pytest.mark.parametrize("name,bad", [
    ("MAX_USER_SERVERS", "-1"), ("MAX_USER_SERVERS", "many"),
    ("MAX_USER_SERVERS", "1.5"), ("MAX_USER_SERVERS", ""),
    ("MAX_USER_TOKENS", "-1"), ("MAX_USER_TOKENS", "many"),
    ("MAX_USER_TOKENS", "1.5"), ("MAX_USER_TOKENS", ""),
    # `int()` takes these; the setting does not (ASCII digits only).
    ("MAX_USER_SERVERS", "+5"), ("MAX_USER_SERVERS", " 5 "),
    ("MAX_USER_TOKENS", "1_0"), ("MAX_USER_TOKENS", "\u0665"),
    ("MAX_USER_TOKENS", "1" * 5000),
])
def test_a_bad_limit_value_stops_the_start(tmp_path, monkeypatch, name, bad):
    with pytest.raises(ConfigError, match=name):
        _load(tmp_path, monkeypatch, **{name: bad})


def test_the_environment_is_read_too(tmp_path, monkeypatch):
    monkeypatch.setenv("MAX_USER_SERVERS", "3")
    monkeypatch.setenv("MAX_USER_TOKENS", "4")
    s = load_settings({"DATA_DIR": str(tmp_path), "ADMIN_PASSWORD": "pw"})
    assert (s.max_user_servers, s.max_user_tokens) == (3, 4)


def test_build_app_passes_the_server_limit_to_the_registry(make_mu_site):
    """`MAX_USER_SERVERS=0`: the seeded user servers load (over the cap), alice
    cannot add, and the admin can."""
    site = make_mu_site(MAX_USER_SERVERS="0")
    before = (site.data / "user_servers.json").read_bytes()
    form = {"kind": "npm", "namespace": "extra", "package": "extra@1.0.0"}
    resp = site.request("alice", "POST", "/servers", data=form)
    assert resp.status_code == 400  # the form page again, with the refusal text
    assert "limit: alice owns" in resp.text and "MAX_USER_SERVERS is 0" in resp.text
    assert (site.data / "user_servers.json").read_bytes() == before
    admin = site.request("admin", "POST", "/servers", data=form)
    assert admin.status_code == 303, admin.text
    assert "extra" in (site.data / "servers.json").read_text()


# --- 5.4 the approval memo ----------------------------------------------------

# One legal change for each field of REVISION_FIELDS, on a user-owned `npm`
# base. A change may also touch a second field the pin rule couples to it
# (`kind` and `source` need a matching `package`). `command` is legal on `npm`:
# the pin rule does not look at it.
BASE = {"namespace": "gh", "kind": "npm", "package": "p@1.0.0", "args": ["a"],
        "env": {"K": "v"}, "owner": "alice"}
CHANGES = {
    "kind": {"kind": "python", "package": "p==1.0.0"},
    "package": {"package": "p@1.0.1"},
    "args": {"args": ["b"]},
    "url": {"url": "http://127.0.0.1:9/mcp"},
    "transport": {"transport": "sse"},
    "headers": {"headers": {"H": "1"}},
    "command": {"command": "run"},
    "env": {"env": {"K": "w"}},
    "source": {"source": f"github:o/r#{SHA}", "package": "p"},
}
GH = ServerKey("alice", "gh")


def _change(field: str) -> dict:
    if field not in CHANGES:
        pytest.fail(f"REVISION_FIELDS gained {field!r}: add a legal change to CHANGES")
    return CHANGES[field]


def _approved(tmp_path: Path, **base) -> Registry:
    reg = _registry(tmp_path)
    reg.add(ServerSpec(**{**BASE, **base}))
    reg.set_approved_revision(GH, revision(reg.get(GH)))
    assert reg.get(GH).approval == "approved"  # the read that fills the memo
    return reg


@pytest.mark.parametrize("field", REVISION_FIELDS)
def test_each_revision_field_edit_un_approves(tmp_path, field):
    change = _change(field)
    reg = _approved(tmp_path)
    variant = ServerSpec(**{**BASE, **change})
    assert getattr(variant, field) != getattr(reg.get(GH), field)
    reg.update(variant)
    stored = reg.get(GH)
    assert stored.approval == "pending"
    assert stored.approved_revision != revision(stored)  # the exact rule (G3)
    fresh = _registry(tmp_path)  # a reload agrees: no stale memo is on disk
    assert fresh.get(GH).approval == "pending"


@pytest.mark.parametrize("field", REVISION_FIELDS)
def test_assigning_a_revision_field_is_seen_by_the_approval(tmp_path, field):
    change = _change(field)
    stored = _approved(tmp_path).get(GH)
    for name, value in ServerSpec(**{**BASE, **change}).model_dump().items():
        if name in change:
            setattr(stored, name, value)
    assert stored.approval == "pending"


def test_assigning_args_to_a_read_approved_record_makes_it_pending(tmp_path):
    stored = _approved(tmp_path).get(GH)
    stored.args = ["other"]
    assert stored.approval == "pending"


def test_a_model_copy_with_an_update_has_its_own_exact_approval(tmp_path):
    stored = _approved(tmp_path).get(GH)
    changed = stored.model_copy(update={"args": ["other"]})
    assert changed.approval == "pending"
    assert stored.approval == "approved"  # the original keeps its own memo


def test_a_non_revision_edit_keeps_the_approval(tmp_path):
    reg = _approved(tmp_path)
    edited = ServerSpec(**{**BASE, "description": "new text"})
    reg.update(edited)
    assert reg.get(GH).description == "new text"
    assert reg.get(GH).approval == "approved"
    assert reg.get(GH).model_copy(update={"description": "x"}).approval == "approved"


class _Counter:
    def __init__(self, monkeypatch) -> None:
        self.n = 0
        real = registry.revision

        def counted(spec):
            self.n += 1
            return real(spec)

        monkeypatch.setattr(registry, "revision", counted)


def test_the_approval_is_computed_once_and_a_plain_copy_keeps_it(tmp_path, monkeypatch):
    stored = _approved(tmp_path).get(GH)
    count = _Counter(monkeypatch)
    for _ in range(3):
        assert stored.approval == "approved"
    assert count.n == 0  # `_approved` already read it
    assert stored.model_copy().approval == "approved"
    assert count.n == 0  # no update: the content is the same, so the memo is valid
    stored.model_copy(update={"description": "x"}).approval  # noqa: B018
    # D6 round 3: the copy carries the pair, and its revision values equal the
    # snapshot, so it reuses the digest (round 2 dropped the memo on update).
    assert count.n == 0
    stored.description = "y"  # not a revision field
    assert stored.approval == "approved" and count.n == 0
    stored.args = ["z"]
    assert stored.approval == "pending" and count.n == 1


def test_a_masked_echo_keeps_the_secrets_and_the_approval(tmp_path):
    secrets = {
        "source": f"git+https://oauth2:SRCSECRET@host/o/r#{SHA}",
        "url": "https://user:URLSECRET@host/mcp?key=QSECRET",
        "env": {"TOKEN": "ENVSECRET"},
        "headers": {"Authorization": "Bearer HDRSECRET"},
    }
    reg = _approved(tmp_path, package="entry", **secrets)
    raw = reg.get(GH)
    echo = redact_spec(raw)  # what a read returns
    assert SECRET_MASK in echo.env["TOKEN"] and SECRET_MASK in echo.headers["Authorization"]
    assert "URLSECRET" not in echo.url and "SRCSECRET" not in echo.source
    reg.update(echo)
    stored = reg.get(GH)
    for name, value in secrets.items():
        assert getattr(stored, name) == value
    assert stored.approval == "approved"
    on_disk = (tmp_path / "user_servers.json").read_text()
    for needle in ("SRCSECRET", "URLSECRET", "ENVSECRET", "HDRSECRET"):
        assert needle in on_disk
    assert _registry(tmp_path).get(GH).approval == "approved"


def test_an_approval_after_a_read_is_seen(tmp_path):
    reg = _registry(tmp_path)
    reg.add(ServerSpec(**BASE))
    assert reg.get(GH).approval == "pending"  # read: fills the memo
    reg.set_approved_revision(GH, revision(reg.get(GH)))
    assert reg.get(GH).approval == "approved"


@pytest.mark.asyncio
async def test_a_supervisor_approval_after_a_read_is_seen(tmp_path):
    from user_servers import ADMIN, ALICE, Env  # noqa: F401

    env = Env(tmp_path / "data")
    try:
        await env.sup.add(ServerSpec(namespace="gh", kind="npm", package="p@1.0.0"), ALICE)
        assert env.stored(GH).approval == "pending"
        await env.sup.approve(GH, revision(env.stored(GH)), ADMIN_ACTOR)
        assert env.stored(GH).approval == "approved"
    finally:
        await env.close()


def test_the_memo_is_not_a_field_a_dump_a_file_or_part_of_equality(tmp_path):
    reg = _approved(tmp_path)
    stored = reg.get(GH)  # its approval was read
    assert "_revision_memo" not in stored.model_dump()
    assert "_revision_memo" not in stored.model_dump_json()
    assert "_revision_memo" not in ServerSpec.model_fields
    assert "_revision_memo" not in (tmp_path / "user_servers.json").read_text()
    # A read record equals the same record that no one read.
    twin = ServerSpec.model_validate(stored.model_dump())
    assert stored == twin and twin == stored
    twin.approval  # noqa: B018
    assert stored == twin
    assert stored.model_dump() == twin.model_dump()


# --- 5.5 the hot path ---------------------------------------------------------

N = 50


def _hot_world(tmp_path: Path):
    w = _world(tmp_path, servers=N + 5)
    keys = [ServerKey("alice", f"srv{i}") for i in range(N)]
    for k in keys:
        w.reg.add(ServerSpec(namespace=k.namespace, kind="npm", package="p@1.0.0",
                             owner="alice"))
        w.policy.add_rule(w.root, subject_kind="user", subject="bob",
                          level="server", server=k.ref, tool=None,
                          effect="allow")
    return w, keys


def test_keys_for_calls_revision_zero_times_on_the_second_run(tmp_path, monkeypatch):
    w, keys = _hot_world(tmp_path)
    for k in keys[::2]:  # approve half; the digest is taken before the count starts
        w.reg.set_approved_revision(k, revision(w.reg.get(k)))
    expected = set(keys[::2])
    count = _Counter(monkeypatch)

    first = w.policy.keys_for(w.bob, "mcp")
    after_first = count.n
    second = w.policy.keys_for(w.bob, "mcp")

    assert 1 <= after_first <= N
    assert count.n == after_first  # the second run called `revision` zero times
    assert set(first.keys) == set(second.keys) == expected
    # The memoized result equals a fresh computation (a reloaded registry).
    fresh = _registry(tmp_path, N + 5)
    assert {s.key for s in fresh.list() if s.approval == "approved"} == expected


def test_an_approval_between_two_runs_is_seen_at_the_cost_of_one_digest(
        tmp_path, monkeypatch):
    w, keys = _hot_world(tmp_path)
    w.policy.keys_for(w.bob, "mcp")
    target = keys[1]
    digest = revision(w.reg.get(target))  # taken before the count starts
    count = _Counter(monkeypatch)
    w.policy.keys_for(w.bob, "mcp")
    assert count.n == 0
    w.reg.set_approved_revision(target, digest)
    reach = w.policy.keys_for(w.bob, "mcp")
    assert set(reach.keys) == {target}
    assert count.n <= 1


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ["http", "sse"])
async def test_the_live_transport_shares_no_header_dict_with_the_record(
        tmp_path, transport):
    """R1 at its one known alias: a header-sink refresh writes into the live
    transport's dict. That dict must not be the stored record's, or the write
    changes the record in place and leaves its approval memo stale."""
    from user_servers import Env

    env = Env(tmp_path / "data")
    try:
        spec = ServerSpec(namespace="rm", kind="remote", url="http://127.0.0.1:9/mcp",
                          transport=transport, headers={"H": "1"}, owner="alice")
        env.sup.registry.add(spec)
        stored = env.sup.registry.get(ServerKey("alice", "rm"))
        env.sup.registry.set_approved_revision(stored.key, revision(stored))
        stored = env.sup.registry.get(stored.key)
        assert stored.approval == "approved"  # fills the memo
        live = env.sup._build_transport(stored)
        live.headers["H"] = "changed"
        live.headers["X"] = "added"
        assert stored.headers == {"H": "1"}
        assert stored.approval == "approved"
    finally:
        await env.close()


# --- 5.6 the approval stays exact (memo rounds 3 and 4) -----------------------


def _exact(rec: ServerSpec) -> str:
    """The rule of "Approval binds a revision", computed with no memo."""
    return "approved" if rec.approved_revision == revision(rec) else "pending"


def _mutate(rec: ServerSpec, field: str) -> None:
    """One in-place change of the list or dict that `field` holds."""
    value = getattr(rec, field)
    if field == "args":
        value.append("x")
    else:
        value["N"] = "x"


@pytest.mark.parametrize("path", ["direct", "model_copy", "redact_spec"])
@pytest.mark.parametrize("field", ["args", "env", "headers"])
def test_an_in_place_change_through_a_shared_container_changes_the_approval(
        tmp_path, field, path):
    stored = _approved(tmp_path).get(GH)  # approval was read: the pair is kept
    assert stored.approval == "approved"
    target = {"direct": stored,
              "model_copy": stored.model_copy(),
              "redact_spec": redact_spec(stored)}[path]
    shared = getattr(target, field) is getattr(stored, field)
    _mutate(target, field)
    # The change reaches the stored record exactly when the container is shared.
    assert (getattr(stored, field) == getattr(target, field)) == shared
    assert stored.approval == _exact(stored)
    assert stored.approval == ("pending" if shared else "approved")
    assert target.approval == _exact(target)
    # A reload agrees with the memo-free rule.
    assert _registry(tmp_path).get(GH).approval == "approved"


@pytest.mark.parametrize("field", ["args", "env", "headers"])
def test_a_model_copy_alias_is_a_shared_container(tmp_path, field):
    """Guards the test above: `model_copy()` is shallow, so the path is real."""
    stored = _approved(tmp_path).get(GH)
    assert getattr(stored.model_copy(), field) is getattr(stored, field)


def test_a_pydantic_copy_with_an_update_has_an_exact_approval(tmp_path):
    stored = _approved(tmp_path).get(GH)
    with pytest.warns(DeprecationWarning):
        changed = stored.copy(update={"args": ["other"]})
    assert changed.approval == _exact(changed) == "pending"
    assert stored.args == ["a"] and stored.approval == "approved"


def test_a_deleted_revision_field_keeps_the_approval_exact(tmp_path):
    stored = _approved(tmp_path).get(GH)
    assert stored.approval == "approved"
    delattr(stored, "args")
    assert "args" not in stored.__dict__
    assert stored.approval == _exact(stored) == "pending"  # no exception


def _unread(**update) -> ServerSpec:
    """A record that no one read, so it holds no pair, with `update` set the
    way pydantic does not validate it (`model_copy(update=)`)."""
    rec = ServerSpec(**BASE).model_copy(update=update)
    assert "_revision_memo" not in rec.__dict__
    return rec


@pytest.mark.filterwarnings("ignore::UserWarning")
def test_an_out_of_type_value_keeps_no_pair(tmp_path):
    """The scenario of the spec delta, through the registry."""
    reg = _approved(tmp_path)
    reg._replace(GH, {"args": [1]})  # `model_copy(update=)`: not validated
    stored = reg.get(GH)
    assert stored.approval == "pending"  # read
    reg.set_approved_revision(GH, revision(reg.get(GH)))
    stored = reg.get(GH)
    assert stored.approval == "approved"  # read again, with approval set
    stored.args[0] = True
    assert stored.approval == _exact(stored)
    assert stored.approved_revision != revision(stored)  # the probe is not vacuous


class _LyingStr(str):
    """A `str` subclass whose `__eq__` always agrees (gate probe six)."""

    __hash__ = str.__hash__

    def __eq__(self, other):
        return True


def _set(field, value):
    return lambda rec: setattr(rec, field, value)


def _item(field, index, value):
    return lambda rec: getattr(rec, field).__setitem__(index, value)


def _inner_append(rec):
    rec.args[0].append("b")


# (start update, change after the approval). Each pair has two digests.
PROBES = {
    "list_1_then_true": ({"args": [1]}, _item("args", 0, True)),
    "list_1_then_float": ({"args": [1]}, _item("args", 0, 1.0)),
    "int_key_then_bool_key": ({"env": {1: "a"}}, _set("env", {True: "a"})),
    "nested_list": ({"args": [["a"]]}, _inner_append),
    "list_in_tuple": ({"args": (["a"],)}, _inner_append),
    "lying_str_subclass": ({"args": [_LyingStr("a")]}, _set("args", ["b"])),
}


@pytest.mark.filterwarnings("ignore::UserWarning")
@pytest.mark.parametrize("name", PROBES)
def test_a_gate_probe_value_keeps_no_pair_and_the_approval_stays_exact(name):
    start, change = PROBES[name]
    rec = _unread(**start)
    assert rec.approval == "pending"  # read: the record is out of type
    assert "_revision_memo" not in rec.__dict__  # the pair is not kept
    rec.approved_revision = revision(rec)  # the admin approves this content
    assert rec.approval == "approved"
    assert "_revision_memo" not in rec.__dict__
    before = revision(rec)
    change(rec)
    after = revision(rec)
    assert after != before, "the probe must change the digest"
    assert rec.approval == _exact(rec) == "pending"


@pytest.mark.filterwarnings("ignore::UserWarning")
def test_a_typed_record_keeps_a_pair_and_a_later_out_of_type_value_is_exact():
    rec = _unread()
    assert rec.approval == "pending"
    assert "_revision_memo" in rec.__dict__  # a validated record keeps the pair
    rec.approved_revision = revision(rec)
    assert rec.approval == "approved"
    rec.args = [1]  # now out of type: the old pair must not answer
    assert rec.approval == _exact(rec) == "pending"


def test_every_revision_field_has_a_memo_shape():
    """A field missing from `_REVISION_SHAPES` fails closed but silently loses
    the hot-path memo; keep the two in step."""
    assert set(registry._REVISION_SHAPES) == set(REVISION_FIELDS)
