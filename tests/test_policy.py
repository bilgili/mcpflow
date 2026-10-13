"""Grant rules, `resolve`, the Reach, and the token and delete rules of AccessPolicy.

Every test is one scenario of `specs/access-policy/spec.md`, `specs/identity/spec.md`,
or `specs/auth/spec.md` (Dashboard user resolution), or one row of the
reference semantics in `specs/tla/multi_user_access.tla`. The expectations
come from the spec and the frozen interfaces in `design.md`
("Public interfaces"), not from the implementation.

Scenarios that need the router or the MCP paths belong to section 4 and
live in `tests/test_router.py`.
"""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import make_user

from mcpflow.auth import HashedTokenVerifier, TokenStore, hash_password
from mcpflow.identity import ADMINS_GROUP, LocalIdentityProvider, User
from mcpflow.policy import AccessPolicy, GrantRule, RuleStore, resolve
from mcpflow.registry import Registry, ServerKey, ServerSpec, revision

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _user(uid: str, *groups: str, admin: bool = False) -> User:
    return User(id=uid, name=uid,
                groups=frozenset(groups) | ({ADMINS_GROUP} if admin else frozenset()),
                provider="local")


_n = [0]


def rule(kind, subject, level, effect, server=None, tool=None) -> GrantRule:
    _n[0] += 1
    return GrantRule(f"r{_n[0]}", kind, subject, level, server, tool, effect, NOW)


# --- resolve: the precedence table (10.6, and the reference model) ----------

ALICE = _user("alice", "eng", "ops")
TIME = ServerKey(None, "time")
OWN = ServerKey("alice", "github")
FOREIGN = ServerKey("bob", "github")


def _row(rules, key, tool, want):
    return pytest.param(rules, key, tool, want)


TABLE = {
    # Level beats subject (AC-3).
    "level_beats_subject_allowed_tool": (
        [rule("user", "alice", "server", "deny", "time"),
         rule("group", "eng", "tool", "allow", "time", "get_current_time")],
        TIME, "get_current_time", True),
    "level_beats_subject_other_tool": (
        [rule("user", "alice", "server", "deny", "time"),
         rule("group", "eng", "tool", "allow", "time", "get_current_time")],
        TIME, "convert_time", False),
    "level_beats_subject_server_decision": (
        [rule("user", "alice", "server", "deny", "time"),
         rule("group", "eng", "tool", "allow", "time", "get_current_time")],
        TIME, None, False),
    # User beats group (AC-3).
    "user_allow_beats_group_deny": (
        [rule("group", "eng", "server", "deny", "time"),
         rule("user", "alice", "server", "allow", "time")],
        TIME, "x", True),
    "user_deny_beats_group_allow": (
        [rule("group", "eng", "server", "allow", "time"),
         rule("user", "alice", "server", "deny", "time")],
        TIME, "x", False),
    # Deny beats allow among equal rules (AC-3).
    "deny_beats_allow_users": (
        [rule("user", "alice", "server", "allow", "time"),
         rule("user", "alice", "server", "deny", "time")],
        TIME, "x", False),
    "deny_beats_allow_users_reversed": (
        [rule("user", "alice", "server", "deny", "time"),
         rule("user", "alice", "server", "allow", "time")],
        TIME, "x", False),
    # Conflicting groups resolve to deny (AC-3).
    "conflicting_groups_deny": (
        [rule("group", "eng", "server", "allow", "time"),
         rule("group", "ops", "server", "deny", "time")],
        TIME, "x", False),
    "agreeing_groups_allow": (
        [rule("group", "eng", "server", "allow", "time"),
         rule("group", "ops", "server", "allow", "time")],
        TIME, "x", True),
    # No rule resolves to deny; the owner default (AC-3, AC-5).
    "no_rule_deny": ([], TIME, "x", False),
    "no_rule_foreign_deny": ([], FOREIGN, "x", False),
    "no_rule_owner_allow": ([], OWN, "x", True),
    "no_rule_owner_server_decision": ([], OWN, None, True),
    "rule_of_another_user_is_ignored": (
        [rule("user", "bob", "server", "allow", "time")], TIME, "x", False),
    "rule_of_a_group_without_alice_is_ignored": (
        [rule("group", "interns", "server", "allow", "time")], TIME, "x", False),
    "rule_for_another_server_is_ignored": (
        [rule("user", "alice", "server", "allow", "other")], TIME, "x", False),
    # An explicit rule beats the owner default.
    "user_deny_beats_owner_default": (
        [rule("user", "alice", "server", "deny", "github@alice")], OWN, "x", False),
    "group_deny_beats_owner_default": (
        [rule("group", "eng", "server", "deny", "github@alice")], OWN, "x", False),
    "tool_deny_beats_owner_default": (
        [rule("user", "alice", "tool", "deny", "github@alice", "x")], OWN, "x", False),
    "tool_deny_leaves_other_owner_tools": (
        [rule("user", "alice", "tool", "deny", "github@alice", "x")], OWN, "y", True),
    "explicit_allow_for_the_owner_still_allows": (
        [rule("user", "alice", "server", "allow", "github@alice")], OWN, "x", True),
    # A global allow covers admin-owned servers only; a global deny covers all.
    "global_allow_covers_admin_owned": (
        [rule("user", "alice", "global", "allow")], TIME, "x", True),
    "global_allow_skips_a_foreign_user_server": (
        [rule("user", "alice", "global", "allow")], FOREIGN, "x", False),
    "global_deny_covers_admin_owned": (
        [rule("user", "alice", "global", "deny")], TIME, "x", False),
    "global_deny_covers_the_owners_server": (
        [rule("user", "alice", "global", "deny")], OWN, "x", False),
    "global_deny_covers_a_foreign_server": (
        [rule("user", "alice", "global", "deny")], FOREIGN, "x", False),
    "group_global_allow_skips_a_foreign_user_server": (
        [rule("group", "eng", "global", "allow")], FOREIGN, "x", False),
    # Level order: tool > server > global.
    "server_allow_beats_global_deny": (
        [rule("user", "alice", "global", "deny"),
         rule("user", "alice", "server", "allow", "time")], TIME, "x", True),
    "server_deny_beats_global_allow": (
        [rule("user", "alice", "global", "allow"),
         rule("user", "alice", "server", "deny", "time")], TIME, "x", False),
    "tool_allow_beats_server_deny": (
        [rule("group", "eng", "server", "deny", "time"),
         rule("group", "eng", "tool", "allow", "time", "x")], TIME, "x", True),
    "tool_deny_beats_server_allow_and_spares_other_tools": (
        [rule("group", "eng", "server", "allow", "time"),
         rule("group", "eng", "tool", "deny", "time", "convert_time")],
        TIME, "get_current_time", True),
    "tool_deny_beats_server_allow": (
        [rule("group", "eng", "server", "allow", "time"),
         rule("group", "eng", "tool", "deny", "time", "convert_time")],
        TIME, "convert_time", False),
    # tool=None asks the server decision, which no tool rule matches.
    "server_decision_ignores_tool_rules": (
        [rule("user", "alice", "tool", "allow", "time", "x")], TIME, None, False),
    "server_decision_uses_the_server_rule": (
        [rule("user", "alice", "tool", "deny", "time", "x"),
         rule("user", "alice", "server", "allow", "time")], TIME, None, True),
    # A grant on a user-owned server by name.
    "server_allow_shares_a_user_server": (
        [rule("user", "alice", "server", "allow", "github@bob")], FOREIGN, "x", True),
}


@pytest.mark.parametrize("name", sorted(TABLE))
def test_resolve_table(name):
    rules, key, tool, want = TABLE[name]
    assert resolve(rules, ALICE, key, tool) is want, name


def test_resolve_does_not_depend_on_rule_order():
    rules = [rule("group", "eng", "server", "allow", "time"),
             rule("group", "ops", "server", "deny", "time"),
             rule("user", "alice", "tool", "allow", "time", "x")]
    assert resolve(rules, ALICE, TIME, "x") is True
    assert resolve(list(reversed(rules)), ALICE, TIME, "x") is True
    assert resolve(rules, ALICE, TIME, "y") is False
    assert resolve(list(reversed(rules)), ALICE, TIME, "y") is False


# --- The world for the AccessPolicy tests ------------------------------------


def make_world(tmp_path: Path, servers=(("time", None, True),)):
    """Users alice (eng), bob, carol; groups eng, ops, interns.

    `servers` holds `(namespace, owner, approved)` triples.
    """
    ident = LocalIdentityProvider(
        tmp_path / "users.json", hash_password("pw", iterations=1000)
    )
    ident.load()
    for g in ("eng", "ops", "interns"):
        ident._create_group(g)
    for uid in ("alice", "bob", "carol"):
        make_user(ident, uid, "pw", groups=["eng"] if uid == "alice" else [])
    tokens = TokenStore(tmp_path / "tokens.json", tmp_path / "user_tokens.json")
    tokens.load()
    reg = Registry(tmp_path / "servers.json", tmp_path / "user_servers.json")
    reg.load()
    for ns, owner, approved in servers:
        spec = ServerSpec(namespace=ns, kind="npm", package="p@1.0.0", owner=owner)
        reg.add(spec)
        if owner is not None and approved:
            reg.set_approved_revision(spec.key, revision(spec))
    rules = RuleStore(tmp_path / "rules.json")
    rules.load()
    policy = AccessPolicy(ident, rules, tokens, reg)
    return SimpleNamespace(
        policy=policy, ident=ident, tokens=tokens, reg=reg, rules=rules,
        root=ident.get_user("admin"), path=tmp_path,
        alice=ident.get_user("alice"), bob=ident.get_user("bob"),
        carol=ident.get_user("carol"),
    )


def allow(w, kind, subject, level, server=None, tool=None, effect="allow"):
    return w.policy.add_rule(
        w.root, subject_kind=kind, subject=subject, level=level,
        server=server, tool=tool, effect=effect,
    )


def _files(path: Path) -> dict[str, str]:
    return {p.name: p.read_text() for p in sorted(path.glob("*.json"))}


# --- Grant rule storage (10.7) -----------------------------------------------


def test_add_a_server_rule(tmp_path):
    w = make_world(tmp_path)
    added = allow(w, "group", "eng", "server", "time")
    assert isinstance(added, GrantRule) and added.id
    stored = json.loads((tmp_path / "rules.json").read_text())
    assert stored["version"] == 1
    (entry,) = stored["rules"]
    assert entry["id"] == added.id
    assert (entry["subject_kind"], entry["subject"], entry["level"],
            entry["server"], entry["effect"]) == ("group", "eng", "server", "time", "allow")
    assert stat.S_IMODE((tmp_path / "rules.json").stat().st_mode) == 0o600


def test_each_rule_gets_a_new_id(tmp_path):
    w = make_world(tmp_path)
    ids = {allow(w, "group", "eng", "server", "time").id,
           allow(w, "group", "ops", "server", "time").id}
    assert len(ids) == 2


def test_rules_survive_a_reload(tmp_path):
    w = make_world(tmp_path)
    allow(w, "user", "alice", "tool", "time", "x", "deny")
    allow(w, "group", "eng", "global")
    fresh = RuleStore(tmp_path / "rules.json")
    fresh.load()
    assert fresh.list() == w.rules.list()


def test_a_missing_rules_file_loads_as_no_rule(tmp_path):
    store = RuleStore(tmp_path / "rules.json")
    store.load()
    assert store.list() == []


@pytest.mark.parametrize("kwargs", [
    dict(level="tool", server="time", tool=None),             # tool rule, no tool
    dict(level="tool", server=None, tool="x"),                # tool rule, no server
    dict(level="server", server="time", tool="x"),            # server rule with a tool
    dict(level="server", server=None, tool=None),             # server rule, no server
    dict(level="global", server="time", tool=None),           # global rule with a server
    dict(level="global", server=None, tool="x"),              # global rule with a tool
    dict(level="galaxy", server=None, tool=None),             # bad level
])
def test_a_malformed_rule_is_refused(tmp_path, kwargs):
    w = make_world(tmp_path)
    allow(w, "group", "eng", "server", "time")
    before = _files(tmp_path)
    with pytest.raises(ValueError):
        w.policy.add_rule(w.root, subject_kind="user", subject="alice",
                          effect="allow", **kwargs)
    assert _files(tmp_path) == before
    assert len(w.rules.list()) == 1


def test_a_bad_effect_or_subject_kind_is_refused(tmp_path):
    w = make_world(tmp_path)
    for bad in (dict(effect="maybe"), dict(subject_kind="team")):
        kw = dict(subject_kind="user", subject="alice", level="server",
                  server="time", tool=None, effect="allow") | bad
        with pytest.raises(ValueError):
            w.policy.add_rule(w.root, **kw)
    assert w.rules.list() == []


def test_a_rule_for_an_unknown_server_is_refused(tmp_path):
    w = make_world(tmp_path)
    allow(w, "group", "eng", "server", "time")
    before = _files(tmp_path)
    with pytest.raises(ValueError, match="server"):
        allow(w, "user", "alice", "server", "nope")
    with pytest.raises(ValueError, match="server"):
        allow(w, "user", "alice", "tool", "nope", "x")
    assert _files(tmp_path) == before


def test_a_rule_for_an_unknown_subject_is_refused(tmp_path):
    w = make_world(tmp_path)
    with pytest.raises(ValueError):
        allow(w, "user", "ghost", "server", "time")
    with pytest.raises(ValueError):
        allow(w, "group", "ghosts", "server", "time")
    assert w.rules.list() == []


def test_a_rule_names_a_user_owned_server_by_reference(tmp_path):
    w = make_world(tmp_path, servers=(("github", "alice", True),))
    added = allow(w, "user", "bob", "server", "github@alice")
    assert added.server == "github@alice"


def test_a_non_admin_actor_cannot_add_or_remove_a_rule(tmp_path):
    w = make_world(tmp_path)
    added = allow(w, "group", "eng", "server", "time")
    before = _files(tmp_path)
    with pytest.raises(PermissionError):
        w.policy.add_rule(w.alice, subject_kind="user", subject="alice",
                          level="server", server="time", tool=None, effect="allow")
    with pytest.raises(PermissionError):
        w.policy.remove_rule(w.alice, added.id)
    assert _files(tmp_path) == before


def test_remove_an_unknown_rule_raises_key_error(tmp_path):
    w = make_world(tmp_path)
    with pytest.raises(KeyError):
        w.rules.remove("nope")
    with pytest.raises(KeyError):
        w.policy.remove_rule(w.root, "nope")


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory modes")
def test_a_failed_write_changes_nothing_in_memory(tmp_path):
    w = make_world(tmp_path)
    allow(w, "group", "eng", "server", "time")
    tmp_path.chmod(0o500)
    try:
        with pytest.raises(OSError):
            allow(w, "group", "ops", "server", "time")
    finally:
        tmp_path.chmod(0o700)
    assert len(w.rules.list()) == 1


# --- Removal cascades, token authorization (10.8) ----------------------------


@pytest.mark.asyncio
async def test_delete_a_user(tmp_path):
    w = make_world(tmp_path)
    _rec, clear = w.policy.mint_token(w.root, "laptop", "mcp", "bob")
    allow(w, "user", "bob", "server", "time")
    allow(w, "user", "carol", "server", "time")  # a rule of another subject stays
    verifier = HashedTokenVerifier(w.tokens, w.ident)
    assert await verifier.verify_token(clear) is not None
    w.policy.delete_user(w.root, "bob")
    assert w.tokens.list_for("bob") == []
    assert '"bob"' not in (tmp_path / "user_tokens.json").read_text()
    assert [r.subject for r in w.rules.list()] == ["carol"]
    assert '"bob"' not in (tmp_path / "rules.json").read_text()
    assert w.ident.get_user("bob") is None
    assert '"bob"' not in (tmp_path / "users.json").read_text()
    assert await verifier.verify_token(clear) is None  # /mcp answers 401


def test_a_user_who_owns_a_server_is_kept(tmp_path):
    w = make_world(tmp_path, servers=(("github", "alice", True),))
    w.policy.mint_token(w.root, "laptop", "mcp", "alice")
    allow(w, "user", "alice", "server", "github@alice", effect="deny")
    before = _files(tmp_path)
    with pytest.raises(ValueError):
        w.policy.delete_user(w.root, "alice")
    assert w.ident.get_user("alice") is not None
    assert len(w.tokens.list_for("alice")) == 1
    assert len(w.rules.list()) == 1
    assert _files(tmp_path) == before


def test_a_pending_server_also_keeps_its_owner(tmp_path):
    w = make_world(tmp_path, servers=(("github", "alice", False),))
    with pytest.raises(ValueError):
        w.policy.delete_user(w.root, "alice")
    assert w.ident.get_user("alice") is not None


def test_the_bootstrap_admin_cannot_be_deleted(tmp_path):
    w = make_world(tmp_path)
    with pytest.raises(ValueError):
        w.policy.delete_user(w.root, "admin")
    assert w.ident.get_user("admin") is not None


def test_a_non_admin_actor_cannot_delete_a_user_or_a_group(tmp_path):
    w = make_world(tmp_path)
    with pytest.raises(PermissionError):
        w.policy.delete_user(w.alice, "bob")
    with pytest.raises(PermissionError):
        w.policy.delete_group(w.alice, "ops")
    assert w.ident.get_user("bob") is not None
    assert "ops" in w.ident.list_groups()


def test_a_recreated_user_starts_with_no_grant(tmp_path):
    w = make_world(tmp_path)
    allow(w, "user", "bob", "server", "time")
    assert w.policy.keys_for(w.bob, "mcp").keys == (ServerKey(None, "time"),)
    w.policy.delete_user(w.root, "bob")
    make_user(w.ident, "bob", "pw")
    bob = w.ident.get_user("bob")
    assert w.rules.list() == []
    assert resolve(w.rules.list(), bob, ServerKey(None, "time"), "x") is False
    assert w.policy.keys_for(bob, "mcp").keys == ()


def test_a_recreated_group_starts_with_no_grant(tmp_path):
    w = make_world(tmp_path)
    allow(w, "group", "ops", "server", "time")
    w.policy.delete_group(w.root, "ops")
    assert "ops" not in w.ident.list_groups()
    assert w.rules.list() == []
    w.ident._create_group("ops")
    w.ident.set_groups("carol", ["ops"])
    carol = w.ident.get_user("carol")
    assert w.policy.keys_for(carol, "mcp").keys == ()


def test_mint_refuses_an_unknown_user_with_value_error(tmp_path):
    """Requirement "Unknown user of a minted token", scenario "An admin mints
    for an unknown user": `ValueError`, never `KeyError`; no token file changes."""
    w = make_world(tmp_path)
    before = _files(tmp_path)
    with pytest.raises(Exception) as exc:  # the exact type is asserted next
        w.policy.mint_token(w.root, "x", "mcp", "ghost")
    assert type(exc.value) is ValueError
    assert str(exc.value) == "user_id: unknown user ghost"
    assert _files(tmp_path) == before


def test_a_non_admin_cannot_probe_for_a_user(tmp_path):
    """Scenario "A non-admin user cannot probe for a user": an unknown user and
    an existing other user get the same `PermissionError` text."""
    w = make_world(tmp_path)
    before = _files(tmp_path)
    texts = []
    for target in ("ghost", "alice"):
        with pytest.raises(PermissionError) as exc:
            w.policy.mint_token(w.bob, "x", "mcp", target)
        texts.append(str(exc.value))
    assert texts == ["a non-admin user mints only an mcp token for themself"] * 2
    assert _files(tmp_path) == before


def test_a_non_admin_user_cannot_mint_an_admin_token(tmp_path):
    w = make_world(tmp_path)
    w.policy.mint_token(w.alice, "keep", "mcp")
    before = _files(tmp_path)
    with pytest.raises(PermissionError):
        w.policy.mint_token(w.alice, "x", "admin")
    with pytest.raises(PermissionError):
        w.policy.mint_token(w.alice, "x", "admin", "alice")
    assert _files(tmp_path) == before


def test_a_non_admin_user_mints_an_mcp_token_for_self_only(tmp_path):
    w = make_world(tmp_path)
    record, clear = w.policy.mint_token(w.alice, "laptop", "mcp")
    assert record.user_id == "alice" and record.scope == "mcp"
    assert w.tokens.lookup(clear, "mcp") is not None
    before = _files(tmp_path)
    with pytest.raises(PermissionError):
        w.policy.mint_token(w.alice, "x", "mcp", "bob")
    assert _files(tmp_path) == before


def test_the_admin_mints_either_scope_for_any_user(tmp_path):
    w = make_world(tmp_path)
    for scope in ("mcp", "admin"):
        record, clear = w.policy.mint_token(w.root, "t", scope, "alice")
        assert record.user_id == "alice" and record.scope == scope
        assert w.tokens.lookup(clear, scope) is not None
    record, _ = w.policy.mint_token(w.root, "own", "mcp")
    assert record.user_id == "admin"  # the default is the actor


def test_a_user_cannot_revoke_a_foreign_token(tmp_path):
    w = make_world(tmp_path)
    bob_rec, bob_clear = w.policy.mint_token(w.bob, "b", "mcp")
    with pytest.raises(KeyError):  # the adapters map it to 404
        w.policy.revoke_token(w.alice, bob_rec.id)
    assert w.tokens.lookup(bob_clear, "mcp") is not None
    assert [r.id for r in w.tokens.list_for("bob")] == [bob_rec.id]


def test_a_user_revokes_their_own_token_and_the_admin_any_token(tmp_path):
    w = make_world(tmp_path)
    mine, mine_clear = w.policy.mint_token(w.alice, "a", "mcp")
    theirs, theirs_clear = w.policy.mint_token(w.bob, "b", "mcp")
    w.policy.revoke_token(w.alice, mine.id)
    assert w.tokens.lookup(mine_clear, "mcp") is None
    w.policy.revoke_token(w.root, theirs.id)
    assert w.tokens.lookup(theirs_clear, "mcp") is None


def test_tokens_for_lists_own_tokens_and_the_admin_sees_all(tmp_path):
    w = make_world(tmp_path)
    a, _ = w.policy.mint_token(w.alice, "a", "mcp")
    b, _ = w.policy.mint_token(w.bob, "b", "mcp")
    assert [r.id for r in w.policy.tokens_for(w.alice)] == [a.id]
    assert {r.id for r in w.policy.tokens_for(w.root)} >= {a.id, b.id}


# --- keys_for and Reach (10.9) -----------------------------------------------

ADMIN_GH = ServerKey(None, "github")
ALICE_GH = ServerKey("alice", "github")
BOB_GH = ServerKey("bob", "github")


def test_one_request_reads_one_rule_set_c3(tmp_path):
    w = make_world(tmp_path)
    rule_ = allow(w, "user", "carol", "server", "time")
    t = ServerKey(None, "time")
    reach = w.policy.keys_for(w.carol, "mcp")
    assert reach.keys == (t,)
    assert rule_ in reach.rules
    w.policy.remove_rule(w.root, rule_.id)  # the admin acts mid-request
    assert reach.allows_tool(t, "x") is True  # the snapshot decides
    assert reach.allows_server(t) is True
    assert rule_ in reach.rules
    after = w.policy.keys_for(w.carol, "mcp")  # the next request reads the new set
    assert after.keys == () and after.allows_tool(t, "x") is False


def test_reach_is_not_changed_by_a_later_add(tmp_path):
    w = make_world(tmp_path)
    t = ServerKey(None, "time")
    reach = w.policy.keys_for(w.carol, "mcp")
    allow(w, "user", "carol", "server", "time")
    assert reach.keys == () and reach.allows_tool(t, "x") is False
    assert w.policy.keys_for(w.carol, "mcp").allows_tool(t, "x") is True


def test_each_user_reaches_their_own_server_ac_5c(tmp_path):
    w = make_world(tmp_path, servers=(("github", "alice", True), ("github", "bob", True)))
    ra = w.policy.keys_for(w.alice, "mcp")
    rb = w.policy.keys_for(w.bob, "mcp")
    assert ra.keys == (ALICE_GH,)
    assert rb.keys == (BOB_GH,)
    assert ra.allows_tool(ALICE_GH, "x") and not ra.allows_tool(BOB_GH, "x")
    assert rb.allows_tool(BOB_GH, "x") and not rb.allows_tool(ALICE_GH, "x")


def test_the_own_server_beats_a_shared_server_ac_5c(tmp_path):
    w = make_world(tmp_path, servers=(("github", None, True), ("github", "alice", True)))
    allow(w, "user", "alice", "server", "github")
    reach = w.policy.keys_for(w.alice, "mcp")
    assert reach.keys == (ALICE_GH,)
    assert reach.allows_tool(ALICE_GH, "x")
    assert not reach.allows_tool(ADMIN_GH, "x")
    assert not reach.allows_server(ADMIN_GH)


def test_a_shared_server_beats_a_foreign_server(tmp_path):
    w = make_world(tmp_path, servers=(("github", None, True), ("github", "bob", True)))
    allow(w, "user", "carol", "server", "github")
    allow(w, "user", "carol", "server", "github@bob")
    reach = w.policy.keys_for(w.carol, "mcp")
    assert reach.keys == (ADMIN_GH,)
    assert not reach.allows_tool(BOB_GH, "x")


def test_the_admin_reaches_the_admin_owned_server_ac_5c(tmp_path):
    w = make_world(tmp_path, servers=(
        ("github", None, True), ("github", "alice", True), ("github", "bob", True)))
    reach = w.policy.keys_for(w.root, "mcp")
    assert reach.keys == (ADMIN_GH,)
    assert reach.allows_tool(ADMIN_GH, "x")
    assert not reach.allows_tool(ALICE_GH, "x") and not reach.allows_server(BOB_GH)


def test_two_foreign_servers_rank_by_owner_id(tmp_path):
    w = make_world(tmp_path, servers=(("github", "bob", True), ("github", "alice", True)))
    for owner in ("bob", "alice"):
        allow(w, "user", "carol", "server", f"github@{owner}")
    assert w.policy.keys_for(w.carol, "mcp").keys == (ALICE_GH,)


def test_a_view_maps_each_namespace_to_one_key(tmp_path):
    w = make_world(tmp_path, servers=(
        ("github", None, True), ("github", "alice", True), ("github", "bob", True),
        ("time", None, True)))
    for user in (w.alice, w.bob, w.carol):
        allow(w, "user", user.id, "global")
        for ref in ("github", "github@alice", "github@bob"):
            allow(w, "user", user.id, "server", ref)
    for user in (w.alice, w.bob, w.carol, w.root):
        keys = w.policy.keys_for(user, "mcp").keys
        namespaces = [k.namespace for k in keys]
        assert len(namespaces) == len(set(namespaces)), user.id
        assert "github" in namespaces, user.id


def test_a_global_allow_keeps_private_servers_out_of_the_view(tmp_path):
    w = make_world(tmp_path, servers=(("github", "alice", True), ("time", None, True)))
    allow(w, "user", "bob", "global")
    reach = w.policy.keys_for(w.bob, "mcp")
    assert reach.keys == (ServerKey(None, "time"),)
    assert not reach.allows_tool(ALICE_GH, "x")


def test_a_pending_server_is_not_in_the_mcp_view_of_its_owner(tmp_path):
    w = make_world(tmp_path, servers=(("github", "alice", False),))
    assert w.policy.keys_for(w.alice, "mcp").keys == ()
    allow(w, "user", "bob", "server", "github@alice")
    assert w.policy.keys_for(w.bob, "mcp").keys == ()


def test_an_owner_deny_removes_the_own_server_from_the_view(tmp_path):
    w = make_world(tmp_path, servers=(("github", "alice", True),))
    assert w.policy.keys_for(w.alice, "mcp").keys == (ALICE_GH,)
    allow(w, "user", "alice", "server", "github@alice", effect="deny")
    reach = w.policy.keys_for(w.alice, "mcp")
    assert not reach.allows_tool(ALICE_GH, "x")


def test_the_dashboard_surface_for_admin_and_user(tmp_path):
    w = make_world(tmp_path, servers=(
        ("github", "alice", False), ("git", "bob", True), ("time", None, True)))
    admin_keys = set(w.policy.keys_for(w.root, "dashboard").keys)
    assert admin_keys == {ServerKey("alice", "github"), ServerKey("bob", "git"),
                          ServerKey(None, "time")}
    reach = w.policy.keys_for(w.alice, "dashboard")
    assert ALICE_GH in reach.keys  # own key in every approval state
    assert ServerKey("bob", "git") not in reach.keys
    allow(w, "user", "alice", "server", "time")
    assert set(w.policy.keys_for(w.alice, "dashboard").keys) == {
        ALICE_GH, ServerKey(None, "time")}


def test_reach_is_false_outside_keys_and_true_inside_for_an_admin(tmp_path):
    w = make_world(tmp_path, servers=(("github", "alice", True), ("time", None, True)))
    reach = w.policy.keys_for(w.root, "mcp")
    assert reach.allows_tool(ServerKey(None, "time"), "anything")
    assert reach.allows_server(ServerKey(None, "time"))
    assert not reach.allows_tool(ALICE_GH, "x")
    assert not reach.allows_server(ALICE_GH)


def test_can_manage_is_for_the_admin_and_the_owner_only(tmp_path):
    w = make_world(tmp_path, servers=(("github", "alice", True),))
    assert w.policy.can_manage(w.root, ALICE_GH)
    assert w.policy.can_manage(w.alice, ALICE_GH)
    assert not w.policy.can_manage(w.bob, ALICE_GH)
    allow(w, "user", "bob", "server", "github@alice")  # a grant is not management
    assert not w.policy.can_manage(w.bob, ALICE_GH)


# --- Setup codes through the policy (user-self-service-password, 7.3) --------
#
# `AccessPolicy` keeps the admin check, the Local-provider check, and the
# clearing of residue; it offers no `set_password`. Scenarios: identity delta
# "Setup code" and "No admin-chosen password".


def test_a_non_admin_actor_cannot_create_a_user_or_issue_a_code(tmp_path):
    w = make_world(tmp_path)
    before = _files(tmp_path)
    with pytest.raises(PermissionError):
        w.policy.create_user(w.alice, "dave")
    with pytest.raises(PermissionError):
        w.policy.issue_setup_code(w.alice, "bob")
    assert w.ident.get_user("dave") is None
    assert w.ident.get_user("bob").pending is False
    assert _files(tmp_path) == before


def test_the_admin_creates_a_pending_user_and_gets_the_code(tmp_path):
    w = make_world(tmp_path)
    user, code = w.policy.create_user(w.root, "dave", name="Dave", groups=["eng"])
    assert user.id == "dave" and user.pending is True
    assert user.groups == frozenset({"eng"})
    assert isinstance(code, str) and code
    assert w.ident.check_setup_code("dave", code) is not None
    assert code not in (tmp_path / "users.json").read_text()
    # An existing id is refused, and the refusal leaves its tokens alone.
    w.policy.mint_token(w.root, "laptop", "mcp", "bob")
    with pytest.raises(ValueError):
        w.policy.create_user(w.root, "bob")
    assert len(w.tokens.list_for("bob")) == 1
    assert w.ident.get_user("bob").pending is False


def test_a_non_local_provider_refuses_creates_and_resets(tmp_path):
    """The Local-provider check: an external provider owns its own users."""
    w = make_world(tmp_path)
    external = SimpleNamespace(kind="keycloak", get_user=w.ident.get_user)
    policy = AccessPolicy(external, w.rules, w.tokens, w.reg)
    with pytest.raises(ValueError):
        policy.local_identity()
    with pytest.raises(ValueError):
        policy.create_user(w.root, "dave")
    with pytest.raises(ValueError):
        policy.issue_setup_code(w.root, "bob")
    # The Local provider answers with itself.
    assert w.policy.local_identity() is w.ident


def test_a_non_local_provider_refuses_remove_member_and_writes_nothing(tmp_path):
    """`remove_member` checks the admin first, then the Local provider."""
    w = make_world(tmp_path)
    external = SimpleNamespace(kind="keycloak", get_user=w.ident.get_user)
    policy = AccessPolicy(external, w.rules, w.tokens, w.reg)
    before = _files(tmp_path)
    with pytest.raises(PermissionError):
        policy.remove_member(w.alice, "eng", "alice")
    with pytest.raises(ValueError, match="manages its own users"):
        policy.remove_member(w.root, "eng", "alice")
    assert _files(tmp_path) == before
    assert w.ident.get_user("alice").groups == frozenset({"eng"})


def test_the_admin_check_runs_before_the_provider_check(tmp_path):
    w = make_world(tmp_path)
    external = SimpleNamespace(kind="keycloak", get_user=lambda uid: None)
    policy = AccessPolicy(external, w.rules, w.tokens, w.reg)
    with pytest.raises(PermissionError):
        policy.create_user(w.alice, "dave")
    with pytest.raises(PermissionError):
        policy.issue_setup_code(w.alice, "bob")


def test_create_clears_the_residue_of_an_interrupted_delete(tmp_path):
    """A delete that stopped after the identity leaves tokens and rules on the
    id; a create of the same id starts clean (design D8b)."""
    w = make_world(tmp_path)
    make_user(w.policy, "dave", "pw")
    w.policy.mint_token(w.root, "laptop", "mcp", "dave")
    allow(w, "user", "dave", "server", "time")
    allow(w, "user", "carol", "server", "time")
    w.ident._delete_user("dave")  # the identity step done, the cascade not
    assert w.tokens.list_for("dave") and len(w.rules.list()) == 2
    user, code = w.policy.create_user(w.root, "dave")
    assert user.pending is True and code
    assert w.tokens.list_for("dave") == []
    assert [r.subject for r in w.rules.list()] == ["carol"]
    assert w.policy.keys_for(w.ident.get_user("dave"), "mcp").keys == ()


def test_a_reset_ends_the_password_and_the_sessions(tmp_path):
    w = make_world(tmp_path)
    old_binding = w.ident.session_binding("bob")
    assert old_binding is not None
    code = w.policy.issue_setup_code(w.root, "bob")
    assert w.ident.get_user("bob").pending is True
    assert w.ident.authenticate("bob", "pw") is None
    assert w.ident.session_binding("bob") is None  # a cookie of bob verifies no more
    assert w.ident.check_setup_code("bob", code) is not None
    # A reset keeps the groups and the role; only the credential ends.
    assert w.ident.get_user("alice").groups == frozenset({"eng"})
    w.policy.issue_setup_code(w.root, "alice")
    assert w.ident.get_user("alice").groups == frozenset({"eng"})


def test_a_reset_of_the_bootstrap_admin_is_refused(tmp_path):
    w = make_world(tmp_path)
    before = _files(tmp_path)
    with pytest.raises(ValueError):
        w.policy.issue_setup_code(w.root, "admin")
    assert _files(tmp_path) == before
    assert w.ident.authenticate("admin", "pw") is not None


def test_a_reset_of_an_unknown_user_raises_key_error(tmp_path):
    w = make_world(tmp_path)
    with pytest.raises(KeyError):
        w.policy.issue_setup_code(w.root, "nobody")


def test_the_policy_has_no_set_password(tmp_path):
    """No admin-chosen password / No set_password."""
    w = make_world(tmp_path)
    assert not hasattr(AccessPolicy, "set_password")
    assert not hasattr(w.policy, "set_password")


# --- Remove one membership (security-page, specs/identity) -------------------


def test_the_admin_removes_one_membership(tmp_path):
    """Remove one membership / Remove a member, through AccessPolicy."""
    w = make_world(tmp_path)
    w.ident.set_groups("alice", ["eng", "ops"])
    w.policy.remove_member(w.root, "eng", "alice")
    assert w.ident.get_user("alice").groups == frozenset({"ops"})
    assert json.loads((tmp_path / "users.json").read_text())  # still valid JSON
    w.policy.remove_member(w.root, "ops", "alice")
    assert w.ident.get_user("alice").groups == frozenset()


def test_a_non_admin_actor_cannot_remove_a_member(tmp_path):
    """Remove one membership / A non-admin actor."""
    w = make_world(tmp_path)
    before = _files(tmp_path)
    with pytest.raises(PermissionError):
        w.policy.remove_member(w.bob, "eng", "alice")
    assert w.ident.get_user("alice").groups == frozenset({"eng"})
    assert _files(tmp_path) == before


def test_the_admin_check_runs_before_the_name_check(tmp_path):
    """`AccessPolicy.remove_member` checks the admin role first: a non-admin
    actor with unknown names gets PermissionError, not KeyError."""
    w = make_world(tmp_path)
    before = _files(tmp_path)
    with pytest.raises(PermissionError):
        w.policy.remove_member(w.bob, "nope", "nobody")
    assert _files(tmp_path) == before


def test_the_policy_remove_of_an_unknown_name_writes_nothing(tmp_path):
    """Remove one membership / An unknown name, through AccessPolicy."""
    w = make_world(tmp_path)
    before = _files(tmp_path)
    with pytest.raises(KeyError):
        w.policy.remove_member(w.root, "eng", "nobody")
    with pytest.raises(KeyError):
        w.policy.remove_member(w.root, "nope", "alice")
    assert _files(tmp_path) == before
