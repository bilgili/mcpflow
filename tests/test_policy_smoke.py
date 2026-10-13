"""Implementer smoke check of section 3. The verifier owns `test_policy.py`."""

from __future__ import annotations

import stat

import pytest
from conftest import make_user

from mcpflow.auth import TokenStore, hash_password
from mcpflow.identity import ADMINS_GROUP, LocalIdentityProvider, User
from mcpflow.policy import AccessPolicy, RuleStore, resolve
from mcpflow.registry import Registry, ServerKey, ServerSpec, revision


def _user(uid: str, *groups: str, admin: bool = False) -> User:
    return User(id=uid, name=uid,
                groups=frozenset(groups) | ({ADMINS_GROUP} if admin else frozenset()),
                provider="local")


@pytest.fixture
def world(tmp_path):
    ident = LocalIdentityProvider(tmp_path / "users.json", hash_password("pw", iterations=1000))
    ident.load()
    for g in ("eng", "ops"):
        ident._create_group(g)
    for uid in ("alice", "bob", "carol"):
        make_user(ident, uid, "pw", groups=["eng"] if uid == "alice" else [])
    tokens = TokenStore(tmp_path / "tokens.json", tmp_path / "user_tokens.json")
    reg = Registry(tmp_path / "servers.json", tmp_path / "user_servers.json")
    for owner in (None, "alice", "bob"):
        spec = ServerSpec(namespace="github", kind="npm", package="p@1.0.0", owner=owner)
        reg.add(spec)
        if owner:
            reg.set_approved_revision(spec.key, revision(spec))
    reg.add(ServerSpec(namespace="time", kind="npm", package="t"))
    rules = RuleStore(tmp_path / "rules.json")
    rules.load()
    return AccessPolicy(ident, rules, tokens, reg), ident, tokens, rules, tmp_path


def test_resolve_order(world):
    policy, *_ = world
    root, alice = _user("admin", admin=True), _user("alice", "eng", "ops")
    t = ServerKey(None, "time")

    def rule(subject_kind, subject, level, effect, tool=None):
        return policy.add_rule(root, subject_kind=subject_kind, subject=subject, level=level,
                               server=None if level == "global" else "time", tool=tool, effect=effect)

    r1, r2 = rule("user", "alice", "server", "deny"), rule("group", "eng", "tool", "allow", "x")
    rs = policy._rules.list()
    assert resolve(rs, alice, t, "x") and not resolve(rs, alice, t, "y")  # level beats subject
    for r in (r1, r2):
        policy.remove_rule(root, r.id)
    rule("group", "eng", "server", "allow"), rule("group", "ops", "server", "deny")
    assert not resolve(policy._rules.list(), alice, t, "x")  # conflicting groups deny
    rule("user", "alice", "server", "allow")
    assert resolve(policy._rules.list(), alice, t, None)  # user beats group
    assert not resolve([], alice, t, "x")  # no rule: deny
    own = ServerKey("alice", "github")
    assert resolve([], alice, own, "x")  # owner default
    g = rule("user", "alice", "global", "allow")
    assert not resolve([g], alice, ServerKey("bob", "github"), "x")  # global allow: shared only
    d = policy.add_rule(root, subject_kind="user", subject="alice", level="global",
                        server=None, tool=None, effect="deny")
    assert not resolve([d], alice, own, "x")  # global deny beats the owner default


def test_store_and_refusals(world):
    policy, _, _, rules, tmp = world
    root = _user("admin", admin=True)
    policy.add_rule(root, subject_kind="group", subject="eng", level="server",
                    server="time", tool=None, effect="allow")
    assert stat.S_IMODE((tmp / "rules.json").stat().st_mode) == 0o600
    before = (tmp / "rules.json").read_text()
    for kw, field in (({"level": "tool", "server": "time", "tool": None}, "tool"),
                      ({"level": "server", "server": "nope", "tool": None}, "server")):
        with pytest.raises(ValueError, match=field):
            policy.add_rule(root, subject_kind="user", subject="alice", effect="allow", **kw)
    assert (tmp / "rules.json").read_text() == before
    with pytest.raises(PermissionError):
        policy.remove_rule(_user("alice"), rules.list()[0].id)
    with pytest.raises(KeyError):
        rules.remove("rule_nope")
    fresh = RuleStore(tmp / "rules.json")
    fresh.load()
    assert fresh.list() == rules.list()


def test_keys_for_view(world):
    policy, *_ = world
    root, carol = _user("admin", admin=True), _user("carol")
    gh, gh_alice, gh_bob = (ServerKey(o, "github") for o in (None, "alice", "bob"))
    assert set(policy.keys_for(root, "mcp").keys) == {gh, ServerKey(None, "time")}
    assert len(policy.keys_for(root, "dashboard").keys) == 4
    assert gh_alice in policy.keys_for(_user("alice"), "mcp").keys  # own wins
    for server in ("github", "github@bob"):
        policy.add_rule(root, subject_kind="user", subject="carol", level="server",
                        server=server, tool=None, effect="allow")
    reach = policy.keys_for(carol, "mcp")
    assert reach.keys == (gh,)  # shared beats foreign
    assert reach.allows_tool(gh, "x") and not reach.allows_tool(gh_bob, "x")
    policy.remove_rule(root, reach.rules[0].id)
    assert reach.allows_tool(gh, "x")  # C3: the snapshot decides


def test_tokens_and_cascade(world):
    policy, ident, tokens, rules, _ = world
    root, alice, bob = _user("admin", admin=True), _user("alice"), _user("bob")
    with pytest.raises(PermissionError):
        policy.mint_token(alice, "x", "admin")
    with pytest.raises(ValueError, match="user_id: unknown user ghost"):
        policy.mint_token(root, "x", "mcp", "ghost")
    rec, _ = policy.mint_token(bob, "b", "mcp")
    with pytest.raises(KeyError):
        policy.revoke_token(alice, rec.id)
    assert policy.tokens_for(alice) == [] and policy.tokens_for(root) == [rec]
    policy.add_rule(root, subject_kind="user", subject="carol", level="server",
                    server="time", tool=None, effect="allow")
    with pytest.raises(ValueError):
        policy.delete_user(root, "alice")  # owns github@alice
    with pytest.raises(ValueError):
        policy.delete_user(root, "admin")
    policy.mint_token(root, "c", "mcp", "carol")
    policy.delete_user(root, "carol")
    assert ident.get_user("carol") is None and tokens.list_for("carol") == [] and rules.list() == []
    policy.delete_group(root, "eng")
    assert "eng" not in ident.list_groups()
