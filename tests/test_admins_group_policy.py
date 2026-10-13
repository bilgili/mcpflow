"""`AccessPolicy` under the reserved group `admins` (admins-group, task 8.4).

Scenarios: access-policy "No grant rule on the group admins" and "Admin
bypass" (Joining admins grants the bypass); identity "Reserved group admins",
"Change memberships by delta", "Remove one membership" (non-admin actor).
Design D2, D6, D8 (policy.py), I6.
"""

from __future__ import annotations

import dataclasses
import inspect
import json
from types import SimpleNamespace

import pytest
from conftest import make_user
from dashboard_site import api_headers, make_mu_site  # noqa: F401
from test_policy import _files, allow, make_world

from mcpflow.auth import TokenStore
from mcpflow.identity import ADMINS_GROUP, LocalIdentityProvider
from mcpflow.policy import AccessPolicy, RuleStore
from mcpflow.registry import ServerKey

TIME = ServerKey(None, "time")
NO_EFFECT = ("subject: members of admins skip rule resolution; "
             "a rule on admins has no effect")


def world_with_a_rule_on_admins(tmp_path, effect="deny"):
    """A world whose `rules.json` holds a group rule on `admins`, written by
    hand (the page refuses to add one): the rule of `eng` rewritten."""
    w = make_world(tmp_path)
    seeded = allow(w, "group", "eng", "server", "time", effect=effect)
    path = tmp_path / "rules.json"
    data = json.loads(path.read_text())
    (entry,) = data["rules"]
    entry["subject"] = ADMINS_GROUP
    path.write_text(json.dumps(data))
    rules = RuleStore(path)
    rules.load()
    w.rules = rules
    w.policy = AccessPolicy(w.ident, rules, w.tokens, w.reg)
    return w, seeded.id


# --- the reserved group is protected, and its rules survive ----------------


def test_a_rule_on_admins_survives_a_refused_delete_group(tmp_path):
    """Scenario "The reserved group cannot be deleted": no grant rule is dropped."""
    w, rule_id = world_with_a_rule_on_admins(tmp_path)
    before = _files(tmp_path)
    with pytest.raises(ValueError):
        w.policy.delete_group(w.root, "admins")
    assert [r.id for r in w.policy.list_rules(w.root)] == [rule_id]
    assert _files(tmp_path) == before  # users.json and rules.json unchanged
    assert "admins" in w.ident.list_groups()


def test_a_rule_on_admins_survives_a_refused_create_group(tmp_path):
    """Scenario "The reserved group cannot be created twice"."""
    w, rule_id = world_with_a_rule_on_admins(tmp_path)
    before = _files(tmp_path)
    with pytest.raises(ValueError):
        w.policy.create_group(w.root, "admins")
    assert [r.id for r in w.policy.list_rules(w.root)] == [rule_id]
    assert _files(tmp_path) == before


# --- the actor gate (I6) ---------------------------------------------------

CALLS = {
    "change_groups": lambda p, a: p.change_groups(a, "alice", add=["ops"]),
    "set_groups": lambda p, a: p.set_groups(a, "alice", ["eng", "ops"]),
    "set_admin": lambda p, a: p.set_admin(a, "alice", True),
    "remove_member": lambda p, a: p.remove_member(a, "eng", "alice"),
    "create_user": lambda p, a: p.create_user(a, "dave", groups=["admins"]),
    "grant_self": lambda p, a: p.change_groups(a, a.id, add=["admins"]),
}


@pytest.mark.parametrize("name", sorted(CALLS))
def test_a_non_admin_actor_is_refused(tmp_path, name):
    """Scenario "A non-admin actor" (I6): `PermissionError`, nothing changes."""
    w = make_world(tmp_path)
    before = _files(tmp_path)
    with pytest.raises(PermissionError):
        CALLS[name](w.policy, w.bob)
    assert _files(tmp_path) == before
    assert w.ident.get_user("bob").is_admin is False


@pytest.mark.parametrize("name", sorted(CALLS))
def test_the_actor_gate_runs_before_the_provider_checks(tmp_path, name):
    """Admin check first, then the Local provider: a non-admin actor against a
    non-Local provider gets `PermissionError`; an admin gets `ValueError`."""
    w = make_world(tmp_path)
    external = SimpleNamespace(kind="keycloak", get_user=w.ident.get_user)
    policy = AccessPolicy(external, w.rules, w.tokens, w.reg)
    before = _files(tmp_path)
    with pytest.raises(PermissionError):
        CALLS[name](policy, w.bob)
    with pytest.raises(ValueError, match="manages its own users"):
        CALLS[name](policy, w.root)
    assert _files(tmp_path) == before


def test_the_admin_check_runs_before_the_name_checks(tmp_path):
    w = make_world(tmp_path)
    with pytest.raises(PermissionError):
        w.policy.change_groups(w.bob, "nobody", add=["nope"])
    with pytest.raises(PermissionError):
        w.policy.set_groups(w.bob, "nobody", ["nope"])


def test_an_actor_in_admins_passes_the_gate(tmp_path):
    """The gate reads membership: an actor with `admins` in its groups is one."""
    w = make_world(tmp_path)
    make_user(w.ident, "boss", groups=[ADMINS_GROUP])
    actor = w.ident.get_user("boss")
    w.policy.change_groups(actor, "alice", add=["ops"])
    assert w.ident.get_user("alice").groups == frozenset({"eng", "ops"})
    outsider = dataclasses.replace(actor, groups=frozenset({"eng"}))
    with pytest.raises(PermissionError):
        w.policy.change_groups(outsider, "alice", add=["interns"])


def test_the_policy_passes_provider_errors_through(tmp_path):
    w = make_world(tmp_path)
    before = _files(tmp_path)
    with pytest.raises(KeyError):
        w.policy.change_groups(w.root, "ghost", add=["eng"])
    with pytest.raises(ValueError):
        w.policy.change_groups(w.root, "alice", add=["nope"])
    with pytest.raises(ValueError):
        w.policy.change_groups(w.root, "alice", add=["eng"], remove=["eng"])
    with pytest.raises(ValueError):
        w.policy.change_groups(w.root, "admin", remove=["admins"])
    with pytest.raises(ValueError):
        w.policy.set_groups(w.root, "alice", ["admins"])
    with pytest.raises(ValueError):
        w.policy.set_groups(w.root, "alice", ["admins"], admin=False)
    with pytest.raises(ValueError):
        w.policy.set_admin(w.root, "admin", False)
    with pytest.raises(ValueError):
        w.policy.remove_member(w.root, "admins", "admin")
    with pytest.raises(ValueError):
        w.policy.create_user(w.root, "dave", admin=False, groups=["admins"])
    assert _files(tmp_path) == before


def test_the_policy_reaches_the_provider(tmp_path):
    w = make_world(tmp_path)
    w.policy.change_groups(w.root, "alice", add=["ops"], remove=["eng"])
    assert w.ident.get_user("alice").groups == frozenset({"ops"})
    w.policy.set_groups(w.root, "alice", ["eng"], admin=True)
    assert w.ident.get_user("alice").groups == frozenset({"admins", "eng"})
    w.policy.set_admin(w.root, "alice", False)
    assert w.ident.get_user("alice").groups == frozenset({"eng"})
    user, code = w.policy.create_user(w.root, "dave", admin=True)
    assert user.is_admin and code
    w.policy.remove_member(w.root, "admins", "dave")
    assert w.ident.get_user("dave").is_admin is False


# --- add_rule ---------------------------------------------------------------


def test_add_rule_refuses_admins(tmp_path):
    """Scenario "A new rule on admins is refused"."""
    w = make_world(tmp_path)
    allow(w, "group", "eng", "server", "time")
    before = _files(tmp_path)
    for level, server in (("server", "time"), ("global", None)):
        with pytest.raises(ValueError) as exc:
            w.policy.add_rule(w.root, subject_kind="group", subject="admins",
                              level=level, server=server, tool=None, effect="deny")
        assert str(exc.value) == NO_EFFECT
    assert _files(tmp_path) == before
    assert len(w.rules.list()) == 1


def test_add_rule_accepts_eng(tmp_path):
    """Scenario "A rule on another group is accepted"."""
    w = make_world(tmp_path)
    added = w.policy.add_rule(w.root, subject_kind="group", subject="eng",
                              level="server", server="time", tool=None, effect="allow")
    assert added.subject == "eng" and added.id
    assert [r.id for r in w.rules.list()] == [added.id]


def test_add_rule_refuses_only_the_group_kind(tmp_path):
    """The refusal needs `subject_kind == "group"`: a user can carry the id `admins`."""
    w = make_world(tmp_path)
    w.ident._create_user("admins")
    added = w.policy.add_rule(w.root, subject_kind="user", subject="admins",
                              level="server", server="time", tool=None, effect="allow")
    assert added.subject_kind == "user"


def test_add_rule_error_order(tmp_path):
    """Admin check, then the shape check, then the refusal for `admins`."""
    w = make_world(tmp_path)
    before = _files(tmp_path)
    with pytest.raises(PermissionError):
        w.policy.add_rule(w.bob, subject_kind="group", subject="admins",
                          level="global", server=None, tool=None, effect="deny")
    # A shape error wins over the `admins` refusal: a tool rule with no tool.
    with pytest.raises(ValueError) as exc:
        w.policy.add_rule(w.root, subject_kind="group", subject="admins",
                          level="tool", server="time", tool=None, effect="deny")
    assert "tool" in str(exc.value) and str(exc.value) != NO_EFFECT
    # A well-formed rule on `admins` gets the refusal, not "unknown subject".
    with pytest.raises(ValueError) as exc:
        w.policy.add_rule(w.root, subject_kind="group", subject="admins",
                          level="global", server=None, tool=None, effect="allow")
    assert str(exc.value) == NO_EFFECT
    assert _files(tmp_path) == before


# --- a loaded rule on admins has no effect ----------------------------------


def test_a_loaded_rule_on_admins_has_no_effect(tmp_path):
    """Scenario "A loaded rule on admins has no effect": the admin still sees
    the tools of `time`; the rule lists and deletes as before."""
    w, rule_id = world_with_a_rule_on_admins(tmp_path, effect="deny")
    assert [r.id for r in w.policy.list_rules(w.root)] == [rule_id]
    admin = w.ident.get_user("admin")
    reach = w.policy.keys_for(admin, "mcp")
    assert TIME in reach.keys
    assert reach.allows_tool(TIME, "x") is True
    # A second admin, made by membership, is not hidden either.
    w.ident.change_groups("alice", add=["admins"])
    alice = w.ident.get_user("alice")
    assert w.policy.keys_for(alice, "mcp").allows_tool(TIME, "x") is True
    # It deletes.
    w.policy.remove_rule(w.root, rule_id)
    assert w.policy.list_rules(w.root) == []
    assert TIME in w.policy.keys_for(admin, "mcp").keys


# --- Admin bypass -----------------------------------------------------------


def test_joining_admins_grants_the_bypass(tmp_path):
    """Scenario "Joining admins grants the bypass": a deny on `eng` (ops
    allows, conflicting groups deny) hides `time`; membership lifts it on the
    next request."""
    w = make_world(tmp_path)
    w.ident.change_groups("alice", add=["ops"])
    allow(w, "group", "ops", "server", "time", effect="allow")
    allow(w, "group", "eng", "server", "time", effect="deny")
    alice = w.ident.get_user("alice")
    assert w.policy.keys_for(alice, "mcp").allows_tool(TIME, "x") is False
    w.policy.change_groups(w.root, "alice", add=["admins"])
    alice = w.ident.get_user("alice")
    assert alice.is_admin
    reach = w.policy.keys_for(alice, "mcp")
    assert TIME in reach.keys and reach.allows_tool(TIME, "x") is True


def test_leaving_admins_ends_the_bypass(tmp_path):
    """The decision reads the membership on every request."""
    w = make_world(tmp_path)
    allow(w, "group", "eng", "server", "time", effect="deny")
    w.policy.change_groups(w.root, "alice", add=["admins"])
    assert w.policy.keys_for(w.ident.get_user("alice"), "mcp").allows_tool(TIME, "x")
    w.policy.remove_member(w.root, "admins", "alice")
    assert not w.policy.keys_for(w.ident.get_user("alice"), "mcp").allows_tool(TIME, "x")


def test_the_admin_role_is_membership_not_a_stored_flag(tmp_path):
    """No user record holds the role apart from its groups."""
    w = make_world(tmp_path)
    w.policy.set_admin(w.root, "alice", True)
    data = json.loads((tmp_path / "users.json").read_text())
    assert all("admin" not in r for r in data["users"])
    alice = next(r for r in data["users"] if r["id"] == "alice")
    assert "admins" in alice["groups"]


# --- the frozen signatures of D8 (policy.py) --------------------------------

P = inspect.Parameter
E = P.empty


def sig(fn) -> list[tuple[str, object, object]]:
    return [(n, p.kind, p.default) for n, p in inspect.signature(fn).parameters.items()]


def test_the_policy_signatures_are_the_frozen_ones():
    assert sig(AccessPolicy.create_user) == [
        ("self", P.POSITIONAL_OR_KEYWORD, E), ("actor", P.POSITIONAL_OR_KEYWORD, E),
        ("user_id", P.POSITIONAL_OR_KEYWORD, E), ("name", P.KEYWORD_ONLY, ""),
        ("admin", P.KEYWORD_ONLY, None), ("groups", P.KEYWORD_ONLY, ()),
    ]
    assert sig(AccessPolicy.change_groups) == [
        ("self", P.POSITIONAL_OR_KEYWORD, E), ("actor", P.POSITIONAL_OR_KEYWORD, E),
        ("user_id", P.POSITIONAL_OR_KEYWORD, E), ("add", P.POSITIONAL_OR_KEYWORD, ()),
        ("remove", P.POSITIONAL_OR_KEYWORD, ()),
    ]
    assert sig(AccessPolicy.set_groups) == [
        ("self", P.POSITIONAL_OR_KEYWORD, E), ("actor", P.POSITIONAL_OR_KEYWORD, E),
        ("user_id", P.POSITIONAL_OR_KEYWORD, E), ("groups", P.POSITIONAL_OR_KEYWORD, E),
        ("admin", P.KEYWORD_ONLY, None),
    ]
    assert sig(AccessPolicy.set_admin) == [
        ("self", P.POSITIONAL_OR_KEYWORD, E), ("actor", P.POSITIONAL_OR_KEYWORD, E),
        ("user_id", P.POSITIONAL_OR_KEYWORD, E), ("admin", P.POSITIONAL_OR_KEYWORD, E),
    ]
    assert sig(AccessPolicy.remove_member) == [
        ("self", P.POSITIONAL_OR_KEYWORD, E), ("actor", P.POSITIONAL_OR_KEYWORD, E),
        ("group", P.POSITIONAL_OR_KEYWORD, E), ("user_id", P.POSITIONAL_OR_KEYWORD, E),
    ]



# --- private-cascade-halves: the create order and the group delete -----------


def world_with_residue(tmp_path):
    """A world where the deleted id `dave` holds a residue token and a residue
    rule: the identity delete ran, the cascade did not."""
    w = make_world(tmp_path)
    make_user(w.policy, "dave", "pw")
    w.policy.mint_token(w.root, "laptop", "mcp", "dave")
    allow(w, "user", "dave", "server", "time")
    w.ident._delete_user("dave")
    assert w.ident.get_user("dave") is None
    assert w.tokens.list_for("dave") and [r.subject for r in w.rules.list()] == ["dave"]
    return w


def _spy(monkeypatch, log, *targets):
    """Record each call of `(class, method name)` in `log`, then run it."""
    for cls, name in targets:
        orig = getattr(cls, name)

        def spy(self, *a, _orig=orig, _name=name, **k):
            log.append(_name)
            return _orig(self, *a, **k)

        monkeypatch.setattr(cls, name, spy)


def test_a_generator_of_groups_is_read_once(tmp_path):
    """Scenario "A generator of groups": the policy and the provider each give
    the new user the group the generator yields."""
    w = make_world(tmp_path)
    w.policy.create_user(w.root, "erin", groups=(g for g in ["eng"]))
    assert w.ident.get_user("erin").groups == frozenset({"eng"})
    w.ident._create_user("dave", groups=(g for g in ["eng"]))
    assert w.ident.get_user("dave").groups == frozenset({"eng"})


@pytest.mark.parametrize("kwargs", [
    {"groups": ["nope"]},
    {"admin": False, "groups": ["admins"]},
    {"name": 5},
], ids=["unknown-group", "contradiction", "name-type"])
def test_a_refused_create_changes_no_store(tmp_path, kwargs):
    """Scenarios "A refused create with an unknown group keeps the residue" and
    "... with a contradiction ...": every refusal comes before the clear."""
    w = world_with_residue(tmp_path)
    before = _files(tmp_path)
    assert {"users.json", "user_tokens.json", "rules.json"} <= set(before)
    with pytest.raises(ValueError):
        w.policy.create_user(w.root, "dave", **kwargs)
    assert _files(tmp_path) == before
    assert w.tokens.list_for("dave") and [r.subject for r in w.rules.list()] == ["dave"]


def test_check_create_user_runs_before_the_clear(tmp_path, monkeypatch):
    """Scenario "The pre-check runs before the clear". `_create_user` calls its
    pre-check again, so only the first four calls count."""
    w = make_world(tmp_path)
    log: list[str] = []
    _spy(monkeypatch, log, (LocalIdentityProvider, "check_create_user"),
         (TokenStore, "revoke_user"), (RuleStore, "drop_subject"),
         (LocalIdentityProvider, "_create_user"))
    w.policy.create_user(w.root, "dave")
    assert log[:4] == ["check_create_user", "revoke_user", "drop_subject", "_create_user"]


def test_check_create_group_runs_before_the_drop(tmp_path, monkeypatch):
    """Scenario "A refused group create drops no rule", and the order of a
    valid create (`_create_group` calls its pre-check again)."""
    w = make_world(tmp_path)
    log: list[str] = []
    _spy(monkeypatch, log, (LocalIdentityProvider, "check_create_group"),
         (RuleStore, "drop_subject"), (LocalIdentityProvider, "_create_group"))
    w.policy.create_group(w.root, "ops2")
    assert log[:3] == ["check_create_group", "drop_subject", "_create_group"]
    log.clear()
    before = _files(tmp_path)
    with pytest.raises(ValueError, match="invalid group name"):
        w.policy.create_group(w.root, "Bad Name")
    assert "drop_subject" not in log
    assert _files(tmp_path) == before


def test_a_failed_identity_write_after_the_clear_leaves_no_residue(tmp_path, monkeypatch):
    """Scenario "A failed identity write after the clear leaves no user and no
    residue"."""
    w = world_with_residue(tmp_path)

    def boom(self, *a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(LocalIdentityProvider, "_save", boom)
    with pytest.raises(OSError):
        w.policy.create_user(w.root, "dave")
    assert w.ident.get_user("dave") is None
    assert w.tokens.list_for("dave") == []
    assert w.rules.list() == []


def test_an_unknown_group_delete_changes_no_store(tmp_path, monkeypatch):
    """Requirement "Removal of a user or a group cascades": every refusal of
    `AccessPolicy.delete_group` comes before the identity write, and an unknown
    group raises `KeyError("nope")` from the provider."""
    w = make_world(tmp_path)
    allow(w, "group", "eng", "server", "time")
    before = _files(tmp_path)
    log: list[str] = []
    _spy(monkeypatch, log, (RuleStore, "drop_subject"))
    with pytest.raises(KeyError) as exc:
        w.policy.delete_group(w.root, "nope")
    assert exc.value.args == ("nope",)
    assert log == []
    assert _files(tmp_path) == before


def test_an_unknown_group_api_delete_answers_404(make_mu_site):  # noqa: F811
    """The same refusal over `/api`: `404` with the name and ` not found`."""
    site = make_mu_site()
    before = (site.data / "users.json").read_bytes()
    resp = site.client.delete("/api/groups/nope", headers=api_headers(site))
    assert resp.status_code == 404
    assert resp.json() == {"error": "nope not found"}
    assert (site.data / "users.json").read_bytes() == before
