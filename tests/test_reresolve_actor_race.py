"""A revoke between the gate and the write, end to end (reresolve-actor-at-write, T6).

Scenarios of `specs/access-policy/spec.md` ("A revoke between the gate and the
write refuses the write", "... a web write ...", "A deleted actor is refused",
"A refused cascade changes no store", "A revoke after the commit does not undo
the write", "A demoted admin's add is refused") and `specs/admin-api/spec.md`
("A deleted actor yields 403 before the target lookup"). Model: `WriteByCurrentAdmin`,
`NoWriteByDeleted`, `CommittedWriteStays`. The revoke runs inside the first
ASGI `receive` of the handler (N2), or at route entry for a request with no body.
"""

from __future__ import annotations

import json

from conftest import ADMIN_ACTOR, make_user
from dashboard_site import bearer, make_mu_site  # noqa: F401
from reresolve_race import (
    delete_user,
    demote_alice,
    make_admin_user,
    make_second_admin,
    revoke_during_body,
    revoke_then_capture,
    stores,
)

ALL = ("users.json", "rules.json", "tokens.json", "user_tokens.json",
       "servers.json", "user_servers.json")
RULE = {"subject_kind": "user", "subject": "bob", "level": "server",
        "server": "time", "effect": "allow"}


def refs(site) -> set[str]:
    return {s.key.ref for s in site.app.state.supervisor.registry.list()}


def test_post_api_rules_by_a_revoked_admin_answers_403(make_mu_site):  # noqa: F811
    """Scenario "A revoke between the gate and the write refuses the write"."""
    site = make_mu_site()
    token = make_second_admin(site)
    revoke, after = revoke_then_capture(site, demote_alice(site), ALL)
    fired = revoke_during_body(site.app, "POST", "/api/rules", revoke)
    resp = site.client.post("/api/rules", headers=bearer(token), json=RULE)
    assert fired, "the revoke never ran: the window was not exercised"
    assert resp.status_code == 403, (resp.status_code, resp.text)
    assert resp.json() == {"error": "the admin role is required"}
    assert stores(site, ALL) == after
    assert site.app.state.supervisor.policy.list_rules(ADMIN_ACTOR) == []


def test_post_users_by_a_revoked_admin_answers_403(make_mu_site):  # noqa: F811
    """Scenario "A revoke between the gate and a web write refuses the write"."""
    site = make_mu_site()
    make_second_admin(site)
    site.login("alice")
    revoke, after = revoke_then_capture(site, demote_alice(site), ALL)
    fired = revoke_during_body(site.app, "POST", "/users", revoke)
    resp = site.request("alice", "POST", "/users", data={"id": "carol"})
    assert fired
    assert (resp.status_code, resp.text) == (403, "the admin role is required")
    assert stores(site, ALL) == after
    assert site.app.state.supervisor.policy.local_identity().get_user("carol") is None


def test_post_api_servers_by_a_revoked_admin_answers_403(make_mu_site):  # noqa: F811
    """Scenario "A demoted admin's add is refused" over `/api`."""
    site = make_mu_site()
    token = make_second_admin(site)
    revoke, after = revoke_then_capture(site, demote_alice(site), ALL)
    fired = revoke_during_body(site.app, "POST", "/api/servers", revoke)
    resp = site.client.post("/api/servers", headers=bearer(token), json={
        "kind": "npm", "namespace": "extra", "package": "extra@1.0.0"})
    assert fired
    assert resp.status_code == 403, (resp.status_code, resp.text)
    assert resp.json() == {"error": "the admin role is required"}
    assert stores(site, ALL) == after
    assert not refs(site) & {"extra", "extra@alice"}


def test_delete_user_by_a_deleted_actor_answers_403(make_mu_site):  # noqa: F811
    """Scenarios "A deleted actor is refused" and "A refused cascade changes no store"."""
    site = make_mu_site()
    policy = site.app.state.supervisor.policy
    token = make_admin_user(site, "erin")
    make_user(policy, "dave")
    policy.mint_token(ADMIN_ACTOR, "t", "mcp", "dave")
    policy.add_rule(ADMIN_ACTOR, subject_kind="user", subject="dave", level="server",
                    server="time", tool=None, effect="allow")
    revoke, after = revoke_then_capture(site, delete_user(site, "erin"), ALL)
    fired = revoke_during_body(site.app, "DELETE", "/api/users/{id}", revoke, at="enter")
    resp = site.client.delete("/api/users/dave", headers=bearer(token))
    assert fired
    assert resp.status_code == 403, (resp.status_code, resp.text)
    assert resp.json() == {"error": "the acting user is unknown"}
    assert stores(site, ALL) == after
    assert policy.local_identity().get_user("dave") is not None
    assert policy.local_identity().get_user("erin") is None


def test_a_deleted_actor_yields_403_before_the_target_lookup(make_mu_site):  # noqa: F811
    """Requirement "The actor check precedes the target lookup" (admin-api)."""
    site = make_mu_site()
    token = make_admin_user(site, "erin")
    revoke, after = revoke_then_capture(site, delete_user(site, "erin"), ALL)
    fired = revoke_during_body(site.app, "POST", "/api/tokens", revoke)
    resp = site.client.post("/api/tokens", headers=bearer(token),
                            json={"name": "t", "user_id": "ghost"})
    assert fired
    assert resp.status_code == 403, (resp.status_code, resp.text)
    assert resp.json() == {"error": "the acting user is unknown"}
    assert stores(site, ALL) == after


def test_a_revoke_after_the_201_leaves_the_rule(make_mu_site):  # noqa: F811
    """Scenario "A revoke after the commit does not undo the write" (`CommittedWriteStays`)."""
    site = make_mu_site()
    token = make_second_admin(site)
    resp = site.client.post("/api/rules", headers=bearer(token), json=RULE)
    assert resp.status_code == 201, resp.text
    rule_id = resp.json()["id"]
    demote_alice(site)()
    stored = json.loads((site.data / "rules.json").read_text())["rules"]
    assert [r["id"] for r in stored] == [rule_id]
