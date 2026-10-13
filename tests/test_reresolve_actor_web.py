"""The add routes answer a write-time refusal with 403 (reresolve-actor-at-write, T3).

Requirement "Add routes answer a write-time refusal with 403" of
`specs/web-ui/spec.md` in the change, and the scenarios of access-policy
"A deleted user's add is refused", "A user add is unchanged", "A non-admin actor
mints an own token as before". Each refusal is held between the gate and the
write by `reresolve_race.revoke_during_body`. Design D4, D5.
"""

from __future__ import annotations

from dashboard_site import make_mu_site  # noqa: F401
from reresolve_race import (
    delete_user,
    demote_alice,
    make_second_admin,
    revoke_during_body,
)

from mcpflow.registry import ServerKey

PUBLIC = "https://mcp.example.org"
REGISTRY_FILES = ("servers.json", "user_servers.json")
NPM_FORM = {"kind": "npm", "namespace": "extra", "package": "extra@1.0.0"}


def files(site, names=REGISTRY_FILES) -> dict[str, bytes | None]:
    return {n: (site.data / n).read_bytes() if (site.data / n).exists() else None
            for n in names}


def admin_alice(site):
    """`alice` is an admin with a session. The session is taken after the promotion."""
    make_second_admin(site)
    site.login("alice")


def refs(site) -> set[str]:
    return {s.key.ref for s in site.app.state.supervisor.registry.list()}


def test_a_demoted_admin_posts_the_add_server_form(make_mu_site):  # noqa: F811
    """Scenario "A demoted admin posts the add-server form"."""
    site = make_mu_site()
    admin_alice(site)
    before = files(site)
    fired = revoke_during_body(site.app, "POST", "/servers", demote_alice(site))
    resp = site.request("alice", "POST", "/servers", data=NPM_FORM)
    assert fired, "the revoke never ran: the window was not exercised"
    assert (resp.status_code, resp.text) == (403, "the admin role is required")
    assert files(site) == before
    assert not refs(site) & {"extra", "extra@alice"}


def test_a_deleted_user_posts_the_add_server_form(make_mu_site):  # noqa: F811
    """Scenario "A deleted user's add is refused"."""
    site = make_mu_site()
    # `delete_user` refuses an owner, so bob's server goes first.
    assert site.request("bob", "POST", "/servers/github@bob/delete").status_code == 303
    before = files(site)
    fired = revoke_during_body(site.app, "POST", "/servers", delete_user(site, "bob"))
    resp = site.request("bob", "POST", "/servers", data=NPM_FORM)
    assert fired
    assert resp.status_code == 403, (resp.status_code, resp.text)
    assert "the acting user is unknown" in resp.text
    assert files(site) == before
    assert "extra@bob" not in refs(site)


def test_a_demoted_admin_posts_the_plain_marketplace_connect(make_mu_site):  # noqa: F811
    site = make_mu_site()
    admin_alice(site)
    sup = site.app.state.supervisor
    sup.registry.remove(ServerKey(None, "time"))  # the plain entry `time` is free
    before = files(site)
    fired = revoke_during_body(site.app, "POST", "/marketplace/{id}/connect",
                               demote_alice(site))
    resp = site.request("alice", "POST", "/marketplace/time/connect",
                        data={"namespace": "time"})
    assert fired
    assert (resp.status_code, resp.text) == (403, "the admin role is required")
    assert files(site) == before
    assert "time" not in refs(site)


def test_a_demoted_admin_posts_the_oauth_marketplace_connect(make_mu_site):  # noqa: F811
    """Scenario "A demoted admin connects an OAuth marketplace entry"."""
    site = make_mu_site(PUBLIC_URL=PUBLIC)
    admin_alice(site)
    sup = site.app.state.supervisor
    before = files(site)
    fired = revoke_during_body(site.app, "POST", "/marketplace/{id}/connect",
                               demote_alice(site))
    resp = site.request("alice", "POST", "/marketplace/gmail/connect", data={
        "namespace": "gmail", "client_id": "abc", "client_secret": "shhh"})
    assert fired
    assert resp.status_code == 403, (resp.status_code, resp.text[:200])
    assert resp.text == "the admin role is required"
    assert files(site) == before
    assert "gmail" not in refs(site)
    assert not (site.data / "creds" / "gmail").exists()
    assert not sup.flows.has_open("gmail")


def test_a_user_add_over_the_web_is_unchanged(make_mu_site):  # noqa: F811
    """Scenario "A user add is unchanged"."""
    site = make_mu_site()
    assert site.request("bob", "POST", "/servers/github@bob/delete").status_code == 303
    resp = site.request("bob", "POST", "/servers", data={
        "kind": "npm", "namespace": "github", "package": "x@1.0.0"})
    assert resp.status_code == 303 and resp.headers["location"] == "/"
    stored = site.app.state.supervisor.registry.get(ServerKey("bob", "github"))
    assert stored.owner == "bob" and stored.approval == "pending"


def test_a_non_admin_mints_an_own_token_on_the_web(make_mu_site):  # noqa: F811
    """Scenario "A non-admin actor mints an own token as before"."""
    site = make_mu_site()
    policy = site.app.state.supervisor.policy
    alice = policy.local_identity().get_user("alice")
    held = len(policy.tokens_for(alice))
    resp = site.request("alice", "POST", "/tokens", data={"name": "second", "scope": "mcp"})
    assert resp.status_code == 200, resp.text[:200]
    assert "second" in resp.text
    assert len(policy.tokens_for(alice)) == held + 1


def test_a_still_admin_posts_the_add_server_form(make_mu_site):  # noqa: F811
    """The control of the refusals: without a revoke the same post succeeds."""
    site = make_mu_site()
    admin_alice(site)
    resp = site.request("alice", "POST", "/servers", data=NPM_FORM)
    assert resp.status_code == 303, (resp.status_code, resp.text[:200])
    assert "extra" in refs(site)
