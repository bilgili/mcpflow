"""The `/api` user and group resources under `admins` (admins-group, task 8.5).

Scenarios: admin-api "User and group resources" (Create an admin over the
API, A contradiction is refused on create, Grant the role over the API,
Groups without admin keep the role, Groups that drop admins without admin are
refused, Groups and admin in one write, Demote the bootstrap admin, Delete
the reserved group, A password key is refused on update); identity "Membership
grants the role" and "Leaving the group revokes the role". Design D8
(api.py), D7, R1, I7.

The site is the seeded gateway of `tests/dashboard_site.py`: users `alice` and
`bob` (active, no groups), the bootstrap `admin`, an admin token.
"""

from __future__ import annotations

import json

import pytest
from dashboard_site import api_headers, bearer, make_mu_site  # noqa: F401


def post(site, path: str, **body):
    return site.client.post(path, headers=api_headers(site), json=body)


def put(site, path: str, **body):
    return site.client.put(path, headers=api_headers(site), json=body)


def users(site) -> dict[str, dict]:
    resp = site.client.get("/api/users", headers=api_headers(site))
    assert resp.status_code == 200, resp.text
    return {u["id"]: u for u in resp.json()}


def users_file(site) -> bytes:
    return (site.data / "users.json").read_bytes()


def rules_listing(site) -> list[dict]:
    return site.client.get("/api/rules", headers=api_headers(site)).json()


@pytest.fixture
def site(make_mu_site):  # noqa: F811
    s = make_mu_site()
    for name in ("eng", "ops"):
        assert post(s, "/api/groups", name=name).status_code == 201
    return s


def make_admin(site, uid: str = "alice") -> None:
    resp = put(site, f"/api/users/{uid}", admin=True)
    assert resp.status_code == 200, resp.text


# --- PUT /api/users/{id} ----------------------------------------------------


def test_put_writes_once_for_groups_and_admin(site, users_writes):
    """Scenario "Groups and admin in one write"."""
    make_admin(site)
    users_writes["n"] = 0
    resp = put(site, "/api/users/alice", admin=False, groups=["ops"])
    assert resp.status_code == 200, resp.text
    assert resp.json()["admin"] is False and resp.json()["groups"] == ["ops"]
    assert users_writes["n"] == 1
    assert users(site)["alice"]["groups"] == ["ops"]


def test_put_groups_without_admin_keeps_the_role(site):
    """Scenario "Groups without admin keep the role"."""
    make_admin(site)
    assert put(site, "/api/users/alice", admin=True, groups=["eng"]).status_code == 200
    resp = put(site, "/api/users/alice", groups=["admins", "ops"])
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["admin"] is True and sorted(body["groups"]) == ["admins", "ops"]
    assert sorted(users(site)["alice"]["groups"]) == ["admins", "ops"]


def test_put_groups_that_drop_admins_answer_400_naming_admin(site):
    """Scenario "Groups that drop admins without admin are refused"."""
    make_admin(site)
    before = users_file(site)
    resp = put(site, "/api/users/alice", groups=["ops"])
    assert resp.status_code == 400
    assert "admin" in resp.text
    assert users(site)["alice"]["admin"] is True
    assert "admins" in users(site)["alice"]["groups"]
    assert users_file(site) == before


def test_put_groups_that_add_admins_without_admin_are_refused(site):
    before = users_file(site)
    resp = put(site, "/api/users/alice", groups=["admins", "eng"])
    assert resp.status_code == 400 and "admin" in resp.text
    assert users(site)["alice"]["admin"] is False
    assert users_file(site) == before


def test_put_contradiction_answers_400(site):
    make_admin(site)
    before = users_file(site)
    resp = put(site, "/api/users/alice", admin=False, groups=["admins"])
    assert resp.status_code == 400
    assert users(site)["alice"]["admin"] is True
    assert users_file(site) == before


def test_put_admin_only_grants(site):
    """Scenario "Grant the role over the API"."""
    resp = put(site, "/api/users/alice", admin=True)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["admin"] is True and "admins" in body["groups"]
    assert body["id"] == "alice" and "pending" in body
    assert "password_hash" not in json.dumps(body)


def test_put_admin_only_revokes(site):
    make_admin(site)
    resp = put(site, "/api/users/alice", admin=False)
    assert resp.status_code == 200
    assert resp.json()["admin"] is False and "admins" not in resp.json()["groups"]


def test_put_admin_only_keeps_the_other_groups(site):
    assert put(site, "/api/users/alice", groups=["eng"]).status_code == 200
    resp = put(site, "/api/users/alice", admin=True)
    assert sorted(resp.json()["groups"]) == ["admins", "eng"]


def test_put_neither_writes_nothing(site, users_writes):
    make_admin(site)
    before = users_file(site)
    users_writes["n"] = 0
    resp = put(site, "/api/users/alice")
    assert resp.status_code == 200, resp.text
    assert resp.json()["id"] == "alice" and resp.json()["admin"] is True
    assert users_writes["n"] == 0 and users_file(site) == before


def test_put_password_is_refused_and_keeps_the_role(site):
    """Scenario "A password key is refused on update"."""
    make_admin(site)
    before = users_file(site)
    resp = put(site, "/api/users/alice", password="pw", admin=False)
    assert resp.status_code == 400 and "password" in resp.text
    assert users(site)["alice"]["admin"] is True
    assert users_file(site) == before


def test_put_demote_the_bootstrap_admin(site):
    """Scenario "Demote the bootstrap admin"."""
    before = users_file(site)
    resp = put(site, "/api/users/admin", admin=False)
    assert resp.status_code == 400
    assert users(site)["admin"]["admin"] is True
    assert "admins" in users(site)["admin"]["groups"]
    assert users_file(site) == before


def test_put_bootstrap_groups_without_admins_are_refused(site):
    before = users_file(site)
    for body in ({"groups": ["eng"]}, {"groups": ["eng"], "admin": False}):
        assert put(site, "/api/users/admin", **body).status_code == 400
    assert users_file(site) == before
    resp = put(site, "/api/users/admin", groups=["admins", "eng"])
    assert resp.status_code == 200
    assert sorted(resp.json()["groups"]) == ["admins", "eng"]


def test_put_unknown_group_and_unknown_user(site):
    before = users_file(site)
    assert put(site, "/api/users/alice", groups=["nope"]).status_code == 400
    assert put(site, "/api/users/ghost", groups=["eng"]).status_code == 404
    assert put(site, "/api/users/ghost", admin=True).status_code == 404
    assert users_file(site) == before


def test_put_validates_every_field_before_the_first_write(site):
    """An invalid `groups` next to a valid `admin` writes neither."""
    before = users_file(site)
    resp = put(site, "/api/users/alice", admin=True, groups=["nope"])
    assert resp.status_code == 400
    assert users(site)["alice"]["admin"] is False
    assert users_file(site) == before


# --- POST /api/users --------------------------------------------------------


def test_post_users_creates_an_admin(site):
    """Scenario "Create an admin over the API"."""
    resp = post(site, "/api/users", id="carol", admin=True, groups=["eng"])
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["admin"] is True and sorted(body["groups"]) == ["admins", "eng"]
    assert body["pending"] is True and body["setup_code"]


def test_post_users_with_admins_in_groups_creates_an_admin(site):
    """An absent `admin` passes `None`, so the groups decide the role."""
    resp = post(site, "/api/users", id="carol", groups=["admins"])
    assert resp.status_code == 201, resp.text
    assert resp.json()["admin"] is True and resp.json()["groups"] == ["admins"]


def test_post_users_without_the_flag_is_not_an_admin(site):
    resp = post(site, "/api/users", id="dave", groups=["eng"])
    assert resp.status_code == 201
    assert resp.json()["admin"] is False and resp.json()["groups"] == ["eng"]


def test_post_users_contradiction_is_400(site):
    """Scenario "A contradiction is refused on create"."""
    before = users_file(site)
    resp = post(site, "/api/users", id="carol", admin=False, groups=["admins"])
    assert resp.status_code == 400
    assert "carol" not in users(site)
    assert users_file(site) == before


@pytest.mark.parametrize("bad", ["yes", 1, 0, None, [], {}])
def test_post_users_non_boolean_admin_is_400(site, bad):
    before = users_file(site)
    resp = post(site, "/api/users", id="carol", admin=bad)
    assert resp.status_code == 400
    assert "carol" not in users(site)
    assert users_file(site) == before


def test_post_users_password_key_is_refused(site):
    resp = post(site, "/api/users", id="carol", password="pw")
    assert resp.status_code == 400 and "password" in resp.text
    assert "carol" not in users(site)


# --- the reserved group ----------------------------------------------------


def test_delete_admins_group_is_400(site):
    """Scenario "Delete the reserved group"."""
    before = users_file(site)
    resp = site.client.delete("/api/groups/admins", headers=api_headers(site))
    assert resp.status_code == 400
    listing = site.client.get("/api/groups", headers=api_headers(site))
    assert "admins" in json.dumps(listing.json())
    assert users_file(site) == before


def test_delete_another_group_is_204(site):
    resp = site.client.delete("/api/groups/ops", headers=api_headers(site))
    assert resp.status_code == 204


def test_delete_admins_group_keeps_a_rule_on_it(site, tmp_path):
    """No grant rule is dropped by the refused delete."""
    before = rules_listing(site)
    resp = site.client.delete("/api/groups/admins", headers=api_headers(site))
    assert resp.status_code == 400
    assert rules_listing(site) == before


def test_post_groups_admins_is_400(site):
    before = users_file(site)
    resp = post(site, "/api/groups", name="admins")
    assert resp.status_code == 400
    assert users_file(site) == before


def test_get_groups_lists_admins_with_its_members(site):
    make_admin(site)
    listing = site.client.get("/api/groups", headers=api_headers(site))
    assert listing.status_code == 200
    text = json.dumps(listing.json())
    assert "admins" in text and "alice" in text and "admin" in text


def test_post_rules_group_admins_is_400(site):
    before = rules_listing(site)
    resp = post(site, "/api/rules", subject_kind="group", subject="admins",
                level="server", server="time", effect="deny")
    assert resp.status_code == 400
    assert "no effect" in resp.text
    assert rules_listing(site) == before


def test_post_rules_group_eng_is_still_accepted(site):
    resp = post(site, "/api/rules", subject_kind="group", subject="eng",
                level="server", server="time", effect="allow")
    assert resp.status_code == 201, resp.text


# --- the derived field -----------------------------------------------------


def test_admin_field_matches_groups_for_every_user(site):
    """`admin` is true if and only if `groups` holds `admins`."""
    make_admin(site, "alice")
    post(site, "/api/users", id="carol", groups=["admins", "eng"])
    post(site, "/api/users", id="dave", groups=["eng"])
    put(site, "/api/users/bob", groups=["ops"])
    listing = site.client.get("/api/users", headers=api_headers(site)).json()
    assert {u["id"] for u in listing} >= {"admin", "alice", "bob", "carol", "dave"}
    for u in listing:
        assert u["admin"] == ("admins" in u["groups"]), u
        assert set(u) >= {"id", "name", "admin", "groups", "pending"}
        assert "password_hash" not in u and "setup_code" not in u


def test_no_saved_file_holds_an_admin_key(site):
    """After a run of API writes: version 2, no `admin` key in any record."""
    make_admin(site)
    post(site, "/api/users", id="carol", admin=True, groups=["eng"])
    put(site, "/api/users/alice", admin=False, groups=["ops"])
    data = json.loads(users_file(site))
    assert data["version"] == 2 and "admins" in data["groups"]
    assert all("admin" not in r for r in data["users"])


# --- the role follows the membership on the next request -------------------


def test_membership_grants_and_leaving_revokes_the_admin_gate(site):
    """Scenarios "Membership grants the role" and "Leaving the group revokes
    the role": the admin-scope token of a member passes `/api`; after the
    member leaves `admins`, the next request answers 401."""
    assert post(site, "/api/users", id="dave", groups=["admins"]).status_code == 201
    minted = post(site, "/api/tokens", name="dave-admin", scope="admin", user_id="dave")
    assert minted.status_code == 201, minted.text
    token = minted.json()["token"]
    assert site.client.get("/api/servers", headers=bearer(token)).status_code == 200
    assert put(site, "/api/users/dave", admin=False).status_code == 200
    assert site.client.get("/api/servers", headers=bearer(token)).status_code == 401
    # Joining again lifts the refusal on the next request.
    assert put(site, "/api/users/dave", groups=["admins"], admin=True).status_code == 200
    assert site.client.get("/api/servers", headers=bearer(token)).status_code == 200


# --- identity-error-ownership: unknown names in a user body -----------------
# Spec admin-api "Unknown names in a user body". The handlers pass the names to
# AccessPolicy; the provider refuses an unknown name. Check order: the body
# shape, the acting user, the provider kind, the user in the path, the names.


def test_api_put_with_a_colliding_name_answers_400(site):
    """V9, scenario "A group equal to the user id"."""
    assert post(site, "/api/users", id="ops").status_code == 201
    assert site.client.delete("/api/groups/ops", headers=api_headers(site)).status_code == 204
    before = users_file(site)
    resp = put(site, "/api/users/ops", groups=["ops"])
    assert resp.status_code == 400, resp.text
    assert resp.json() == {"error": "groups: unknown group ops"}
    assert users(site)["ops"]["groups"] == []
    assert users_file(site) == before


def test_api_checks_the_target_before_the_listed_names(site):
    """V10, scenario "The user in the path comes before the group names"."""
    before = users_file(site)
    resp = put(site, "/api/users/ghost", groups=["nope"])
    assert resp.status_code == 404, resp.text
    assert resp.json() == {"error": "ghost not found"}
    assert users_file(site) == before


def test_api_checks_the_actor_before_the_listed_names(site):
    """V11, scenario "The acting user comes before the group names".

    The demotion runs at the body read: after the bearer gate admitted, before
    the group names are checked. It is NOT injected in `policy.list_groups`.
    """
    from conftest import ADMIN_ACTOR
    from reresolve_race import make_admin_user, revoke_during_body

    token = make_admin_user(site, "carol")
    policy = site.app.state.supervisor.policy
    fired = revoke_during_body(
        site.app, "PUT", "/api/users/{id}",
        lambda: policy.set_admin(ADMIN_ACTOR, "carol", False))
    resp = site.client.put("/api/users/alice", headers=bearer(token),
                           json={"groups": ["nope"]})
    assert fired, "the demotion never ran: the window was not exercised"
    assert resp.status_code == 403, (resp.status_code, resp.text)
    assert users(site)["alice"]["groups"] == []


def test_api_unknown_group_answers_stay(site):
    """V12, scenarios "An unknown group in a create" and "A duplicate id comes
    before the group names"; the PUT with an unknown group."""
    before = users_file(site)
    resp = put(site, "/api/users/alice", groups=["nope"])
    assert resp.status_code == 400
    assert resp.json() == {"error": "groups: unknown group nope"}
    resp = post(site, "/api/users", id="carol", groups=["nope"])
    assert resp.status_code == 400
    assert resp.json() == {"error": "groups: unknown group nope"}
    assert "carol" not in users(site)
    resp = post(site, "/api/users", id="alice", groups=["nope"])
    assert resp.status_code == 400
    assert resp.json() == {"error": "user alice already exists"}
    assert users_file(site) == before


# --- private-cascade-halves: a refused create keeps the residue -------------


def residue_of_dave(site) -> dict[str, bytes]:
    """Give the deleted id `dave` a residue token and a residue rule: create
    `dave` and mint and grant over `/api`, then run the identity delete alone
    (an interrupted `delete_user`). Return the bytes of the stores."""
    assert post(site, "/api/users", id="dave").status_code == 201
    assert post(site, "/api/tokens", name="laptop", user_id="dave").status_code == 201
    assert post(site, "/api/rules", subject_kind="user", subject="dave",
                level="server", server="time", effect="allow").status_code == 201
    site.app.state.supervisor.policy.local_identity()._delete_user("dave")
    assert "dave" not in users(site)
    return {n: (site.data / n).read_bytes()
            for n in ("users.json", "tokens.json", "user_tokens.json", "rules.json")}


def test_a_refused_api_create_keeps_the_residue(site):
    """Scenario "A refused create with an unknown group keeps the residue",
    over `POST /api/users`: `400`, and no store changes."""
    before = residue_of_dave(site)
    resp = post(site, "/api/users", id="dave", groups=["nope"])
    assert resp.status_code == 400
    assert resp.json() == {"error": "groups: unknown group nope"}
    after = {n: (site.data / n).read_bytes() for n in before}
    assert after == before
