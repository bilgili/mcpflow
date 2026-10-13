"""The group picker route and the Users page routes (admins-group, task 8.6).

Scenarios: web-ui "Group picker" (Save adds and removes, A stale picker does
not revoke / re-grant the role, Uncheck every box, The bootstrap user saves,
An unknown group in the post) and "Users and groups pages" (Create an admin
from the dashboard, The admin route is gone, The reserved group refuses a
delete); "Membership tags" (Remove the admin role with the x). Design D5, D7,
D8 (web.py), I6, I7, I8, R5.

A stale picker is simulated by what the browser would post: `was` holds the
groups the picker showed as checked at render time, `groups` the boxes checked
at submit. Another tab or admin is simulated by a write between the render
and the post.
"""

from __future__ import annotations

import pytest
from dashboard_site import api_headers, make_mu_site  # noqa: F401
from test_security_page import Doc

USERS = "/security#users"


def req(site, method: str, path: str, uid: str = "admin", **kw):
    return site.request(uid, method, path, **kw)


def picker(site, uid: str, was=(), groups=None, **kw):
    """Post what a picker of `uid` posts."""
    data: dict = {"was": list(was)}
    if groups is not None:
        data["groups"] = list(groups)
    return req(site, "POST", f"/users/{uid}/groups", data=data, **kw)


def user_groups(site, uid: str) -> set[str]:
    listing = site.client.get("/api/users", headers=api_headers(site)).json()
    return set(next(u for u in listing if u["id"] == uid)["groups"])


def put_api(site, uid: str, **body):
    resp = site.client.put(f"/api/users/{uid}", headers=api_headers(site), json=body)
    assert resp.status_code == 200, resp.text


def users_file(site) -> bytes:
    return (site.data / "users.json").read_bytes()


@pytest.fixture
def site(make_mu_site):  # noqa: F811
    s = make_mu_site()
    for name in ("eng", "ops"):
        resp = req(s, "POST", "/groups", data={"name": name})
        assert resp.status_code == 303, resp.text
    return s


def set_up(site, uid: str, *groups: str) -> None:
    """Give `uid` exactly `groups` (a picker with no `was` only adds)."""
    resp = picker(site, uid, was=sorted(user_groups(site, uid) - {"admins"}),
                  groups=groups)
    assert resp.status_code == 303, resp.text


# --- Group picker -----------------------------------------------------------


def test_save_adds_and_removes(site):
    """Scenario "Save adds and removes"."""
    set_up(site, "alice", "eng")
    resp = picker(site, "alice", was=["eng"], groups=["ops"])
    assert resp.status_code == 303
    assert resp.headers["location"] == USERS
    assert user_groups(site, "alice") == {"ops"}


def test_a_stale_picker_does_not_revoke(site):
    """Scenario "A stale picker does not revoke the role" (I7)."""
    # The picker of alice renders: no group, so `was` is empty.
    put_api(site, "alice", admin=True)  # another admin grants the role
    resp = picker(site, "alice", was=[], groups=["ops"])
    assert resp.status_code == 303
    assert user_groups(site, "alice") == {"admins", "ops"}


def test_a_stale_picker_with_a_save_of_no_change_does_not_revoke(site):
    put_api(site, "alice", admin=True)
    assert picker(site, "alice", was=[], groups=[]).status_code == 303
    assert "admins" in user_groups(site, "alice")


def test_a_stale_picker_does_not_regrant(site):
    """Scenario "A stale picker does not re-grant the role" (I7)."""
    put_api(site, "alice", admin=True)  # the picker renders with admins checked
    put_api(site, "alice", admin=False)  # another admin revokes
    resp = picker(site, "alice", was=["admins"], groups=["admins"])  # save, no change
    assert resp.status_code == 303
    assert "admins" not in user_groups(site, "alice")


def test_a_stale_picker_on_eng_keeps_a_concurrent_add(site):
    """I8: a group that the admin did not toggle keeps its current state."""
    set_up(site, "alice", "eng")
    put_api(site, "alice", groups=["eng", "ops"])  # a concurrent add of ops
    # Stale save with no change, then one that toggles eng only.
    assert picker(site, "alice", was=["eng"], groups=["eng"]).status_code == 303
    assert user_groups(site, "alice") == {"eng", "ops"}
    assert picker(site, "alice", was=["eng"], groups=[]).status_code == 303
    assert user_groups(site, "alice") == {"ops"}


def test_a_stale_picker_keeps_a_concurrent_remove(site):
    set_up(site, "alice", "eng", "ops")
    put_api(site, "alice", groups=["eng"])  # a concurrent removal of ops
    assert picker(site, "alice", was=["eng", "ops"], groups=["eng", "ops"]).status_code == 303
    assert user_groups(site, "alice") == {"eng"}


def test_the_picker_alone_grants_and_revokes_admins(site):
    assert picker(site, "alice", was=[], groups=["admins"]).status_code == 303
    assert user_groups(site, "alice") == {"admins"}
    assert picker(site, "alice", was=["admins"], groups=[]).status_code == 303
    assert user_groups(site, "alice") == set()


def test_an_empty_groups_field_removes_every_was_group(site):
    """Scenario "Uncheck every box": the post holds no `groups` field."""
    set_up(site, "alice", "eng", "ops")
    resp = picker(site, "alice", was=["eng", "ops"], groups=None)
    assert resp.status_code == 303
    assert user_groups(site, "alice") == set()


def test_an_empty_groups_field_removes_the_role_too(site):
    put_api(site, "alice", admin=True, groups=["eng"])
    assert picker(site, "alice", was=["admins", "eng"]).status_code == 303
    assert user_groups(site, "alice") == set()


def test_neither_field_is_303_with_no_write(site, users_writes):
    before = users_file(site)
    users_writes["n"] = 0
    resp = req(site, "POST", "/users/alice/groups", data={})
    assert resp.status_code == 303 and resp.headers["location"] == USERS
    assert users_writes["n"] == 0 and users_file(site) == before


def test_a_was_value_with_a_comma_is_not_split(site):
    """`was` is not split on commas: `eng,ops` names one group, which does not
    exist. A split would silently remove `eng` and `ops`."""
    set_up(site, "alice", "eng", "ops")
    before = users_file(site)
    resp = req(site, "POST", "/users/alice/groups", data={"was": "eng,ops"})
    assert resp.status_code == 400
    assert "groups: unknown group eng,ops" in resp.text
    assert user_groups(site, "alice") == {"eng", "ops"}
    assert users_file(site) == before


def test_a_cached_page_without_was_is_add_only(site):
    """R5: a page of the previous build posts `groups` and no `was`. The
    handler reads that as add-only, so an unchecked box removes nothing."""
    set_up(site, "alice", "eng")
    assert req(site, "POST", "/users/alice/groups", data={"groups": ["ops"]}).status_code == 303
    assert user_groups(site, "alice") == {"eng", "ops"}


def test_typed_groups_are_split_on_commas_and_spaces(site):
    resp = req(site, "POST", "/users/alice/groups", data={"groups": "eng, ops"})
    assert resp.status_code == 303
    assert user_groups(site, "alice") == {"eng", "ops"}


def test_an_unknown_group_is_400_in_the_users_section(site):
    """Scenario "An unknown group in the post"."""
    set_up(site, "alice", "eng")
    before = users_file(site)
    resp = req(site, "POST", "/users/alice/groups", data={"groups": "nope"})
    assert resp.status_code == 400
    doc = Doc(resp.text)
    # The refusal shows in its own section (the banner above has no section).
    assert [e["section"] for e in doc.errors
            if e["section"] and "unknown group nope" in e["text"]] == ["users"]
    assert "groups: unknown group nope" in resp.text
    assert user_groups(site, "alice") == {"eng"}
    assert users_file(site) == before


def test_an_unknown_group_in_was_is_400(site):
    before = users_file(site)
    resp = req(site, "POST", "/users/alice/groups", data={"was": "nope"})
    assert resp.status_code == 400 and "groups: unknown group nope" in resp.text
    assert users_file(site) == before


def test_a_refused_delta_changes_nothing(site):
    """An unknown group next to a valid add: neither lands (I5)."""
    before = users_file(site)
    resp = req(site, "POST", "/users/alice/groups", data={"groups": ["eng", "nope"]})
    assert resp.status_code == 400
    assert user_groups(site, "alice") == set()
    assert users_file(site) == before


def test_an_unknown_user_is_404(site):
    assert req(site, "POST", "/users/ghost/groups", data={"groups": ["eng"]}).status_code == 404
    assert req(site, "POST", "/users/ghost/groups", data={}).status_code == 404


def test_a_double_post_makes_no_second_write(site, users_writes):
    users_writes["n"] = 0
    assert picker(site, "alice", was=[], groups=["eng"]).status_code == 303
    assert users_writes["n"] == 1
    once = users_file(site)
    assert picker(site, "alice", was=[], groups=["eng"]).status_code == 303
    assert users_writes["n"] == 1
    assert users_file(site) == once
    assert user_groups(site, "alice") == {"eng"}


def test_the_bootstrap_save_with_eng_answers_303(site):
    """Scenario "The bootstrap user saves": the disabled `admins` box posts
    nothing, and `was` leaves it out."""
    resp = picker(site, "admin", was=[], groups=["eng"])
    assert resp.status_code == 303
    assert user_groups(site, "admin") == {"admins", "eng"}


def test_the_bootstrap_user_cannot_be_removed_from_admins_by_a_post(site):
    """A hand-made post that names `admins` in `was` and not in `groups`."""
    before = users_file(site)
    resp = picker(site, "admin", was=["admins"], groups=[])
    assert resp.status_code == 400
    assert Doc(resp.text).errors and "admins" in resp.text
    assert user_groups(site, "admin") == {"admins"}
    assert users_file(site) == before


def test_a_non_admin_user_cannot_post_groups(site):
    before = users_file(site)
    for path in ("/users/alice/groups", "/users/bob/groups"):
        resp = req(site, "POST", path, uid="alice", data={"groups": ["admins"]})
        assert resp.status_code == 403
    assert users_file(site) == before
    assert "admins" not in user_groups(site, "alice")


# --- Users and groups pages -------------------------------------------------


def test_post_users_alice_admin_is_404(site):
    """Scenario "The admin route is gone"."""
    before = users_file(site)
    for body in ({"admin": "on"}, {}):
        assert req(site, "POST", "/users/alice/admin", data=body).status_code == 404
    assert req(site, "POST", "/users/admin/admin", data={"admin": "on"}).status_code == 404
    assert user_groups(site, "alice") == set()
    assert users_file(site) == before


def test_post_users_ignores_admin_on(site):
    """The create form has no admin checkbox; an `admin` field is ignored."""
    resp = req(site, "POST", "/users", data={"id": "carol", "groups": "eng", "admin": "on"})
    assert resp.status_code == 200, resp.text
    assert user_groups(site, "carol") == {"eng"}


def test_create_an_admin_with_typed_groups(site):
    """Scenario "Create an admin from the dashboard"."""
    resp = req(site, "POST", "/users", data={"id": "carol", "groups": "admins, eng"})
    assert resp.status_code == 200, resp.text
    assert user_groups(site, "carol") == {"admins", "eng"}


def test_create_a_user_with_an_unknown_group_is_400(site):
    before = users_file(site)
    resp = req(site, "POST", "/users", data={"id": "carol", "groups": "nope"})
    assert resp.status_code == 400
    assert "groups: unknown group nope" in resp.text
    assert users_file(site) == before


def test_the_reserved_group_refuses_a_delete(site):
    """Scenario "The reserved group refuses a delete"."""
    before = users_file(site)
    resp = req(site, "POST", "/groups/admins/delete")
    assert resp.status_code == 400
    doc = Doc(resp.text)
    assert [e["section"] for e in doc.errors
            if e["section"] and "admins" in e["text"]] == ["groups"]
    assert users_file(site) == before
    assert "admins" in site.client.get("/api/groups", headers=api_headers(site)).text


def test_the_x_on_admins_removes_the_role(site):
    """Scenario "Remove the admin role with the x"."""
    put_api(site, "alice", admin=True)
    resp = req(site, "POST", "/groups/admins/members/alice/remove?from=users")
    assert resp.status_code == 303 and resp.headers["location"] == USERS
    assert "admins" not in user_groups(site, "alice")


def test_the_x_route_refuses_the_bootstrap_membership(site):
    before = users_file(site)
    resp = req(site, "POST", "/groups/admins/members/admin/remove?from=users")
    assert resp.status_code == 400
    assert user_groups(site, "admin") == {"admins"}
    assert users_file(site) == before


def test_a_non_admin_user_cannot_remove_a_member_of_admins(site):
    put_api(site, "bob", admin=True)
    resp = req(site, "POST", "/groups/admins/members/bob/remove", uid="alice")
    assert resp.status_code == 403
    assert "admins" in user_groups(site, "bob")


def test_the_security_context_holds_admins_group(site, monkeypatch):
    """The page renders with the reserved name in its context (D8, web.py)."""
    from jinja2 import Template

    seen: list[dict] = []
    real = Template.render

    def spy(self, *args, **kwargs):
        seen.append({**(args[0] if args and isinstance(args[0], dict) else {}), **kwargs})
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Template, "render", spy)
    assert req(site, "GET", "/security").status_code == 200
    assert [c["admins_group"] for c in seen if "admins_group" in c] == ["admins"]


# --- identity-error-ownership: unknown names in a membership post -----------
# Spec web-ui "Unknown names in a membership post". The provider owns the kind
# of the error; a name in the body that equals the path name is a body name.


def _errors_in(resp, section: str, needle: str) -> list[str]:
    """The sections of the error elements whose text holds `needle`."""
    return [e["section"] for e in Doc(resp.text).errors
            if e["section"] and needle in e["text"] and e["section"] == section]


def test_the_members_post_with_a_colliding_name_answers_400(site):
    """V6, scenario "A member equal to the group name"."""
    assert req(site, "POST", "/groups", data={"name": "dev"}).status_code == 303
    before = users_file(site)
    resp = req(site, "POST", "/groups/dev/members", data={"members": "dev"})
    assert resp.status_code == 400, resp.text
    assert _errors_in(resp, "groups", "members: unknown user dev") == ["groups"]
    assert users_file(site) == before


def test_the_groups_post_with_a_colliding_name_answers_400(site):
    """V7, scenario "A group equal to the user id"."""
    resp = req(site, "POST", "/users", data={"id": "ops"})
    assert resp.status_code in (200, 303), resp.text
    assert req(site, "POST", "/groups/ops/delete").status_code == 303  # no group `ops`
    assert "ops" not in site.client.get("/api/groups", headers=api_headers(site)).text
    before = users_file(site)
    resp = req(site, "POST", "/users/ops/groups", data={"groups": "ops"})
    assert resp.status_code == 400, resp.text
    assert _errors_in(resp, "users", "groups: unknown group ops") == ["users"]
    assert user_groups(site, "ops") == set()
    assert users_file(site) == before


def test_non_colliding_membership_answers_stay(site):
    """V8: the five answers of scenarios "An unknown group in the path", "An
    unknown member", "An unknown user in the path" and the two body refusals."""
    before = users_file(site)
    resp = req(site, "POST", "/groups/nope/members", data={"members": "ghost"})
    assert resp.status_code == 404 and resp.text.strip() == "nope not found"
    resp = req(site, "POST", "/groups/eng/members", data={"members": "ghost"})
    assert resp.status_code == 400
    assert _errors_in(resp, "groups", "members: unknown user ghost") == ["groups"]
    resp = req(site, "POST", "/users/ghost/groups", data={"groups": "nope"})
    assert resp.status_code == 404 and resp.text.strip() == "ghost not found"
    resp = req(site, "POST", "/users/alice/groups", data={"groups": "nope"})
    assert resp.status_code == 400
    assert _errors_in(resp, "users", "groups: unknown group nope") == ["users"]
    resp = req(site, "POST", "/users", data={"id": "carol", "groups": "nope"})
    assert resp.status_code == 400
    assert _errors_in(resp, "users", "groups: unknown group nope") == ["users"]
    assert users_file(site) == before


def test_a_refused_web_create_keeps_the_residue(site):
    """Scenario "A refused create with an unknown group keeps the residue",
    over the web `POST /users`: `400` in the Users section, no store changes."""
    headers = api_headers(site)
    assert site.client.post("/api/users", headers=headers, json={"id": "dave"}).status_code == 201
    assert site.client.post("/api/tokens", headers=headers,
                            json={"name": "laptop", "user_id": "dave"}).status_code == 201
    assert site.client.post("/api/rules", headers=headers, json={
        "subject_kind": "user", "subject": "dave", "level": "server",
        "server": "time", "effect": "allow"}).status_code == 201
    site.app.state.supervisor.policy.local_identity()._delete_user("dave")
    names = ("users.json", "tokens.json", "user_tokens.json", "rules.json")
    before = {n: (site.data / n).read_bytes() for n in names}
    resp = req(site, "POST", "/users", data={"id": "dave", "groups": "nope"})
    assert resp.status_code == 400
    doc = Doc(resp.text)
    assert [e["section"] for e in doc.errors
            if e["section"] and "unknown group nope" in e["text"]] == ["users"]
    assert "groups: unknown group nope" in resp.text
    assert {n: (site.data / n).read_bytes() for n in names} == before
