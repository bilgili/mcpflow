"""The Security page: one admin page for users, groups, and rules.

Every test is one scenario of `openspec/changes/security-page/specs/web-ui/spec.md`
(requirements Security page, Membership tags, and the modified Users and
groups pages, Grant rules page, and Role-scoped dashboard). The expectations
come from the spec and the frozen interfaces of `design.md` (D1 to D6), not
from the implementation. The markup is read with `html.parser`, never with a
substring of the template.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

import pytest
from dashboard_site import api_headers, make_mu_site  # noqa: F401


# --- reading the page ------------------------------------------------------


class Doc(HTMLParser):
    """One pass over a page: sections, h1, forms, nav, banner, errors, buttons."""

    def __init__(self, body: str):
        super().__init__(convert_charrefs=True)
        self.h1 = 0
        self.section_ids: list[str | None] = []
        self.form_depth = 0
        self.max_form_depth = 0
        self.forms: list[tuple[str | None, dict]] = []  # (section, attrs)
        self.nav_links: list[tuple[str, str]] = []  # (href, text)
        self.errors: list[dict] = []  # {section, role, links, text}
        self.buttons: list[dict] = []  # {section, form_action, attrs, text}
        self.summaries: list[tuple[str | None, str]] = []
        self.inputs: list[tuple[str | None, dict]] = []
        self.form_fields: list[tuple[str | None, dict]] = []  # (form action, attrs)
        self.classes: list[tuple[str | None, str, list[str]]] = []  # (section, tag, classes)
        self.hx_attrs = 0
        self._section: str | None = None
        self._in_nav = False
        self._open_a: list | None = None
        self._err: dict | None = None
        self._btn: dict | None = None
        self._sum: list[str] | None = None
        self._form_action: list[str | None] = []
        self.feed(body)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        self.hx_attrs += sum(1 for k in a if k.startswith("hx-"))
        if tag == "h1":
            self.h1 += 1
        elif tag == "section":
            self._section = a.get("id")
            self.section_ids.append(a.get("id"))
        elif tag == "nav":
            self._in_nav = True
        elif tag == "a":
            href = a.get("href", "")
            if self._in_nav:
                self._open_a = [href, ""]
            if self._err is not None:
                self._err["links"].append(href)
        elif tag == "form":
            self.form_depth += 1
            self.max_form_depth = max(self.max_form_depth, self.form_depth)
            self.forms.append((self._section, a))
            self._form_action.append(a.get("action"))
        elif tag == "button":
            self._btn = {"section": self._section,
                         "form_action": self._form_action[-1] if self._form_action else None,
                         "attrs": a, "text": ""}
        elif tag == "summary":
            self._sum = []
        elif tag == "input":
            self.inputs.append((self._section, a))
            self.form_fields.append((self._form_action[-1] if self._form_action else None, a))
        if a.get("class"):
            self.classes.append((self._section, tag, a["class"].split()))
        if "error" in (a.get("class") or "").split() and self._err is None:
            self._err = {"section": self._section, "role": a.get("role"), "links": [],
                         "text": "", "tag": tag}
            self.errors.append(self._err)

    def handle_endtag(self, tag):
        if tag == "section":
            self._section = None
        elif tag == "nav":
            self._in_nav = False
        elif tag == "a" and self._open_a is not None:
            self.nav_links.append((self._open_a[0], self._open_a[1].strip()))
            self._open_a = None
        elif tag == "form":
            self.form_depth -= 1
            self._form_action.pop()
        elif tag == "button" and self._btn is not None:
            self.buttons.append(self._btn)
            self._btn = None
        elif tag == "summary" and self._sum is not None:
            self.summaries.append((self._section, "".join(self._sum).strip()))
            self._sum = None
        if self._err is not None and tag == self._err["tag"]:
            self._err = None

    def handle_data(self, data):
        if self._open_a is not None:
            self._open_a[1] += data
        if self._err is not None:
            self._err["text"] += data
        if self._btn is not None:
            self._btn["text"] += data
        if self._sum is not None:
            self._sum.append(data)


class Tags(HTMLParser):
    """One membership cell: the tags in order, the `<details>` split, the summary,
    and every plain text outside tags (where a count would show)."""

    def __init__(self, fragment: str):
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, bool]] = []  # (item, inside <details>)
        self.summaries: list[str] = []
        self.texts: list[str] = []
        self.details = 0
        self.forms: list[str] = []
        self._details_depth = 0
        self._code: list[str] | None = None
        self._sum: list[str] | None = None
        self._skip = 0  # inside <button>
        self.feed(fragment)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "details":
            self.details += 1
            self._details_depth += 1
        elif tag == "code":
            self._code = []
        elif tag == "summary":
            self._sum = []
        elif tag == "button":
            self._skip += 1
        elif tag == "form":
            self.forms.append(a.get("action", ""))

    def handle_endtag(self, tag):
        if tag == "details":
            self._details_depth -= 1
        elif tag == "code" and self._code is not None:
            self.tags.append(("".join(self._code), self._details_depth > 0))
            self._code = None
        elif tag == "summary" and self._sum is not None:
            self.summaries.append("".join(self._sum).strip())
            self._sum = None
        elif tag == "button":
            self._skip -= 1

    def handle_data(self, data):
        if self._code is not None:
            self._code.append(data)
        elif self._sum is not None:
            self._sum.append(data)
        elif not self._skip and data.strip():
            self.texts.append(data.strip())


def section(body: str, name: str) -> str:
    return body.split(f'<section id="{name}">')[1].split("</section>")[0]


def row(html: str, first_cell: str) -> str:
    """The `<tr>` whose first cell is `<code>first_cell</code>`."""
    return next(r for r in html.split("<tr>") if f"<td><code>{first_cell}</code>" in r)


def cell_tags(html: str, first_cell: str) -> Tags:
    """The membership cell of a row: the Members cell of a group row, or the
    Groups cell of a user row (the cell with the tags)."""
    r = row(html, first_cell)
    cells = r.split("<td")
    cell = next(c for c in cells[2:] if ("none" in c or "/members/" in c))
    cell = cell.split(">", 1)[1]  # drop the rest of the `<td ...>` tag
    return Tags(cell.split("<div popover", 1)[0])  # the picker is not a tag list


def accessible_name(btn: dict) -> str:
    a = btn["attrs"]
    return (a.get("aria-label") or btn["text"].strip() or a.get("title") or "")


# --- setup helpers ----------------------------------------------------------


def group(site, name: str):
    resp = site.request("admin", "POST", "/groups", data={"name": name})
    assert resp.status_code == 303, resp.text


def add_user(site, uid: str, *groups: str):
    resp = site.request("admin", "POST", "/users", data={"id": uid, "groups": list(groups)})
    assert resp.status_code == 200, resp.text


def put_groups(site, uid: str, *groups: str):
    resp = site.request("admin", "POST", f"/users/{uid}/groups", data={"groups": list(groups)})
    assert resp.status_code == 303, resp.text


def security(site, uid: str = "admin"):
    return site.request(uid, "GET", "/security")


def members_of(site, name: str) -> set[str]:
    users = site.client.get("/api/users", headers=api_headers(site)).json()
    return {u["id"] for u in users if name in u["groups"]}


def remove(site, g: str, u: str, query: str = "", uid: str = "admin"):
    return site.request(uid, "POST", f"/groups/{g}/members/{u}/remove{query}")


# --- Security page ----------------------------------------------------------


def test_one_page_holds_three_sections(make_mu_site):
    """Security page / One page holds three sections."""
    site = make_mu_site()
    resp = security(site)
    assert resp.status_code == 200
    doc = Doc(resp.text)
    assert doc.section_ids == ["users", "groups", "rules"]
    assert doc.h1 == 1
    # Each section starts with an <h2>.
    for name in ("users", "groups", "rules"):
        assert re.match(r"\s*<h2>", section(resp.text, name)), name


def test_the_page_needs_no_javascript(make_mu_site):
    """Security page: no tabs; every write works without JavaScript. The one
    inline script only filters the picker, updates its count, and resets it on
    close: it loads nothing, posts nothing, and every form posts without htmx."""
    site = make_mu_site()
    group(site, "eng")
    put_groups(site, "alice", "eng")
    body = security(site).text
    main = body.split("<main>")[1]
    scripts = re.findall(r"<script([^>]*)>(.*?)</script>", main, re.DOTALL)
    assert len(scripts) == 1
    attrs, code = scripts[0]
    assert "src" not in attrs
    assert not re.search(r"fetch\(|XMLHttpRequest|\.submit\(|htmx", code)
    assert Doc(body).hx_attrs == 0
    assert all(f[1].get("method", "").lower() == "post" for f in Doc(body).forms
               if f[0] is not None)


def test_the_header_has_one_link(make_mu_site):
    """Security page / The header has one link (on `/` and on `/security`)."""
    site = make_mu_site()
    for path in ("/", "/security"):
        links = Doc(site.request("admin", "GET", path).text).nav_links
        hrefs = [h for h, _ in links]
        assert hrefs.count("/security") == 1, (path, links)
        assert ("/security", "Security") in links
        for gone in ("/users", "/groups", "/rules"):
            assert gone not in hrefs, (path, gone)
        texts = [t for _, t in links]
        assert not {"Users", "Groups", "Rules"} & set(texts)


@pytest.mark.parametrize("name", ["users", "groups", "rules"])
def test_an_old_bookmark(make_mu_site, name):
    """Security page / An old bookmark."""
    site = make_mu_site()
    resp = site.request("admin", "GET", f"/{name}")
    assert resp.status_code == 303
    assert resp.headers["location"] == f"/security#{name}"


@pytest.mark.parametrize("path", ["/security", "/users", "/groups", "/rules"])
def test_a_non_admin_user_cannot_open_the_security_pages(make_mu_site, path):
    """Role-scoped dashboard / Admin-only pages refuse a user."""
    site = make_mu_site()
    assert site.request("alice", "GET", path).status_code == 403


# --- Membership tags --------------------------------------------------------


def test_a_short_list(make_mu_site):
    """Membership tags / A short list: tags, no `+N more`, no count."""
    site = make_mu_site()
    group(site, "ops")
    put_groups(site, "bob", "ops")
    put_groups(site, "alice", "ops")
    tags = cell_tags(section(security(site).text, "groups"), "ops")
    assert [t for t, _ in tags.tags] == ["alice", "bob"]
    assert tags.details == 0 and tags.summaries == []
    assert not any("more" in t for t in tags.texts)
    assert tags.texts == [], f"a count showed for two items: {tags.texts}"


def test_a_list_of_exactly_three_has_no_count(make_mu_site):
    """Membership tags: three or fewer items show no count and no `<details>`."""
    site = make_mu_site()
    group(site, "ops")
    for uid in ("admin", "alice", "bob"):
        put_groups(site, uid, "ops")
    tags = cell_tags(section(security(site).text, "groups"), "ops")
    assert [t for t, _ in tags.tags] == ["admin", "alice", "bob"]
    assert tags.details == 0 and tags.texts == []


def test_a_long_list(make_mu_site):
    """Membership tags / A long list: count 17, first three sorted, `+14 more`."""
    site = make_mu_site()
    group(site, "eng")
    ids = [f"m{n:02d}" for n in range(17)]
    for uid in reversed(ids):  # create out of order: the macro does the sorting
        add_user(site, uid, "eng")
    tags = cell_tags(section(security(site).text, "groups"), "eng")
    assert "17" in tags.texts
    outside = [t for t, inside in tags.tags if not inside]
    inside = [t for t, inside in tags.tags if inside]
    assert outside == ids[:3]
    assert tags.details == 1 and tags.summaries == ["+14 more"]
    assert inside == ids[3:] and len(inside) == 14


def test_a_list_of_four_shows_plus_one(make_mu_site):
    """Membership tags: N is the length minus 3 (boundary, 4 items)."""
    site = make_mu_site()
    group(site, "eng")
    for uid in ("admin", "alice", "bob"):
        put_groups(site, uid, "eng")
    add_user(site, "dave", "eng")
    tags = cell_tags(section(security(site).text, "groups"), "eng")
    assert "4" in tags.texts
    assert tags.summaries == ["+1 more"]
    assert [t for t, i in tags.tags if i] == ["dave"]


def test_the_users_section_sorts_and_folds_the_groups(make_mu_site):
    """Membership tags: the Users section uses the same list rules for the
    groups of a user."""
    site = make_mu_site()
    names = ["g5", "g1", "g4", "g2", "g3"]
    for g in names:
        group(site, g)
    put_groups(site, "alice", *names)
    tags = cell_tags(section(security(site).text, "users"), "alice")
    assert [t for t, i in tags.tags if not i] == ["g1", "g2", "g3"]
    assert [t for t, i in tags.tags if i] == ["g4", "g5"]
    assert tags.summaries[0] == "+2 more" and "5" in tags.texts


def test_an_empty_list(make_mu_site):
    """Membership tags / An empty list: `none`, and no tag form."""
    site = make_mu_site()
    group(site, "qa")
    tags = cell_tags(section(security(site).text, "groups"), "qa")
    assert tags.texts == ["none"]
    assert tags.tags == [] and tags.forms == []


def test_the_tags_wrap_in_the_cell(make_mu_site):
    """Membership tags: the tags wrap, so the cell grows in height only."""
    site = make_mu_site()
    group(site, "eng")
    put_groups(site, "alice", "eng")
    doc = Doc(security(site).text)
    # The container of the tags renders with class `tags`, in both sections,
    # and each tag is a `tag` element.
    for sec in ("groups", "users"):
        kinds = [c for s_, _, c in doc.classes if s_ == sec]
        assert ["tags"] in kinds, (sec, kinds)
        assert ["tag"] in kinds, (sec, kinds)
    css = site.client.get("/static/style.css").text
    rule = re.search(r"\.tags\s*\{([^}]*)\}", css)
    assert rule and re.search(r"flex-wrap:\s*wrap", rule.group(1)), "the .tags rule must wrap"


def test_remove_a_member_with_the_x(make_mu_site):
    """Membership tags / Remove a member with the x."""
    site = make_mu_site()
    group(site, "eng")
    put_groups(site, "alice", "eng")
    put_groups(site, "bob", "eng")
    resp = remove(site, "eng", "alice", "?from=groups")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/security#groups"
    assert members_of(site, "eng") == {"bob"}
    tags = cell_tags(section(security(site).text, "groups"), "eng")
    assert [t for t, _ in tags.tags] == ["bob"]


def test_a_removal_changes_one_membership_only(make_mu_site):
    """Membership tags: the × removes one membership and leaves the others."""
    site = make_mu_site()
    group(site, "eng")
    group(site, "ops")
    put_groups(site, "alice", "eng", "ops")
    put_groups(site, "bob", "eng", "ops")
    assert remove(site, "eng", "alice", "?from=groups").status_code == 303
    users = {u["id"]: set(u["groups"])
             for u in site.client.get("/api/users", headers=api_headers(site)).json()}
    assert users["alice"] == {"ops"} and users["bob"] == {"eng", "ops"}


def test_the_same_removal_from_the_users_section(make_mu_site):
    """Membership tags / The same removal from the Users section."""
    site = make_mu_site()
    group(site, "eng")
    put_groups(site, "alice", "eng")
    r = row(section(security(site).text, "users"), "alice")
    actions = Tags(r).forms
    assert "/groups/eng/members/alice/remove?from=users" in actions
    resp = site.request("admin", "POST", "/groups/eng/members/alice/remove?from=users")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/security#users"
    assert members_of(site, "eng") == set()


def test_the_groups_section_forms_post_with_from_groups(make_mu_site):
    """Membership tags: the Groups section sets `from=groups`."""
    site = make_mu_site()
    group(site, "eng")
    put_groups(site, "alice", "eng")
    r = row(section(security(site).text, "groups"), "eng")
    assert Tags(r).forms.count("/groups/eng/members/alice/remove?from=groups") == 1
    assert not any("from=users" in f for f in Tags(r).forms)


@pytest.mark.parametrize("query", [
    "?from=https://evil.test", "?from=rules", "?from=", "?from=%2F%2Fevil.test", "",
])
def test_an_unknown_return_section(make_mu_site, query):
    """Membership tags / An unknown return section: the closed set of `from`."""
    site = make_mu_site()
    group(site, "eng")
    put_groups(site, "alice", "eng")
    resp = remove(site, "eng", "alice", query)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/security#groups"
    assert members_of(site, "eng") == set()


def test_an_unknown_member(make_mu_site):
    """Membership tags / An unknown member (and an unknown group)."""
    site = make_mu_site()
    group(site, "eng")
    put_groups(site, "alice", "eng")
    assert remove(site, "eng", "nobody").status_code == 404
    assert remove(site, "nope", "alice").status_code == 404
    assert remove(site, "eng", "nobody", "?from=users").status_code == 404
    assert members_of(site, "eng") == {"alice"}


def test_removing_a_non_member_is_a_redirect(make_mu_site):
    """Remove one membership / A user who is not a member: the route answers
    303 and changes nothing."""
    site = make_mu_site()
    group(site, "eng")
    put_groups(site, "alice", "eng")
    resp = remove(site, "eng", "bob", "?from=users")
    assert resp.status_code == 303 and resp.headers["location"] == "/security#users"
    assert members_of(site, "eng") == {"alice"}


def test_a_non_admin_user_cannot_remove(make_mu_site):
    """Membership tags / A non-admin user."""
    site = make_mu_site()
    group(site, "eng")
    put_groups(site, "alice", "eng")
    resp = remove(site, "eng", "alice", uid="bob")
    assert resp.status_code == 403
    assert members_of(site, "eng") == {"alice"}
    # The member removing their own membership is a non-admin too.
    assert remove(site, "eng", "alice", uid="alice").status_code == 403
    assert members_of(site, "eng") == {"alice"}


def test_a_removal_needs_a_session(make_mu_site):
    """The removal route is behind the session gate."""
    site = make_mu_site()
    group(site, "eng")
    put_groups(site, "alice", "eng")
    site.client.cookies.clear()
    resp = site.client.post("/groups/eng/members/alice/remove")
    assert resp.status_code == 401  # SessionGate: a POST without a user
    assert members_of(site, "eng") == {"alice"}


def test_the_x_buttons_have_accessible_names(make_mu_site):
    """Membership tags: the name of the button is `Remove <user> from <group>`."""
    site = make_mu_site()
    group(site, "eng")
    group(site, "ops")
    put_groups(site, "alice", "eng", "ops")
    put_groups(site, "bob", "eng")
    doc = Doc(security(site).text)
    for sec in ("groups", "users"):
        tag_buttons = [b for b in doc.buttons
                       if b["section"] == sec and "/members/" in (b["form_action"] or "")]
        names = sorted(accessible_name(b) for b in tag_buttons)
        assert names == ["Remove alice from eng", "Remove alice from ops",
                         "Remove bob from eng"], (sec, names)


def test_the_edit_groups_control_names_its_user(make_mu_site):
    """Row menu: one `⋯` button for each row, naming its user and targeting
    that row's menu, whose `Edit user` item opens the dialog of that user."""
    site = make_mu_site()
    group(site, "eng")
    body = security(site).text
    doc = Doc(body)
    menus = [b for b in doc.buttons if b["section"] == "users"
             and "menu-btn" in (b["attrs"].get("class") or "").split()]
    assert sorted(b["attrs"]["popovertarget"] for b in menus) == [
        "menu-of-admin", "menu-of-alice", "menu-of-bob"]
    assert sorted(b["attrs"]["aria-label"] for b in menus) == [
        "Actions for admin", "Actions for alice", "Actions for bob"]
    assert not [b for b in doc.buttons if "group-edit" in (b["attrs"].get("class") or "").split()]
    for uid in ("admin", "alice", "bob"):
        assert len(re.findall(rf'<div popover id="menu-of-{uid}"', body)) == 1
        assert len(re.findall(rf'<dialog id="edit-{uid}"', body)) == 1
        assert "groups-of-" not in body


def test_the_edit_groups_form_checks_exactly_the_groups_of_its_user(make_mu_site):
    """Group picker: the form of a user holds one checkbox named `groups` for
    each group (`admins` included), `checked` on the groups of that user."""
    site = make_mu_site()
    for g in ("eng", "ops", "qa"):
        group(site, g)
    put_groups(site, "alice", "eng", "ops")
    doc = Doc(security(site).text)
    for uid, want in (("alice", {"eng", "ops"}), ("bob", set())):
        boxes = [a for act, a in doc.form_fields
                 if act == f"/users/{uid}/groups" and a.get("type") == "checkbox"]
        assert {a.get("name") for a in boxes} == {"groups"}, uid
        assert sorted(a["value"] for a in boxes) == ["admins", "eng", "ops", "qa"], uid
        assert {a["value"] for a in boxes if "checked" in a} == want, uid


def test_no_form_holds_another_form(make_mu_site):
    """Membership tags / No nested forms: the page of users that hold groups,
    a long list, and an error page."""
    site = make_mu_site()
    group(site, "eng")
    group(site, "ops")
    put_groups(site, "alice", "eng", "ops")
    put_groups(site, "bob", "eng")
    for n in range(6):
        add_user(site, f"m{n}", "eng", "ops")
    pages = [security(site).text,
             site.request("admin", "POST", "/groups", data={"name": "Bad Name"}).text]
    for body in pages:
        doc = Doc(body)
        assert doc.max_form_depth == 1
        assert doc.form_depth == 0  # every form closed
        # The edit dialog sits beside the table: its form is not around the tag
        # forms or the menu forms of the row.
        cell = row(section(body, "users"), "alice")
        assert "/users/alice/groups" not in Tags(cell).forms
        assert Tags(section(body, "users")).forms.count("/users/alice/groups") == 1


# --- Users and groups pages (modified) --------------------------------------


def test_the_create_form_has_no_password_field(make_mu_site):
    """Users and groups pages / The create form has no password."""
    site = make_mu_site()
    doc = Doc(security(site).text)
    assert [i for i in doc.inputs if i[1].get("type") == "password"] == []
    assert [i for i in doc.inputs if i[1].get("name") == "password"] == []


def test_the_create_form_holds_id_name_and_groups(make_mu_site):
    """Users and groups pages: the create dialog has id, name, and a list of
    group checkboxes, and no Admin checkbox. The filter has no name."""
    site = make_mu_site()
    group(site, "eng")
    body = security(site).text
    doc = Doc(body)
    create = {a.get("name") for act, a in doc.form_fields if act == "/users"}
    assert create == {None, "id", "name", "groups"}
    assert re.search(r'<dialog id="create-user" class="userdlg">', body)
    assert 'commandfor="create-user" command="show-modal"' in body
    assert [i for i in doc.inputs if i[1].get("name") == "admin"] == []


def test_create_a_user_shows_the_code_once_in_the_users_section(make_mu_site):
    """Users and groups pages / Create a user from the dashboard (AC-7)."""
    site = make_mu_site()
    group(site, "eng")
    resp = site.request("admin", "POST", "/users", data={"id": "dave", "groups": "eng"})
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "no-store"
    code = re.search(r'id="setup-code">([^<]+)<', resp.text).group(1)
    users = section(resp.text, "users")
    assert code in users and "/login/setup" in users
    assert resp.text.count(code) == 1
    assert Doc(resp.text).section_ids == ["users", "groups", "rules"]
    later = security(site)
    assert later.status_code == 200 and code not in later.text
    assert 'id="setup-code"' not in later.text
    r = row(section(later.text, "users"), "dave")
    assert "pending" in r
    assert [t for t, _ in cell_tags(section(later.text, "users"), "dave").tags] == ["eng"]


def test_reset_a_user_shows_a_new_code_once(make_mu_site):
    """Users and groups pages / Reset a user."""
    site = make_mu_site()
    resp = site.request("admin", "POST", "/users/alice/setup-code")
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "no-store"
    code = re.search(r'id="setup-code">([^<]+)<', resp.text).group(1)
    assert code in section(resp.text, "users")
    later = security(site)
    assert code not in later.text
    assert "pending" in row(section(later.text, "users"), "alice")


def test_create_a_group_redirects_to_its_anchor(make_mu_site):
    """Users and groups pages / Create a group from the dashboard (AC-7)."""
    site = make_mu_site()
    resp = site.request("admin", "POST", "/groups", data={"name": "eng"})
    assert resp.status_code == 303 and resp.headers["location"] == "/security#groups"
    tags = cell_tags(section(security(site).text, "groups"), "eng")
    assert tags.texts == ["none"]


def test_every_other_user_and_group_form_redirects_to_its_anchor(make_mu_site):
    """Users and groups pages: a success redirects with 303 to the anchor of
    the section of the form."""
    site = make_mu_site()
    group(site, "eng")
    add_user(site, "dave")
    checks = [
        ("/users/dave/groups", {"groups": "eng"}, "/security#users"),
        ("/groups/eng/delete", {}, "/security#groups"),
        ("/users/dave/delete", {}, "/security#users"),
    ]
    for path, data, where in checks:
        resp = site.request("admin", "POST", path, data=data)
        assert resp.status_code == 303, (path, resp.status_code)
        assert resp.headers["location"] == where, path


def test_user_delete_asks_in_a_dialog_before_it_posts(make_mu_site):
    """Users section: the menu Delete only opens a confirm dialog; the POST
    form lives inside that dialog, and the bootstrap row has neither."""
    site = make_mu_site()
    add_user(site, "dave")
    users = section(security(site).text, "users")
    assert 'commandfor="delete-dave" command="show-modal"' in users
    dialog = re.search(r'<dialog id="delete-dave"[^>]*>(.*?)</dialog>', users, re.S)
    assert dialog and 'action="/users/dave/delete"' in dialog.group(1)
    assert "/users/dave/delete" not in users.replace(dialog.group(0), "")
    assert "delete-admin" not in users


def _groups_of_user(site, uid: str) -> list[str]:
    users = site.client.get("/api/users", headers=api_headers(site)).json()
    return next(u["groups"] for u in users if u["id"] == uid)


def test_group_edit_members_posts_a_delta_and_redirects(make_mu_site):
    """Groups section: the member picker adds the boxes checked at save and
    removes the ones that were checked and are not. A user in neither set
    keeps its membership, so a stale picker undoes no concurrent change."""
    site = make_mu_site()
    for g in ("eng", "ops"):
        group(site, g)
    for uid in ("dave", "erin", "fay"):
        add_user(site, uid)
    site.request("admin", "POST", "/users/dave/groups", data={"groups": ["eng", "ops"], "was": []})
    site.request("admin", "POST", "/users/erin/groups", data={"groups": ["eng"], "was": []})
    resp = site.request(
        "admin", "POST", "/groups/eng/members", data={"members": ["fay", "erin"], "was": ["erin", "dave"]}
    )
    assert resp.status_code == 303 and resp.headers["location"] == "/security#groups"
    assert _groups_of_user(site, "dave") == ["ops"]
    assert _groups_of_user(site, "erin") == ["eng"]
    assert _groups_of_user(site, "fay") == ["eng"]
    # A stale picker that never named `dave` leaves him alone.
    site.request("admin", "POST", "/groups/eng/members", data={"members": ["erin"], "was": ["erin"]})
    assert _groups_of_user(site, "fay") == ["eng"]


def test_group_edit_members_refusals(make_mu_site):
    """Groups section: an unknown user is a refusal (400) that changes
    nothing, an unknown group is a 404, and `admins` is refused."""
    site = make_mu_site()
    group(site, "eng")
    add_user(site, "dave")
    resp = site.request(
        "admin", "POST", "/groups/eng/members", data={"members": ["dave", "ghost"], "was": []}
    )
    assert resp.status_code == 400 and "unknown user ghost" in resp.text
    assert _groups_of_user(site, "dave") == []
    assert site.request("admin", "POST", "/groups/nope/members", data={"members": []}).status_code == 404
    resp = site.request("admin", "POST", "/groups/admins/members", data={"members": ["dave"], "was": []})
    assert resp.status_code == 400 and _groups_of_user(site, "dave") == []


def test_a_refused_group_create_reopens_only_the_group_dialog(make_mu_site):
    """Groups section: a refused create renders the create-group dialog open
    with the reason, and leaves the create-user dialog closed."""
    site = make_mu_site()
    resp = site.request("admin", "POST", "/groups", data={"name": "Bad Name"})
    assert resp.status_code == 400
    assert re.search(r'<dialog id="create-group"[^>]* open', resp.text)
    assert not re.search(r'<dialog id="create-user"[^>]* open', resp.text)
    dialog = re.search(r'<dialog id="create-group".*?</dialog>', resp.text, re.S).group(0)
    assert 'role="alert"' in dialog
    # Plain words, not the pattern of the check.
    assert "invalid group name" in dialog and "^[a-z]" not in resp.text and "must match" not in resp.text


def test_groups_rows_open_a_menu_with_dialogs(make_mu_site):
    """Groups section: create, edit members, and delete are dialogs. The
    POST forms live inside the dialogs, `admins` has no menu, and the delete
    dialog is a `confirmdlg` the reset script leaves alone."""
    site = make_mu_site()
    group(site, "eng")
    add_user(site, "dave")
    groups = section(security(site).text, "groups")
    assert 'commandfor="create-group" command="show-modal"' in groups
    assert 'commandfor="group:eng:members" command="show-modal"' in groups
    assert 'commandfor="group:eng:delete" command="show-modal"' in groups
    for dlg, action in (("group:eng:members", "/groups/eng/members"), ("group:eng:delete", "/groups/eng/delete")):
        body = re.search(rf'<dialog id="{dlg}"[^>]*>(.*?)</dialog>', groups, re.S).group(1)
        assert f'action="{action}"' in body
    assert 'class="confirmdlg"' in groups
    assert 'name="members" value="dave"' in groups
    assert "group:admins:" not in groups


def test_a_user_and_a_group_never_share_a_dom_id(make_mu_site):
    """Security page: a `commandfor` or `popovertarget` opens the FIRST element
    with its id. User `group-eng` next to group `eng` must not make the group's
    Delete open the user's dialog."""
    site = make_mu_site()
    group(site, "eng")
    add_user(site, "group-eng")
    ids = re.findall(r'\sid="([^"]+)"', security(site).text)
    assert len(ids) == len(set(ids)), sorted({i for i in ids if ids.count(i) > 1})


def test_the_bootstrap_admin_refusals_show_in_the_users_section(make_mu_site):
    """Users and groups pages / The bootstrap admin cannot be deleted, and
    cannot be reset."""
    site = make_mu_site()
    for path in ("/users/admin/delete", "/users/admin/setup-code"):
        resp = site.request("admin", "POST", path)
        assert resp.status_code == 400, path
        doc = Doc(resp.text)
        sections = [e["section"] for e in doc.errors]
        assert sorted(s or "" for s in sections) == ["", "users"], (path, sections)
        assert 'id="setup-code"' not in resp.text
    assert "<code>admin</code>" in section(security(site).text, "users")
    # The password of `admin` did not change.
    assert site.client.post("/login", data={"user": "", "password": "secret"}
                            ).status_code == 303


@pytest.mark.parametrize("path,data,name", [
    ("/groups", {"name": "Bad Name"}, "groups"),
    ("/users", {"id": "Bad Id"}, "users"),
    ("/users/admin/delete", {}, "users"),
    ("/rules", {"subject_kind": "nonsense", "subject": "x", "level": "server",
                "effect": "allow"}, "rules"),
])
def test_a_refusal_shows_in_its_own_section(make_mu_site, path, data, name):
    """Users and groups pages / A refusal shows in its own section: status 400,
    the error in the section of the form, and no error in the other two."""
    site = make_mu_site()
    resp = site.request("admin", "POST", path, data=data)
    assert resp.status_code == 400, resp.text
    in_sections = {e["section"] for e in Doc(resp.text).errors if e["section"]}
    assert in_sections == {name}
    # The page still holds all three sections in order.
    assert Doc(resp.text).section_ids == ["users", "groups", "rules"]


def test_a_refusal_is_visible_at_the_top_of_the_page(make_mu_site):
    """Users and groups pages / A refusal is visible at the top of the page."""
    site = make_mu_site()
    resp = site.request("admin", "POST", "/groups/admins/delete")
    assert resp.status_code == 400
    doc = Doc(resp.text)
    banners = [e for e in doc.errors if e["section"] is None]
    assert len(banners) == 1
    banner = banners[0]
    assert banner["role"] == "alert" and banner["links"] == ["#groups"]
    assert "groups" in banner["text"].lower()
    # The banner sits above the first section.
    assert resp.text.index('role="alert"') < resp.text.index('<section id="users">')
    # The section shows the full error, and so does the banner count once.
    own = [e for e in doc.errors if e["section"] == "groups"]
    assert len(own) == 1 and "reserved group" in own[0]["text"]
    assert [e for e in doc.errors if e["section"] in ("users", "rules")] == []


@pytest.mark.parametrize("name,path,data", [
    ("users", "/users/admin/delete", {}),
    ("rules", "/rules", {"subject_kind": "nonsense"}),
])
def test_the_banner_links_to_the_section_of_the_error(make_mu_site, name, path, data):
    site = make_mu_site()
    resp = site.request("admin", "POST", path, data=data)
    assert resp.status_code == 400
    banner = [e for e in Doc(resp.text).errors if e["section"] is None]
    assert len(banner) == 1 and banner[0]["links"] == [f"#{name}"]
    assert banner[0]["role"] == "alert"


def test_a_clean_page_has_no_banner(make_mu_site):
    site = make_mu_site()
    assert Doc(security(site).text).errors == []


def test_an_error_page_still_lists_every_section(make_mu_site):
    """D1: one context for all sections. A refusal of the Users section still
    lists the groups and the users for the Rules form."""
    site = make_mu_site()
    group(site, "eng")
    put_groups(site, "alice", "eng")
    resp = site.request("admin", "POST", "/users/admin/delete")
    assert resp.status_code == 400
    assert [t for t, _ in cell_tags(section(resp.text, "groups"), "eng").tags] == ["alice"]
    rules = section(resp.text, "rules")
    for subject in ("alice", "bob", "eng"):
        assert f'<option value="{subject}">' in rules


# --- The role control and the create form (read from the rendered forms) ---


def _forms_to(doc: Doc, action: str) -> list[dict]:
    return [a for _, a in doc.forms if a.get("action") == action]


def _fields_to(doc: Doc, action: str) -> dict[str, str]:
    """What a browser posts from the form: the named inputs with a value."""
    return {a["name"]: a.get("value", "") for act, a in doc.form_fields
            if act == action and a.get("name")}


def _buttons_to(doc: Doc, action: str) -> list[str]:
    return [b["text"].strip() for b in doc.buttons if b["form_action"] == action]


def _is_admin(site, uid: str) -> bool:
    users = site.client.get("/api/users", headers=api_headers(site)).json()
    return next(u["admin"] for u in users if u["id"] == uid)


def test_a_non_admin_row_has_no_role_form_and_the_picker_grants_the_role(make_mu_site):
    """Users section: no form to `/users/<id>/admin`, no `Make admin` button;
    the picker (add `admins`) grants the role."""
    site = make_mu_site()
    doc = Doc(security(site).text)
    assert _forms_to(doc, "/users/alice/admin") == []
    assert "Make admin" not in [b["text"].strip() for b in doc.buttons]
    assert not _is_admin(site, "alice")
    resp = site.request("admin", "POST", "/users/alice/groups",
                        data={"was": [], "groups": ["admins"]})
    assert resp.status_code == 303
    assert _is_admin(site, "alice")


def test_an_admin_row_shows_the_admins_tag_and_its_x_revokes(make_mu_site):
    """Users section: an admin row has no `Revoke` button; the tag `admins`
    holds a x form that takes the role away."""
    site = make_mu_site()
    assert site.request("admin", "POST", "/users/alice/groups",
                        data={"groups": ["admins"]}).status_code == 303
    doc = Doc(security(site).text)
    assert _forms_to(doc, "/users/alice/admin") == []
    assert "Revoke" not in [b["text"].strip() for b in doc.buttons]
    action = "/groups/admins/members/alice/remove?from=users"
    assert len(_forms_to(doc, action)) == 1
    assert _is_admin(site, "alice")
    assert site.request("admin", "POST", action).status_code == 303
    assert not _is_admin(site, "alice")


def test_the_bootstrap_row_has_no_role_or_reset_form(make_mu_site):
    """Users section: the bootstrap `admin` row has no role, reset, or delete
    form and shows `set by ADMIN_PASSWORD`. Its groups form stays: `admin` may
    hold groups (design D4). The Admin column is gone."""
    site = make_mu_site()
    body = security(site).text
    actions = {a.get("action") for _, a in Doc(body).forms}
    assert {a for a in actions if (a or "").startswith("/users/admin/")} == {
        "/users/admin/groups"}
    text = " ".join(re.sub(r"<[^>]+>", " ", row(section(body, "users"), "admin")).split())
    assert "set by ADMIN_PASSWORD" in text
    assert "Admin" not in re.findall(r"<th>([^<]*)</th>", section(body, "users"))


@pytest.mark.parametrize("typed", ["eng, ops", "eng ops"])
def test_the_create_form_takes_groups_split_on_comma_or_space(make_mu_site, typed):
    """Users section: the typed `groups` field splits on commas and spaces."""
    site = make_mu_site()
    group(site, "eng")
    group(site, "ops")
    resp = site.request("admin", "POST", "/users", data={"id": "dave", "groups": typed})
    assert resp.status_code == 200, resp.text
    tags = cell_tags(section(resp.text, "users"), "dave")
    assert [t for t, _ in tags.tags] == ["eng", "ops"]
    users = site.client.get("/api/users", headers=api_headers(site)).json()
    assert next(u["groups"] for u in users if u["id"] == "dave") == ["eng", "ops"]


def test_the_create_form_refuses_an_unknown_group_in_the_users_section(make_mu_site):
    """Users section: an unknown group is a refusal of the form (400); the
    reason shows in the Users section only and the user is not created."""
    site = make_mu_site()
    group(site, "eng")
    resp = site.request("admin", "POST", "/users", data={"id": "dave", "groups": "nogroup"})
    assert resp.status_code == 400
    assert "unknown group" in section(resp.text, "users")
    assert "unknown group" not in section(resp.text, "groups")
    assert "unknown group" not in section(resp.text, "rules")
    assert {e["section"] for e in Doc(resp.text).errors if e["section"]} == {"users"}
    users = site.client.get("/api/users", headers=api_headers(site)).json()
    assert "dave" not in {u["id"] for u in users}
    assert 'id="setup-code"' not in resp.text


# --- Grant rules page (modified) --------------------------------------------


def _add_rule(site):
    return site.request("admin", "POST", "/rules", data={
        "subject_kind": "group", "subject": "eng", "level": "server",
        "server": "time", "effect": "allow"})


def test_the_rules_section_offers_the_add_form_and_the_note(make_mu_site):
    """Grant rules page: the add form fields and the global-allow statement."""
    site = make_mu_site()
    body = security(site).text
    names = {i[1].get("name") for i in Doc(body).inputs if i[0] == "rules"}
    assert "subject" in names and "tool" in names
    for select in ("subject_kind", "level", "server", "effect"):
        assert f'name="{select}"' in section(body, "rules")
    text = re.sub(r"<[^>]+>", " ", section(body, "rules"))
    assert re.search(r"global allow covers admin-owned servers only", " ".join(text.split()))


def test_add_and_delete_a_rule_redirect_to_the_rules_anchor(make_mu_site):
    """Grant rules page / Add a rule ... / Delete a rule from the dashboard."""
    site = make_mu_site()
    group(site, "eng")
    resp = _add_rule(site)
    assert resp.status_code == 303 and resp.headers["location"] == "/security#rules"
    rules = section(security(site).text, "rules")
    rid = re.search(r"<td><code>(r[^<]*|[^<]+)</code></td>\s*<td>group <code>eng</code>", rules)
    assert rid, rules
    cells = row(rules, rid.group(1))
    for want in ("eng", "server", "time", "allow"):
        assert want in cells
    assert f"/rules/{rid.group(1)}/delete" in cells
    resp = site.request("admin", "POST", f"/rules/{rid.group(1)}/delete")
    assert resp.status_code == 303 and resp.headers["location"] == "/security#rules"
    assert rid.group(1) not in section(security(site).text, "rules")


# --- The create dialog reopens on a refused create ---------------------------


def test_a_refused_create_renders_the_create_dialog_open_with_the_reason(make_mu_site):
    """A refused create answers 400 with the create dialog open and the reason
    inside it, once: the section line does not repeat it."""
    site = make_mu_site()
    resp = site.request("admin", "POST", "/users", data={"id": "Bad Id"})
    assert resp.status_code == 400
    body = resp.text
    dialog = re.search(r'<dialog id="create-user" class="userdlg" open>(.*?)</dialog>', body, re.S)
    assert dialog, "the create dialog renders open"
    assert 'role="alert"' in dialog.group(1)
    assert body.count('class="error"') == 1  # the reason shows in the dialog only


def test_a_refused_delete_keeps_the_create_dialog_closed(make_mu_site):
    site = make_mu_site()
    resp = site.request("admin", "POST", "/users/admin/delete")
    assert resp.status_code >= 400
    assert '<dialog id="create-user" class="userdlg">' in resp.text
    assert "userdlg\" open" not in resp.text


def test_the_create_id_field_carries_the_server_id_rule(make_mu_site):
    """The browser stops a bad id before the post: the field's `pattern` is the
    id rule of the provider, with a plain `title`."""
    body = security(make_mu_site()).text
    tag = re.search(r'<input id="create-user-id"[^>]*>', body, re.S).group(0)
    assert 'pattern="[a-z0-9][a-z0-9_\\-]{0,63}"' in tag
    assert 'title="Lowercase letters, digits, - and _, up to 64 characters"' in tag


def test_dom_ids_stay_unique_when_a_user_id_ends_like_a_child_id(make_mu_site):
    """A user `alice-filter` must not take the id of the filter input in the
    dialog of `alice`: the child ids use a separator the user id rule forbids."""
    site = make_mu_site()
    # `alice` is seeded by the site; add the user whose dialog id would collide.
    assert site.request("admin", "POST", "/users", data={"id": "alice-filter"}).status_code == 200
    ids = re.findall(r'\bid="([^"]+)"', security(site).text)
    assert len(ids) == len(set(ids)), sorted(i for i in ids if ids.count(i) > 1)
