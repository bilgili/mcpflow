"""Markup, style, and picker acceptance of the Security page (admins-group, 8.7, 8.8).

Scenarios: web-ui "Group picker", "Users and groups pages", "Membership tags"
(No nested forms, The admins tag shows a shield, The bootstrap membership is
locked, Remove a member with the x); access-policy "No grant rule on the group
admins" (the Rules datalist). Design D9, D6, R7, R8.

The markup is read into a small tree with `html.parser`, never matched with a
substring of the template. The DOM contract of D9 is the oracle: class names,
attribute names, and texts. The CSS is read as text from the static file.

Decision E3: no browser harness. "Cancel discards the ticks" is checked on the
text of the inline script (the literals the design names); the orchestrator
checks the real browser behavior by hand.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from html.parser import HTMLParser
from pathlib import Path

import pytest
from dashboard_site import make_mu_site  # noqa: F401

STATIC = Path(__file__).resolve().parent.parent / "src" / "mcpflow" / "static" / "style.css"
LOCK_TITLE = "Locked for the bootstrap user"
VOID = {"input", "br", "hr", "img", "meta", "link", "source", "wbr"}


# --- a small DOM -----------------------------------------------------------


class Node:
    def __init__(self, tag: str, attrs: dict, parent: Node | None):
        self.tag, self.attrs, self.parent = tag, attrs, parent
        self.children: list[Node | str] = []

    @property
    def classes(self) -> list[str]:
        return (self.attrs.get("class") or "").split()

    def walk(self) -> Iterator[Node]:
        for c in self.children:
            if isinstance(c, Node):
                yield c
                yield from c.walk()

    def find(self, tag: str | None = None, cls: str | None = None, **attrs) -> list[Node]:
        out = []
        for n in self.walk():
            if tag and n.tag != tag:
                continue
            if cls and cls not in n.classes:
                continue
            if any((k.replace("_", "-") not in n.attrs) if v is True
                   else n.attrs.get(k.replace("_", "-")) != v for k, v in attrs.items()):
                continue
            out.append(n)
        return out

    def text(self) -> str:
        return "".join(c if isinstance(c, str) else c.text() for c in self.children)

    def ancestors(self) -> Iterator[Node]:
        n = self.parent
        while n is not None:
            yield n
            n = n.parent

    def index_in_doc(self, root: Node) -> int:
        return next(i for i, n in enumerate(root.walk()) if n is self)


class Tree(HTMLParser):
    def __init__(self, html: str):
        super().__init__(convert_charrefs=True)
        self.root = Node("#root", {}, None)
        self._cur = self.root
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        node = Node(tag, dict(attrs), self._cur)
        self._cur.children.append(node)
        if tag not in VOID:
            self._cur = node

    def handle_startendtag(self, tag, attrs):
        self._cur.children.append(Node(tag, dict(attrs), self._cur))

    def handle_endtag(self, tag):
        n = self._cur
        while n is not self.root and n.tag != tag:
            n = n.parent
        if n is not self.root:
            self._cur = n.parent

    def handle_data(self, data):
        self._cur.children.append(data)


# --- the page --------------------------------------------------------------


def post(site, path: str, uid: str = "admin", **kw):
    return site.request(uid, "POST", path, **kw)


@pytest.fixture
def page(make_mu_site):  # noqa: F811
    """`/security` of a site with groups `aaa`, `zeta`, `eng`, `ops`, `alpha`
    (created unsorted); `alice` in `admins` and `eng`; `bob` in 4 groups, so
    his cell has a `+N more` control."""
    site = make_mu_site()
    for g in ("aaa", "zeta", "eng", "ops", "alpha"):
        assert post(site, "/groups", data={"name": g}).status_code == 303
    assert post(site, "/users/alice/groups",
                data={"groups": ["admins", "eng"]}).status_code == 303
    assert post(site, "/users/bob/groups",
                data={"groups": ["ops", "zeta", "alpha", "eng"]}).status_code == 303
    resp = site.request("admin", "GET", "/security")
    assert resp.status_code == 200
    site.body = resp.text
    site.tree = Tree(resp.text).root
    return site


def section(tree: Node, name: str) -> Node:
    (node,) = tree.find("section", id=name)
    return node


def popover(tree: Node, uid: str) -> Node:
    """The edit dialog of `uid`: the group list lives there."""
    (node,) = tree.find("dialog", id=f"edit-{uid}")
    return node


def user_row(tree: Node, uid: str) -> Node:
    for tr in section(tree, "users").find("tr"):
        code = tr.find("code")
        if code and code[0].text() == uid:
            return tr
    raise AssertionError(f"no row for {uid}")


# --- 8.7: the picker and the pages -----------------------------------------


def test_no_form_holds_another_form(page):
    """Scenario "No nested forms"."""
    forms = page.tree.find("form")
    assert len(forms) > 10
    for form in forms:
        assert not any(a.tag == "form" for a in form.ancestors()), form.attrs
        assert not form.find("form")


def test_the_row_menu_opens_the_edit_dialog(page):
    """The `⋯` button opens the row menu; its `Edit user` item opens the dialog.
    The row has no `Edit` button and no popover list of groups."""
    for uid in ("admin", "alice", "bob"):
        row = user_row(page.tree, uid)
        assert not row.find("button", cls="group-edit")
        (btn,) = row.find("button", cls="menu-btn")
        assert btn.attrs["type"] == "button"
        assert btn.attrs["aria-label"] == f"Actions for {uid}"
        (menu,) = row.find("div", popover=True)
        assert btn.attrs["popovertarget"] == menu.attrs["id"] == f"menu-of-{uid}"
        assert "row-menu" in menu.classes
        (item,) = [b for b in menu.find("button") if b.text().strip() == "Edit user"]
        assert item.attrs["command"] == "show-modal"
        assert item.attrs["commandfor"] == f"edit-{uid}"
        dlg = popover(page.tree, uid)
        assert "userdlg" in dlg.classes
        assert not any(a.tag == "form" or "tag" in a.classes for a in dlg.ancestors())
    assert not page.tree.find(cls="group-pop")


def test_the_menu_keeps_reset_and_delete_for_every_user_but_the_bootstrap(page):
    for uid in ("alice", "bob"):
        menu = user_row(page.tree, uid).find("div", popover=True)[0]
        actions = {f.attrs["action"]: [b.text().strip() for b in f.find("button")]
                   for f in menu.find("form")}
        # Reset posts from the menu; Delete only opens its confirm dialog.
        assert actions == {f"/users/{uid}/setup-code": ["Reset password"]}
        assert [b.attrs.get("commandfor") for b in menu.find("button", cls="danger")] == [f"delete-{uid}"]
    menu = user_row(page.tree, "admin").find("div", popover=True)[0]
    assert not menu.find("form")


def test_the_picker_form_posts_to_the_user(page):
    for uid in ("admin", "alice", "bob"):
        dlg = popover(page.tree, uid)
        (form,) = dlg.find("form")
        assert form.attrs["method"].lower() == "post"
        assert form.attrs["action"] == f"/users/{uid}/groups"
        assert dlg.find("h3")[0].text().strip() == "Edit user"
        assert [c.text() for c in form.find("code")] == [uid]  # the id is shown, not posted
        assert "id" not in {i.attrs.get("name") for i in form.find("input")}
        assert [b.attrs.get("type") for b in form.find("button")] == ["button", "button", "submit"]


def test_the_picker_lists_every_group_sorted_and_admins_is_not_pinned(page):
    expected = ["aaa", "admins", "alpha", "eng", "ops", "zeta"]
    for uid in ("admin", "alice", "bob"):
        pop = popover(page.tree, uid)
        (listing,) = pop.find("div", cls="group-list")
        values = [i.attrs["value"] for i in listing.find("input", type="checkbox")]
        assert values == expected, uid
        labels = listing.find("label")
        assert [re.sub(r"\s+", "", lb.text()) for lb in labels] == expected
        # `admins` is an ordinary entry: no pin, no note, no shield.
        assert not pop.find("svg", cls="shield")
        assert not [n for n in pop.walk() if "note" in " ".join(n.classes)]


def test_the_picker_checks_exactly_the_groups_of_its_user(page):
    members = {"admin": {"admins"}, "alice": {"admins", "eng"},
               "bob": {"ops", "zeta", "alpha", "eng"}}
    for uid, groups in members.items():
        pop = popover(page.tree, uid)
        boxes = pop.find("input", type="checkbox")
        assert all(b.attrs["name"] == "groups" for b in boxes)
        assert {b.attrs["value"] for b in boxes if "checked" in b.attrs} == groups


def test_the_picker_posts_was_for_every_checked_group_but_the_locked_one(page):
    for uid, was in {"alice": ["admins", "eng"],
                     "bob": ["alpha", "eng", "ops", "zeta"],
                     "admin": []}.items():
        pop = popover(page.tree, uid)
        hidden = pop.find("input", type="hidden")
        assert all(h.attrs["name"] == "was" for h in hidden)
        assert sorted(h.attrs["value"] for h in hidden) == was, uid


def test_the_bootstrap_picker_has_no_was_admins(page):
    """The `admins` box of `admin` is checked, disabled, and locked; `was`
    leaves it out, so a delta never names it."""
    pop = popover(page.tree, "admin")
    assert not [h for h in pop.find("input", type="hidden") if h.attrs["value"] == "admins"]
    (box,) = [b for b in pop.find("input", type="checkbox") if b.attrs["value"] == "admins"]
    assert "checked" in box.attrs and "disabled" in box.attrs
    lock = box.parent.find("span", cls="lock")
    assert len(lock) == 1
    assert lock[0].attrs["title"] == LOCK_TITLE and lock[0].attrs["aria-label"] == "Locked"
    assert lock[0].index_in_doc(pop) > box.index_in_doc(pop)  # the lock follows the box
    # No other box is locked.
    assert [b.attrs["value"] for b in pop.find("input", type="checkbox")
            if "disabled" in b.attrs] == ["admins"]
    assert len(pop.find("span", cls="lock")) == 1


def test_a_non_bootstrap_picker_has_no_lock(page):
    for uid in ("alice", "bob"):
        pop = popover(page.tree, uid)
        assert not pop.find("span", cls="lock")
        assert not [b for b in pop.find("input", type="checkbox") if "disabled" in b.attrs]


def test_the_filter_input_has_no_name(page):
    for uid in ("admin", "alice", "bob"):
        (flt,) = popover(page.tree, uid).find("input", cls="group-filter")
        assert flt.attrs["type"] == "search"
        assert "name" not in flt.attrs
        assert flt.attrs["placeholder"] == "Filter groups"
        assert [lb for lb in popover(page.tree, uid).find("label")
                if lb.attrs.get("for") == flt.attrs["id"]]


def test_cancel_closes_its_dialog(page):
    for uid in ("admin", "alice", "bob"):
        pop = popover(page.tree, uid)
        (foot,) = pop.find("div", cls="pop-foot")
        cancel = [b for b in foot.find("button") if b.text().strip() == "Cancel"]
        assert len(cancel) == 1
        assert cancel[0].attrs["type"] == "button"
        assert cancel[0].attrs["commandfor"] == f"edit-{uid}"
        assert cancel[0].attrs["command"] == "close"
        (save,) = [b for b in foot.find("button") if b.text().strip() == "Save"]
        assert save.attrs["type"] == "submit"


def test_the_count_is_the_number_of_checked_boxes_at_render(page):
    """Scenario "Group picker": the text `N selected`, the server renders N."""
    for uid, n in {"admin": 1, "alice": 2, "bob": 4}.items():
        pop = popover(page.tree, uid)
        (count,) = pop.find("span", cls="count")
        assert count.text().strip() == f"{n} selected"
        assert n == len([b for b in pop.find("input", type="checkbox") if "checked" in b.attrs])


def test_the_users_section_has_no_admin_controls(page):
    """Scenario "The create form has no password and no admin checkbox" and
    "Users and groups pages": no Admin column, no "Make admin", no "Revoke"."""
    users = section(page.tree, "users")
    (head,) = users.find("thead")
    assert [th.text().strip() for th in head.find("th")] == ["User", "Name", "Groups", ""]
    button_texts = {re.sub(r"\s+", " ", b.text()).strip() for b in users.find("button")}
    assert not {"Make admin", "Revoke"} & button_texts
    text = users.text()
    assert "Make admin" not in text and "Revoke" not in text
    assert not [i for i in users.find("input") if i.attrs.get("name") == "admin"]
    create = [f for f in users.find("form") if f.attrs.get("action") == "/users"]
    assert len(create) == 1
    assert not create[0].find("input", type="password")
    assert {i.attrs.get("name") for i in create[0].find("input")} == {None, "id", "name", "groups"}
    assert {c.attrs["name"] for c in create[0].find("input", type="checkbox")} == {"groups"}


def test_the_admins_row_of_the_groups_section_has_no_delete_form(page):
    """Scenario "The reserved group has no delete control"."""
    groups = section(page.tree, "groups")
    actions = [f.attrs.get("action") for f in groups.find("form")]
    assert "/groups/admins/delete" not in actions
    assert "/groups/eng/delete" in actions  # the other groups keep theirs
    assert not [f for f in page.tree.find("form") if f.attrs.get("action") == "/groups/admins/delete"]


def test_the_rules_datalist_leaves_out_admins(page):
    """Scenario "No grant rule on the group admins": the Rules section does
    not suggest `admins` as a subject."""
    rules = section(page.tree, "rules")
    (datalist,) = rules.find("datalist", id="rule-subjects")
    values = [o.attrs.get("value") for o in datalist.find("option")]
    assert "admins" not in values
    assert {"eng", "ops", "alice", "bob"} <= set(values)


# --- actor-guard-review-fixes, fix 2: the filter box has no form owner ------

def filter_dialogs(tree: Node) -> list[Node]:
    """Every dialog of the page that holds a `.group-filter` box, found by
    walking the page. The page must hold at least one user dialog and one
    members dialog, so the two tests below cannot pass on an empty list."""
    dialogs = [d for d in tree.find("dialog") if d.find("input", cls="group-filter")]
    ids = [d.attrs["id"] for d in dialogs]
    assert {"create-user", "edit-admin", "edit-alice", "edit-bob"} <= set(ids), ids
    assert any(i.startswith("group:") and i.endswith(":members") for i in ids), ids
    return dialogs


def form_owner(node: Node, tree: Node) -> Node | None:
    """The form owner of a control, by the algorithm of the HTML standard.

    A `form` attribute names the owner: the `<form>` of the document with that
    id, or no owner when no form has it. Without the attribute, the owner is the
    nearest ancestor `<form>`, or none. The search walks the whole document."""
    if "form" in node.attrs:
        hits = [n for n in tree.walk() if n.tag == "form" and n.attrs.get("id") == node.attrs["form"]]
        return hits[0] if hits else None
    return next((a for a in node.ancestors() if a.tag == "form"), None)


def dialog(tree: Node, dom_id: str) -> Node:
    (node,) = tree.find("dialog", id=dom_id)
    return node


def test_form_owner_follows_the_html_algorithm():
    """The helper itself: a self-test on a tiny document, so the two tests below
    do not pass because the helper always answers `None`."""
    tree = Tree(
        '<form id="f1"><input id="a"><input id="b" form="nope"><input id="c" form="f2">'
        '</form><form id="f2"></form><input id="d" form="f1"><input id="e">').root
    owner = {n.attrs["id"]: form_owner(n, tree) for n in tree.find("input")}
    assert owner["a"].attrs["id"] == "f1"
    assert owner["b"] is None  # names no form: no owner, though inside a form
    assert owner["c"].attrs["id"] == "f2"  # the attribute beats the ancestor
    assert owner["d"].attrs["id"] == "f1"
    assert owner["e"] is None


def test_the_filter_box_has_no_form_owner(page):
    """Scenario "The filter box has no form owner" (design test 10)."""
    ids = {n.attrs["id"] for n in page.tree.walk() if "id" in n.attrs}
    for dlg in filter_dialogs(page.tree):
        dom_id = dlg.attrs["id"]
        (flt,) = dlg.find("input", cls="group-filter")
        assert flt.attrs["id"] == f"{dom_id}:filter"
        assert flt.attrs["type"] == "search"
        assert flt.attrs["form"] == f"{dom_id}:detached", dom_id
        assert "name" not in flt.attrs
        # Without the attribute the box sits inside the dialog form, so the
        # attribute is what removes the owner.
        assert any(a.tag == "form" for a in flt.ancestors())
        assert f"{dom_id}:detached" not in ids
        assert form_owner(flt, page.tree) is None, dom_id


def test_the_other_controls_belong_to_the_dialog_form(page):
    """Scenarios "Enter in the id field submits the create dialog" and "Enter in
    the filter box of the create dialog submits nothing" (design test 11)."""
    for dlg in filter_dialogs(page.tree):
        dom_id = dlg.attrs["id"]
        (form,) = dlg.find("form")
        controls = [n for n in dlg.walk() if n.tag in ("input", "button", "select", "textarea")]
        flt = dlg.find("input", cls="group-filter")[0]
        others = [c for c in controls if c is not flt]
        assert others
        for c in others:
            assert "form" not in c.attrs, (dom_id, c.tag, c.attrs)
            assert form_owner(c, page.tree) is form, (dom_id, c.tag, c.attrs)
        assert [b.attrs.get("type") for b in form.find("button")].count("submit") == 1
        names = {i.attrs.get("name") for i in form.find("input")}
        if dom_id == "create-user":
            assert {"id", "name"} <= names
        else:
            assert not {"id", "name"} & names
        if dom_id.startswith("group:"):
            assert "members" in names  # `was` only exists for a group that has members


# --- 8.8: chips ------------------------------------------------------------


def chips(tree: Node, sec: str) -> list[Node]:
    return [n for n in section(tree, sec).find("div") if "tag" in n.classes]


def chip_name(chip: Node) -> str:
    return chip.find("code")[0].text()


def test_the_x_is_a_submit_button_inside_the_chip_form_inside_the_tag(page):
    """Scenarios "Remove a member with the x" and "The same removal from the
    Users section"."""
    seen = 0
    for chip in chips(page.tree, "users"):
        if "nox" in chip.classes:
            continue
        cell_row = next(a for a in chip.ancestors() if a.tag == "tr")
        user = cell_row.find("code")[0].text()
        group = chip_name(chip)
        (form,) = chip.find("form")
        assert form.parent is chip
        assert form.attrs["method"].lower() == "post"
        assert form.attrs["action"] == f"/groups/{group}/members/{user}/remove?from=users"
        (btn,) = form.find("button")
        assert btn.parent is form
        assert btn.attrs["type"] == "submit" and "tag-x" in btn.classes
        assert btn.attrs["aria-label"] == f"Remove {user} from {group}"
        assert btn.find("svg") and btn.find("svg")[0].attrs["aria-hidden"] == "true"
        assert btn.text().strip() == ""  # the name comes from aria-label
        seen += 1
    assert seen >= 5
    # The same shape in the Groups section, with `from=groups`.
    for chip in chips(page.tree, "groups"):
        if "nox" in chip.classes:
            continue
        group = next(a for a in chip.ancestors() if a.tag == "tr").find("code")[0].text()
        (form,) = chip.find("form")
        assert form.attrs["action"] == (
            f"/groups/{group}/members/{chip_name(chip)}/remove?from=groups")
        assert form.find("button")[0].attrs["aria-label"] == (
            f"Remove {chip_name(chip)} from {group}")


def test_the_admins_chip_has_an_aria_hidden_shield(page):
    """Scenario "The admins tag shows a shield"."""
    row = user_row(page.tree, "alice")
    (chip,) = [c for c in chips(page.tree, "users")
               if chip_name(c) == "admins" and c in list(row.walk())]
    assert "admins" in chip.classes
    (shield,) = chip.find("svg", cls="shield")
    assert shield.attrs["aria-hidden"] == "true"
    assert shield.index_in_doc(chip) < chip.find("code")[0].index_in_doc(chip)  # before the name
    assert chip.find("button", cls="tag-x")  # and a x button
    # Another chip has no shield and no `admins` class.
    other = [c for c in chips(page.tree, "users") if chip_name(c) == "eng"]
    assert other and all("admins" not in c.classes and not c.find("svg", cls="shield")
                         for c in other)


def test_the_bootstrap_admins_chip_is_locked_in_both_sections(page):
    """Scenario "The bootstrap membership is locked"."""
    # Users section: the tag `admins` in the row of `admin`.
    row = user_row(page.tree, "admin")
    (chip,) = [c for c in chips(page.tree, "users")
               if chip_name(c) == "admins" and c in list(row.walk())]
    assert chip.classes == ["tag", "admins", "nox"]
    assert not chip.find("form") and not chip.find("button")
    (lock,) = chip.find("span", cls="lock")
    assert lock.attrs["title"] == LOCK_TITLE
    # Groups section: the tag `admin` in the row of `admins`.
    (grow,) = [tr for tr in section(page.tree, "groups").find("tr")
               if tr.find("code") and tr.find("code")[0].text() == "admins"]
    (gchip,) = [c for c in chips(page.tree, "groups")
                if chip_name(c) == "admin" and c in list(grow.walk())]
    assert gchip.classes == ["tag", "nox"]
    assert not gchip.find("form") and not gchip.find("button")
    (glock,) = gchip.find("span", cls="lock")
    assert glock.attrs["title"] == LOCK_TITLE
    # The lock is for this one pair only: every other chip keeps its x.
    locked = [c for c in chips(page.tree, "users") + chips(page.tree, "groups")
              if "nox" in c.classes]
    assert len(locked) == 2
    # The user `admin` in another group is not locked.
    (eng,) = [tr for tr in section(page.tree, "groups").find("tr")
              if tr.find("code") and tr.find("code")[0].text() == "eng"]
    assert eng.find("button", cls="tag-x")


def test_the_shield_does_not_show_in_the_groups_section(page):
    assert not section(page.tree, "groups").find("svg", cls="shield")
    assert not [c for c in chips(page.tree, "groups") if "admins" in c.classes]


def test_a_long_list_keeps_its_count_and_more_control(page):
    """The macro keeps the count and the `+N more` `<details>` for `bob`'s 4 groups."""
    row = user_row(page.tree, "bob")
    (details,) = row.find("details")
    assert details.find("summary")[0].text().strip() == "+1 more"
    visible = [chip_name(c) for c in row.find("div") if "tag" in c.classes
               and not any(a is details for a in c.ancestors())]
    assert visible == ["alpha", "eng", "ops"]  # the first three, sorted


# --- 8.8: the style --------------------------------------------------------


def css_text() -> str:
    return re.sub(r"/\*.*?\*/", "", STATIC.read_text(), flags=re.DOTALL)


def blocks(css: str) -> list[tuple[str, str]]:
    """Every `selector { body }` of the file, nested `@supports` included."""
    out = []
    for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", css):
        out.append((re.sub(r"\s+", " ", m.group(1)).strip(), m.group(2)))
    return out


def decls(body: str) -> dict[str, str]:
    d = {}
    for part in body.split(";"):
        if ":" in part:
            k, v = part.split(":", 1)
            d[k.strip()] = re.sub(r"\s+", " ", v).strip()
    return d


def rule(selector: str) -> dict[str, str]:
    """The merged declarations of every block whose selector list names `selector`."""
    merged: dict[str, str] = {}
    for sel, body in blocks(css_text()):
        if selector in [s.strip() for s in sel.split(",")]:
            merged.update(decls(body))
    assert merged, f"no rule for {selector}"
    return merged


def count_rules(selector: str) -> int:
    return sum(selector in [s.strip() for s in sel.split(",")] for sel, _ in blocks(css_text()))


def test_the_group_list_scrolls_inside_a_box():
    d = rule(".group-list")
    assert d["max-height"] == "150px" and d["overflow"] == "auto"
    assert rule(".group-list label")["display"] == "flex"


def test_a_hidden_label_is_not_displayed():
    """`display: flex` overrides the `hidden` attribute, so the rule is required."""
    assert rule(".group-list label[hidden]")["display"] == "none"


def test_the_tag_is_a_borderless_rounded_chip():
    d = rule(".tag")
    assert d["border"] == "0"
    assert d["border-radius"] == "999px"
    assert d["background"] == "var(--chip-bg)"
    assert d["display"] == "inline-flex"
    assert count_rules(".tag") == 1


def test_the_chip_colors_are_declared():
    root = rule(":root")
    assert "color-mix" in root["--chip-bg"] and "--accent" in root["--chip-bg"]
    assert "--chip-fg" in root


def test_the_x_resets_the_button_style_and_keeps_a_24_px_target():
    d = rule(".tag-x")
    assert d["all"] == "unset"
    assert d["width"] == "24px" and d["height"] == "24px"
    assert count_rules(".tag-x") == 1


def test_the_x_hover_adds_no_border():
    d = rule(".tag-x:hover")
    assert d["border"] == "0"
    assert "radial-gradient" in d["background"]


def test_the_x_has_a_focus_ring():
    d = rule(".tag-x:focus-visible")
    assert d["outline"].startswith("2px solid")


def test_the_dialog_style_and_the_menu_anchor_fallback():
    assert rule("dialog.userdlg")["width"] == "min(420px, 94vw)"
    css = css_text()
    supports = re.search(r"@supports\s*\(position-area:\s*bottom\)\s*\{(.*?\}\s*)\}", css, re.DOTALL)
    assert supports and "position-area" in supports.group(1)
    assert rule(".pop-foot")["display"] == "flex"


def test_the_old_check_label_rule_is_gone():
    assert ".form-row label.check" not in css_text()


# --- 8.8: the script (E3: static assertions) -------------------------------


def inline_script(page) -> str:
    scripts = [s for s in section(page.tree, "users").find("script") if "src" not in s.attrs]
    assert len(scripts) == 1
    return scripts[0].text()


def test_the_script_resets_the_form_on_close(page):
    """Scenario "Cancel discards the ticks" (E3: static)."""
    js = inline_script(page)
    close = js.index('"close"')
    reset = js.index("form.reset()")
    assert reset > close
    # The close that upgrades an open dialog to a modal must not reset it, or
    # the reason a refused write shows in the dialog is wiped.
    assert close < js.index("e.target.open") < reset
    # The reset also clears the filter, shows every label, and resets the count.
    tail = js[close:]
    assert re.search(r'\.group-filter"\)\.value\s*=\s*""', tail)
    assert re.search(r"hidden\s*=\s*false", tail)
    assert re.search(r"count\(", tail) or '" selected"' in tail


def test_the_script_filters_and_counts_by_event_delegation(page):
    js = inline_script(page)
    assert re.search(r'addEventListener\(\s*"input"', js) and ".group-filter" in js
    assert re.search(r"\.hidden\s*=", js)  # the filter hides labels with `hidden`
    assert re.search(r'addEventListener\(\s*"change"', js) and ".group-list" in js
    assert "selected" in js


def test_the_script_never_posts_or_submits(page):
    """The filter is not a selection (R8): the script has no submit or fetch."""
    js = inline_script(page)
    assert "submit(" not in js and "fetch(" not in js and "XMLHttpRequest" not in js


# --- 8.8: without JavaScript -----------------------------------------------


def browser_post(site, uid: str, *, check=(), uncheck=()):
    """Submit the rendered picker of `uid` the way a browser without
    JavaScript does: checked, enabled boxes and the hidden fields."""
    tree = Tree(site.request("admin", "GET", "/security").text).root
    form = popover(tree, uid).find("form")[0]
    data: dict[str, list[str]] = {}
    for box in form.find("input", type="checkbox"):
        value = box.attrs["value"]
        on = ("checked" in box.attrs and value not in uncheck) or value in check
        if on and "disabled" not in box.attrs:
            data.setdefault("groups", []).append(value)
    for hid in form.find("input", type="hidden"):
        data.setdefault(hid.attrs["name"], []).append(hid.attrs["value"])
    return site.request("admin", "POST", form.attrs["action"], data=data)


def groups_now(site, uid: str) -> set[str]:
    from dashboard_site import api_headers

    listing = site.client.get("/api/users", headers=api_headers(site)).json()
    return set(next(u for u in listing if u["id"] == uid)["groups"])


def test_without_javascript_the_picker_post_works(page):
    """Scenario "Save adds and removes", from the rendered form."""
    resp = browser_post(page, "alice", check=["ops"], uncheck=["eng"])
    assert resp.status_code == 303 and resp.headers["location"] == "/security#users"
    assert groups_now(page, "alice") == {"admins", "ops"}


def test_without_javascript_an_unchanged_save_changes_nothing(page):
    before = (page.data / "users.json").read_bytes()
    for uid in ("alice", "bob", "admin"):
        assert browser_post(page, uid).status_code == 303
    assert (page.data / "users.json").read_bytes() == before


def test_without_javascript_the_bootstrap_save_succeeds(page):
    """Scenario "The bootstrap user saves": the disabled box posts nothing."""
    resp = browser_post(page, "admin", check=["eng"])
    assert resp.status_code == 303
    assert groups_now(page, "admin") == {"admins", "eng"}


def test_without_javascript_unchecking_every_box_posts_no_groups_field(page):
    resp = browser_post(page, "bob", uncheck=["ops", "zeta", "alpha", "eng"])
    assert resp.status_code == 303
    assert groups_now(page, "bob") == set()


def test_without_javascript_the_picker_alone_revokes_the_role(page):
    resp = browser_post(page, "alice", uncheck=["admins"])
    assert resp.status_code == 303
    assert groups_now(page, "alice") == {"eng"}


def test_without_javascript_the_x_form_works(page):
    """Scenario "The same removal from the Users section", from the rendered form."""
    row = user_row(page.tree, "alice")
    (chip,) = [c for c in row.find("div") if "tag" in c.classes and chip_name(c) == "eng"]
    action = chip.find("form")[0].attrs["action"]
    resp = page.request("admin", "POST", action)
    assert resp.status_code == 303 and resp.headers["location"] == "/security#users"
    assert groups_now(page, "alice") == {"admins"}
