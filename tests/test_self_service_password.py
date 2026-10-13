"""Self-service passwords over HTTP (user-self-service-password, tasks 7.4, 7.7).

Every test is one scenario of `specs/auth/spec.md` (Login and session cookie,
Setup sign-in, Password change by the user) or `specs/web-ui/spec.md` (Sign-in
form, Users and groups pages, Setup page, Settings page). The expectations come
from the spec and `design.md` D5 to D7, not from the implementation.

One real `build_app` over a tiny data dir (no child) behind Starlette's
`TestClient`. Cookies go in an explicit `Cookie` header, so one test holds
several browsers. The 1-second wait of a refusal is observed, not slept:
`sleeps` records every `asyncio.sleep(>= 1)` and returns at once. A race is
set up by running the change on the event loop right after the hash (or the
`authenticate`) that the route offloaded with `asyncio.to_thread`, the seam
the spec names.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from dataclasses import dataclass
from html.parser import HTMLParser

import pytest
from conftest import ADMIN_ACTOR, make_settings, make_user
from starlette.testclient import TestClient

from mcpflow.auth import hash_password
from mcpflow.gateway import build_app
from mcpflow.identity import LocalIdentityProvider
from mcpflow.web import _LOGIN_ERROR, _SETUP_ERROR

ALICE_PW = "pw-alice-0123456789"
NEW_PW = "brand-new-pw-42"
MISMATCH = re.compile(r"differ|match|same", re.IGNORECASE)  # a reason about the mismatch


# --- a tiny HTML reader: the forms and inputs of a page --------------------


class _Forms(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.forms.append({**attrs, "inputs": []})
        elif tag == "input":
            if self.forms:
                self.forms[-1]["inputs"].append(attrs)
            else:  # an input outside any form still counts
                self.forms.append({"action": None, "inputs": [attrs]})


def forms(html: str) -> list[dict]:
    parser = _Forms()
    parser.feed(html)
    return parser.forms


def inputs(html: str) -> list[dict]:
    return [i for f in forms(html) for i in f["inputs"]]


def input_named(html: str, name: str) -> dict:
    (found,) = [i for i in inputs(html) if i.get("name") == name]
    return found


def password_inputs(html: str) -> list[dict]:
    return [i for i in inputs(html) if i.get("type") == "password"]


def code_on_page(html: str) -> str:
    """The one-time setup code a users page shows (the same marker `test_web.py`
    reads)."""
    return re.search(r'id="setup-code">([^<]+)<', html).group(1)


# --- the site --------------------------------------------------------------


@dataclass
class Site:
    app: object
    client: TestClient
    policy: object
    expired_code: str  # the code of pending `old`, created 8 days ago
    cookies: dict[str, str]

    def send(self, method: str, path: str, cookie: str | None = None, **kw):
        headers = dict(kw.pop("headers", {}))
        if cookie:
            headers["Cookie"] = f"mcpflow_session={cookie}"
        resp = self.client.request(method, path, headers=headers, **kw)
        self.client.cookies.clear()
        return resp

    def sign_in(self, user: str, password: str) -> str:
        resp = self.send("POST", "/login", data={"user": user, "password": password, "next": "/"})
        assert resp.status_code == 303, resp.text
        return cookie_of(resp)

    def admin(self) -> str:
        return self.cookies.setdefault("admin", self.sign_in("", "secret"))

    @property
    def identity(self):
        return self.policy._identity

    def new_pending(self, uid: str) -> str:
        _user, code = self.policy.create_user(ADMIN_ACTOR, uid)
        return code

    def setup(self, user: str, code: str, password: str = NEW_PW, confirm: str | None = None, **kw):
        return self.send("POST", "/login/setup", data={
            "user": user, "code": code, "password": password,
            "confirm": password if confirm is None else confirm}, **kw)


def cookie_of(resp) -> str:
    return resp.cookies["mcpflow_session"]


def redirects_to_login(resp) -> bool:
    return resp.status_code == 303 and resp.headers["location"].startswith("/login")


@pytest.fixture
def site(tmp_path):
    (tmp_path / "logs").mkdir()
    ident = LocalIdentityProvider(tmp_path / "users.json",
                                  hash_password("secret", iterations=1000))
    ident.load()
    make_user(ident, "alice", ALICE_PW)
    # A user whose code ended before the app started: the code was made 8 days ago.
    old = LocalIdentityProvider(tmp_path / "users.json",
                                hash_password("secret", iterations=1000),
                                clock=lambda: time.time() - 8 * 24 * 3600)
    old.load()
    _user, expired = old._create_user("old")
    app = build_app(make_settings(tmp_path))
    with TestClient(app, follow_redirects=False) as client:
        yield Site(app, client, app.state.policy, expired, {})


@pytest.fixture
def sleeps(monkeypatch):
    """Record each `asyncio.sleep` of 1 second or more; return at once."""
    recorded: list[float] = []
    real = asyncio.sleep

    async def fake(delay, *a, **k):
        if delay >= 1:
            recorded.append(delay)
            return await real(0)
        return await real(delay, *a, **k)

    monkeypatch.setattr(asyncio, "sleep", fake)
    return recorded


@pytest.fixture
def offloads(monkeypatch):
    """Record the name of each function a route offloads with `asyncio.to_thread`.

    `then[name] = fn` runs `fn()` on the event loop right after the offloaded
    call of that name returns: the moment a race lands in the 0.3 s gap.
    """
    names: list[str] = []
    then: dict = {}
    real = asyncio.to_thread

    async def fake(func, *args, **kwargs):
        name = getattr(func, "__name__", "")
        names.append(name)
        result = await real(func, *args, **kwargs)
        if name in then:
            then[name]()
        return result

    monkeypatch.setattr(asyncio, "to_thread", fake)
    return names, then


def assert_refused_like(resp, reference, *, users=()):
    """Same status, same body (the posted user names aside), and no cookie."""
    assert resp.status_code == reference.status_code
    assert "set-cookie" not in resp.headers

    def norm(r):
        text = r.text
        for u in users:
            text = text.replace(u, "<USER>")
        return text

    assert norm(resp) == norm(reference)


# --- Sign-in form (web-ui) -------------------------------------------------


def test_the_form_links_to_the_first_sign_in(site):
    """Sign-in form / The form links to the first sign-in."""
    resp = site.send("GET", "/login")
    assert resp.status_code == 200
    assert 'href="/login/setup"' in resp.text
    assert input_named(resp.text, "user") and input_named(resp.text, "password")


def test_the_header_names_the_user_and_links_to_settings(site):
    """Sign-in form / The header names the user."""
    resp = site.send("GET", "/", site.sign_in("alice", ALICE_PW))
    assert resp.status_code == 200
    assert "alice" in resp.text
    assert 'href="/settings"' in resp.text
    assert any(f.get("action") == "/logout" for f in forms(resp.text)), "no sign-out control"


# --- Setup page (web-ui) ---------------------------------------------------


def test_the_setup_form_is_prefilled(site):
    """Setup page / The form is prefilled."""
    resp = site.send("GET", "/login/setup", params={"user": "alice"})
    assert resp.status_code == 200
    assert input_named(resp.text, "user").get("value") == "alice"
    assert input_named(resp.text, "code").get("value") in (None, "")
    for name in ("password", "confirm"):
        field = input_named(resp.text, name)
        assert field["type"] == "password"
        assert field["autocomplete"] == "new-password"
    assert "8" in resp.text  # the page states the minimum length
    bare = site.send("GET", "/login/setup")
    assert bare.status_code == 200
    assert input_named(bare.text, "user").get("value") in (None, "")


def test_a_refusal_does_not_echo_secrets(site, sleeps):
    """Setup page / A refusal does not echo secrets."""
    site.new_pending("carol")
    for password, confirm in (("hunter2hunter2", "hunter2hunter2"),
                              ("hunter2hunter2", "different-confirm-9")):
        resp = site.setup("carol", "WRONG-code-123", password, confirm)
        assert resp.status_code == 400
        for secret in ("WRONG-code-123", "hunter2hunter2", "different-confirm-9"):
            assert secret not in resp.text
    # Also for the right code, refused by a mismatch before the check.
    code = site.new_pending("dave")
    resp = site.setup("dave", code, "hunter2hunter2", "different-confirm-9")
    assert resp.status_code == 400
    for secret in (code, "hunter2hunter2", "different-confirm-9"):
        assert secret not in resp.text


# --- Setup sign-in (auth) --------------------------------------------------


def test_first_sign_in(site):
    """Setup sign-in / First sign-in."""
    code = site.new_pending("carol")
    resp = site.setup("carol", code, NEW_PW)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"
    assert cookie_of(resp).startswith("carol.")
    flags = resp.headers["set-cookie"].lower()
    assert "httponly" in flags and "samesite=lax" in flags and "path=/" in flags
    assert "max-age=" in flags
    assert site.identity.get_user("carol").pending is False
    assert site.identity.authenticate("carol", NEW_PW) is not None
    # The cookie opens the dashboard, and a later password sign-in works.
    assert site.send("GET", "/", cookie_of(resp)).status_code == 200
    assert site.sign_in("carol", NEW_PW).startswith("carol.")


def test_a_cross_origin_setup_sign_in_is_refused(site):
    """Cross-site request protection / Cross-origin setup sign-in refused."""
    code = site.new_pending("carol")
    resp = site.setup("carol", code, headers={"Origin": "https://evil.test"})
    assert resp.status_code == 403
    assert "set-cookie" not in resp.headers
    assert site.identity.get_user("carol").pending is True
    assert site.identity.authenticate("carol", NEW_PW) is None
    # The code was not spent: a same-origin post of it succeeds.
    ok = site.setup("carol", code, headers={"Origin": "http://testserver"})
    assert ok.status_code == 303
    assert cookie_of(ok).startswith("carol.")
    assert site.identity.get_user("carol").pending is False


def test_a_pasted_code_with_whitespace_still_works(site):
    """A code pasted from a chat or a mail carries a trailing newline."""
    code = site.new_pending("carol")
    resp = site.setup("carol", f"  {code}\n", NEW_PW)
    assert resp.status_code == 303
    assert site.identity.get_user("carol").pending is False


def test_a_code_works_once(site, sleeps):
    """Setup sign-in / A code works once."""
    code = site.new_pending("carol")
    assert site.setup("carol", code).status_code == 303
    again = site.setup("carol", code, "another-pw-99")
    assert again.status_code == 400
    assert "set-cookie" not in again.headers
    assert _SETUP_ERROR in again.text
    assert sleeps and sleeps[-1] >= 1
    assert site.identity.authenticate("carol", NEW_PW) is not None
    assert site.identity.authenticate("carol", "another-pw-99") is None


def test_one_error_for_every_refusal(site, sleeps):
    """Setup sign-in / One error for every refusal."""
    carol_code = site.new_pending("carol")
    site.new_pending("erin")
    reference = site.setup("nobody", "unknown-code-xyz")
    assert reference.status_code == 400 and _SETUP_ERROR in reference.text
    assert "set-cookie" not in reference.headers
    refusals = {
        "unknown user": ("nobody", carol_code),
        "wrong code": ("erin", "wrong-code-0123456"),
        "expired code": ("old", site.expired_code),
        "active user": ("alice", carol_code),
        "bootstrap": ("admin", "any-code-at-all"),
        "bootstrap with the env password": ("admin", "secret"),
    }
    users = {u for u, _ in refusals.values()} | {"nobody"}
    for label, (user, code) in refusals.items():
        sleeps.clear()
        resp = site.setup(user, code)
        assert_refused_like(resp, reference, users=users)
        assert sleeps and sleeps[0] >= 1, label
    # None of the refusals used up or changed any code or password.
    assert site.identity.check_setup_code("carol", carol_code) is not None
    assert site.identity.authenticate("alice", ALICE_PW) is not None
    assert site.identity.authenticate("admin", "secret") is not None
    assert site.identity.get_user("old").pending is True


def test_a_refusal_really_waits_one_second(site):
    """Setup sign-in: at least 1 second, measured (no `sleeps` patch)."""
    start = time.perf_counter()
    resp = site.setup("nobody", "wrong-code-0123456")
    assert time.perf_counter() - start >= 1.0
    assert resp.status_code == 400


def test_a_mismatch_refuses_before_any_check(site, sleeps, monkeypatch):
    """Setup sign-in / A mismatch refuses before any check."""
    code = site.new_pending("carol")
    checks: list[tuple] = []
    real = site.identity.check_setup_code

    def spy(user_id, c):
        checks.append((user_id, c))
        return real(user_id, c)

    monkeypatch.setattr(site.identity, "check_setup_code", spy)
    resp = site.setup("carol", code, NEW_PW, "something-else-1")
    assert resp.status_code == 400
    assert MISMATCH.search(resp.text)
    assert "set-cookie" not in resp.headers
    assert checks == []
    assert site.identity.get_user("carol").pending is True
    # The reason uses no user data: an unknown user gets the same reason.
    other = site.setup("nobody", "x" * 16, NEW_PW, "something-else-1")
    assert_refused_like(other, resp, users=("carol", "nobody"))
    assert checks == []
    # The code still works.
    assert site.setup("carol", code).status_code == 303


def test_a_short_password_refuses_before_any_check(site, sleeps, monkeypatch):
    code = site.new_pending("carol")
    checks: list[tuple] = []
    real = site.identity.check_setup_code
    monkeypatch.setattr(site.identity, "check_setup_code",
                        lambda u, c: checks.append(u) or real(u, c))
    resp = site.setup("carol", code, "short")
    assert resp.status_code == 400
    assert "8" in resp.text  # names the minimum
    assert "set-cookie" not in resp.headers
    assert checks == []
    assert site.identity.get_user("carol").pending is True
    assert site.setup("carol", code).status_code == 303


def test_a_reset_during_the_hash(site, sleeps, offloads):
    """Setup sign-in / A reset during the hash."""
    _names, then = offloads
    code = site.new_pending("carol")
    box: dict = {}
    then["hash_password"] = lambda: box.setdefault("new", site.policy.issue_setup_code(
        ADMIN_ACTOR, "carol"))
    resp = site.setup("carol", code)
    assert resp.status_code == 400
    assert _SETUP_ERROR in resp.text
    assert "set-cookie" not in resp.headers
    assert sleeps and sleeps[0] >= 1
    assert box["new"] != code
    assert site.identity.get_user("carol").pending is True
    assert site.identity.authenticate("carol", NEW_PW) is None
    then.clear()
    # The new code still works; the old one does not.
    assert site.setup("carol", code).status_code == 400
    done = site.setup("carol", box["new"])
    assert done.status_code == 303 and cookie_of(done).startswith("carol.")


def test_the_setup_cookie_ends_with_a_later_reset(site):
    """Password change invalidates sessions / through the setup page, then reset."""
    code = site.new_pending("carol")
    cookie = cookie_of(site.setup("carol", code))
    assert site.send("GET", "/", cookie).status_code == 200
    site.policy.issue_setup_code(ADMIN_ACTOR, "carol")
    assert redirects_to_login(site.send("GET", "/", cookie))


def test_a_non_local_provider_refuses_the_setup_route(site, sleeps, monkeypatch):
    """Setup sign-in: the route refuses when `local_identity()` raises."""
    code = site.new_pending("carol")

    def refuse():
        raise ValueError("the keycloak provider manages its own users")

    monkeypatch.setattr(site.policy, "local_identity", refuse)
    resp = site.setup("carol", code)
    assert resp.status_code == 400
    assert "set-cookie" not in resp.headers
    assert site.identity.get_user("carol").pending is True
    monkeypatch.undo()
    assert site.setup("carol", code).status_code == 303


# --- Login with a pending user (auth: Login and session cookie) ------------


def test_a_pending_user_cannot_sign_in_at_the_login_page(site, sleeps):
    """Login and session cookie / Pending user."""
    code = site.new_pending("carol")
    wrong = site.send("POST", "/login", data={"user": "alice", "password": "nope", "next": "/"})
    assert wrong.status_code == 200 and _LOGIN_ERROR in wrong.text
    for password in ("", code):
        sleeps.clear()
        resp = site.send("POST", "/login", data={"user": "carol", "password": password,
                                                 "next": "/"})
        assert resp.status_code == 200
        assert "set-cookie" not in resp.headers
        assert _LOGIN_ERROR in resp.text
        assert resp.text.replace("carol", "alice") == wrong.text
        assert sleeps and sleeps[0] >= 1
    assert site.identity.get_user("carol").pending is True


def test_a_reset_ends_a_session_of_the_dashboard(site):
    """Password change invalidates sessions / through a reset by the admin."""
    cookie = site.sign_in("alice", ALICE_PW)
    assert site.send("GET", "/", cookie).status_code == 200
    resp = site.send("POST", "/users/alice/setup-code", site.admin())
    assert resp.status_code == 200
    assert redirects_to_login(site.send("GET", "/", cookie))
    assert site.send("POST", "/servers/time/restart", cookie).status_code == 401


# --- Login timing (7.7) ----------------------------------------------------


def test_a_pending_user_costs_one_verification_at_the_login_page(tmp_path, monkeypatch, sleeps):
    """Sign-in time does not reveal a user name: a pending user, an unknown
    user, and a wrong password each cost one `pbkdf2_sha256` verification of
    the same iteration count."""
    (tmp_path / "logs").mkdir()
    ident = LocalIdentityProvider(tmp_path / "users.json",
                                  hash_password("secret", iterations=600_000))
    ident.load()
    make_user(ident, "alice", ALICE_PW, iterations=600_000)
    app = build_app(make_settings(tmp_path))
    calls: list[tuple] = []
    real = hashlib.pbkdf2_hmac

    def counting(*args, **kwargs):
        calls.append(args)
        return real(*args, **kwargs)

    with TestClient(app, follow_redirects=False) as client:
        _user, code = app.state.policy.create_user(ADMIN_ACTOR, "carol")
        monkeypatch.setattr(hashlib, "pbkdf2_hmac", counting)
        costs = {}
        for label, user, password in (("known", "alice", "wrong-pw-9"),
                                      ("unknown", "nobody", "wrong-pw-9"),
                                      ("pending empty", "carol", ""),
                                      ("pending code", "carol", code)):
            calls.clear()
            resp = client.post("/login", data={"user": user, "password": password, "next": "/"})
            assert resp.status_code == 200 and _LOGIN_ERROR in resp.text, label
            costs[label] = [c[3] for c in calls]  # iteration count of each call
    assert all(len(v) == 1 for v in costs.values()), costs
    assert len({v[0] for v in costs.values()}) == 1, costs


# --- Settings page (web-ui, auth) ------------------------------------------


def test_a_user_sees_the_change_form(site):
    """Settings page / A user sees the form."""
    resp = site.send("GET", "/settings", site.sign_in("alice", ALICE_PW))
    assert resp.status_code == 200
    (form,) = [f for f in forms(resp.text) if f.get("action") == "/settings/password"]
    assert (form.get("method") or "").lower() == "post"
    by_name = {i["name"]: i for i in form["inputs"] if "name" in i}
    assert {"current", "password", "confirm"} <= set(by_name)
    for name in ("current", "password", "confirm"):
        assert by_name[name]["type"] == "password"


def test_the_admin_sees_a_note_and_no_form(site):
    """Settings page / The admin sees a note."""
    resp = site.send("GET", "/settings", site.admin())
    assert resp.status_code == 200
    assert password_inputs(resp.text) == []
    assert "ADMIN_PASSWORD" in resp.text
    assert not any(f.get("action") == "/settings/password" for f in forms(resp.text))


def test_the_settings_routes_need_a_session(site):
    assert redirects_to_login(site.send("GET", "/settings"))
    resp = site.send("POST", "/settings/password", data={
        "current": ALICE_PW, "password": NEW_PW, "confirm": NEW_PW})
    assert resp.status_code == 401
    assert site.identity.authenticate("alice", ALICE_PW) is not None


def change(site, cookie, current=ALICE_PW, password=NEW_PW, confirm=None, **kw):
    return site.send("POST", "/settings/password", cookie, data={
        "current": current, "password": password,
        "confirm": password if confirm is None else confirm}, **kw)


def test_a_user_changes_the_password(site):
    """Password change by the user / A user changes the password."""
    old = site.sign_in("alice", ALICE_PW)
    resp = change(site, old)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/settings?changed=1"
    new = cookie_of(resp)
    assert new.startswith("alice.") and new != old
    assert redirects_to_login(site.send("GET", "/", old))
    assert site.send("GET", "/", new).status_code == 200
    assert site.identity.authenticate("alice", NEW_PW) is not None
    assert site.identity.authenticate("alice", ALICE_PW) is None
    # The page shows a success note after the change, and none before.
    plain = site.send("GET", "/settings", new)
    noted = site.send("GET", "/settings?changed=1", new)
    assert noted.status_code == 200 and noted.text != plain.text
    assert re.search(r"changed|updated", noted.text, re.IGNORECASE)


def test_another_session_ends(site):
    """Password change by the user / Another session ends."""
    browser_a = site.sign_in("alice", ALICE_PW)
    browser_b = site.sign_in("alice", ALICE_PW)
    assert site.send("GET", "/", browser_b).status_code == 200
    resp = change(site, browser_a)
    assert resp.status_code == 303
    assert redirects_to_login(site.send("GET", "/", browser_b))
    assert redirects_to_login(site.send("GET", "/", browser_a))
    assert site.send("GET", "/", cookie_of(resp)).status_code == 200


def test_a_wrong_current_password(site, sleeps):
    """Password change by the user / A wrong current password."""
    cookie = site.sign_in("alice", ALICE_PW)
    resp = change(site, cookie, current="not-her-password")
    assert resp.status_code == 400
    assert "set-cookie" not in resp.headers
    assert sleeps and sleeps[0] >= 1
    assert site.identity.authenticate("alice", ALICE_PW) is not None
    assert site.identity.authenticate("alice", NEW_PW) is None
    assert site.send("GET", "/", cookie).status_code == 200  # the session stays


def test_a_wrong_current_password_really_waits_one_second(site):
    cookie = site.sign_in("alice", ALICE_PW)
    start = time.perf_counter()
    resp = change(site, cookie, current="not-her-password")
    assert time.perf_counter() - start >= 1.0
    assert resp.status_code == 400


def test_a_mismatch_or_a_short_password_is_refused(site, sleeps):
    cookie = site.sign_in("alice", ALICE_PW)
    mismatch = change(site, cookie, confirm="something-else-1")
    assert mismatch.status_code == 400 and MISMATCH.search(mismatch.text)
    short = change(site, cookie, password="short")
    assert short.status_code == 400 and "8" in short.text
    for resp in (mismatch, short):
        assert "set-cookie" not in resp.headers
    assert site.identity.authenticate("alice", ALICE_PW) is not None
    assert site.send("GET", "/", cookie).status_code == 200


def test_a_user_changes_only_their_own_password(site):
    """Password change by the user: no field names another user."""
    site.sign_in("alice", ALICE_PW)
    make_user(site.policy, "bob", "bob-pw-0123456")
    cookie = site.sign_in("bob", "bob-pw-0123456")
    resp = site.send("POST", "/settings/password", cookie, data={
        "user": "alice", "id": "alice", "current": "bob-pw-0123456",
        "password": NEW_PW, "confirm": NEW_PW})
    assert resp.status_code == 303
    assert site.identity.authenticate("bob", NEW_PW) is not None
    assert site.identity.authenticate("alice", ALICE_PW) is not None
    assert site.identity.authenticate("alice", NEW_PW) is None


def test_a_reset_during_the_change(site, sleeps, offloads):
    """Password change by the user / A reset during the change."""
    _names, then = offloads
    cookie = site.sign_in("alice", ALICE_PW)
    box: dict = {}
    then["hash_password"] = lambda: box.setdefault("code", site.policy.issue_setup_code(
        ADMIN_ACTOR, "alice"))
    resp = change(site, cookie)
    assert resp.status_code == 400
    assert "again" in resp.text.lower()  # a message to try again
    assert "set-cookie" not in resp.headers
    assert site.identity.get_user("alice").pending is True
    assert site.identity.authenticate("alice", NEW_PW) is None
    assert site.identity.check_setup_code("alice", box["code"]) is not None


def test_a_reset_during_the_check_of_the_current_password(site, sleeps, offloads):
    """The second interleaving point of the route (design D6, TLA+ model): a
    reset after the binding read and before the swap."""
    _names, then = offloads
    cookie = site.sign_in("alice", ALICE_PW)
    box: dict = {}
    then["authenticate"] = lambda: box.setdefault("code", site.policy.issue_setup_code(
        ADMIN_ACTOR, "alice"))
    resp = change(site, cookie)
    assert resp.status_code == 400 and "set-cookie" not in resp.headers
    assert site.identity.get_user("alice").pending is True
    assert site.identity.authenticate("alice", NEW_PW) is None


def test_the_bootstrap_user_cannot_change_the_password_here(site, sleeps, offloads):
    """Password change by the user / The bootstrap user cannot change the
    password here: refused first, with no slow work."""
    names, _then = offloads
    before = (site.identity.session_binding("admin"),)
    admin = site.admin()
    names.clear()  # the sign-in above offloaded its own check
    resp = change(site, admin, current="secret")
    assert resp.status_code == 400
    assert "ADMIN_PASSWORD" in resp.text
    assert "set-cookie" not in resp.headers
    assert names == []  # no offloaded work at all: no verify, no hash
    assert sleeps == []
    assert (site.identity.session_binding("admin"),) == before
    assert site.identity.authenticate("admin", "secret") is not None
    assert site.identity.authenticate("admin", NEW_PW) is None


def test_the_settings_route_refuses_when_the_provider_is_not_local(site, monkeypatch):
    cookie = site.sign_in("alice", ALICE_PW)

    def refuse():
        raise ValueError("the keycloak provider manages its own users")

    monkeypatch.setattr(site.policy, "local_identity", refuse)
    resp = change(site, cookie)
    assert resp.status_code == 400
    assert "set-cookie" not in resp.headers
    assert site.identity.authenticate("alice", ALICE_PW) is not None


def test_a_cross_site_post_cannot_change_a_password(site):
    """The Origin check of the session gate covers `/settings/password`."""
    cookie = site.sign_in("alice", ALICE_PW)
    resp = change(site, cookie, headers={"Origin": "https://evil.test"})
    assert resp.status_code == 403
    assert site.identity.authenticate("alice", ALICE_PW) is not None


# --- Users page (web-ui) ---------------------------------------------------


def test_the_create_form_has_no_password(site):
    """Users and groups pages / The create form has no password."""
    resp = site.send("GET", "/security", site.admin())
    assert resp.status_code == 200
    assert password_inputs(resp.text) == []
    create = [f for f in forms(resp.text)
              if any(i.get("name") == "id" for i in f["inputs"])]
    assert create, "no create form"
    assert all(i.get("name") != "password" for f in create for i in f["inputs"])


def test_create_a_user_shows_the_code_once(site):
    """Users and groups pages / Create a user from the dashboard (AC-7)."""
    admin = site.admin()
    resp = site.send("POST", "/users", admin, data={"id": "dave", "name": "Dave"})
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "no-store"
    code = code_on_page(resp.text)
    assert "/login/setup" in resp.text  # the address the user opens
    assert "7" in resp.text  # the lifetime in days
    assert site.identity.check_setup_code("dave", code) is not None
    later = site.send("GET", "/security", admin)
    assert later.status_code == 200
    assert code not in later.text
    row = next(r for r in later.text.split("<tr>") if "<code>dave</code>" in r)
    assert "pending" in row.lower()
    alice_row = next(r for r in later.text.split("<tr>") if "<code>alice</code>" in r)
    assert "pending" not in alice_row.lower()
    # The code works end to end.
    done = site.setup("dave", code)
    assert done.status_code == 303 and cookie_of(done).startswith("dave.")
    after = site.send("GET", "/security", admin)
    assert "pending" not in next(
        r for r in after.text.split("<tr>") if "<code>dave</code>" in r).lower()


def test_a_create_refusal_shows_no_code(site):
    resp = site.send("POST", "/users", site.admin(), data={"id": "Alice@home"})
    assert resp.status_code == 400
    assert 'id="setup-code"' not in resp.text
    dup = site.send("POST", "/users", site.admin(), data={"id": "alice"})
    assert dup.status_code == 400 and 'id="setup-code"' not in dup.text
    assert site.identity.authenticate("alice", ALICE_PW) is not None


def test_reset_a_user(site):
    """Users and groups pages / Reset a user."""
    admin = site.admin()
    old = site.sign_in("alice", ALICE_PW)
    resp = site.send("POST", "/users/alice/setup-code", admin)
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "no-store"
    code = code_on_page(resp.text)
    assert site.identity.get_user("alice").pending is True
    assert site.identity.authenticate("alice", ALICE_PW) is None
    assert site.identity.check_setup_code("alice", code) is not None
    assert redirects_to_login(site.send("GET", "/", old))
    later = site.send("GET", "/security", admin)
    assert code not in later.text
    # A second reset replaces the code.
    second = code_on_page(site.send("POST", "/users/alice/setup-code", admin).text)
    assert second != code
    assert site.identity.check_setup_code("alice", code) is None
    assert site.setup("alice", second).status_code == 303


def test_the_bootstrap_admin_cannot_be_reset(site):
    """Users and groups pages / The bootstrap admin cannot be reset."""
    admin = site.admin()
    resp = site.send("POST", "/users/admin/setup-code", admin)
    assert resp.status_code == 400
    assert 'id="setup-code"' not in resp.text
    assert site.identity.authenticate("admin", "secret") is not None
    assert site.identity.get_user("admin").pending is False
    assert site.send("GET", "/", admin).status_code == 200  # the session lives


def test_the_admin_set_password_route_is_gone(site):
    """No admin-chosen password: the admin has no route that sets one."""
    resp = site.send("POST", "/users/alice/password", site.admin(),
                     data={"password": "chosen-by-admin-1"})
    assert resp.status_code in (404, 405)
    assert site.identity.authenticate("alice", "chosen-by-admin-1") is None
    assert site.identity.authenticate("alice", ALICE_PW) is not None
    resp = site.send("POST", "/users", site.admin(),
                     data={"id": "dave", "password": "chosen-by-admin-1"})
    assert resp.status_code == 200  # the field is not read
    assert site.identity.get_user("dave").pending is True
    assert site.identity.authenticate("dave", "chosen-by-admin-1") is None
