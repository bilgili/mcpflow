"""The route walk of the deny-by-default dashboard gate (multi-user-access 10G).

Scenarios from `specs/auth/spec.md` "Dashboard routes deny a non-admin user by
default", `specs/web-ui/spec.md` "Role-scoped dashboard", and
`specs/tool-visibility/spec.md` "A non-admin user cannot mute". The expected
set is design D3, not the code. The walk enumerates the routes of the real app
from the Starlette router; it hard-codes only the skip prefixes and D3.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from conftest import make_settings, make_user
from starlette.middleware import Middleware
from starlette.responses import PlainTextResponse
from starlette.routing import Mount, Route
from starlette.testclient import TestClient
from user_servers import fake_npx, npm_spec, path_with

from mcpflow.auth import SessionGate, TokenStore, hash_password
from mcpflow.gateway import build_app
from mcpflow.identity import LocalIdentityProvider
from mcpflow.registry import Registry, ServerKey, revision
from mcpflow.web import USER_ROUTES

# The one skip list: the public prefixes of `specs/auth` ("Every route except
# /health, /login, /static/*, /mcp, /api/*, and /.well-known/* SHALL require a
# valid session") and the /mcp and /api mounts, which other gates own.
SKIP_PREFIXES = ("/health", "/login", "/static", "/mcp", "/api", "/.well-known")

# Design D3 / `specs/auth`: every route a non-admin user reaches. Nothing else.
D3_ROUTES = frozenset({
    ("GET", "/"), ("GET", "/tools/tree"), ("GET", "/servers"),
    ("GET", "/add-server"), ("POST", "/servers"), ("POST", "/import/json"),
    ("GET", "/servers/{ref}"), ("POST", "/servers/{ref}"),
    ("GET", "/servers/{ref}/edit"), ("GET", "/servers/{ref}/log"),
    ("POST", "/servers/{ref}/enable"), ("POST", "/servers/{ref}/disable"),
    ("POST", "/servers/{ref}/restart"), ("POST", "/servers/{ref}/delete"),
    ("GET", "/tokens"), ("POST", "/tokens"), ("POST", "/tokens/{id}/delete"),
    ("POST", "/logout"),
    ("GET", "/settings"), ("POST", "/settings/password"),
})

PASSWORDS = {"alice": "pw-alice-0123456789", "bob": "pw-bob-0123456789"}
GH_ALICE = ServerKey("alice", "github")
GH_BOB = ServerKey("bob", "github")
UserRoutes = tuple[tuple[frozenset[str], re.Pattern[str]], ...]


# --- route enumeration and the walk ---------------------------------------


def skipped(path: str) -> bool:
    return any(path == p or path.startswith(p + "/") for p in SKIP_PREFIXES)


def app_routes(app) -> list[tuple[str, str]]:
    """Every (method, path template) of the app, mounts included."""
    out: set[tuple[str, str]] = set()

    def visit(routes, prefix: str) -> None:
        for r in routes:
            path = prefix + r.path
            if isinstance(r, Mount):
                sub = getattr(r, "routes", None) or []
                if not sub and not skipped(path):
                    raise AssertionError(f"opaque mount {path!r} cannot be walked")
                visit(sub, path)
            elif isinstance(r, Route):
                out.update((m, path) for m in (r.methods or ()))
            elif not skipped(path):
                raise AssertionError(f"unknown route type at {path!r}: {r!r}")

    visit(app.routes, "")
    return sorted(out)


def concrete(template: str, params: dict[str, str]) -> str:
    """Substitute a syntactically valid value for every path parameter."""
    def value(m: re.Match) -> str:
        name = m.group(1)
        if name == "id" and not template.startswith("/tokens"):
            return params.get("user_id", "bob")
        return params.get(name, "x1")
    return re.sub(r"\{(\w+)(?::\w+)?\}", value, template)


def listed(user_routes: UserRoutes, method: str, path: str) -> bool:
    return any(method in ms and pat.fullmatch(path) for ms, pat in user_routes)


@dataclass
class WalkReport:
    walked: list[tuple[str, str, int]] = field(default_factory=list)
    open_unlisted: list[tuple[str, str, int]] = field(default_factory=list)
    orphan_entries: list[tuple[str, str]] = field(default_factory=list)

    def passed(self) -> set[tuple[str, str]]:
        return {(m, t) for m, t, s in self.walked if s != 403}


def walk(app, send: Callable[[str, str], int], user_routes: UserRoutes,
         params: dict[str, str]) -> WalkReport:
    """Send every non-skipped route and method; report both failure directions.

    `open_unlisted`: a route answered a non-admin user with anything but 403
    and no entry matches it. `orphan_entries`: an entry matches no route.
    """
    rep = WalkReport()
    routes = [(m, t, concrete(t, params)) for m, t in app_routes(app) if not skipped(t)]
    for method, template, path in routes:
        status = send(method, path)
        rep.walked.append((method, template, status))
        if status != 403 and not listed(user_routes, method, path):
            rep.open_unlisted.append((method, template, status))
    for methods, pat in user_routes:
        for m in sorted(methods):
            if not any(m == rm and pat.fullmatch(p) for rm, _, p in routes):
                rep.orphan_entries.append((m, pat.pattern))
    return rep


# --- a live app with two users and three running children -----------------


def seed(data: Path) -> tuple[str, str]:
    """Users alice and bob; admin `time`; approved `github@alice`, `github@bob`.

    Return the id of a token of alice and an admin token (clear text).
    """
    (data / "logs").mkdir(parents=True)
    ident = LocalIdentityProvider(data / "users.json",
                                  hash_password("secret", iterations=1000))
    ident.load()
    for uid, pw in PASSWORDS.items():
        make_user(ident, uid, pw)
    reg = Registry(data / "servers.json", data / "user_servers.json")
    reg.load()
    reg.add(npm_spec("time", package="@acme/time@1.0.0"))
    for key in (GH_ALICE, GH_BOB):
        reg.add(npm_spec("github", owner=key.owner))
        reg.set_approved_revision(key, revision(reg.get(key)))
    store = TokenStore(data / "tokens.json", data / "user_tokens.json")
    store.load()
    alice_rec, _ = store.create("laptop", "mcp", "alice")
    _, admin_token = store.create("ops", "admin", "admin")
    return alice_rec.id, admin_token


@dataclass
class Site:
    app: object
    client: TestClient
    alice_token_id: str
    admin_token: str
    npx_log: Path
    cookies: dict[str, str] = field(default_factory=dict)

    @property
    def params(self) -> dict[str, str]:
        return {"ref": GH_ALICE.ref, "id": self.alice_token_id,
                "name": "staff", "action": "noop", "user_id": "bob"}

    def login(self, uid: str) -> str:
        if uid not in self.cookies:
            resp = self.client.post(
                "/login", data={"user": uid, "password": PASSWORDS[uid], "next": "/"})
            assert resp.status_code == 303, resp.text
            self.cookies[uid] = resp.cookies["mcpflow_session"]
            self.client.cookies.clear()
        return self.cookies[uid]

    def request(self, uid: str, method: str, path: str, **kw):
        headers = {"Cookie": f"mcpflow_session={self.login(uid)}"}
        resp = self.client.request(method, path, headers=headers, **kw)
        self.client.cookies.clear()
        return resp

    def sender(self, uid: str) -> Callable[[str, str], int]:
        return lambda method, path: self.request(uid, method, path).status_code

    def status(self, key: ServerKey) -> str:
        return self.app.state.supervisor.get(key).status

    def wait_running(self, *keys: ServerKey, timeout: float = 40.0) -> None:
        end = time.time() + timeout
        while time.time() < end:
            if all(self.status(k) == "running" for k in keys):
                return
            time.sleep(0.1)
        raise AssertionError({k.ref: self.status(k) for k in keys})

    def launches(self) -> int:
        return len(self.npx_log.read_text().splitlines()) if self.npx_log.exists() else 0


def widen_gate(app, extra: UserRoutes) -> None:
    """Give the app's SessionGate more entries than `USER_ROUTES` holds."""
    for i, mw in enumerate(app.user_middleware):
        if mw.cls is SessionGate:
            kw = dict(mw.kwargs, user_routes=tuple(mw.kwargs["user_routes"]) + extra)
            app.user_middleware[i] = Middleware(SessionGate, *mw.args, **kw)
            return
    raise AssertionError("no SessionGate on the app")


def spy(app, method: str, path: str) -> list[int]:
    """Count the calls that reach the handler of one route."""
    calls: list[int] = []
    for r in app.router.routes:
        if isinstance(r, Route) and r.path == path and method in (r.methods or ()):
            inner = r.app

            async def counted(scope, receive, send, inner=inner):
                calls.append(1)
                await inner(scope, receive, send)

            r.app = counted
            return calls
    raise AssertionError(f"no route {method} {path}")


@pytest.fixture
def make_site(tmp_path, monkeypatch):
    sites: list[TestClient] = []
    log = fake_npx(tmp_path / "bin")
    monkeypatch.setenv("PATH", path_with(tmp_path / "bin"))

    def make(prepare: Callable[[object], None] | None = None) -> Site:
        data = tmp_path / f"d{len(sites)}"
        alice_tid, admin_token = seed(data)
        app = build_app(make_settings(data))
        if prepare is not None:
            prepare(app)
        client = TestClient(app, raise_server_exceptions=False, follow_redirects=False)
        client.__enter__()
        sites.append(client)
        site = Site(app, client, alice_tid, admin_token, log)
        site.wait_running(GH_ALICE, GH_BOB)
        return site

    yield make
    for client in sites:
        client.__exit__(None, None, None)


# --- 10.28: the walk over the real app ------------------------------------


def test_route_walk_non_admin_passes_exactly_the_d3_routes(make_site):
    site = make_site()
    rep = walk(site.app, site.sender("alice"), USER_ROUTES, site.params)
    print(f"\nwalked {len(rep.walked)} route-methods; non-403: {sorted(rep.passed())}")
    # Every route of the app outside the skip list was walked, nothing hard-coded.
    assert len(rep.walked) == len([r for r in app_routes(site.app) if not skipped(r[1])])
    assert rep.open_unlisted == [], rep.open_unlisted
    assert rep.orphan_entries == [], rep.orphan_entries
    assert rep.passed() == D3_ROUTES, {
        "beyond D3": sorted(rep.passed() - D3_ROUTES),
        "missing from D3": sorted(D3_ROUTES - rep.passed()),
    }


def test_route_walk_admin_session_passes_every_route(make_site):
    """The other side of the role check: an admin is never refused by it."""
    site = make_site()
    alice = walk(site.app, site.sender("alice"), USER_ROUTES, site.params)
    # Logged in by the empty user name, which means `admin` (specs/auth).
    resp = site.client.post("/login", data={"user": "", "password": "secret", "next": "/"})
    assert resp.status_code == 303
    site.cookies["admin"] = resp.cookies["mcpflow_session"]
    site.client.cookies.clear()
    admin = walk(site.app, site.sender("admin"), USER_ROUTES, site.params)
    refused = [(m, t) for m, t, s in admin.walked if s == 403]
    assert refused == [], refused
    assert len(admin.walked) == len(alice.walked)


# --- 10.29: the walk fails in both directions -----------------------------


REPORTS_ENTRY: UserRoutes = ((frozenset({"GET"}), re.compile("/reports")),)


def _add_reports(app) -> None:
    app.router.routes.insert(0, Route("/reports", lambda request: PlainTextResponse("ok")))


def test_walk_reports_an_open_route_without_an_entry(make_site):
    """A route answers 200 to a non-admin and `USER_ROUTES` holds no entry."""
    def prepare(app):
        _add_reports(app)
        widen_gate(app, REPORTS_ENTRY)  # the gate lets it through; the list does not

    site = make_site(prepare)
    assert site.request("alice", "GET", "/reports").status_code == 200
    rep = walk(site.app, site.sender("alice"), USER_ROUTES, site.params)
    assert ("GET", "/reports", 200) in rep.open_unlisted
    assert rep.passed() != D3_ROUTES


def test_walk_reports_an_entry_that_matches_no_route(make_site):
    site = make_site()
    stray: UserRoutes = (
        (frozenset({"GET"}), re.compile("/nowhere")),
        (frozenset({"DELETE"}), re.compile("/tokens")),  # route exists, method does not
    )
    rep = walk(site.app, site.sender("alice"), USER_ROUTES + stray, site.params)
    assert ("GET", "/nowhere") in rep.orphan_entries
    assert ("DELETE", "/tokens") in rep.orphan_entries
    assert len(rep.orphan_entries) == 2, rep.orphan_entries


FOREIGN_REFS = {
    "foreign": GH_BOB.ref,           # exists, owned by bob
    "shared": "time",                # exists, admin-owned, not managed by alice
}
# A missing key of alice herself is not here: `can_manage` holds for the owner
# of a key (server-registry delta), and `GET /servers/{ns}/edit` redirects 303
# by the web-ui spec. The D3 promise is about a non-owner's view only.
ABSENT_REFS = {
    "missing": "nothere@bob",
    "missing-other-user": "github@carol",
    "missing-shared": "nothere",
    "malformed": "a@b@c",
    "malformed-owner": "github@",
}


def _normal(body: str, ref: str) -> str:
    return body.replace(ref, "<REF>")


def test_every_listed_server_route_answers_404_for_a_foreign_reference(make_site):
    site = make_site()
    before = site.launches()
    server_routes = [
        (m, t) for m, t in app_routes(site.app)
        if "{ref}" in t and not skipped(t) and listed(USER_ROUTES, m, concrete(t, site.params))
    ]
    assert {r for r in server_routes} == {r for r in D3_ROUTES if "{ref}" in r[1]}
    leaks = []
    for method, template in server_routes:
        seen = {}
        for label, ref in {**FOREIGN_REFS, **ABSENT_REFS}.items():
            resp = site.request("alice", method, template.replace("{ref}", ref))
            seen[label] = (resp.status_code, resp.headers.get("content-type"),
                           _normal(resp.text, ref))
        if any(s[0] != 404 for s in seen.values()) or len(set(seen.values())) != 1:
            leaks.append((method, template, {k: v[:2] for k, v in seen.items()}))
    assert leaks == [], leaks
    # No foreign child moved: still running, no extra launch.
    assert site.status(GH_BOB) == "running"
    assert site.status(ServerKey(None, "time")) == "running"
    time.sleep(0.5)
    assert site.launches() == before


# --- 10.30: the named scenarios -------------------------------------------


def test_a_route_missing_from_the_list_fails_closed(make_site):
    site = make_site()
    probes = [("GET", "/oauth/callback"), ("POST", "/visibility/root"),
              ("GET", "/marketplace")]
    calls = {p: spy(site.app, *p) for p in probes}
    for method, path in probes:
        resp = site.request("alice", method, path)
        assert resp.status_code == 403, (method, path, resp.status_code)
    assert all(c == [] for c in calls.values()), "a handler ran"


def test_a_listed_route_passes(make_site):
    site = make_site()
    calls = spy(site.app, "GET", "/tools/tree")
    resp = site.request("alice", "GET", "/tools/tree")
    assert resp.status_code == 200
    assert calls == [1]
    # The tree of her Reach: her own server, not the server of bob.
    assert GH_ALICE.ref in resp.text
    assert GH_BOB.ref not in resp.text


def test_a_listed_server_route_refuses_a_foreign_server(make_site):
    site = make_site()
    before = site.launches()
    resp = site.request("bob", "POST", f"/servers/{GH_ALICE.ref}/restart")
    assert resp.status_code == 404
    time.sleep(0.5)
    assert site.status(GH_ALICE) == "running"
    assert site.launches() == before, "the child restarted"


def test_the_route_walk_covers_a_new_route(make_site):
    """A later change adds GET /reports without an entry: 403, walk stays green."""
    site = make_site(_add_reports)
    calls = spy(site.app, "GET", "/reports")
    rep = walk(site.app, site.sender("alice"), USER_ROUTES, site.params)
    assert ("GET", "/reports", 403) in rep.walked
    assert rep.open_unlisted == [] and rep.orphan_entries == []
    assert rep.passed() == D3_ROUTES
    assert calls == []


def test_admin_only_pages_refuse_a_user(make_site):
    site = make_site()
    for path in ("/marketplace", "/users", "/groups", "/rules", "/security"):
        assert site.request("alice", "GET", path).status_code == 403, path


def test_a_non_admin_user_cannot_mute(make_site):
    site = make_site()
    admin = {"Authorization": f"Bearer {site.admin_token}"}
    tools_before = site.client.get("/api/tools", headers=admin)
    assert tools_before.status_code == 200
    calls = spy(site.app, "POST", "/visibility/root")
    resp = site.request("alice", "POST", "/visibility/root",
                        data={"muted": "true", "hidden": "true", "mute": "1"})
    assert resp.status_code == 403
    assert calls == []
    assert site.client.get("/api/tools", headers=admin).json() == tools_before.json()


# --- user-self-service-password (7.6) --------------------------------------
#
# `/login/setup` starts with `/login`, so the gate treats it as public: the
# walk skips it, and these tests check it by hand. The settings routes are
# D3 routes (above); `/users/{id}/setup-code` has no entry, so it is
# admin-only.


def test_the_new_routes_are_in_the_app(make_site):
    site = make_site()
    routes = set(app_routes(site.app))
    assert {("GET", "/login/setup"), ("POST", "/login/setup"),
            ("GET", "/settings"), ("POST", "/settings/password"),
            ("POST", "/users/{id}/setup-code")} <= routes


def test_the_setup_page_is_public(make_site):
    """`/login/setup` GET and POST answer with no cookie: 200 and 400, never a
    303 to `/login`."""
    site = make_site()
    page = site.client.get("/login/setup")
    assert page.status_code == 200
    posted = site.client.post("/login/setup", data={
        "user": "alice", "code": "wrong", "password": "pw-0123456789",
        "confirm": "pw-0123456789"})
    assert posted.status_code == 400
    assert "location" not in posted.headers
    assert not listed(USER_ROUTES, "GET", "/login/setup")  # public, not a user route


def test_a_non_admin_reaches_both_settings_routes(make_site):
    site = make_site()
    assert site.request("alice", "GET", "/settings").status_code == 200
    # The handler runs: a bad body answers 400 from the route, not 403 from the gate.
    resp = site.request("alice", "POST", "/settings/password", data={
        "current": PASSWORDS["alice"], "password": "pw-0123456789",
        "confirm": "not-the-same-9"})
    assert resp.status_code == 400
    assert listed(USER_ROUTES, "GET", "/settings")
    assert listed(USER_ROUTES, "POST", "/settings/password")


def test_the_reset_route_stays_admin_only(make_site):
    site = make_site()
    assert not listed(USER_ROUTES, "POST", "/users/bob/setup-code")
    calls = spy(site.app, "POST", "/users/{id}/setup-code")
    resp = site.request("alice", "POST", "/users/bob/setup-code")
    assert resp.status_code == 403
    assert calls == [], "the handler ran"
    resp = site.client.post("/login", data={"user": "bob", "password": PASSWORDS["bob"],
                                            "next": "/"})
    assert resp.status_code == 303, "bob was reset by a non-admin"
    site.client.cookies.clear()
    # The admin passes, so the 403 above is the role check and not a missing route.
    admin = site.client.post("/login", data={"user": "", "password": "secret", "next": "/"})
    resp = site.client.post("/users/bob/setup-code",
                            headers={"Cookie": f"mcpflow_session={admin.cookies['mcpflow_session']}"})
    site.client.cookies.clear()
    assert resp.status_code == 200


# --- security-page (5.4): the Security routes are admin-only ----------------

REMOVE = "/groups/{name}/members/{user_id}/remove"


def test_the_security_routes_are_admin_only(make_site):
    """`GET /security` and the membership removal are in the app, in no entry
    of USER_ROUTES, and a non-admin user gets 403 before the handler runs."""
    site = make_site()
    routes = set(app_routes(site.app))
    assert {("GET", "/security"), ("POST", REMOVE)} <= routes
    remove_path = concrete(REMOVE, site.params)
    assert remove_path == "/groups/staff/members/bob/remove"
    assert not listed(USER_ROUTES, "GET", "/security")
    assert not listed(USER_ROUTES, "POST", remove_path)
    page = spy(site.app, "GET", "/security")
    removal = spy(site.app, "POST", REMOVE)
    assert site.request("alice", "GET", "/security").status_code == 403
    assert site.request("alice", "POST", remove_path).status_code == 403
    assert site.request("alice", "POST", remove_path + "?from=users").status_code == 403
    assert page == [] and removal == [], "a handler ran for a non-admin user"


def test_the_route_walk_reports_the_security_routes_as_403(make_site):
    site = make_site()
    rep = walk(site.app, site.sender("alice"), USER_ROUTES, site.params)
    assert ("GET", "/security", 403) in rep.walked
    assert ("POST", REMOVE, 403) in rep.walked
    for method, path in (("GET", "/security"), ("POST", REMOVE)):
        assert (method, path) not in rep.passed()
    assert rep.open_unlisted == [] and rep.orphan_entries == []


def test_the_admin_reaches_the_security_routes(make_site):
    """The 403 above is the role check, not a missing route."""
    site = make_site()
    admin = site.client.post("/login", data={"user": "", "password": "secret", "next": "/"})
    cookie = {"Cookie": f"mcpflow_session={admin.cookies['mcpflow_session']}"}
    site.client.cookies.clear()
    assert site.client.get("/security", headers=cookie).status_code == 200
    # An unknown group is a 404 from the handler, not a 403 from the gate.
    resp = site.client.post("/groups/staff/members/bob/remove", headers=cookie)
    assert resp.status_code == 404
