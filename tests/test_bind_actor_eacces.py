"""A disk permission error is an internal error (bind-actor-to-server-writes, T3 and T11).

Requirement "A file-system permission error is an internal error" of
`specs/admin-api/spec.md` and requirement "Web routes answer a write-time
refusal with 403" of `specs/web-ui/spec.md`. A `PermissionError` with an
`errno` is not a refusal: the response is `500` and never holds the operating
system text. A refusal of the policy still answers `403`. The `TestClient` of
`make_mu_site` is built with `raise_server_exceptions=False`, so the test sees
the `500` instead of the re-raised error.
"""

from __future__ import annotations

from dashboard_site import api_headers, bearer, make_mu_site  # noqa: F401
from reresolve_race import demote_alice, make_second_admin, revoke_during_body
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Mount, Route
from starlette.testclient import TestClient

from mcpflow import web
from mcpflow.api import API_EXCEPTION_HANDLERS
from mcpflow.identity import LocalIdentityProvider
from mcpflow.registry import Registry

NEW_TIME = {"kind": "npm", "package": "@acme/time@1.0.0", "args": ["--changed"]}


def eacces(path: str = "/data/x.json") -> PermissionError:
    return PermissionError(13, "Permission denied", path)


def test_a_disk_permission_error_on_put_api_servers_answers_500(make_mu_site, monkeypatch):  # noqa: F811
    """Scenario "A disk permission error answers 500"."""
    site = make_mu_site()

    def boom(self, spec):
        raise eacces(str(site.data / "servers.json"))

    monkeypatch.setattr(Registry, "update", boom)
    resp = site.client.put("/api/servers/time", headers=api_headers(site), json=NEW_TIME)
    assert resp.status_code == 500, (resp.status_code, resp.text)
    assert resp.json() == {"error": "internal error"}
    assert "Permission denied" not in resp.text and "servers.json" not in resp.text


def test_a_disk_permission_error_on_post_users_answers_500(make_mu_site, monkeypatch):  # noqa: F811
    """Scenario "A disk permission error is not a refusal"."""
    site = make_mu_site()

    def boom(self, users, groups):
        raise eacces(str(site.data / "users.json"))

    monkeypatch.setattr(LocalIdentityProvider, "_save", boom)
    resp = site.request("admin", "POST", "/users", data={"id": "carol"})
    assert resp.status_code == 500, (resp.status_code, resp.text)
    assert "Permission denied" not in resp.text
    assert "users.json" not in resp.text


def test_a_disk_permission_error_on_a_web_server_write_answers_500(make_mu_site, monkeypatch):  # noqa: F811
    """The same rule on a web server route: the handler does not turn it into a 403."""
    site = make_mu_site()

    def boom(self, key, enabled):
        raise eacces()

    monkeypatch.setattr(Registry, "set_enabled", boom)
    resp = site.request("admin", "POST", "/servers/time/disable")
    assert resp.status_code == 500, (resp.status_code, resp.text)
    assert "Permission denied" not in resp.text


def test_a_policy_refusal_still_answers_403_on_the_api(make_mu_site):  # noqa: F811
    """Scenario "A policy refusal still answers 403"."""
    site = make_mu_site()
    token = make_second_admin(site)
    fired = revoke_during_body(site.app, "DELETE", "/api/servers/{ref}", demote_alice(site),
                               at="enter")
    resp = site.client.delete("/api/servers/time", headers=bearer(token))
    assert fired
    assert resp.status_code == 403, (resp.status_code, resp.text)
    assert resp.json() == {"error": "the admin role is required"}


def test_the_web_handler_is_registered_on_the_root_app(make_mu_site):  # noqa: F811
    """Requirement "Web routes answer a write-time refusal with 403": one handler on the app."""
    assert web.WEB_EXCEPTION_HANDLERS == {PermissionError: web._err_refusal}
    site = make_mu_site()
    assert site.app.exception_handlers[PermissionError] is web._err_refusal
    api = next(r for r in site.app.routes if isinstance(r, Mount) and r.path == "/api")
    api_handlers = api.app.exception_handlers
    assert api_handlers[PermissionError] is not web._err_refusal
    assert api_handlers[PermissionError] is API_EXCEPTION_HANDLERS[PermissionError]
    assert Exception in api_handlers


def build_routes_only(error: Exception, *, handlers: bool) -> TestClient:
    """A tiny app whose one route raises `error`, as an app from `build_routes` alone."""

    async def route(request):
        raise error

    app = Starlette(
        routes=[Route("/boom", route, methods=["GET"]),
                Route("/ok", lambda r: PlainTextResponse("ok"), methods=["GET"])],
        exception_handlers=web.WEB_EXCEPTION_HANDLERS if handlers else None,
    )
    return TestClient(app, raise_server_exceptions=False)


def test_the_web_handler_maps_a_refusal_to_403_with_its_text():
    client = build_routes_only(PermissionError("the admin role is required"), handlers=True)
    resp = client.get("/boom")
    assert (resp.status_code, resp.text) == (403, "the admin role is required")


def test_the_web_handler_lets_an_errno_error_be_a_500():
    client = build_routes_only(eacces(), handlers=True)
    resp = client.get("/boom")
    assert resp.status_code == 500
    assert "Permission denied" not in resp.text


def test_an_app_without_the_handler_answers_500_for_a_refusal():
    """The reason a test of an app from `build_routes` alone registers the handlers."""
    client = build_routes_only(PermissionError("the admin role is required"), handlers=False)
    assert client.get("/boom").status_code == 500
