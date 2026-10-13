"""`/api` behaviour of the write-time actor check without a race (reresolve-actor-at-write, T6).

Scenarios: admin-api "An unknown target yields 404" (the path target of
`DELETE /api/users/<id>`); access-policy "A still-admin
actor writes" and "A self-removal of the admin role answers the committed
result" (design D6, R7).
"""

from __future__ import annotations

from dashboard_site import bearer, make_mu_site  # noqa: F401
from reresolve_race import make_second_admin


def test_an_unknown_target_yields_404(make_mu_site):  # noqa: F811
    site = make_mu_site()
    token = make_second_admin(site)
    resp = site.client.delete("/api/users/ghost", headers=bearer(token))
    assert resp.status_code == 404, (resp.status_code, resp.text)
    assert resp.json() == {"error": "ghost not found"}


def test_a_still_admin_actor_writes_over_the_api(make_mu_site):  # noqa: F811
    site = make_mu_site()
    token = make_second_admin(site)
    resp = site.client.post("/api/groups", headers=bearer(token), json={"name": "ops"})
    assert resp.status_code == 201, (resp.status_code, resp.text)
    groups = site.client.get("/api/groups", headers=bearer(token)).json()
    assert "ops" in str(groups)


def test_self_removal_of_the_admin_role_answers_200_then_401(make_mu_site):  # noqa: F811
    site = make_mu_site()
    token = make_second_admin(site)
    resp = site.client.put("/api/users/alice", headers=bearer(token), json={"admin": False})
    assert resp.status_code == 200, (resp.status_code, resp.text)
    body = resp.json()
    assert body["id"] == "alice" and body["admin"] is False
    assert site.client.get("/api/users", headers=bearer(token)).status_code == 401
