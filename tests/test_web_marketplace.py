"""The marketplace page over HTTP.

Scenarios from `specs/marketplace/spec.md` (Search and categories,
Marketplace grid, Entry detail, Connect action, Invalid catalog files are
skipped) and `specs/web-ui/spec.md` (Marketplace page).
"""

from __future__ import annotations

import json
import re

import httpx
from conftest import fake_child_spec, seed_registry

from mcpflow.registry import Registry, ServerSpec

HX = {"HX-Request": "true"}


def _masked(key: str, html: str) -> bool:
    """`"KEY": "•••"` in the spec preview, with Jinja's quote escaping."""
    return re.search(rf'(&#34;|"){key}(&#34;|"): (&#34;|")•••(&#34;|")', html) is not None


def _local(data_dir, name, entry):
    (data_dir / "catalog").mkdir(exist_ok=True)
    (data_dir / "catalog" / name).write_text(
        entry if isinstance(entry, str) else json.dumps(entry)
    )


# --- Marketplace page (web-ui) ------------------------------------------------


def test_nav_order(server_factory):
    client = server_factory().login()
    html = client.get("/marketplace").text
    client.close()
    names = re.findall(r'<nav>.*?</nav>', html, re.S)[0]
    assert re.findall(r">([A-Za-z]+)</a>", names) == ["Dashboard", "Marketplace", "Tokens"]


def test_marketplace_without_session(server_factory):
    server = server_factory()
    resp = httpx.get(server.base_url + "/marketplace", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login?next=/marketplace"


def test_connect_cross_origin_refused(server_factory):
    server = server_factory()
    resp = httpx.post(
        server.base_url + "/marketplace/time/connect",
        data={"namespace": "time"},
        headers={"Origin": "https://evil.test"},
    )
    assert resp.status_code in (401, 403)


# --- Grid, search, categories -------------------------------------------------


def test_page_lists_cards(server_factory):
    client = server_factory().login()
    html = client.get("/marketplace").text
    client.close()
    assert 'href="/marketplace/gmail"' in html
    assert 'href="/marketplace/slack"' in html
    assert 'href="/add-server"' in html
    assert "<dialog" in html


def test_search_by_tool_swaps_grid_only(server_factory):
    client = server_factory().login()
    html = client.get("/marketplace/grid", params={"q": "send_email"}, headers=HX).text
    client.close()
    assert "<nav>" not in html
    assert 'href="/marketplace/gmail"' in html
    assert 'href="/marketplace/slack"' not in html


def test_category_filter(server_factory):
    client = server_factory().login()
    html = client.get("/marketplace", params={"cat": "google"}).text
    client.close()
    assert 'href="/marketplace/gmail"' in html
    assert 'href="/marketplace/github"' not in html
    assert 'name="cat" value="google" class="active"' in html


def test_rail_submits_the_search_form(server_factory):
    # A category click carries the live query: the rail buttons submit the
    # same GET form as the search box, and no hidden `cat` input competes.
    client = server_factory().login()
    html = client.get("/marketplace").text
    client.close()
    assert '<form id="market"' in html
    assert 'type="submit" form="market" name="cat" value="google"' in html
    assert 'type="hidden" name="cat"' not in html


def test_search_and_category_combine(server_factory):
    client = server_factory().login()
    html = client.get("/marketplace", params={"cat": "dev", "q": "git"}).text
    client.close()
    ids = re.findall(r'class="card" href="/marketplace/([a-z0-9_]+)"', html)
    assert ids == ["git", "github", "gitlab"]


def test_rail_counts_ignore_query(server_factory):
    client = server_factory().login()
    full = client.get("/marketplace").text
    narrow = client.get("/marketplace", params={"q": "send_email"}).text
    client.close()
    rail = lambda h: re.findall(r'name="cat" value="[a-z]+"[^>]*>[^<]*<small>(\d+)</small>', h)
    assert rail(full) == rail(narrow) and rail(full)
    assert "1 of " in narrow


def test_unknown_category_falls_back_to_all(server_factory):
    client = server_factory().login()
    html = client.get("/marketplace", params={"cat": "nope"}).text
    client.close()
    assert 'href="/marketplace/gmail"' in html and 'href="/marketplace/github"' in html
    assert 'name="cat" value="" class="active"' in html


def test_connected_shows_namespaces(server_factory):
    a = ServerSpec(namespace="gmail", kind="npm", package="x", enabled=False, catalog="gmail")
    b = ServerSpec(namespace="gmail_work", kind="npm", package="x", enabled=False, catalog="gmail")
    client = server_factory(seed_registry(a, b)).login()
    html = client.get("/marketplace", params={"cat": "google"}).text
    client.close()
    card = html.split('href="/marketplace/gmail"')[1].split("</a>")[0]
    assert "Connected" in card and "gmail, gmail_work" in card
    assert ">Connect<" not in card


def test_unconnected_shows_connect(server_factory):
    client = server_factory().login()
    html = client.get("/marketplace", params={"cat": "chat"}).text
    client.close()
    card = html.split('href="/marketplace/slack"')[1].split("</a>")[0]
    assert ">Connect<" in card and "Connected" not in card


def test_skipped_local_file_listed(server_factory):
    def seed(data_dir):
        _local(data_dir, "bad.json", "{not json")
        _local(
            data_dir,
            "acme.json",
            {
                "id": "acme",
                "name": "Acme",
                "vendor": "Acme",
                "category": "util",
                "description": "x",
                "spec": {"kind": "npm", "package": "acme"},
            },
        )

    client = server_factory(seed).login()
    html = client.get("/marketplace").text
    client.close()
    assert "bad.json" in html
    assert 'href="/marketplace/acme"' in html
    assert ">local<" in html


# --- Entry detail -------------------------------------------------------------


def test_detail_partial_on_htmx(server_factory):
    client = server_factory().login()
    html = client.get("/marketplace/gmail", headers=HX).text
    client.close()
    assert "<nav>" not in html
    assert 'method="dialog"' in html
    assert "gmail_search_emails" in html


def test_detail_page_without_htmx(server_factory):
    client = server_factory().login()
    html = client.get("/marketplace/gmail").text
    client.close()
    assert "<nav>" in html
    assert 'href="/marketplace"' in html
    assert "gmail_search_emails" in html


def test_detail_hides_secret_values(server_factory):
    client = server_factory().login()
    html = client.get("/marketplace/slack").text
    client.close()
    assert _masked("SLACK_BOT_TOKEN", html)
    assert re.search(r'name="setup_SLACK_BOT_TOKEN"[^>]*value=', html) is None


def test_detail_oauth_notice(server_factory):
    # `asana` is a remote `auth: "oauth"` entry with no block, so it keeps the
    # notice and the optional header. (`linear` became a header-sink oauth entry
    # in remote-oauth, so it is now connectable.)
    client = server_factory().login()
    html = client.get("/marketplace/asana").text
    client.close()
    assert "cannot complete an OAuth sign-in" in html
    assert 'name="setup_Authorization"' in html


def test_detail_unknown_404(server_factory):
    client = server_factory().login()
    resp = client.get("/marketplace/nope")
    client.close()
    assert resp.status_code == 404


# --- Connect action -----------------------------------------------------------


def test_connect_registers_and_starts(server_factory):
    server = server_factory(CHILD_START_TIMEOUT="2")
    client = server.login()
    resp = client.post("/marketplace/time/connect", data={"namespace": "time"})
    assert resp.status_code == 303 and resp.headers["location"] == "/servers"
    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    spec = reg.get("time")
    assert spec.kind == "python" and spec.package == "mcp-server-time"
    assert spec.catalog == "time"
    assert server.supervisor.get("time").status in ("starting", "running", "failed")
    client.close()


def test_connect_required_secret_missing_echoes_no_secret(server_factory):
    server = server_factory()
    client = server.login()
    resp = client.post(
        "/marketplace/slack/connect",
        data={"namespace": "slack", "setup_SLACK_BOT_TOKEN": "", "setup_SLACK_TEAM_ID": "T1SECRET"},
    )
    client.close()
    assert resp.status_code == 400
    assert "SLACK_BOT_TOKEN" in resp.text and 'class="error"' in resp.text
    # The 400 re-render masks the preview and echoes no setup value.
    assert "T1SECRET" not in resp.text
    assert _masked("SLACK_TEAM_ID", resp.text) and _masked("SLACK_BOT_TOKEN", resp.text)
    assert re.search(r'name="setup_[A-Z_]+"[^>]*value=', resp.text) is None
    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    assert not [s for s in reg.list() if s.namespace == "slack"]


def test_connect_posted_args_win(server_factory):
    server = server_factory(CHILD_START_TIMEOUT="2")
    client = server.login()
    resp = client.post("/marketplace/fs/connect", data={"namespace": "fs", "args": "/mnt/a /mnt/b"})
    client.close()
    assert resp.status_code == 303
    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    assert reg.get("fs").args == ["/mnt/a", "/mnt/b"]


def test_400_shows_posted_args_in_preview_and_run_command(server_factory):
    # A duplicate namespace forces the 400; the re-render must show the args
    # the admin posted, not the catalog defaults, in both panes.
    server = server_factory(seed_registry(fake_child_spec("fs", "good")))
    client = server.login()
    resp = client.post("/marketplace/fs/connect", data={"namespace": "fs", "args": "/mnt/x"})
    client.close()
    assert resp.status_code == 400
    assert "/mnt/x" in resp.text and "/data" not in resp.text.split("Runs as")[1]
    assert "server-filesystem /mnt/x" in resp.text


def test_connect_entry_args_when_form_posts_none(server_factory):
    server = server_factory(CHILD_START_TIMEOUT="2")
    client = server.login()
    resp = client.post("/marketplace/fs/connect", data={"namespace": "fs"})
    client.close()
    assert resp.status_code == 303
    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    assert reg.get("fs").args == ["/data"]


def test_connect_duplicate_namespace(server_factory):
    server = server_factory(seed_registry(fake_child_spec("time", "good")))
    client = server.login()
    resp = client.post("/marketplace/time/connect", data={"namespace": "time"})
    client.close()
    assert resp.status_code == 400
    assert "already exists" in resp.text
    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    assert len([s for s in reg.list() if s.namespace == "time"]) == 1


def test_connect_second_account(server_factory):
    # `slack` is an `env` entry; `gmail` carries no setup field now (oauth).
    first = ServerSpec(namespace="slack", kind="npm", package="x", enabled=False, catalog="slack")
    server = server_factory(seed_registry(first), CHILD_START_TIMEOUT="2")
    client = server.login()
    resp = client.post(
        "/marketplace/slack/connect",
        data={
            "namespace": "slack_work",
            "setup_SLACK_BOT_TOKEN": "xoxb-work",
            "setup_SLACK_TEAM_ID": "T123",
        },
    )
    client.close()
    assert resp.status_code == 303
    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    assert reg.get("slack").catalog == "slack" and reg.get("slack_work").catalog == "slack"
    assert reg.get("slack_work").env == {"SLACK_BOT_TOKEN": "xoxb-work", "SLACK_TEAM_ID": "T123"}


def test_connect_header_lands_in_headers(server_factory):
    server = server_factory(CHILD_START_TIMEOUT="2")
    client = server.login()
    resp = client.post(
        "/marketplace/github/connect",
        data={"namespace": "gh", "setup_Authorization": "Bearer x"},
    )
    client.close()
    assert resp.status_code == 303
    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    spec = reg.get("gh")
    assert spec.kind == "remote" and spec.headers == {"Authorization": "Bearer x"}
    assert spec.env == {}


def test_connect_unknown_404(server_factory):
    client = server_factory().login()
    resp = client.post("/marketplace/nope/connect", data={"namespace": "x"})
    client.close()
    assert resp.status_code == 404
