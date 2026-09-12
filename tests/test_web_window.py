"""The unified dashboard: the server window, the add window, and the tree poll.

Scenarios from `specs/web-ui/spec.md` (Server window, Tool tree poll, Tools
dashboard, Servers page, Add-server form with tabs, JSON paste import).
"""

from __future__ import annotations

import re
from pathlib import Path

from conftest import fake_child_spec, seed_registry

from mcpflow.registry import Registry, ServerSpec

HX = {"HX-Request": "true"}

_DASHBOARD = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "mcpflow"
    / "templates"
    / "dashboard.html"
)

_STYLE = (
    Path(__file__).resolve().parents[1] / "src" / "mcpflow" / "static" / "style.css"
)


def _tagged(ns: str = "gmail") -> ServerSpec:
    return ServerSpec(
        namespace=ns,
        kind="npm",
        package="@scope/pkg",
        enabled=False,
        catalog="gmail",
    )


def _header_child(ns: str = "linear") -> ServerSpec:
    return ServerSpec(
        namespace=ns,
        kind="remote",
        url="https://linear.test/mcp",
        transport="http",
        headers={"Authorization": "Bearer SEKRETTOKEN"},
        enabled=False,
    )


def _groups(body: str) -> list[str]:
    return re.findall(r"<details[^>]*class=\"ns-group\"[^>]*>", body)


# --- Server window -----------------------------------------------------------


def test_details_returns_the_partial_with_the_htmx_header(server_factory):
    server = server_factory(seed_registry(fake_child_spec("time", "good")))
    server.wait(running=1)
    client = server.login()
    resp = client.get("/servers/time", headers=HX)
    client.close()
    assert resp.status_code == 200
    body = resp.text
    # A partial: the frame only, no page chrome.
    assert "<!doctype" not in body.lower()
    assert "<nav>" not in body
    assert 'class="dhead"' in body and 'class="dbody"' in body
    # The dialog's own close control, not the page's back link.
    assert 'method="dialog"' in body


def test_window_renders_as_a_page_without_htmx(server_factory):
    server = server_factory(seed_registry(fake_child_spec("time", "good")))
    server.wait(running=1)
    client = server.login()
    body = client.get("/servers/time").text
    client.close()
    assert "<!doctype" in body.lower()
    assert "<nav>" in body
    assert 'class="detail page"' in body
    assert "Runs as" in body
    assert 'action="/servers/time/restart"' in body


def test_window_shows_the_raw_source_in_the_input_only(server_factory):
    raw = "git+https://oauth2:SEKRETTOKEN@host/o/r"
    spec = ServerSpec(
        namespace="tool", kind="python", package="my-tool", source=raw, enabled=False
    )
    server = server_factory(seed_registry(spec))
    client = server.login()
    body = client.get("/servers/tool").text
    client.close()
    # The command is redacted; the token appears in the form input alone.
    assert "uvx --from git+https://***@host/o/r my-tool" in body
    assert body.count("SEKRETTOKEN") == 1
    assert f'name="source" value="{raw}"' in body


def test_save_redirects_to_the_dashboard(server_factory):
    server = server_factory(
        seed_registry(_tagged("gmail")), CHILD_START_TIMEOUT="2"
    )
    client = server.login()
    resp = client.post(
        "/servers/gmail",
        data={"kind": "npm", "package": "@scope/pkg", "description": "changed"},
    )
    client.close()
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"
    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    assert reg.get("gmail").description == "changed"


def test_save_keeps_the_authorization_header_of_a_header_sink_child(server_factory):
    server = server_factory(
        seed_registry(_header_child()), CHILD_START_TIMEOUT="2"
    )
    client = server.login()
    body = client.get("/servers/linear").text
    # The textarea holds the raw header, so the save posts it back unchanged.
    assert "Authorization=Bearer SEKRETTOKEN" in body
    resp = client.post(
        "/servers/linear",
        data={
            "kind": "remote",
            "url": "https://linear.test/mcp",
            "transport": "http",
            "headers": "Authorization=Bearer SEKRETTOKEN",
            "description": "changed",
        },
    )
    client.close()
    assert resp.status_code == 303
    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    spec = reg.get("linear")
    assert spec.headers["Authorization"] == "Bearer SEKRETTOKEN"
    assert spec.description == "changed"


def test_save_with_a_bad_value_re_renders_the_window(server_factory):
    server = server_factory(
        seed_registry(_tagged("gmail")), CHILD_START_TIMEOUT="2"
    )
    client = server.login()
    resp = client.post(
        "/servers/gmail",
        data={"kind": "nonsense", "package": "@scope/pkg", "description": "typed"},
    )
    client.close()
    assert resp.status_code == 400
    body = resp.text
    # The full window page, with the reason and the typed values.
    assert "<!doctype" in body.lower()
    assert 'class="error"' in body
    assert 'value="typed"' in body


def test_a_failed_action_re_renders_the_window(server_factory):
    # A disabled child is `stopped`; `restart` refuses it with a RegistryError.
    server = server_factory(
        seed_registry(_tagged("gmail")), CHILD_START_TIMEOUT="2"
    )
    client = server.login()
    plain = client.post("/servers/gmail/restart")
    htmx = client.post("/servers/gmail/restart", headers=HX)
    client.close()
    assert plain.status_code == 400
    assert "<!doctype" in plain.text.lower()
    assert "is not running" in plain.text
    # An htmx caller keeps the bare reason.
    assert htmx.status_code == 400
    assert "<!doctype" not in htmx.text.lower()
    assert "is not running" in htmx.text


def test_the_forms_in_the_window_do_not_nest(server_factory):
    server = server_factory(
        seed_registry(_tagged("gmail")), CHILD_START_TIMEOUT="2"
    )
    client = server.login()
    body = client.get("/servers/gmail").text
    client.close()
    assert 'id="server-form"' in body
    assert 'form="server-form"' in body
    # The edit form closes before the first action form opens.
    edit = body.index('id="server-form"')
    close = body.index("</form>", edit)
    assert close < body.index('action="/servers/gmail/restart"')


def test_the_window_lists_the_published_names_in_one_column(server_factory):
    """A published name carries the namespace prefix and is far longer than a
    catalogue tool name. In two columns it overflowed its column and painted
    over the next one, which is unreadable rather than merely clipped."""
    server = server_factory(seed_registry(fake_child_spec("time", "two")))
    server.wait(running=1)
    client = server.login()
    body = client.get("/servers/time").text
    client.close()
    assert 'class="tools published"' in body
    css = _STYLE.read_text()
    assert ".tools.published { columns: 1; }" in css
    # The break rule guards every tool list, including the marketplace's.
    tools_li = [ln for ln in css.splitlines() if ln.startswith(".tools li")][0]
    assert "overflow-wrap: anywhere" in tools_li


def test_a_btn_anchor_is_styled_as_a_button():
    """`.btn` is worn by both <button> and <a>. Without these the anchor keeps
    the user-agent link look and reads as a link inside a border."""
    css = _STYLE.read_text()
    rule = css[css.index("button, .btn {") : css.index("input, textarea, select")]
    assert "text-decoration: none" in rule
    assert "display: inline-block" in rule


def test_the_window_shows_the_catalog_identity(server_factory):
    server = server_factory(
        seed_registry(_tagged("gmail")), CHILD_START_TIMEOUT="2"
    )
    client = server.login()
    body = client.get("/servers/gmail").text
    client.close()
    head = body[body.index('class="dhead"') : body.index('class="dbody"')]
    assert "background:#d93025" in head
    assert "Gmail" in head


def test_a_child_without_a_catalog_entry_shows_a_plain_monogram(server_factory):
    server = server_factory(seed_registry(fake_child_spec("time", "good")))
    server.wait(running=1)
    client = server.login()
    body = client.get("/servers/time").text
    client.close()
    assert 'class="icon plain"' in body


def test_edit_route_redirects(server_factory):
    server = server_factory(
        seed_registry(_tagged("gmail")), CHILD_START_TIMEOUT="2"
    )
    client = server.login()
    resp = client.get("/servers/gmail/edit")
    client.close()
    assert resp.status_code == 303
    assert resp.headers["location"] == "/servers/gmail"


def test_unknown_namespace_is_not_found(server_factory):
    server = server_factory()
    client = server.login()
    resp = client.get("/servers/nope")
    client.close()
    assert resp.status_code == 404


# --- Tool tree poll ----------------------------------------------------------


def test_the_tree_polls_while_a_child_starts(server_factory):
    # A slow child stays `starting` for the length of this request.
    server = server_factory(
        seed_registry(fake_child_spec("slow", "hang")), CHILD_START_TIMEOUT="30"
    )
    server.wait(starting=1)
    client = server.login()
    body = client.get("/").text
    client.close()
    root = body[body.index('<div id="tools-tree"') :].split(">", 1)[0]
    assert 'hx-get="/tools/tree"' in root
    assert 'hx-trigger="every 3s"' in root
    assert 'hx-target="#tools-tree"' in root
    assert 'hx-swap="outerHTML"' in root
    assert 'hx-sync="this:drop"' in root
    assert 'hx-disinherit="*"' in root


def test_the_tree_does_not_poll_when_every_child_is_settled(server_factory):
    server = server_factory(seed_registry(fake_child_spec("time", "good")))
    server.wait(running=1)
    client = server.login()
    body = client.get("/").text
    client.close()
    root = body[body.index('<div id="tools-tree"') :].split(">", 1)[0]
    assert "hx-trigger" not in root
    assert 'hx-get="/tools/tree"' not in root
    assert 'hx-disinherit="*"' in root


def test_the_poll_route_renders_the_tree_collapsed(server_factory):
    server = server_factory(seed_registry(fake_child_spec("time", "good")))
    server.wait(running=1)
    client = server.login()
    resp = client.get("/tools/tree")
    client.close()
    assert resp.status_code == 200
    body = resp.text
    # The partial only, every group collapsed.
    assert "<!doctype" not in body.lower()
    assert '<div id="tools-tree"' in body
    assert _groups(body)
    assert not any("open" in g for g in _groups(body))


def test_a_control_answer_renders_the_tree_collapsed(server_factory):
    server = server_factory(seed_registry(fake_child_spec("time", "good")))
    server.wait(running=1)
    client = server.login()
    body = client.post(
        "/visibility/namespaces/time", headers=HX
    ).text
    client.close()
    assert _groups(body)
    assert not any("open" in g for g in _groups(body))


def test_the_details_control_does_not_share_the_poll_queue(server_factory):
    server = server_factory(seed_registry(fake_child_spec("time", "good")))
    server.wait(running=1)
    client = server.login()
    body = client.get("/").text
    client.close()
    control = re.search(r"<a[^>]*hx-get=\"/servers/time\"[^>]*>", body)
    assert control is not None
    tag = control.group(0)
    # Its own target and swap, and no sync: the root disinherits everything.
    assert 'hx-target="#detail"' in tag
    assert 'hx-swap="innerHTML"' in tag
    assert "hx-sync" not in tag


def test_the_dashboard_restores_the_open_groups_after_a_swap():
    source = _DASHBOARD.read_text()
    assert "htmx:beforeSwap" in source
    assert "htmx:afterSwap" in source
    # `afterSettle` runs 20 ms after the insert; the restore must not wait.
    assert "htmx:afterSettle" not in source
    assert 'getElementById("tools-tree")' in source
    assert "data-ns" in source


# --- Dashboard and add window ------------------------------------------------


def test_servers_redirects_to_the_dashboard(server_factory):
    server = server_factory()
    client = server.login()
    resp = client.get("/servers")
    client.close()
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"


def test_add_window_npm_tab_partial(server_factory):
    server = server_factory()
    client = server.login()
    resp = client.get("/add-server?tab=npm", headers=HX)
    client.close()
    assert resp.status_code == 200
    body = resp.text
    assert "<!doctype" not in body.lower()
    assert 'id="server-form"' in body
    assert 'form="server-form"' in body
    assert 'href="/add-server?tab=npm"' in body


def test_add_window_json_tab_parses_from_the_footer(server_factory):
    server = server_factory()
    client = server.login()
    body = client.get("/add-server?tab=json", headers=HX).text
    client.close()
    assert 'id="import-form"' in body
    assert 'form="import-form"' in body
    assert 'id="server-form"' not in body


def test_add_window_renders_as_a_page_without_htmx(server_factory):
    server = server_factory()
    client = server.login()
    body = client.get("/add-server").text
    client.close()
    assert "<!doctype" in body.lower()
    assert "<nav>" in body
    assert 'class="tabs"' in body


def test_a_child_named_new_keeps_its_window(server_factory):
    spec = ServerSpec(
        namespace="new", kind="npm", package="@scope/pkg", enabled=False
    )
    server = server_factory(seed_registry(spec), CHILD_START_TIMEOUT="2")
    client = server.login()
    resp = client.get("/servers/new")
    client.close()
    assert resp.status_code == 200
    assert 'action="/servers/new"' in resp.text


def test_a_stopped_child_shows_a_group(server_factory):
    spec = ServerSpec(
        namespace="weather", kind="npm", package="@scope/pkg", enabled=False
    )
    server = server_factory(seed_registry(spec), CHILD_START_TIMEOUT="2")
    client = server.login()
    body = client.get("/").text
    client.close()
    assert 'data-ns="weather"' in body
    assert "status-stopped" in body
    assert "No tools yet." in body


def test_the_server_row_shows_the_command_and_only_details(server_factory):
    spec = ServerSpec(
        namespace="time",
        kind="python",
        package="mcp-server-time",
        args=["--local-timezone", "UTC"],
        enabled=False,
    )
    server = server_factory(seed_registry(spec), CHILD_START_TIMEOUT="2")
    client = server.login()
    body = client.get("/").text
    client.close()
    row = body[body.index('class="server-row"') :]
    row = row[: row.index("</div>")]
    assert "uvx mcp-server-time --local-timezone UTC" in row
    assert 'href="/servers/time"' in row
    for action in ("restart", "enable", "disable", "delete"):
        assert f"/servers/time/{action}" not in row


def test_import_json_returns_the_add_window_prefilled(server_factory):
    server = server_factory()
    client = server.login()
    resp = client.post(
        "/import/json",
        data={
            "config": '{"mcpServers": {"fs": {"command": "npx", '
            '"args": ["-y", "@scope/pkg", "/data"]}}}'
        },
        headers=HX,
    )
    client.close()
    assert resp.status_code == 200
    body = resp.text
    assert "<!doctype" not in body.lower()
    assert 'id="server-form"' in body
    assert 'form="server-form"' in body
    assert 'value="fs"' in body
    assert 'value="@scope/pkg"' in body


def test_a_bad_paste_keeps_the_text(server_factory):
    server = server_factory()
    client = server.login()
    resp = client.post(
        "/import/json", data={"config": "not json at all"}, headers=HX
    )
    client.close()
    assert resp.status_code == 400
    body = resp.text
    assert 'id="import-form"' in body
    assert "not json at all" in body
    assert 'class="error"' in body


def test_the_add_page_controls_navigate_instead_of_swapping(server_factory):
    """The page has no `#detail` element. htmx handles a click before the
    browser does, so an hx-get at a missing target would abort the navigation
    and leave the tab dead."""
    server = server_factory()
    client = server.login()
    page = client.get("/add-server?tab=json").text
    dialog = client.get("/add-server?tab=json", headers=HX).text
    client.close()
    # The page keeps the plain link and the plain post, and no htmx target.
    assert 'href="/add-server?tab=npm"' in page
    assert "#detail" not in page
    assert "hx-get" not in page
    assert 'action="/import/json"' in page
    assert "hx-post" not in page
    # The dialog keeps both.
    assert 'hx-target="#detail"' in dialog
    assert 'hx-post="/import/json"' in dialog


def test_the_dialog_lets_a_400_window_swap():
    """htmx answers a 4xx with `swap:false`, so without this override the JSON
    parse error would render nothing. It sits on the dialog because htmx fires
    `beforeSwap` on the swap target, not on the form that made the request."""
    source = _DASHBOARD.read_text()
    dialog = source[source.index("<dialog id=\"detail\"") :]
    dialog = dialog[: dialog.index("</dialog>")]
    assert "before-swap" in dialog
    assert "400" in dialog
    assert "shouldSwap" in dialog


def test_the_restore_script_ignores_a_rejected_swap():
    """A rejected answer replaces nothing, so it leaves no record to spend.
    A stale record would re-open a group the admin collapsed after it."""
    source = _DASHBOARD.read_text()
    assert "shouldSwap" in source


def test_no_import_result_element_remains(server_factory):
    server = server_factory()
    client = server.login()
    pages = [
        client.get("/").text,
        client.get("/add-server").text,
        client.get("/add-server?tab=json", headers=HX).text,
        client.post(
            "/import/json", data={"config": "nope"}, headers=HX
        ).text,
    ]
    client.close()
    for body in pages:
        assert "import-result" not in body
