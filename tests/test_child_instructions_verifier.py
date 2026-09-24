"""Verifier tests for `child-instructions`, derived from the spec scenarios.

These cover what `test_child_instructions.py` leaves open: both negotiation
paths end to end with freshness, session scope, the tool-mute boundary, each
failure shape (raise with a secret, blob, blank), concurrent order,
and the exact cap boundaries. Expected strings are the spec's literals, not
the module constants.
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

import pytest
from conftest import fake_child_spec
from test_child_instructions import discover, initialize, text_child
from test_visibility import admin, call, mute, ns_path, tool_path

from mcpflow.auth import TokenStore
from mcpflow.instructions import render_instructions
from mcpflow.registry import Registry, ServerSpec

CHILD = str(Path(__file__).parent / "fake_instructions_child.py")
CAP = 16384
MARKER = "[mcpflow: instructions truncated at 16384 bytes]"
SECRET = "sk-verifier-secret-0123456789"


def child(namespace: str, mode: str, **env) -> ServerSpec:
    return ServerSpec(
        namespace=namespace,
        kind="custom",
        command=sys.executable,
        args=[CHILD, mode],
        env=env,
    )


def start(server_factory, *specs, running: int):
    tokens: dict = {}

    def seed(data_dir):
        reg = Registry(data_dir / "servers.json")
        reg.load()
        for spec in specs:
            reg.add(spec)
        store = TokenStore(data_dir / "tokens.json")
        store.load()
        tokens["mcp"] = store.create("mcp")[1]
        tokens["admin"] = store.create("admin", scope="admin")[1]

    server = server_factory(seed)
    counts = server.wait(running=running)
    assert counts["running"] == running, counts
    return server, server.base_url, tokens


def warnings_for(caplog, namespace: str) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING
        and r.name.startswith("mcpflow")
        and f" {namespace}" in r.getMessage()
    ]


# --- Parity: the default (discover) client and the legacy (initialize) client --


def test_both_negotiation_paths_see_fresh_text(server_factory, tmp_path):
    """Scenario `Discover matches initialize` + `The next initialize carries new
    text`, on both paths, for a default agent-shaped client."""
    skills, path = text_child(tmp_path, "skills", "v1")
    _s, base, tokens = start(server_factory, skills, running=1)
    tok = tokens["mcp"]

    assert discover(base, tok) == "## skills\nv1"
    assert initialize(base, tok) == "## skills\nv1"
    path.write_text("v2")
    assert discover(base, tok) == "## skills\nv2"
    assert initialize(base, tok) == "## skills\nv2"


def test_discover_honours_a_namespace_mute(server_factory, tmp_path):
    skills, _ = text_child(tmp_path, "skills", "catalog")
    server, base, tokens = start(server_factory, skills, running=1)
    with admin(server) as client:
        mute(client, ns_path("skills"))
    assert discover(base, tokens["mcp"]) is None
    assert initialize(base, tokens["mcp"]) is None


def test_admin_scope_session_gets_the_same_instructions(server_factory, tmp_path):
    """The spec gate is `registry.visibility(spec)` only; no scope term."""
    skills, _ = text_child(tmp_path, "skills", "catalog")
    _s, base, tokens = start(server_factory, skills, running=1)
    expected = "## skills\ncatalog"
    assert initialize(base, tokens["mcp"]) == expected
    assert initialize(base, tokens["admin"]) == expected
    assert discover(base, tokens["admin"]) == expected


def test_a_tool_mute_does_not_remove_the_block(server_factory, tmp_path):
    """Only `hide_all` gates the read; a muted tool leaves the block."""
    skills, _ = text_child(tmp_path, "skills", "catalog")
    server, base, tokens = start(server_factory, skills, running=1)
    with admin(server) as client:
        mute(client, tool_path("skills"), tool="get_current_time")
    assert initialize(base, tokens["mcp"]) == "## skills\ncatalog"


# --- Order under concurrency ---------------------------------------------------


def test_blocks_keep_registry_order_when_the_first_read_is_slowest(
    server_factory, tmp_path
):
    c = child("c", "delayed", BODY="gamma")
    a, _ = text_child(tmp_path, "a", "alpha")
    d = child("d", "delayed", BODY="delta")
    e = child("e", "delayed", BODY="epsilon")
    b, _ = text_child(tmp_path, "b", "beta")
    _s, base, tokens = start(server_factory, c, a, d, e, b, running=5)

    t0 = time.monotonic()
    text = initialize(base, tokens["mcp"])
    elapsed = time.monotonic() - t0

    assert text == (
        "## c\ngamma\n\n## a\nalpha\n\n## d\ndelta\n\n## e\nepsilon\n\n## b\nbeta"
    )
    # "The supervisor SHALL run the reads concurrently": three 1 s reads take
    # about 1 s together, not 3 s.
    assert elapsed < 2.2


# --- Failure shapes ------------------------------------------------------------


def test_raising_read_scrubs_the_secret_and_keeps_status(server_factory, caplog):
    caplog.set_level(logging.WARNING)
    bad = child("bad", "raise", API_TOKEN=SECRET)
    server, base, tokens = start(server_factory, bad, running=1)
    sup = server.supervisor
    before = sup.get("bad").last_error

    assert initialize(base, tokens["mcp"]) is None

    lines = warnings_for(caplog, "bad")
    assert len(lines) == 1, lines
    assert "bad" in lines[0]
    assert SECRET not in lines[0]
    assert all(SECRET not in r.getMessage() for r in caplog.records)
    assert sup.get("bad").status == "running"
    assert sup.get("bad").last_error == before
    assert call(base, tokens["mcp"], "bad_echo", {"text": "ok"}) == "ok"


def test_non_text_read_contributes_no_block_and_logs_once(server_factory, caplog):
    caplog.set_level(logging.WARNING)
    server, base, tokens = start(server_factory, child("bin", "blob"), running=1)

    assert initialize(base, tokens["mcp"]) is None
    assert len(warnings_for(caplog, "bin")) == 1
    assert server.supervisor.get("bin").status == "running"


def test_blank_read_contributes_no_block_and_does_not_log(server_factory, caplog):
    caplog.set_level(logging.WARNING)
    server, base, tokens = start(server_factory, child("empty", "blank"), running=1)

    assert initialize(base, tokens["mcp"]) is None
    assert warnings_for(caplog, "empty") == []
    assert server.supervisor.get("empty").status == "running"


def test_every_failure_shape_at_once_still_delivers_the_good_block(
    server_factory, tmp_path
):
    """Scenario `The other children still contribute`, widened to every shape."""
    good, _ = text_child(tmp_path, "good", "fine")
    specs = [
        fake_child_spec("slow", "slowres"),
        child("bad", "raise", API_TOKEN=SECRET),
        child("bin", "blob"),
        child("empty", "blank"),
        fake_child_spec("time", "good"),
        good,
    ]
    server, base, tokens = start(server_factory, *specs, running=len(specs))

    assert initialize(base, tokens["mcp"]) == "## good\nfine"
    assert discover(base, tokens["mcp"]) == "## good\nfine"
    assert all(c.status == "running" for c in server.supervisor.children())


# --- Cap boundaries (renderer owns the cap) ------------------------------------


def test_exactly_cap_bytes_is_unchanged(caplog):
    caplog.set_level(logging.WARNING)
    text = "a" * CAP
    assert render_instructions(None, [("k", text)]) == "## k\n" + text
    assert warnings_for(caplog, "k") == []


def test_one_byte_over_the_cap_is_truncated_with_the_spec_marker(caplog):
    caplog.set_level(logging.WARNING)
    out = render_instructions(None, [("k", "a" * (CAP + 1))])
    header, body = out.split("\n", 1)
    kept, marker = body.rsplit("\n", 1)
    assert header == "## k"
    assert marker == MARKER
    assert kept == "a" * CAP
    assert len(warnings_for(caplog, "k")) == 1


@pytest.mark.parametrize("lead", [0, 1, 2, 3])
def test_four_byte_characters_cut_on_a_boundary(lead):
    text = "x" * lead + "\U0001f600" * CAP
    out = render_instructions(None, [("k", text)])
    kept, marker = out.split("\n", 1)[1].rsplit("\n", 1)
    assert marker == MARKER
    kept_bytes = kept.encode()
    assert len(kept_bytes) <= CAP
    # Largest prefix within the cap that ends on a character boundary.
    assert kept == "x" * lead + "\U0001f600" * ((CAP - lead) // 4)


def test_multibyte_block_truncated_end_to_end(server_factory):
    body = "é" * 10000  # 20000 bytes
    _s, base, tokens = start(server_factory, child("big", "body", BODY=body), running=1)
    text = initialize(base, tokens["mcp"])
    header, rest = text.split("\n", 1)
    kept, marker = rest.rsplit("\n", 1)
    assert header == "## big"
    assert marker == MARKER
    assert kept == "é" * (CAP // 2)


def test_multibyte_block_within_the_cap_is_unchanged_end_to_end(server_factory):
    body = "ü→😀 catalog"
    _s, base, tokens = start(server_factory, child("u", "body", BODY=body), running=1)
    assert initialize(base, tokens["mcp"]) == "## u\n" + body


# --- Generic contract ----------------------------------------------------------


def test_the_new_module_names_no_store():
    src = Path(__file__).parent.parent / "src" / "mcpflow" / "instructions.py"
    assert "store" not in src.read_text().lower()

