"""The Calendar entry's formats against the real child.

Every other test in this suite asserts the shape MCP Flow writes. This one
asserts the only thing that finally matters: that the pinned child reads it.
A format is a contract with a program that this project does not own, so the
contract is checked against that program.

The rest of the suite runs offline (see `conftest.py`). This module needs
`npx` and the network, so it is opt-in:

    MCPFLOW_LIVE_CHILD_TESTS=1 PYTHONPATH=src pytest tests/test_gcal_child.py

The first run installs the package and takes about a minute.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

from mcpflow.catalog import BUILTIN_DIR, Catalog
from mcpflow.oauth import CLIENT_FORMATS, TOKEN_FORMATS, ClientCreds, CredStore

pytestmark = [
    pytest.mark.skipif(
        not os.environ.get("MCPFLOW_LIVE_CHILD_TESTS"),
        reason="opt-in: needs npx and the network",
    ),
    pytest.mark.skipif(shutil.which("npx") is None, reason="npx is not installed"),
]

# A response shaped like Google's, with values that are not credentials.
_RESPONSE = {
    "access_token": "not-a-real-access-token",
    "refresh_token": "not-a-real-refresh-token",
    "scope": "https://www.googleapis.com/auth/calendar",
    "token_type": "Bearer",
    "expires_in": 3600,
}


def _entry():
    cat = Catalog.load(
        BUILTIN_DIR,
        None,
        providers=frozenset({"google", "linear"}),
        client_formats=CLIENT_FORMATS,
        token_formats=TOKEN_FORMATS,
    )
    return cat.get("gcal")


def _run_child(tmp_path, entry, client_fmt: str, token_fmt: str):
    """Write the two credential files the way MCP Flow does, start the child
    on the command the entry names, and return its stderr and the token file.

    The child is a stdio server: with stdin closed it starts, reports what it
    found, and waits. The timeout is the stop signal, not a failure.
    """
    store = CredStore(tmp_path)
    store.write_client("gcal", client_fmt, ClientCreds("fake-id", "fake-secret"))
    store.write_token("gcal", token_fmt, dict(_RESPONSE))
    paths = store.paths("gcal")

    env = dict(os.environ)
    # The entry's own two variables, and nothing ambient that steers the child:
    # `TRANSPORT` would take it off stdio, and the other two move its account
    # mode off the key the `google-calendar` format writes.
    for key in ("TRANSPORT", "GOOGLE_ACCOUNT_MODE", "NODE_ENV"):
        env.pop(key, None)
    env[entry.oauth.client_file.env] = str(paths.client)
    env[entry.oauth.token_file.env] = str(paths.token)

    before = paths.token.read_bytes()
    proc = subprocess.Popen(
        ["npx", "-y", entry.spec.package],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
    )
    try:
        _, err = proc.communicate(timeout=90)
    except subprocess.TimeoutExpired:
        proc.kill()
        _, err = proc.communicate()
    return err, before, paths.token.read_bytes()


def test_the_pinned_child_reads_what_mcp_flow_writes(tmp_path):
    """The whole change, end to end, on the command `build_command` produces."""
    entry = _entry()
    err, before, after = _run_child(
        tmp_path,
        entry,
        entry.oauth.client_file.format,
        entry.oauth.token_file.format,
    )
    assert "Valid tokens found for account(s): normal" in err, err
    assert "Invalid credentials file format" not in err
    assert "No authenticated accounts found" not in err
    # The child left the credential alone. This is what the flat token shape
    # would not do, and it is why `gcal` names `google-calendar`.
    assert before == after


def test_the_web_client_format_would_fail_this_child(tmp_path):
    """`google-client`, which `gmail` and `gdrive` use, is not usable here.

    This is the blocker the first version of the proposal missed, so it gets a
    test rather than a sentence.
    """
    entry = _entry()
    err, _, _ = _run_child(
        tmp_path, entry, "google-client", entry.oauth.token_file.format
    )
    assert "Invalid credentials file format" in err, err


def test_the_flat_token_format_makes_the_child_rewrite_the_file(tmp_path):
    """`google-auth-library` works, and that is the trap.

    The child upgrades the file through a migration branch, which is a shape
    it has announced it is leaving, and it rewrites the credential to do so.
    """
    entry = _entry()
    err, before, after = _run_child(
        tmp_path, entry, entry.oauth.client_file.format, "google-auth-library"
    )
    assert "Valid tokens found for account(s): normal" in err, err
    assert before != after
    assert list(json.loads(after)) == ["normal"]
