"""The OAuth callback query never reaches the access log.

Scenarios from `openspec/changes/redact-oauth-callback-log/specs/oauth-client/spec.md`
(Callback query stays out of the access log).
"""

from __future__ import annotations

import copy
import logging
import logging.config

import pytest
from uvicorn.config import LOGGING_CONFIG
from uvicorn.logging import AccessFormatter

from mcpflow.gateway import _AccessQueryMask, build_app

CODE = "4/0AbCdEf-authcode"
STATE = "s3cr3t-state-value"


@pytest.fixture
def access(caplog, settings):
    """Build the app (installs the mask), then capture `uvicorn.access`.

    uvicorn's access logger does not propagate, so the caplog handler goes on
    the logger itself. Returns a function that logs one access record the way
    uvicorn's protocol does and yields the line `AccessFormatter` renders.
    """
    build_app(settings)
    lg = logging.getLogger("uvicorn.access")
    level, propagate = lg.level, lg.propagate
    lg.setLevel(logging.INFO)
    lg.propagate = False  # as uvicorn's LOGGING_CONFIG sets it
    lg.addHandler(caplog.handler)
    fmt = AccessFormatter('%(client_addr)s - "%(request_line)s" %(status_code)s', use_colors=False)

    def emit(target: str, status: int = 303) -> str:
        caplog.clear()
        lg.info('%s - "%s %s HTTP/%s" %d', "127.0.0.1:5000", "GET", target, "1.1", status)
        (record,) = caplog.records
        return fmt.format(record)

    yield emit
    lg.removeHandler(caplog.handler)
    lg.setLevel(level)
    lg.propagate = propagate


def test_callback_code_and_state_are_masked(access):
    line = access(f"/oauth/callback?code={CODE}&state={STATE}")
    assert "/oauth/callback?code=•••&state=•••" in line
    assert CODE not in line and STATE not in line


def test_provider_error_keeps_its_reason(access):
    line = access(f"/oauth/callback?error=access_denied&state={STATE}", status=400)
    assert "error=access_denied" in line
    assert "state=•••" in line
    assert STATE not in line


@pytest.mark.parametrize(
    "target",
    [
        f"/oauth/callback?co%64e={CODE}&state={STATE}",
        f"/oauth/callback?state={STATE}&code={CODE}&code={CODE}x",
        f"/prefix/oauth/callback?code={CODE}&state={STATE}",
    ],
)
def test_encoded_repeated_or_prefixed_names_are_masked(access, target):
    line = access(target)
    assert CODE not in line and STATE not in line


def test_other_queries_pass_unchanged(access):
    line = access("/servers/gmail/log?lines=100", status=200)
    assert "/servers/gmail/log?lines=100" in line


def test_filter_survives_the_uvicorn_logging_configuration(access, caplog):
    # uvicorn.Config applies LOGGING_CONFIG after build_app returns; dictConfig
    # drops the logger's handlers (the caplog one too), so re-attach it.
    logging.config.dictConfig(copy.deepcopy(LOGGING_CONFIG))
    logging.getLogger("uvicorn.access").addHandler(caplog.handler)
    line = access(f"/oauth/callback?code={CODE}&state={STATE}")
    assert "code=•••&state=•••" in line
    assert CODE not in line


def test_filter_installs_once(settings):
    build_app(settings)
    build_app(settings)
    for name in ("uvicorn.access", "uvicorn.error"):
        lg = logging.getLogger(name)
        assert sum(isinstance(f, _AccessQueryMask) for f in lg.filters) == 1


def test_live_callback_access_line_is_masked(server_factory, caplog):
    """A real request through uvicorn's protocol; the route still reads the code."""
    server = server_factory()
    lg = logging.getLogger("uvicorn.access")
    level = lg.level
    lg.setLevel(logging.INFO)
    lg.addHandler(caplog.handler)
    try:
        client = server.login()
        try:
            resp = client.get(f"/oauth/callback?code={CODE}&state={STATE}")
        finally:
            client.close()
    finally:
        lg.removeHandler(caplog.handler)
        lg.setLevel(level)
    assert resp.status_code == 400  # unknown state: "authorization expired"
    fmt = AccessFormatter('"%(request_line)s" %(status_code)s', use_colors=False)
    lines = [fmt.format(r) for r in caplog.records if r.name == "uvicorn.access"]
    callback = [ln for ln in lines if "/oauth/callback" in ln]
    assert callback, lines
    assert all(CODE not in ln and STATE not in ln for ln in lines)
    assert "code=•••&state=•••" in callback[0]


def test_mask_matches_starlette_query_parsing():
    """Round trip: nothing Starlette would read as `code`/`state` survives."""
    import random

    from starlette.datastructures import QueryParams

    from mcpflow.gateway import _mask_query

    rng = random.Random(20260923)
    names = ["code", "state", "CODE", "co%64e", "st%61te", "code+", "+code", "c+ode",
             "error", "lines", "", "code%00", "%63%6F%64%65"]
    values = ["", "x", "4/0Ab", "a=b", "a?b", "%26", "a+b", "%3D"]
    for _ in range(20000):
        parts = []
        for _ in range(rng.randint(1, 5)):
            name = rng.choice(names)
            parts.append(name if rng.random() < 0.1 else f"{name}={rng.choice(values)}SECRET")
        query = rng.choice(["&", "&&", ";"]).join(parts)
        masked = _mask_query(f"/oauth/callback?{query}").partition("?")[2]
        params = QueryParams(masked)
        for key in ("code", "state"):
            for value in params.getlist(key):
                assert "SECRET" not in value, (query, masked)


def test_live_websocket_upgrade_target_is_masked(server_factory, caplog):
    """uvicorn's WebSocket protocols log the target through `uvicorn.error`:
    `"WebSocket <target>" 403` at INFO and the websockets `< GET <target>`
    request line at DEBUG. Neither may carry the callback code or state."""
    import socket
    from urllib.parse import urlsplit

    server = server_factory()
    lg = logging.getLogger("uvicorn.error")
    level = lg.level
    lg.setLevel(logging.DEBUG)
    lg.addHandler(caplog.handler)
    try:
        url = urlsplit(server.base_url)
        with socket.create_connection((url.hostname, url.port), timeout=5) as sock:
            sock.sendall(
                (
                    f"GET /oauth/callback?code={CODE}&state={STATE} HTTP/1.1\r\n"
                    f"Host: {url.netloc}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                    "Sec-WebSocket-Version: 13\r\n\r\n"
                ).encode()
            )
            assert sock.recv(4096)  # the handshake is refused; wait for it
    finally:
        lg.removeHandler(caplog.handler)
        lg.setLevel(level)
    lines = [r.getMessage() for r in caplog.records if r.name == "uvicorn.error"]
    target = [ln for ln in lines if "/oauth/callback" in ln]
    assert target, lines
    assert all(CODE not in ln and STATE not in ln for ln in lines), target
    assert any("code=•••&state=•••" in ln for ln in target)
