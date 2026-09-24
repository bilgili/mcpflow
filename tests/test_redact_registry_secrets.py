"""redact-registry-secrets: no outward view of a server record holds a secret.

Scenarios from `openspec/changes/redact-registry-secrets/specs/`:
server-registry (Outward view of a server record, Masked value round trip),
admin-api (Child object hides secrets), web-ui (Server window hides secrets).
"""

from __future__ import annotations

import asyncio
import json
import time

import httpx
import pytest
from conftest import fake_child_spec, seed_registry
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

from mcpflow.auth import TokenStore
from mcpflow.registry import (
    SECRET_MASK,
    Registry,
    RegistryError,
    ServerSpec,
    redact_secrets,
    redact_spec,
    redact_url,
    spec_command,
    url_secrets,
)
from mcpflow.supervisor import scrub_secrets

M = SECRET_MASK
GL_TOKEN = "glpat-abc-secret-1"
QV_TOKEN = "tok-quiver-secret-1"
URL_KEY = "k-999999-secret"


def _remote(ns: str = "quiver", **extra) -> ServerSpec:
    extra.setdefault("url", f"https://u:pw-secret@a.example/mcp?api_key={URL_KEY}&r=eu")
    extra.setdefault("headers", {"Authorization": f"Bearer {QV_TOKEN}"})
    return ServerSpec(namespace=ns, kind="remote", enabled=False, **extra)


def _gitlab() -> ServerSpec:
    return fake_child_spec(
        "gitlab", env={"GITLAB_PERSONAL_ACCESS_TOKEN": GL_TOKEN, "EMPTY": ""},
        enabled=False,
    )


def _reg(tmp_path, *specs) -> Registry:
    reg = Registry(tmp_path / "servers.json")
    reg.load()
    for s in specs:
        reg.add(s)
    return reg


def _body(spec: ServerSpec, **changes) -> ServerSpec:
    """What a client sends back after a read: the redacted view, edited."""
    return redact_spec(spec).model_copy(update=changes)


# --- the outward view --------------------------------------------------------


def test_env_and_header_values_are_masked_keys_kept():
    spec = _gitlab().model_copy(update={"headers": {"Authorization": "Bearer t"}})
    view = redact_spec(spec)
    assert view.env == {"GITLAB_PERSONAL_ACCESS_TOKEN": M, "EMPTY": ""}
    assert view.headers == {"Authorization": M}
    assert redact_secrets({}) == {}


def test_url_keeps_its_endpoint_and_hides_credentials():
    url = "https://u:pw@host.example/mcp?api_key=k-999&region=eu&flag#frag"
    assert redact_url(url) == f"https://{M}@host.example/mcp?api_key={M}&region={M}&flag#frag"
    plain = "https://host.example/mcp"
    assert redact_url(plain) == plain
    assert redact_url("https://h/mcp?empty=&x") == "https://h/mcp?empty=&x"
    assert redact_url(None) is None


def test_url_secrets_cover_userinfo_and_query_values():
    secrets = url_secrets("https://u:pw@h/mcp?a=v%2Fx&b=&c")
    assert {"u:pw", "pw", "v%2Fx", "v/x"} <= set(secrets)
    assert "" not in secrets
    assert url_secrets(None) == []


def test_semicolon_query_and_encoded_userinfo_are_covered():
    url = "https://u:pass%40word@h/mcp?region=eu;api_key=semi-secret-1"
    # `&` splits pairs; a `;` tail stays inside the masked value.
    assert redact_url(url) == f"https://{M}@h/mcp?region={M}"
    # Codex round 3: an empty-looking value with a `;` tail is still masked.
    lead = "https://h/mcp?api_key=;long-secret-123&x=1"
    assert redact_url(lead) == f"https://h/mcp?api_key={M}&x={M}"
    assert "long-secret-123" in url_secrets(lead)
    # Codex round 4: base64 padding in the first `;` piece stays in the value.
    padded = "https://h/mcp?api_key=c2VjcmV0MTI=;region=eu"
    assert "c2VjcmV0MTI=" in url_secrets(padded)
    out = scrub_secrets("invalid api key c2VjcmV0MTI=", url_secrets(padded))
    assert "c2VjcmV0MTI" not in out
    secrets = set(url_secrets(url))
    assert {"semi-secret-1", "pass@word", "pass%40word"} <= secrets
    out = scrub_secrets("auth failed for pass@word key semi-secret-1", list(secrets))
    assert "pass@word" not in out and "semi-secret-1" not in out


def test_oauth_header_write_refuses_a_mask(tmp_path):
    reg = _reg(tmp_path, _remote(headers={}, oauth_pending=True))
    before = (tmp_path / "servers.json").read_text()
    with pytest.raises(RegistryError) as exc:
        reg.set_oauth_header("quiver", "Authorization", f"Bearer {M}")
    assert str(exc.value).startswith("headers:")
    assert (tmp_path / "servers.json").read_text() == before
    assert reg.get("quiver").oauth_pending is True


def test_decoded_forms_are_scrubbed_through_the_supervisor():
    """Codex round 2: `+` form-decoding in a query value, and percent-decoding
    of a source credential, must both reach the scrub set."""
    from mcpflow.supervisor import Supervisor

    remote = _remote(url="https://h/mcp?api_key=alpha+beta-secret")
    out = scrub_secrets("bad key alpha beta-secret", Supervisor._secrets_of(None, remote))
    assert "alpha beta-secret" not in out
    src = ServerSpec(
        namespace="src", kind="python", package="p", enabled=False,
        source="git+https://oauth2:pass%40word-secret@host.example/o/r",
    )
    out = scrub_secrets("clone failed: pass@word-secret", Supervisor._secrets_of(None, src))
    assert "pass@word-secret" not in out


def test_remote_command_line_masks_the_url():
    line = spec_command(_remote())
    assert URL_KEY not in line and "pw-secret" not in line
    assert line.startswith("HTTP https://")


def test_redact_spec_leaves_the_stored_record_raw(tmp_path):
    reg = _reg(tmp_path, _gitlab())
    redact_spec(reg.get("gitlab"))
    assert reg.get("gitlab").env["GITLAB_PERSONAL_ACCESS_TOKEN"] == GL_TOKEN


def test_diagnostic_scrub_masks_a_url_credential():
    from mcpflow.supervisor import Supervisor

    secrets = Supervisor._secrets_of(None, _remote())  # reads no instance state
    text = f"Client error '401' for url 'https://a.example/mcp?api_key={URL_KEY}&r=eu'"
    out = scrub_secrets(text, secrets)
    assert URL_KEY not in out


# --- the round trip ----------------------------------------------------------


def test_echo_keeps_every_stored_secret(tmp_path):
    reg = _reg(tmp_path, _gitlab(), _remote())
    reg.update(_body(reg.get("gitlab"), description="changed"))
    reg.update(_body(reg.get("quiver")))
    fresh = Registry(tmp_path / "servers.json")
    fresh.load()
    assert fresh.get("gitlab").env == {"GITLAB_PERSONAL_ACCESS_TOKEN": GL_TOKEN, "EMPTY": ""}
    assert fresh.get("gitlab").description == "changed"
    assert fresh.get("quiver").headers["Authorization"] == f"Bearer {QV_TOKEN}"
    assert URL_KEY in fresh.get("quiver").url and "pw-secret" in fresh.get("quiver").url
    # Parse, do not grep: `_write` escapes the mask as \u2022 on disk.
    assert M not in json.dumps(
        json.loads((tmp_path / "servers.json").read_text()), ensure_ascii=False
    )


def test_new_value_replaces_the_stored_secret(tmp_path):
    reg = _reg(tmp_path, _gitlab(), _remote())
    reg.update(_body(reg.get("gitlab"), env={"GITLAB_PERSONAL_ACCESS_TOKEN": "glpat-new"}))
    new_url = "https://b.example/mcp?api_key=k-new"
    reg.update(_body(reg.get("quiver"), url=new_url, headers={"Authorization": "Bearer n"}))
    assert reg.get("gitlab").env == {"GITLAB_PERSONAL_ACCESS_TOKEN": "glpat-new"}
    assert reg.get("quiver").url == new_url
    assert reg.get("quiver").headers == {"Authorization": "Bearer n"}


@pytest.mark.parametrize(
    ("ns", "changes", "field"),
    [
        ("gitlab", {"env": {"RENAMED_TOKEN": M}}, "env"),
        ("quiver", {"headers": {"Authorization": f"Bearer {M}"}}, "headers"),
        ("quiver", {"url": f"https://b.example/mcp?api_key={M}"}, "url"),
        ("quiver", {"url": "https://b.example/mcp?api_key=%E2%80%A2%E2%80%A2%E2%80%A2"}, "url"),
        ("quiver", {"url": "https://b.example/mcp?api_key=%e2%80%a2%E2%80%A2%e2%80%A2"}, "url"),
    ],
)
def test_update_that_leaves_a_mask_is_refused(tmp_path, ns, changes, field):
    reg = _reg(tmp_path, _gitlab(), _remote())
    before = (tmp_path / "servers.json").read_text()
    with pytest.raises(RegistryError) as exc:
        reg.update(_body(reg.get(ns), **changes))
    assert str(exc.value).startswith(f"{field}:")
    # The message names the field, never a value.
    for secret in (GL_TOKEN, QV_TOKEN, URL_KEY, "pw-secret"):
        assert secret not in str(exc.value)
    assert (tmp_path / "servers.json").read_text() == before


@pytest.mark.parametrize(
    ("spec", "field"),
    [
        (redact_spec(_remote("clone")), "headers"),
        (redact_spec(_gitlab()).model_copy(update={"namespace": "clone"}), "env"),
        (
            ServerSpec(
                namespace="clone", kind="python", package="p", enabled=False,
                source="git+https://***@host.example/o/r",
            ),
            "source",
        ),
        (
            ServerSpec(
                namespace="clone", kind="python", package="p", enabled=False,
                source="git+https://%2A%2a%2A@host.example/o/r",
            ),
            "source",
        ),
    ],
)
def test_add_of_a_masked_clone_is_refused(tmp_path, spec, field):
    reg = _reg(tmp_path)
    with pytest.raises(RegistryError) as exc:
        reg.add(spec)
    assert str(exc.value).startswith(f"{field}:")
    assert reg.list() == []


# --- admin MCP and REST ------------------------------------------------------


def _seed(holder: dict, *specs: ServerSpec):
    def seed(data_dir):
        seed_registry(*specs)(data_dir)
        store = TokenStore(data_dir / "tokens.json")
        store.load()
        holder["admin"] = store.create("admin", "admin")[1]

    return seed


def _call(base: str, token: str, name: str, args: dict):
    async def run():
        transport = StreamableHttpTransport(
            base + "/mcp", headers={"Authorization": f"Bearer {token}"}
        )
        async with Client(transport) as c:
            return (await c.call_tool(name, args)).data

    return asyncio.run(run())


def _no_secret(text: str) -> None:
    for secret in (GL_TOKEN, QV_TOKEN, URL_KEY, "pw-secret"):
        assert secret not in text


def test_admin_mcp_list_and_get_hide_secrets_and_round_trip(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder, _gitlab(), _remote()))
    base, tok = server.base_url, holder["admin"]
    listed = _call(base, tok, "mcpflow_list_servers", {})
    _no_secret(json.dumps(listed))
    by_ns = {c["namespace"]: c for c in listed}
    assert by_ns["gitlab"]["env"]["GITLAB_PERSONAL_ACCESS_TOKEN"] == M
    assert by_ns["quiver"]["headers"]["Authorization"] == M
    got = _call(base, tok, "mcpflow_get_server", {"namespace": "gitlab"})
    _no_secret(json.dumps(got))
    # Send the read back unchanged (minus the live-status fields).
    spec = {k: v for k, v in got.items()
            if k not in ("status", "last_error", "tool_count", "started_at")}
    answer = _call(base, tok, "mcpflow_update_server", {"namespace": "gitlab", "spec": spec})
    _no_secret(json.dumps(answer))
    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    assert reg.get("gitlab").env["GITLAB_PERSONAL_ACCESS_TOKEN"] == GL_TOKEN


def test_rest_answers_hide_secrets(server_factory):
    holder: dict = {}
    server = server_factory(_seed(holder, _gitlab()))
    h = {"Authorization": f"Bearer {holder['admin']}"}
    with httpx.Client(base_url=server.base_url, headers=h) as c:
        _no_secret(c.get("/api/servers").text)
        _no_secret(c.get("/api/servers/gitlab").text)
        created = c.post("/api/servers", json=_remote().model_dump(mode="json"))
        assert created.status_code == 201
        _no_secret(created.text)
        body = c.get("/api/servers/quiver").json()
        body = {k: v for k, v in body.items()
                if k not in ("status", "last_error", "tool_count", "started_at")}
        put = c.put("/api/servers/quiver", json=body)
        assert put.status_code == 200
        _no_secret(put.text)
        clone = c.post("/api/servers", json={**body, "namespace": "clone"})
        assert clone.status_code == 400
    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    assert reg.get("quiver").headers["Authorization"] == f"Bearer {QV_TOKEN}"
    assert URL_KEY in reg.get("quiver").url


# --- web ---------------------------------------------------------------------


def test_edit_form_shows_masks_and_save_keeps_secret(server_factory):
    server = server_factory(seed_registry(_gitlab()), CHILD_START_TIMEOUT="2")
    client = server.login()
    page = client.get("/servers/gitlab").text
    assert f"GITLAB_PERSONAL_ACCESS_TOKEN={M}" in page
    _no_secret(page)
    resp = client.post(
        "/servers/gitlab",
        data={
            "kind": "custom",
            "command": _gitlab().command,
            "args": " ".join(_gitlab().args),
            "env": f"GITLAB_PERSONAL_ACCESS_TOKEN={M}\nEMPTY=",
        },
    )
    client.close()
    assert resp.status_code == 303
    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    assert reg.get("gitlab").env["GITLAB_PERSONAL_ACCESS_TOKEN"] == GL_TOKEN


def test_import_preview_keeps_pasted_values(server_factory):
    server = server_factory()
    client = server.login()
    resp = client.post(
        "/import/json",
        data={"config": '{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@scope/pkg"], '
                        '"env": {"TOKEN": "pasted-secret"}}}}'},
    )
    client.close()
    assert "TOKEN=pasted-secret" in resp.text


# --- launch reads raw values -------------------------------------------------


def test_child_restarted_after_echo_update_gets_raw_env(server_factory, tmp_path):
    pid_file = tmp_path / "pids.txt"
    spec = fake_child_spec("envchild", env={"MCPFLOW_PID_FILE": str(pid_file)})
    holder: dict = {}
    server = server_factory(_seed(holder, spec))
    server.wait(running=1)
    first = pid_file.read_text().split()
    got = _call(server.base_url, holder["admin"], "mcpflow_get_server",
                {"namespace": "envchild"})
    assert got["env"]["MCPFLOW_PID_FILE"] == M
    spec_body = {k: v for k, v in got.items()
                 if k not in ("status", "last_error", "tool_count", "started_at")}
    _call(server.base_url, holder["admin"], "mcpflow_update_server",
          {"namespace": "envchild", "spec": spec_body})
    # The restarted child wrote its pid to the raw path, so it got the raw value.
    deadline = time.time() + 30
    while time.time() < deadline and len(pid_file.read_text().split()) <= len(first):
        time.sleep(0.1)
    assert len(pid_file.read_text().split()) > len(first)
