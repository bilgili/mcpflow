"""Verifier tests for `child-catalog-freshness`.

Derived from the change's spec deltas (`mcp-gateway` Child catalog freshness,
`server-registry` Per-child cache TTL, `web-ui` Cache TTL form field,
`admin-api` Cache TTL round-trip) and the frozen interfaces in `design.md`
(`Settings.child_cache_ttl: float  # seconds; >= 0`, the path table for
`ServerSpec` construction). They close gaps the implementer tests leave open.
"""

from __future__ import annotations

import json
import re
import sys

import pytest
from conftest import FAKE_SERVER, fake_child_spec, make_settings, seed_registry
from test_api import api  # noqa: F401  (fixture)
from test_gateway import mcp_call
from test_visibility import _seed as _seed_logged
from test_visibility import call_log

from mcpflow.catalog import SpecTemplate
from mcpflow.config import ConfigError
from mcpflow.registry import Registry, RegistryError, spec_from_dict


def _custom(ns: str, **extra) -> dict:
    return {
        "namespace": ns,
        "kind": "custom",
        "command": sys.executable,
        "args": [FAKE_SERVER, "good"],
        **extra,
    }


# --- Validation: the ">= 0" contract ------------------------------------------
# design.md freezes `child_cache_ttl: float  # seconds; >= 0`. NaN is not >= 0,
# and `nan < 0` is False, so a `< 0` guard lets it through.


@pytest.mark.parametrize("value", ["nan", "-nan"])
def test_nan_child_cache_ttl_rejected(tmp_path, value):
    with pytest.raises(ConfigError, match="CHILD_CACHE_TTL"):
        make_settings(tmp_path, CHILD_CACHE_TTL=value)


@pytest.mark.parametrize("value", ["nan", float("nan")])
def test_nan_spec_cache_ttl_rejected(value):
    with pytest.raises(RegistryError, match="cache_ttl"):
        spec_from_dict(_custom("skills", cache_ttl=value))


@pytest.mark.parametrize("value", [0.0, 2.5, 300.0, "inf"])
def test_every_accepted_cache_ttl_survives_a_restart(tmp_path, value):
    # server-registry: "The registry SHALL persist cache_ttl in servers.json".
    # A value the spec accepts must load back as the same value; a value the
    # registry cannot persist must be rejected at validation instead.
    try:
        spec = spec_from_dict(_custom("skills", cache_ttl=value))
    except RegistryError:
        return
    path = tmp_path / "servers.json"
    reg = Registry(path)
    reg.load()
    reg.add(spec)
    again = Registry(path)
    again.load()
    assert again.get("skills").cache_ttl == spec.cache_ttl


def test_negative_zero_is_not_below_zero(tmp_path):
    assert make_settings(tmp_path, CHILD_CACHE_TTL="-0").child_cache_ttl == 0.0


# --- Registry ownership -------------------------------------------------------


def test_update_takes_a_new_caller_value(tmp_path):
    reg = Registry(tmp_path / "servers.json")
    reg.load()
    reg.add(spec_from_dict(_custom("skills")))
    reg.update(spec_from_dict(_custom("skills", cache_ttl=5)))
    assert reg.get("skills").cache_ttl == 5.0


def test_registry_owned_mutators_keep_cache_ttl(tmp_path):
    # design.md path table: `_replace` preserves the field.
    path = tmp_path / "servers.json"
    reg = Registry(path)
    reg.load()
    reg.add(spec_from_dict(_custom("skills", cache_ttl=0)))
    reg.set_enabled("skills", False)
    reg.set_muted("skills", True)
    reg.set_tool_muted("skills", "get_current_time", True)
    again = Registry(path)
    again.load()
    assert again.get("skills").cache_ttl == 0.0


def test_catalog_entry_can_set_cache_ttl():
    template = SpecTemplate.model_validate({"kind": "custom", "command": "x", "cache_ttl": 0})
    assert template.cache_ttl == 0
    inherited = SpecTemplate.model_validate({"kind": "custom", "command": "x"})
    assert inherited.cache_ttl is None


# --- Admin API: PUT ---------------------------------------------------------


def test_put_sets_and_omitted_resets_to_null(api):  # noqa: F811
    a = api()
    body = _custom("skills", enabled=False)
    assert a.client.post("/api/servers", json=body, headers=a.headers).status_code == 201
    put = a.client.put(
        "/api/servers/skills", json={**body, "cache_ttl": 0}, headers=a.headers
    )
    assert put.status_code == 200 and put.json()["cache_ttl"] == 0.0
    assert a.client.get("/api/servers/skills", headers=a.headers).json()["cache_ttl"] == 0.0
    put = a.client.put("/api/servers/skills", json=body, headers=a.headers)
    assert put.status_code == 200 and put.json()["cache_ttl"] is None
    disk = json.loads((a.data / "servers.json").read_text())["servers"][0]
    assert disk["cache_ttl"] is None


def test_put_negative_400_names_cache_ttl(api):  # noqa: F811
    a = api()
    body = _custom("skills", enabled=False)
    a.client.post("/api/servers", json=body, headers=a.headers)
    put = a.client.put(
        "/api/servers/skills", json={**body, "cache_ttl": -5}, headers=a.headers
    )
    assert put.status_code == 400
    assert "cache_ttl" in put.json()["error"]


# --- Web form -----------------------------------------------------------------


def _field(html: str) -> str:
    return re.search(r'<input name="cache_ttl"[^>]*>', html).group(0)


def test_add_form_has_the_field_for_every_kind(server_factory):
    server = server_factory()
    client = server.login()
    try:
        for kind in ("python", "npm", "remote", "custom"):
            html = client.get(f"/add-server?tab={kind}").text
            assert f'name="kind" value="{kind}"' in html
            assert _field(html)
    finally:
        client.close()


def test_edit_form_shows_none_blank_and_fraction(server_factory):
    server = server_factory(
        seed_registry(
            fake_child_spec("a", "good", enabled=False),
            fake_child_spec("b", "good", enabled=False, cache_ttl=2.5),
        )
    )
    client = server.login()
    try:
        assert 'value=""' in _field(client.get("/servers/a").text)
        assert 'value="2.5"' in _field(client.get("/servers/b").text)
    finally:
        client.close()


def test_edit_form_blank_clears_to_inherit(server_factory):
    # web-ui: "_spec_from_form SHALL pass a blank field as None".
    server = server_factory(
        seed_registry(fake_child_spec("skills", "good", enabled=False, cache_ttl=0))
    )
    client = server.login()
    try:
        html = client.get("/servers/skills").text
        form = dict(re.findall(r'<input name="(\w+)"[^>]*value="([^"]*)"', html))
        form.update(kind="custom", cache_ttl="")
        assert client.post("/servers/skills", data=form).status_code == 303
    finally:
        client.close()
    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    assert reg.get("skills").cache_ttl is None


@pytest.mark.parametrize("bad", ["-1", "abc", "nan"])
def test_add_form_bad_value_400_names_cache_ttl(server_factory, bad):
    server = server_factory()
    client = server.login()
    try:
        resp = client.post(
            "/servers",
            data={"kind": "python", "namespace": "t", "package": "p", "cache_ttl": bad},
        )
    finally:
        client.close()
    assert resp.status_code == 400
    assert "cache_ttl" in resp.text
    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    assert [s.namespace for s in reg.list()] == []


# --- Gateway behaviour: resolution order, proven without private attributes ---


def _grow(server_factory, tmp_path, *, cache_ttl=None, **settings):
    grow = tmp_path / "grow"
    holder: dict = {}
    spec = fake_child_spec(
        "grow", "grow", cache_ttl=cache_ttl, env={"MCPFLOW_GROW": str(grow)}
    )
    server = server_factory(_seed_logged(spec, holder=holder), **settings)
    server.wait(running=1)
    return server, holder["clear"], grow


def test_gateway_default_zero_is_inherited(server_factory, tmp_path):
    # cache_ttl None + CHILD_CACHE_TTL=0 => the child resolves the new tool.
    server, token, grow = _grow(server_factory, tmp_path, CHILD_CACHE_TTL="0")
    mcp_call(server.base_url, token, "grow_get_current_time", {})
    grow.touch()
    assert mcp_call(server.base_url, token, "grow_extra", {}) == "extra"


def test_per_child_value_wins_over_gateway_default(server_factory, tmp_path):
    # cache_ttl 300 + CHILD_CACHE_TTL=0 => the override wins; the lookup misses.
    server, token, grow = _grow(
        server_factory, tmp_path, cache_ttl=300, CHILD_CACHE_TTL="0"
    )
    mcp_call(server.base_url, token, "grow_get_current_time", {})
    grow.touch()
    with pytest.raises(Exception, match=r"Unknown tool: 'grow_extra'"):
        mcp_call(server.base_url, token, "grow_extra", {})
    assert "extra" not in call_log(server)


def test_long_ttl_miss_is_unknown_tool_not_a_crash(server_factory, tmp_path):
    # Tightens "New tool not callable under a long TTL": the refusal is the
    # unknown-tool error, the child stays up and serves the next call, and the
    # call log is live (so its missing `extra` line is meaningful).
    server, token, grow = _grow(server_factory, tmp_path, cache_ttl=300)
    mcp_call(server.base_url, token, "grow_get_current_time", {})
    grow.touch()
    with pytest.raises(Exception, match=r"Unknown tool: 'grow_extra'"):
        mcp_call(server.base_url, token, "grow_extra", {})
    assert mcp_call(server.base_url, token, "grow_get_current_time", {})
    log = call_log(server)
    assert log.count("get_current_time") == 2
    assert "extra" not in log
