"""The `catalog` tag on `ServerSpec`.

Scenarios from `specs/server-registry/spec.md` (Catalog tag): the registry
persists the tag, keeps it through every update whichever caller runs it,
and never lets an update change it.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from conftest import make_settings, seed_registry
from starlette.testclient import TestClient

from mcpflow.auth import TokenStore
from mcpflow.gateway import build_app
from mcpflow.registry import Registry, ServerSpec


def _npm(namespace: str, **extra) -> ServerSpec:
    return ServerSpec(namespace=namespace, kind="npm", package="@scope/pkg", **extra)


def test_file_without_catalog_loads_as_none(tmp_path):
    path = tmp_path / "servers.json"
    path.write_text(
        '{"version": 1, "servers": ['
        '{"namespace": "time", "kind": "npm", "package": "@scope/pkg"}]}'
    )
    reg = Registry(path)
    reg.load()
    assert reg.get("time").catalog is None


def test_catalog_tag_round_trips(tmp_path):
    reg = Registry(tmp_path / "servers.json")
    reg.load()
    reg.add(_npm("gmail", catalog="gmail"))
    again = Registry(tmp_path / "servers.json")
    again.load()
    assert again.get("gmail").catalog == "gmail"


def test_catalog_tag_is_free_text(tmp_path):
    reg = Registry(tmp_path / "servers.json")
    reg.load()
    reg.add(_npm("x", catalog="no_such_entry"))
    assert reg.get("x").catalog == "no_such_entry"


def test_update_without_tag_keeps_it(tmp_path):
    reg = Registry(tmp_path / "servers.json")
    reg.load()
    reg.add(_npm("gmail", catalog="gmail"))
    reg.update(_npm("gmail", description="changed"))
    assert reg.get("gmail").catalog == "gmail"
    assert reg.get("gmail").description == "changed"


def test_update_cannot_change_tag(tmp_path):
    reg = Registry(tmp_path / "servers.json")
    reg.load()
    reg.add(_npm("gmail", catalog="gmail"))
    reg.update(_npm("gmail", catalog="other"))
    assert reg.get("gmail").catalog == "gmail"


@pytest.fixture
def api(tmp_path):
    data = tmp_path / "d"
    (data / "logs").mkdir(parents=True)
    reg = Registry(data / "servers.json")
    reg.load()
    reg.add(_npm("gmail", enabled=False, catalog="gmail"))
    store = TokenStore(data / "tokens.json")
    store.load()
    _, token = store.create("admin", "admin")
    client = TestClient(build_app(make_settings(data)), raise_server_exceptions=True)
    client.__enter__()
    yield SimpleNamespace(client=client, headers={"Authorization": f"Bearer {token}"})
    client.__exit__(None, None, None)


def test_child_json_includes_tag(api):
    body = api.client.get("/api/servers/gmail", headers=api.headers).json()
    assert body["catalog"] == "gmail"


def test_rest_put_omits_tag_keeps_it(api):
    body = {"namespace": "gmail", "kind": "npm", "package": "@scope/pkg",
            "enabled": False, "description": "changed"}
    put = api.client.put("/api/servers/gmail", json=body, headers=api.headers)
    assert put.status_code == 200, put.text
    got = api.client.get("/api/servers/gmail", headers=api.headers).json()
    assert got["catalog"] == "gmail" and got["description"] == "changed"


def test_edit_form_save_keeps_tag(server_factory):
    tagged = _npm("gmail", enabled=False, catalog="gmail")
    server = server_factory(seed_registry(tagged), CHILD_START_TIMEOUT="2")
    client = server.login()
    edit = client.get("/servers/gmail/edit").text
    assert 'name="catalog"' not in edit
    resp = client.post(
        "/servers/gmail",
        data={"kind": "npm", "package": "@scope/pkg", "description": "changed"},
    )
    client.close()
    assert resp.status_code == 303
    reg = Registry(server.data_dir / "servers.json")
    reg.load()
    assert reg.get("gmail").catalog == "gmail"
    assert reg.get("gmail").description == "changed"
