"""The persisted registry.

Scenarios from `specs/server-registry/spec.md` (Persistent registry file,
Persisted and in-memory registries agree) and `specs/mcp-gateway/spec.md`
(Child kinds, Unique namespaces).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from mcpflow.registry import (
    Registry,
    RegistryError,
    ServerSpec,
    spec_from_dict,
)


def _npm(namespace: str, **extra) -> ServerSpec:
    return ServerSpec(namespace=namespace, kind="npm", package="@scope/pkg", **extra)


# --- Source field (git-source-packages) --------------------------------------


def test_source_rejected_on_remote():
    with pytest.raises(ValidationError) as exc:
        ServerSpec(
            namespace="r", kind="remote", url="https://x/mcp", source="https://s"
        )
    assert "source" in str(exc.value)


def test_source_rejected_on_custom():
    with pytest.raises(ValidationError) as exc:
        ServerSpec(namespace="c", kind="custom", command="x", source="https://s")
    assert "source" in str(exc.value)


def test_source_bad_prefix_rejected():
    with pytest.raises(ValidationError) as exc:
        ServerSpec(namespace="p", kind="python", package="p", source="ftp://x")
    assert "source" in str(exc.value)


@pytest.mark.parametrize(
    "src",
    ["git+https://h/o/r", "https://h/t.tgz", "github:o/r", "/srv/tool"],
)
def test_source_prefixes_pass(src):
    spec = ServerSpec(namespace="p", kind="python", package="p", source=src)
    assert spec.source == src


def test_source_empty_string_is_none():
    spec = ServerSpec(namespace="p", kind="python", package="p", source="   ")
    assert spec.source is None


def test_file_without_source_loads_as_none(tmp_path):
    path = tmp_path / "servers.json"
    path.write_text(
        '{"version": 1, "servers": ['
        '{"namespace": "time", "kind": "npm", "package": "@scope/pkg"}]}'
    )
    reg = Registry(path)
    reg.load()
    assert reg.get("time").source is None


def test_redact_source():
    from mcpflow.registry import redact_source

    assert (
        redact_source("git+https://oauth2:TOKEN@gitlab.example/o/r")
        == "git+https://***@gitlab.example/o/r"
    )
    # A @ref after the path is not user information.
    assert redact_source("git+https://host/o/r@ref") == "git+https://host/o/r@ref"
    assert redact_source("github:o/r") == "github:o/r"
    assert redact_source("/srv/tool") == "/srv/tool"
    assert redact_source(None) is None


def test_source_secrets():
    from mcpflow.registry import source_secrets

    # user:pass — the whole user information and the bare password both mask.
    assert source_secrets("git+https://oauth2:SEKRETTOKEN123@host/o/r") == [
        "oauth2:SEKRETTOKEN123",
        "SEKRETTOKEN123",
    ]
    # A bare-token user information (no colon) yields only itself.
    assert source_secrets("https://SEKRETTOKEN123@host/o/r") == ["SEKRETTOKEN123"]
    # A `@` in a query does not stretch the userinfo past the authority; the
    # bare password still masks (urlsplit bounds it to the netloc).
    assert source_secrets("https://user:SEKRETTOKEN123@host/o/r?x=a@b") == [
        "user:SEKRETTOKEN123",
        "SEKRETTOKEN123",
    ]
    # No credential: nothing to mask.
    assert source_secrets("git+https://host/o/r@ref") == []
    assert source_secrets("github:o/r") == []
    assert source_secrets("/srv/tool") == []
    assert source_secrets(None) == []


def test_update_keeps_source_on_redacted_echo(tmp_path):
    from mcpflow.registry import redact_source

    reg = Registry(tmp_path / "servers.json")
    reg.load()
    raw = "git+https://oauth2:TOKEN@host/o/r"
    reg.add(ServerSpec(namespace="p", kind="python", package="p", source=raw))
    # A client echoes the redacted GET body back to PUT: keep the credential.
    echoed = ServerSpec(
        namespace="p", kind="python", package="p", source=redact_source(raw)
    )
    reg.update(echoed)
    assert reg.get("p").source == raw
    # A new credential is adopted.
    new = "git+https://oauth2:NEW@host/o/r"
    reg.update(ServerSpec(namespace="p", kind="python", package="p", source=new))
    assert reg.get("p").source == new


# --- Reserved namespaces (admin-mcp-provider) --------------------------------


def test_reserved_namespace_mcpflow_rejected():
    with pytest.raises(RegistryError) as exc:
        spec_from_dict({"namespace": "mcpflow", "kind": "custom", "command": "x"})
    assert str(exc.value).startswith("namespace:")
    assert "namespace mcpflow is reserved" in str(exc.value)


def test_reserved_prefix_mcpflow_underscore_rejected():
    with pytest.raises(RegistryError) as exc:
        spec_from_dict({"namespace": "mcpflow_list", "kind": "custom", "command": "x"})
    assert str(exc.value).startswith("namespace:")
    assert "namespace mcpflow_list is reserved" in str(exc.value)


def test_prefix_without_underscore_passes():
    spec = spec_from_dict({"namespace": "mcpflower", "kind": "custom", "command": "x"})
    assert spec.namespace == "mcpflower"


def test_load_refuses_reserved_namespace(tmp_path):
    path = tmp_path / "servers.json"
    path.write_text(
        '{"version": 1, "servers": ['
        '{"namespace": "mcpflow", "kind": "npm", "package": "@scope/pkg"}]}'
    )
    reg = Registry(path)
    with pytest.raises(ValidationError):
        reg.load()


# --- Persistent registry file (12.4) -----------------------------------------


def test_missing_file(tmp_path):
    path = tmp_path / "servers.json"
    reg = Registry(path)
    reg.load()
    assert reg.list() == []
    assert not path.exists()
    reg.add(_npm("time"))
    assert path.exists()


def test_restart_keeps_children(tmp_path):
    path = tmp_path / "servers.json"
    reg = Registry(path)
    reg.load()
    reg.add(_npm("time"))
    # A fresh process loads the same file.
    reloaded = Registry(path)
    reloaded.load()
    assert [s.namespace for s in reloaded.list()] == ["time"]


def test_duplicate_namespace_rejected(tmp_path):
    path = tmp_path / "servers.json"
    reg = Registry(path)
    reg.load()
    reg.add(_npm("time"))
    before = path.read_bytes()
    with pytest.raises(RegistryError):
        reg.add(_npm("time"))
    # The file is unchanged.
    assert path.read_bytes() == before


def test_load_rejects_duplicate_namespace(tmp_path):
    # A hand-edited file with two entries under one namespace must not load.
    path = tmp_path / "servers.json"
    path.write_text(
        '{"version": 1, "servers": ['
        '{"namespace": "time", "kind": "npm", "package": "@scope/pkg"},'
        '{"namespace": "time", "kind": "npm", "package": "@scope/pkg2"}]}'
    )
    reg = Registry(path)
    with pytest.raises(RegistryError):
        reg.load()


def test_invalid_namespace_rejected(tmp_path):
    # The admin adds a child with namespace "My-Server".
    with pytest.raises(RegistryError) as exc:
        spec_from_dict(
            {"namespace": "My-Server", "kind": "npm", "package": "@scope/pkg"}
        )
    assert "namespace" in str(exc.value)


def test_quiescent_state(tmp_path):
    path = tmp_path / "servers.json"
    reg = Registry(path)
    reg.load()
    reg.add(_npm("a"))
    reg.add(_npm("b"))
    reg.set_enabled("a", False)
    # With no operation in flight, the file equals the in-memory list.
    fresh = Registry(path)
    fresh.load()
    assert [s.model_dump() for s in fresh.list()] == [
        s.model_dump() for s in reg.list()
    ]


# --- Child kinds and atomic write (12.5) -------------------------------------


def test_per_kind_required_fields():
    # python and npm require package.
    with pytest.raises(ValidationError):
        ServerSpec(namespace="p", kind="python")
    with pytest.raises(ValidationError):
        ServerSpec(namespace="n", kind="npm")
    # remote requires url.
    with pytest.raises(ValidationError):
        ServerSpec(namespace="r", kind="remote")
    # custom requires command.
    with pytest.raises(ValidationError):
        ServerSpec(namespace="c", kind="custom")
    # Valid specs for each kind construct without error.
    ServerSpec(namespace="p", kind="python", package="mcp-server-time")
    ServerSpec(namespace="n", kind="npm", package="@scope/pkg")
    ServerSpec(namespace="r", kind="remote", url="https://x.test/mcp")
    ServerSpec(namespace="c", kind="custom", command="/bin/echo")


def test_atomic_write_on_every_mutator(tmp_path):
    path = tmp_path / "servers.json"
    reg = Registry(path)
    reg.load()

    def on_disk() -> list[str]:
        fresh = Registry(path)
        fresh.load()
        return [s.namespace for s in fresh.list()]

    reg.add(_npm("time"))
    assert on_disk() == ["time"]

    reg.add(_npm("fs"))
    assert on_disk() == ["time", "fs"]

    reg.update(_npm("time", args=["--x"]))
    fresh = Registry(path)
    fresh.load()
    assert fresh.get("time").args == ["--x"]

    reg.set_enabled("fs", False)
    fresh = Registry(path)
    fresh.load()
    assert fresh.get("fs").enabled is False

    reg.remove("time")
    assert on_disk() == ["fs"]
