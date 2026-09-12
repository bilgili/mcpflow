"""The registry persists a visibility change before it adopts it.

A visibility change has three views: the file, the registry's memory, and the
live `Visibility` transform. If the write fails, all three must stay on the
old value. Adopting in memory first would leave the dashboard reading the new
policy while /mcp still enforces the old one.
"""

from __future__ import annotations

import json

import pytest
from conftest import fake_child_spec

from mcpflow.registry import Registry


@pytest.fixture
def registry(tmp_path):
    reg = Registry(tmp_path / "servers.json")
    reg.load()
    reg.add(fake_child_spec("time", "two"))
    return reg


def break_writes(reg, monkeypatch):
    def boom(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(reg, "_write", boom)


def reread(reg) -> Registry:
    fresh = Registry(reg._path)
    fresh.load()
    return fresh


def test_a_failed_write_leaves_the_root_level_unchanged(registry, monkeypatch):
    break_writes(registry, monkeypatch)
    with pytest.raises(OSError):
        registry.set_root_muted(True)
    assert registry.root_muted() is False
    assert reread(registry).root_muted() is False


def test_a_failed_write_leaves_the_namespace_level_unchanged(registry, monkeypatch):
    break_writes(registry, monkeypatch)
    with pytest.raises(OSError):
        registry.set_muted("time", True)
    assert registry.get("time").muted is False
    assert reread(registry).get("time").muted is False


def test_a_failed_write_leaves_the_tool_level_unchanged(registry, monkeypatch):
    break_writes(registry, monkeypatch)
    with pytest.raises(OSError):
        registry.set_tool_muted("time", "get_current_time", True)
    assert registry.get("time").disabled_tools == []
    assert reread(registry).get("time").disabled_tools == []


def test_memory_and_file_agree_after_every_visibility_write(registry):
    registry.set_root_muted(True)
    registry.set_muted("time", True)
    registry.set_tool_muted("time", "get_current_time", True)
    fresh = reread(registry)
    assert fresh.root_muted() == registry.root_muted()
    assert fresh.get("time").muted == registry.get("time").muted
    assert fresh.get("time").disabled_tools == registry.get("time").disabled_tools


def test_a_tool_name_is_stored_verbatim(registry):
    """The child owns the name and matching is exact, so the registry must
    not trim or normalise it."""
    odd = "  spaced  "
    registry.set_tool_muted("time", odd, True)
    assert registry.get("time").disabled_tools == [odd]
    assert reread(registry).get("time").disabled_tools == [odd]
    # And the exact same string unmutes it again.
    registry.set_tool_muted("time", odd, False)
    assert registry.get("time").disabled_tools == []


def test_the_file_carries_the_root_flag(registry):
    registry.set_root_muted(True)
    data = json.loads(registry._path.read_text())
    assert data["muted"] is True
