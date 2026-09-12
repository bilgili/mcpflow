"""The inline source store.

Scenarios from `specs/inline-source-servers/spec.md` (Source store ownership,
Source file validation, Atomic replacement) and `specs/server-registry/spec.md`
(Source ownership).
"""

from __future__ import annotations

import os
import stat

import pytest

from mcpflow.sources import (
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_TOTAL_BYTES,
    SourceStore,
)


def _store(tmp_path) -> SourceStore:
    return SourceStore(tmp_path / "servers")


def _mode(path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


# --- Atomic replacement ------------------------------------------------------


def test_write_creates_dir_0700_files_0600_with_parents(tmp_path):
    store = _store(tmp_path)
    path = store.write("app", {"main.py": "print(1)", "pkg/util.py": "x = 1"})
    assert path == store.path_for("app")
    assert _mode(path) == 0o700
    assert _mode(path / "pkg") == 0o700
    assert _mode(path / "main.py") == 0o600
    assert (path / "pkg" / "util.py").read_text() == "x = 1"


def test_second_write_replaces_tree(tmp_path):
    store = _store(tmp_path)
    store.write("app", {"a.py": "1", "b.py": "2"})
    store.write("app", {"a.py": "3"})
    path = store.path_for("app")
    assert (path / "a.py").read_text() == "3"
    assert not (path / "b.py").exists()


def test_leftover_tmp_and_old_are_cleared(tmp_path):
    store = _store(tmp_path)
    root = tmp_path / "servers"
    root.mkdir(mode=0o700, parents=True)
    # A crashed prior write can leave `.tmp` and `.old` with stray files.
    for suffix in (".tmp", ".old"):
        stale = root / f"app{suffix}"
        stale.mkdir(mode=0o700)
        (stale / "stray.py").write_text("stale")
    store.write("app", {"main.py": "ok"})
    path = store.path_for("app")
    assert (path / "main.py").read_text() == "ok"
    assert not (path / "stray.py").exists()
    assert not (root / "app.tmp").exists()
    assert not (root / "app.old").exists()


def test_nested_intermediate_dirs_are_0700(tmp_path):
    # Every directory of a staged tree is 0700, not just the deepest one.
    store = _store(tmp_path)
    path = store.write("app", {"a/b/c.py": "x"})
    assert _mode(path / "a") == 0o700
    assert _mode(path / "a" / "b") == 0o700
    assert _mode(path / "a" / "b" / "c.py") == 0o600


def test_write_refuses_symlinked_root(tmp_path):
    # A child that replaces DATA_DIR/servers with a symlink must not make the
    # store write or delete through the link's target.
    store = _store(tmp_path)
    target = tmp_path / "outside"
    target.mkdir()
    os.symlink(target, tmp_path / "servers")
    with pytest.raises(ValueError, match="symlink"):
        store.write("app", {"main.py": "x"})
    with pytest.raises(ValueError, match="symlink"):
        store.remove("app")
    assert list(target.iterdir()) == []  # nothing written through the link


@pytest.mark.parametrize("namespace", ["../escape", "a/b", "Bad"])
def test_remove_rejects_bad_namespace(tmp_path, namespace):
    store = _store(tmp_path)
    with pytest.raises(ValueError):
        store.remove(namespace)


def test_write_refuses_symlink_final_target_untouched(tmp_path):
    store = _store(tmp_path)
    root = tmp_path / "servers"
    root.mkdir(mode=0o700, parents=True)
    target = tmp_path / "outside"
    target.mkdir()
    (target / "keep.py").write_text("keep")
    os.symlink(target, root / "app")
    with pytest.raises(ValueError, match="symlink"):
        store.write("app", {"main.py": "x"})
    # The link's target is untouched.
    assert (target / "keep.py").read_text() == "keep"


# --- Source file validation --------------------------------------------------


@pytest.mark.parametrize(
    "key",
    ["../x.py", "a//b.py", "/abs.py", "dir\\file.py", "nul\x00.py"],
)
def test_write_rejects_bad_key(tmp_path, key):
    store = _store(tmp_path)
    with pytest.raises(ValueError) as exc:
        store.write("app", {key: "x"})
    assert key in str(exc.value)


@pytest.mark.parametrize("namespace", ["mcpflow", "mcpflow_list"])
def test_write_rejects_reserved_namespace(tmp_path, namespace):
    # The store honors the same reserved rule as the registry, so it never
    # holds a tree that no child could ever register.
    store = _store(tmp_path)
    with pytest.raises(ValueError, match="reserved"):
        store.write(namespace, {"main.py": "x"})
    assert not store.path_for(namespace).exists()


def test_write_rejects_empty_map(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(ValueError, match="empty"):
        store.write("app", {})


def test_write_rejects_too_many_files(tmp_path):
    store = _store(tmp_path)
    files = {f"f{i}.py": "x" for i in range(MAX_FILES + 1)}
    with pytest.raises(ValueError, match=str(MAX_FILES)):
        store.write("app", files)


def test_write_rejects_oversize_file(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(ValueError) as exc:
        store.write("app", {"big.py": "a" * (MAX_FILE_BYTES + 1)})
    assert "big.py" in str(exc.value)


def test_write_rejects_oversize_total(tmp_path):
    store = _store(tmp_path)
    # Several files each under the per-file cap but over the total cap.
    chunk = "a" * (MAX_FILE_BYTES)
    files = {f"f{i}.py": chunk for i in range((MAX_TOTAL_BYTES // MAX_FILE_BYTES) + 1)}
    with pytest.raises(ValueError, match="total"):
        store.write("app", files)


def test_write_rejects_directory_prefix_conflict(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(ValueError) as exc:
        store.write("app", {"a": "1", "a/b": "2"})
    msg = str(exc.value)
    assert "a" in msg and "a/b" in msg


# --- Source ownership --------------------------------------------------------


def test_owns_resolves_dotdot_and_symlinked_parents(tmp_path):
    store = _store(tmp_path)
    store.write("app", {"main.py": "x"})
    direct = str(store.path_for("app"))
    dotted = str(store.path_for("app") / "pkg" / "..")  # resolves back to app
    assert store.owns(direct, "app") is True
    assert store.owns(dotted, "app") is True
    assert store.owns(direct, "other") is False


def test_owner_of(tmp_path):
    store = _store(tmp_path)
    assert store.owner_of(str(store.path_for("app"))) == "app"
    # The root itself owns no namespace.
    assert store.owner_of(str(store.root)) == ""
    # Non-local sources are not under the root.
    assert store.owner_of("github:o/r") is None
    assert store.owner_of("git+https://host/o/r") is None
    assert store.owner_of(None) is None
    # A path outside the root.
    assert store.owner_of(str(tmp_path / "elsewhere")) is None
