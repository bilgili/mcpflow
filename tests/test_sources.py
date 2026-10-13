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
    # `path_for` validates too, so look the path up under the root directly.
    assert not (store.root / namespace).exists()


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


# --- 10E (10.20): the source store under a server reference -----------------
#
# Guarded invariant: OpTouchesOnlyOwnPaths
# (specs/tla/multi_user_access_lifecycle.tla, negative config
# multi_user_access_lifecycle_nskeyed.cfg).

from keyed_stores import BAD_REFS, tree

REF = "demo@alice"


def test_directory_and_file_modes_under_a_user_reference(tmp_path):
    """Directory and file modes, for reference `demo@alice`."""
    store = _store(tmp_path)
    path = store.write(REF, {"pkg/__init__.py": "", "pkg/server.py": "..."})
    assert path == tmp_path / "servers" / REF
    assert _mode(path) == 0o700 and _mode(path / "pkg") == 0o700
    assert _mode(path / "pkg" / "__init__.py") == 0o600
    assert _mode(path / "pkg" / "server.py") == 0o600


def test_a_symlink_at_the_final_path_is_refused_under_a_user_reference(tmp_path):
    """A symlink at the final path is refused: the link target is unchanged
    and no `.tmp` directory remains."""
    store = _store(tmp_path)
    root = tmp_path / "servers"
    root.mkdir(mode=0o700)
    target = tmp_path / "outside"
    target.mkdir()
    (target / "keep.py").write_text("keep")
    os.symlink(target, root / REF)
    before = tree(target)
    with pytest.raises(ValueError):
        store.write(REF, {"main.py": "x"})
    assert tree(target) == before
    assert not (root / f"{REF}.tmp").exists()


def test_remove_of_an_absent_directory_under_a_user_reference(tmp_path):
    """Remove of an absent directory returns without error."""
    _store(tmp_path).remove(REF)


def test_leftover_staging_directory_is_replaced_under_a_user_reference(tmp_path):
    """Leftover staging directory is replaced: the final directory holds
    exactly the new files."""
    store = _store(tmp_path)
    stale = tmp_path / "servers" / f"{REF}.tmp"
    stale.mkdir(parents=True)
    (stale / "stray.py").write_text("stale")
    path = store.write(REF, {"main.py": "ok"})
    assert sorted(p.name for p in path.iterdir()) == ["main.py"]


def test_second_write_replaces_the_tree_under_a_user_reference(tmp_path):
    """Second write replaces the tree: `b.py` is gone."""
    store = _store(tmp_path)
    store.write(REF, {"a.py": "1", "b.py": "2"})
    path = store.write(REF, {"a.py": "3"})
    assert sorted(p.name for p in path.iterdir()) == ["a.py"]


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory modes")
def test_failed_staging_leaves_the_old_tree_under_a_user_reference(tmp_path):
    """Failed staging leaves the old tree: a filesystem error during staging
    (the store root is read-only) keeps `servers/demo@alice` unchanged."""
    store = _store(tmp_path)
    store.write(REF, {"a.py": "1", "b.py": "2"})
    root = tmp_path / "servers"
    before = tree(root / REF)
    os.chmod(root, 0o500)
    try:
        with pytest.raises(OSError):
            store.write(REF, {"c.py": "3"})
    finally:
        os.chmod(root, 0o700)
    assert tree(root / REF) == before


def test_remove_of_a_user_server_keeps_the_admin_tree(tmp_path):
    """Remove of a user server keeps the admin tree (F2): `github`,
    `github.tmp`, and `github.old` do not change.
    Invariant: OpTouchesOnlyOwnPaths."""
    store = _store(tmp_path)
    store.write("github", {"main.py": "admin"})
    store.write("github@alice", {"main.py": "alice"})
    root = tmp_path / "servers"
    for suffix in (".tmp", ".old"):
        (root / f"github{suffix}").mkdir(mode=0o700)
        (root / f"github{suffix}" / "f.py").write_text(suffix)
    admin = {n: tree(root / n) for n in ("github", "github.tmp", "github.old")}
    store.remove("github@alice")
    assert not (root / "github@alice").exists()
    assert {n: tree(root / n) for n in admin} == admin


def test_a_user_reference_is_accepted(tmp_path):
    """A user reference is accepted: its path is `servers/github@alice`."""
    store = _store(tmp_path)
    assert store.path_for("github@alice") == tmp_path / "servers" / "github@alice"


@pytest.mark.parametrize("ref", BAD_REFS)
def test_path_traversal_in_the_owner_id_is_refused(tmp_path, ref):
    """Path traversal in the owner id is refused: `remove`, `write`, and
    `path_for` raise `ValueError`, and no path under or above `servers/`
    changes. Invariant: OpTouchesOnlyOwnPaths."""
    store = _store(tmp_path)
    store.write("github", {"main.py": "admin"})
    for rel in ("servers/x/f.py", "servers/github@alice/x/f.py",
                "servers/%2f/f.py", "tokens/keep.json", "x/f.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(rel)
    before = tree(tmp_path)
    for call in (lambda: store.remove(ref),
                 lambda: store.write(ref, {"main.py": "x"}),
                 lambda: store.path_for(ref)):
        with pytest.raises(ValueError):
            call()
    assert tree(tmp_path) == before


def test_a_symlinked_user_directory_is_not_owned_by_the_user(tmp_path):
    """A symlink at `servers/x@alice` that points at `servers/github` is not
    the directory of `x@alice`: `owns` resolves it and refuses."""
    store = _store(tmp_path)
    store.write("github", {"main.py": "admin"})
    link = tmp_path / "servers" / "x@alice"
    os.symlink(tmp_path / "servers" / "github", link)
    assert store.owns(str(link), "x@alice") is False
    assert store.owner_of(str(link)) == "github"
