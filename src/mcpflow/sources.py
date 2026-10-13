"""The inline source store under `DATA_DIR/servers/`.

`SourceStore` is the one writer and the one deleter under its root. A write
stages every file into a fresh `<ref>.tmp` directory and then swaps it in, so
a reader (a `uvx --from` or `npx --package=` spawn) sees either the old tree or
the new tree, never a mix. The store never follows or creates a symlink, and it
never awaits, so two concurrent tool calls for one reference serialise on the
event loop.

Every method takes the server reference: `<namespace>` for an admin-owned
child, `<namespace>@<owner>` for a user-owned one. An operation on one
reference touches only `<ref>`, `<ref>.tmp`, and `<ref>.old`, so the removal of
`github@alice` never touches admin-owned `github`.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from .registry import RESERVED_NAMESPACE, ServerKey

MAX_FILES = 200
MAX_TOTAL_BYTES = 1024 * 1024  # 1 MiB
MAX_FILE_BYTES = 512 * 1024  # 512 KiB

# The store validates the reference itself, so it is safe when called alone.
# `ServerKey.parse` owns the shape, which is exactly this pattern: no dot, no
# slash, no second `@`, so the reference is one safe path segment, `<ref>.tmp`
# / `<ref>.old` never collide with a reference, and no reference names a path
# outside the root or the directory of another reference. The reserved rule
# for `mcpflow`/`mcpflow_*` applies to the namespace part, so the store never
# holds a tree no child could ever register.
REF_PATTERN = r"^[a-z][a-z0-9_]{0,31}(@[a-z0-9][a-z0-9_-]{0,63})?$"


def _check_ref(ref: str) -> None:
    """Raise `ValueError` for a bad reference. No filesystem access."""
    try:
        key = ServerKey.parse(ref)
    except ValueError:
        raise ValueError(f"reference {ref!r} must match {REF_PATTERN}") from None
    if key.namespace == RESERVED_NAMESPACE or key.namespace.startswith(
        RESERVED_NAMESPACE + "_"
    ):
        raise ValueError(
            f"namespace {key.namespace} is reserved: mcpflow and mcpflow_* are reserved"
        )


def total_bytes(files: dict[str, str]) -> int:
    """Sum of the UTF-8 byte length of every value."""
    return sum(len(v.encode("utf-8")) for v in files.values())


def _mkdirs_0700(base: Path, rel_dir: Path) -> None:
    """Create every level of `base / rel_dir` at mode 0700.

    `Path.mkdir(parents=True, mode=...)` sets the mode on the leaf only and
    leaves intermediate parents at `0o777 & ~umask`. Create each segment
    explicitly so every directory of a staged tree is 0700, not just the
    deepest one.
    """
    cur = base
    for part in rel_dir.parts:
        cur = cur / part
        if not cur.exists():
            os.mkdir(cur, 0o700)


def _unlink_or_rmtree(path: Path) -> None:
    """Remove `path` whether it is a symlink, a directory, or a file.

    A symlink is unlinked, never followed: `shutil.rmtree` on a symlink raises,
    and following one would let a confused-deputy write escape the root.
    No-op when the path is absent.
    """
    if path.is_symlink():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def _validate(ref: str, files: dict[str, str]) -> None:
    """Raise `ValueError` on the first fault. The message names the fault."""
    _check_ref(ref)
    if not files:
        raise ValueError("files is empty")
    if len(files) > MAX_FILES:
        raise ValueError(f"too many files: {len(files)} exceeds {MAX_FILES}")
    for key, value in files.items():
        if key.startswith("/"):
            raise ValueError(f"key {key} must be a relative path, not start with /")
        if "\\" in key:
            raise ValueError(f"key {key} must not contain a backslash")
        if "\x00" in key:
            raise ValueError(f"key {key} must not contain a NUL")
        segments = key.split("/")
        if any(seg in ("", ".", "..") for seg in segments):
            raise ValueError(f"key {key} has an empty, '.', or '..' segment")
        if len(value.encode("utf-8")) > MAX_FILE_BYTES:
            raise ValueError(f"key {key} exceeds {MAX_FILE_BYTES} bytes")
    # No key may be a directory prefix of another: `a` cannot be a file when
    # `a/b` needs `a` as a directory.
    seg_lists = {key: key.split("/") for key in files}
    for a, a_seg in seg_lists.items():
        for b, b_seg in seg_lists.items():
            if a is not b and len(a_seg) < len(b_seg) and b_seg[: len(a_seg)] == a_seg:
                raise ValueError(f"key {a} is a directory prefix of key {b}")
    total = total_bytes(files)
    if total > MAX_TOTAL_BYTES:
        raise ValueError(f"total {total} bytes exceeds {MAX_TOTAL_BYTES}")


class SourceStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def path_for(self, ref: str) -> Path:
        """`root / ref`. Validates `ref` first; no filesystem access."""
        _check_ref(ref)
        return self.root / ref

    def write(self, ref: str, files: dict[str, str]) -> Path:
        _validate(ref, files)
        final = self.path_for(ref)
        tmp = self.root / f"{ref}.tmp"
        old = self.root / f"{ref}.old"

        if final.is_symlink():
            # A rename would move the link, not its target, but refuse rather
            # than build a tree beside a link the admin did not expect.
            raise ValueError(f"{final} is a symlink")
        if self.root.is_symlink():
            # A symlinked root would make every rename and rmtree act through
            # the link's target, outside the store. The store never follows a
            # symlink, so refuse rather than build or delete beyond the root.
            raise ValueError(f"{self.root} is a symlink")

        # The root owns its tree; create it on the first write.
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)

        # Clear any leftover of a crashed prior write before staging.
        _unlink_or_rmtree(tmp)
        _unlink_or_rmtree(old)

        os.mkdir(tmp, 0o700)
        for key, value in files.items():
            dest = tmp / key
            _mkdirs_0700(tmp, Path(key).parent)
            fd = os.open(
                dest,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(value)

        # Swap: the final path is absent only for the instant between the two
        # renames. A crash there leaves `.old` and `.tmp`; the next write's
        # leftover clearing repairs it.
        if final.exists() or final.is_symlink():
            os.rename(final, old)
        os.rename(tmp, final)
        _unlink_or_rmtree(old)
        return final

    def remove(self, ref: str) -> None:
        """Delete `<ref>`, `<ref>.tmp`, and `<ref>.old`. No-op when all absent.

        The reference is validated before any filesystem access, so a crafted
        `github@../x` raises and deletes nothing, and no reference names the
        directory of another reference.
        """
        final = self.path_for(ref)
        if self.root.is_symlink():
            raise ValueError(f"{self.root} is a symlink")
        _unlink_or_rmtree(final)
        _unlink_or_rmtree(self.root / f"{ref}.tmp")
        _unlink_or_rmtree(self.root / f"{ref}.old")

    def owns(self, source: str | None, ref: str) -> bool:
        """True when `source` is a local path that resolves to this ref's dir.

        Symlinks and `..` in `source` resolve first. The own directory is
        the resolved root joined with `ref`, NOT resolved itself, so a symlink
        planted at `servers/<ref>` that points at another reference's tree
        never makes that tree count as this reference's.
        """
        own = self.path_for(ref)
        if not isinstance(source, str) or not source.startswith("/"):
            return False
        return Path(source).resolve() == self.root.resolve() / own.name

    def owner_of(self, source: str | None) -> str | None:
        """The reference whose directory holds `source`, after resolution.

        Symlinks and `..` resolve first, so `servers/tool@alice/../github`
        names `github`. The result is the first path segment under the root.
        `owner_of(str(root))` returns `""` (the root itself owns no reference),
        so the ownership rule rejects a source of `DATA_DIR/servers`. A source
        outside the root, or not a local path, returns `None`. `a.tmp` and
        `a.old` come back as-is and match no reference.
        """
        if not isinstance(source, str) or not source.startswith("/"):
            return None
        resolved = Path(source).resolve()
        root = self.root.resolve()
        if resolved == root:
            return ""
        try:
            rel = resolved.relative_to(root)
        except ValueError:
            return None
        return rel.parts[0]
