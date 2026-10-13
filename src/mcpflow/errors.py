"""The one mapping from an owner's refusal to an HTTP status.

`/api` and the dashboard both read it, so a refusal answers the same status on
both surfaces. Each adapter keeps only its body: JSON on `/api`, a bare text or
a re-rendered page on the dashboard.

A `PermissionError` is a refusal only without an `errno`: a disk `EACCES` is
also a `PermissionError` (an `OSError`), and it is an internal error, not a 403
with the operating system text. That one predicate is the whole fix.
"""

from __future__ import annotations

from .supervisor import RevisionConflict

# The refusals an owner raises. Order matters for `refusal`: `RegistryError`
# is a `ValueError`, and `PermissionError` is not one.
REFUSALS: tuple[type[Exception], ...] = (
    PermissionError,
    KeyError,
    RevisionConflict,
    ValueError,
)


def refusal(exc: Exception) -> tuple[int, str]:
    """The status and the text of one refusal: `PermissionError` 403,
    `KeyError` 404, `RevisionConflict` 409, `ValueError` 400.

    A `PermissionError` with an `errno` (a disk `EACCES`) is not a refusal:
    it raises `TypeError` like any other non-refusal, so the caller answers
    500."""
    if isinstance(exc, PermissionError) and exc.errno is None:
        return 403, str(exc)
    if isinstance(exc, KeyError):
        # `str(KeyError("x"))` is `"'x'"` with quotes, so read `args[0]`.
        return 404, f"{exc.args[0] if exc.args else 'resource'} not found"
    if isinstance(exc, RevisionConflict):
        return 409, "revision mismatch"
    if isinstance(exc, ValueError):
        return 400, str(exc)
    raise TypeError(f"not a refusal: {exc!r}") from exc
