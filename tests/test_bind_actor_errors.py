"""`errors.refusal` and the disk permission error (bind-actor-to-server-writes, T3, unit part).

Requirement "A file-system permission error is an internal error" of
`specs/admin-api/spec.md`: a `PermissionError` is a refusal only when its
`errno` is `None`. The HTTP side is in `tests/test_bind_actor_eacces.py`.
"""

from __future__ import annotations

import errno

import pytest

from mcpflow.errors import REFUSALS, refusal
from mcpflow.supervisor import RevisionConflict


def test_a_refusal_without_errno_is_403():
    assert refusal(PermissionError("x")) == (403, "x")
    assert refusal(PermissionError("the admin role is required")) == (
        403, "the admin role is required")


def test_a_permission_error_with_errno_is_not_a_refusal():
    original = PermissionError(13, "Permission denied", "/data/servers.json")
    with pytest.raises(TypeError) as exc:
        refusal(original)
    assert exc.value.__cause__ is original


@pytest.mark.parametrize("code", [errno.EACCES, errno.EPERM])
def test_any_errno_makes_it_an_internal_error(code):
    with pytest.raises(TypeError):
        refusal(PermissionError(code, "denied"))


def test_a_permission_error_built_from_text_only_has_no_errno():
    """The shape that policy code raises: one message, `errno` None."""
    exc = PermissionError("the acting user is unknown")
    assert exc.errno is None
    assert refusal(exc)[0] == 403


def test_the_other_refusals_are_unchanged():
    assert refusal(KeyError("github@carol")) == (404, "github@carol not found")
    assert refusal(KeyError()) == (404, "resource not found")
    assert refusal(RevisionConflict("github@bob", "abc"))[0] == 409
    assert refusal(ValueError("bad field")) == (400, "bad field")


def test_a_non_refusal_still_raises_type_error():
    with pytest.raises(TypeError):
        refusal(RuntimeError("boom"))


def test_refusals_is_the_same_tuple():
    assert REFUSALS == (PermissionError, KeyError, RevisionConflict, ValueError)
