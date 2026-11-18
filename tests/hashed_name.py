"""One owner of the hashed app-tool name format (fastmcp 4.2.0: `__<digest>_<local>`).

The prefix comes from fastmcp, so a format change shows up here, not in each test.
Import as `from hashed_name import hashed_name`; `fake_*` child scripts run from
`tests/`, so the same import works there.
"""

from fastmcp.server.providers.addressing import hash_tool, hashed_backend_name

_PREFIX = hashed_backend_name("a", "b").removesuffix(f"{hash_tool('a', 'b')}_b")
# A layout that no longer ends in `<digest>_<local>` leaves the whole sample
# name here; fail at import with a clear message instead of in every test.
assert len(_PREFIX) < len(hashed_backend_name("a", "b")), "fastmcp hashed name layout changed"


def hashed_name(digest: str, local: str) -> str:
    """The name a client sends for `local` under `digest`; the digest may be bad."""
    return f"{_PREFIX}{digest}_{local}"
