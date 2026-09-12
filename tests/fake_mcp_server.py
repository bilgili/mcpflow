"""A fake child MCP server for the verifier suite.

The supervisor spawns this over stdio as a `custom` child:
`<python> fake_mcp_server.py <mode> [arg]`.

Modes:
- `good`   : serve one tool `get_current_time(timezone: string)`.
- `two`    : serve `get_current_time` and `convert_time`, so a test can mute
             one tool and assert the sibling survives.
- `slow`   : like `two`, but wait for the file named by `MCPFLOW_RELEASE`
             before serving, so a test can act while the child status is
             still `starting` without racing a fixed sleep.
- `fail`   : write an error to stderr and exit non-zero (probe failure).
- `hang`   : sleep without speaking MCP (probe timeout).

`MCPFLOW_CALL_LOG` names a file the child appends one line to per tool call.
A test reads it to prove a refused call never reached the child.
"""

import os
import sys
import time

_MODE = sys.argv[1] if len(sys.argv) > 1 else "good"
_ARG = sys.argv[2] if len(sys.argv) > 2 else None
_CALL_LOG = os.environ.get("MCPFLOW_CALL_LOG")


def _record(name: str) -> None:
    if not _CALL_LOG:
        return
    with open(_CALL_LOG, "a") as f:
        f.write(name + "\n")


def _main() -> None:
    if _MODE == "fail":
        sys.stderr.write("child boom: could not start the server\n")
        sys.stderr.flush()
        sys.exit(1)
    if _MODE == "hang":
        time.sleep(300)
        return
    if _MODE == "slow":
        # Block until the test releases us. A fixed sleep would race a slow
        # CI box or a slow login hash.
        release = os.environ.get("MCPFLOW_RELEASE")
        deadline = time.time() + 60
        while release and not os.path.exists(release) and time.time() < deadline:
            time.sleep(0.05)

    from fastmcp import FastMCP

    mcp = FastMCP("fake")

    @mcp.tool
    def get_current_time(timezone: str = "UTC") -> str:
        "Return the current time in a timezone."
        _record("get_current_time")
        return "2026-01-01T00:00:00Z"

    if _MODE in ("two", "slow"):

        @mcp.tool
        def convert_time(timezone: str = "UTC") -> str:
            "Convert a time to a timezone."
            _record("convert_time")
            return "2026-01-01T12:00:00Z"

    mcp.run()


if __name__ == "__main__":
    _main()
