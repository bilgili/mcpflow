"""A configurable fake child for the 10D router tests.

`<python> fake_router_child.py <app> <tool,tool,...> [--id <id>] [--http <port>]`

- Each tool `<t>` returns `"<CHILD_ID>:<t>"`, so a test sees which server a
  call reached. Each tool carries `meta.fastmcp.tool_hash = hash_tool(app, t)`,
  `meta.fastmcp.app = app`, and `meta.ui.visibility = ["model", "app"]`, so
  the FastMCP hashed path and app path can resolve it. No tool carries the
  `mcpflow.action` tag: the child is plain, not action-capable.
- One resource `res://<app>/info`, one resource template
  `tpl://<app>/{name}`, and one prompt `<app>_prompt`.
- A second template `tpl_alt` at `tpl://<app>/{other}`, which matches the same
  URIs as `tpl` and returns `"alt:" + other`. Muting the template `tpl` shows
  the per-server fallback to `tpl_alt`.
- For each tool `<t>`, also a prompt named `<t>`. Its body logs `prompt:<t>`
  and returns `"<CHILD_ID>:<t>"`, so a test sees which server rendered it and
  whether a refused prompt reached the child. The log line is not `call:`, so
  `Live.calls` ignores it.
- One resource `urn:<app>:shared`. It has no `://`, so the namespace transform
  leaves it unrewritten and no get can reach it.
- `INSTRUCTIONS` (env): when set, a resource `instructions://self` with it.
- `MCPFLOW_CALL_LOG` (env): one line per tool call (`call:<t>`) and per
  `tools/list` (`list`). A test reads it to prove a refused request never
  reached the child.
- `--hash-as <name>`: every tool carries `hash_tool(app, <name>)`, the one
  identity an app mounted twice gives its two copies.
- `--http <port>`: serve Streamable HTTP at `/mcp` on 127.0.0.1, so a
  user-owned `remote` server (no host code, D7b) can point at this child.
"""

import os
import sys

from fastmcp import FastMCP
from fastmcp.server.middleware import Middleware
from fastmcp.server.providers.addressing import hash_tool

APP = sys.argv[1]
TOOLS = [t for t in sys.argv[2].split(",") if t]
# `--id` names the server in each answer; the app name when absent.
CHILD_ID = sys.argv[sys.argv.index("--id") + 1] if "--id" in sys.argv else APP
LOG = os.environ.get("MCPFLOW_CALL_LOG")
HASH_AS = sys.argv[sys.argv.index("--hash-as") + 1] if "--hash-as" in sys.argv else None


def _record(line: str) -> None:
    if LOG:
        with open(LOG, "a") as f:
            f.write(line + "\n")


class _Count(Middleware):
    async def on_list_tools(self, context, call_next):
        _record("list")
        return await call_next(context)


mcp = FastMCP("fake-" + APP)
mcp.add_middleware(_Count())


def _make(name: str):
    def tool(timezone: str = "UTC") -> str:
        _record("call:" + name)
        return f"{CHILD_ID}:{name}"

    tool.__name__ = name
    tool.__doc__ = f"Fake tool {name}."
    return tool


for _t in TOOLS:
    mcp.tool(
        _make(_t),
        name=_t,
        meta={
            "fastmcp": {"tool_hash": hash_tool(APP, HASH_AS or _t), "app": APP},
            "ui": {"visibility": ["model", "app"]},
        },
    )


def _make_prompt(name: str):
    def prompt_of_tool() -> str:
        _record("prompt:" + name)
        return f"{CHILD_ID}:{name}"

    return prompt_of_tool


for _t in TOOLS:
    mcp.prompt(_make_prompt(_t), name=_t, description=f"Fake prompt {_t}.")


@mcp.resource(f"urn:{APP}:shared")
def shared() -> str:
    return "shared of " + CHILD_ID


@mcp.resource(f"res://{APP}/info")
def info() -> str:
    return "info of " + CHILD_ID


@mcp.resource(f"tpl://{APP}/{{name}}")
def tpl(name: str) -> str:
    return name


@mcp.resource(f"tpl://{APP}/{{other}}", name="tpl_alt")
def tpl_alt(other: str) -> str:
    return "alt:" + other


@mcp.prompt(name=f"{APP}_prompt")
def prompt() -> str:
    "A fake prompt."
    return "prompt of " + CHILD_ID


if os.environ.get("INSTRUCTIONS"):

    @mcp.resource("instructions://self", mime_type="text/markdown")
    def instructions() -> str:
        return os.environ["INSTRUCTIONS"]


if __name__ == "__main__":
    if "--http" in sys.argv:
        port = int(sys.argv[sys.argv.index("--http") + 1])
        mcp.run(transport="http", host="127.0.0.1", port=port, show_banner=False)
    else:
        mcp.run(show_banner=False)
