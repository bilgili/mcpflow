"""A fake child for the verifier's `instructions://self` failure shapes.

`<python> fake_instructions_child.py <mode>`. Every mode serves one tool
`echo`, so the child reaches `running`. Modes:

- `raise`    : the read raises; the message echoes env `API_TOKEN`.
- `blob`     : the read returns binary contents only.
- `blank`    : the read returns whitespace only.
- `delayed`  : the read sleeps 1 s, then returns env `BODY`.
- `body`     : the read returns env `BODY` (any text, e.g. multibyte).
"""

import asyncio
import os
import sys

from fastmcp import FastMCP
from fastmcp.exceptions import ResourceError

MODE = sys.argv[1]
mcp = FastMCP("fake-instructions")


@mcp.tool
def echo(text: str = "x") -> str:
    "Echo the text."
    return text


if MODE == "raise":

    @mcp.resource("instructions://self")
    def raising() -> str:
        raise ResourceError(f"backend refused token {os.environ['API_TOKEN']}")

elif MODE == "blob":

    @mcp.resource("instructions://self", mime_type="application/octet-stream")
    def blob() -> bytes:
        return b"\x00\x01binary"

elif MODE == "blank":

    @mcp.resource("instructions://self", mime_type="text/plain")
    def blank() -> str:
        return "  \n\t\n"

elif MODE == "delayed":

    @mcp.resource("instructions://self", mime_type="text/plain")
    async def delayed() -> str:
        await asyncio.sleep(1.0)
        return os.environ["BODY"]

elif MODE == "body":

    @mcp.resource("instructions://self", mime_type="text/plain")
    def body() -> str:
        return os.environ["BODY"]

mcp.run()
