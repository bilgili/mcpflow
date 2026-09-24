"""The gateway's aggregated `instructions`.

`Supervisor.instructions_blocks` reads the raw text of each child. This module
owns what the gateway does with it: the header, the join, the per-child cap,
and the two middleware hooks that put the result on `initialize` and
`server/discover`.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from fastmcp.server.middleware import Middleware
from mcp import types as mt

if TYPE_CHECKING:
    from .supervisor import Supervisor

logger = logging.getLogger(__name__)

INSTRUCTIONS_BLOCK_CAP: int = 16 * 1024  # bytes of UTF-8, per child
# The marker embeds the default cap. A future setting changes both together.
TRUNCATION_MARKER: str = "[mcpflow: instructions truncated at 16384 bytes]"


def render_instructions(
    own: str | None, blocks: list[tuple[str, str]]
) -> str | None:
    """Join the gateway's own instructions and one block per child.

    Block format: `## {namespace}\\n{text.rstrip()}`. Blocks join with one
    blank line. `own`, when non-empty, comes first with one blank line.
    Returns None when `own` is empty and `blocks` is empty.
    """
    parts: list[str] = [own] if own else []
    for namespace, text in blocks:
        raw = text.encode()
        if len(raw) > INSTRUCTIONS_BLOCK_CAP:
            # errors="ignore" drops a character the cut split in two, so the
            # prefix ends on a character boundary.
            text = (
                raw[:INSTRUCTIONS_BLOCK_CAP].decode(errors="ignore").rstrip()
                + "\n"
                + TRUNCATION_MARKER
            )
            logger.warning(
                "instructions block for %s truncated at %d bytes",
                namespace,
                INSTRUCTIONS_BLOCK_CAP,
            )
        parts.append(f"## {namespace}\n{text.rstrip()}")
    return "\n\n".join(parts) if parts else None


class ChildInstructionsMiddleware(Middleware):
    """Put the children's instructions on every new gateway session.

    The read runs after `call_next`, so a failed gateway `initialize` reads no
    child. `instructions_blocks` never raises, so a child read never fails the
    request.
    """

    def __init__(self, supervisor: Supervisor) -> None:
        self.supervisor = supervisor

    async def _instructions(self, own: str | None) -> str | None:
        return render_instructions(own, await self.supervisor.instructions_blocks())

    async def on_initialize(
        self, context, call_next
    ) -> mt.InitializeResult | None:
        result = await call_next(context)
        if result is None:
            return None
        text = await self._instructions(result.instructions)
        return result.model_copy(update={"instructions": text})

    async def on_discover(
        self, context, call_next
    ) -> mt.DiscoverResult | dict[str, Any]:
        result = await call_next(context)
        if not isinstance(result, mt.DiscoverResult):
            return result
        text = await self._instructions(result.instructions)
        return result.model_copy(update={"instructions": text})
