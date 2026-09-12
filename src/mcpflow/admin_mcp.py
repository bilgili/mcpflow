"""The built-in admin MCP server and its scope filter.

`build_admin_server` builds one in-process `FastMCP` whose tools mirror the
REST API: each tool calls exactly one `Supervisor` method, then
serializes the result with `child_json` or `tools_json` from `api.py`. No tool
holds a rule. `build_app` mounts it under the namespace `mcpflow`, so the tools
publish as `mcpflow_<tool>`.

`ScopeFilter` is one `Transform` on the admin provider. It hides every
component of that provider from a session whose `AccessToken` does not carry
the `admin` scope, so an `mcp` session neither lists nor calls a `mcpflow_*` tool.
The filter fails closed: no token means not admin. `Supervisor.register_builtin`
installs it as the innermost transform of the chain.
"""

from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable, Sequence
from typing import TYPE_CHECKING, Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.transforms import (
    GetPromptNext,
    GetResourceNext,
    GetResourceTemplateNext,
    GetToolNext,
    Transform,
    VersionSpec,
)

from .api import child_json, tools_json
from .registry import spec_from_dict

if TYPE_CHECKING:
    from mcp.types import Prompt, Resource, ResourceTemplate, Tool

    from .supervisor import Supervisor


def _map_errors(
    fn: Callable[..., Awaitable[Any]],
) -> Callable[..., Awaitable[Any]]:
    """Map an owner error to a `ToolError`; leave everything else to the mask.

    One decorator, applied to every tool at registration and not admin-server
    middleware. Middleware runs outside `call_tool` and would only see an
    already-masked `ToolError`, so it could not read the `ValueError` message.
    A `ValueError` (which covers `RegistryError` and a spec validation error)
    becomes a `ToolError` with the error text; a `KeyError` for an unknown
    namespace becomes `ToolError("<ns> not found")`, the same wording as the
    REST `404`. Any other exception passes through and the admin server's own
    `mask_error_details=True` hides its text from the client.
    """

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return await fn(*args, **kwargs)
        except ValueError as exc:
            raise ToolError(str(exc)) from exc
        except KeyError as exc:
            raise ToolError(f"{exc.args[0]} not found") from exc

    return wrapper


class ScopeFilter(Transform):
    """Hide every component of the admin provider from a non-admin session.

    The predicate holds when the request carries an `AccessToken` with the
    filter's scope. `get_access_token()` returns `None` outside an HTTP request
    or when no bearer token authenticated the session, so a missing token is
    not admin and the filter fails closed.

    The filter is the innermost transform of the admin chain, and that position
    is load-bearing. This filter removes a component; a `Visibility` transform
    only marks one. The pin above it re-enables the pinned tools, so a pin over
    a removed component would publish a `mcpflow_*` tool to an `mcp` session.
    """

    def __init__(self, scope: str = "admin") -> None:
        self.scope = scope

    def _is_admin(self) -> bool:
        token = get_access_token()
        return token is not None and self.scope in token.scopes

    async def list_tools(self, tools: Sequence[Tool]) -> Sequence[Tool]:
        return tools if self._is_admin() else []

    async def get_tool(
        self, name: str, call_next: GetToolNext, *, version: VersionSpec | None = None
    ) -> Tool | None:
        if not self._is_admin():
            return None
        return await call_next(name, version=version)

    async def list_resources(
        self, resources: Sequence[Resource]
    ) -> Sequence[Resource]:
        return resources if self._is_admin() else []

    async def get_resource(
        self,
        uri: str,
        call_next: GetResourceNext,
        *,
        version: VersionSpec | None = None,
    ) -> Resource | None:
        if not self._is_admin():
            return None
        return await call_next(uri, version=version)

    async def list_resource_templates(
        self, templates: Sequence[ResourceTemplate]
    ) -> Sequence[ResourceTemplate]:
        return templates if self._is_admin() else []

    async def get_resource_template(
        self,
        uri: str,
        call_next: GetResourceTemplateNext,
        *,
        version: VersionSpec | None = None,
    ) -> ResourceTemplate | None:
        if not self._is_admin():
            return None
        return await call_next(uri, version=version)

    async def list_prompts(self, prompts: Sequence[Prompt]) -> Sequence[Prompt]:
        return prompts if self._is_admin() else []

    async def get_prompt(
        self,
        name: str,
        call_next: GetPromptNext,
        *,
        version: VersionSpec | None = None,
    ) -> Prompt | None:
        if not self._is_admin():
            return None
        return await call_next(name, version=version)


def build_admin_server(supervisor: Supervisor) -> FastMCP:
    """Build the `mcpflow-admin` server with the fourteen admin tools.

    `mask_error_details=True` because a mounted server masks its own errors;
    the gateway's mask does not reach it. No tool sets `meta.ui.visibility`:
    the hashed-name path `get_tool_by_hash` skips transforms, so a visibility
    key on an admin tool would let an `mcp` session resolve it. That rule now
    guards the tool visibility too: the same bypass would answer a call to a
    `mcpflow_*` tool that the admin muted.
    """
    admin = FastMCP("mcpflow-admin", mask_error_details=True)

    async def _tools_body() -> dict:
        views = await supervisor.tools()
        return tools_json(supervisor.root_muted(), supervisor.mcpflow_muted(), views)

    async def list_servers() -> list[dict]:
        """List every child server with its live status."""
        return [child_json(c) for c in supervisor.children()]

    async def get_server(namespace: str) -> dict:
        """Get one child server by namespace."""
        return child_json(supervisor.get(namespace))

    async def add_server(spec: dict) -> dict:
        """Add a child server from a spec and start it."""
        child = await supervisor.add(spec_from_dict(spec))
        return child_json(child)

    async def update_server(namespace: str, spec: dict) -> dict:
        """Replace a child server's spec. The namespace argument names the
        resource and wins over any `namespace` in the body."""
        spec = {**spec, "namespace": namespace}
        child = await supervisor.update(spec_from_dict(spec))
        return child_json(child)

    async def remove_server(namespace: str) -> None:
        """Remove a child server and stop it."""
        await supervisor.remove(namespace)

    async def enable_server(namespace: str) -> dict:
        """Enable a child server."""
        await supervisor.enable(namespace)
        return child_json(supervisor.get(namespace))

    async def disable_server(namespace: str) -> dict:
        """Disable a child server."""
        await supervisor.disable(namespace)
        return child_json(supervisor.get(namespace))

    async def restart_server(namespace: str) -> dict:
        """Restart a child server."""
        await supervisor.restart(namespace)
        return child_json(supervisor.get(namespace))

    async def server_log(namespace: str, lines: int = 100) -> str:
        """Read the tail of a child server's log, capped at 1000 lines."""
        return supervisor.log_tail(namespace, min(lines, 1000))

    async def list_tools() -> dict:
        """List every child tool with its visibility, the dashboard view."""
        return await _tools_body()

    async def set_root_muted(muted: bool) -> dict:
        """Mute or unmute the root. A muted root hides every child tool."""
        supervisor.set_root_muted(muted)
        return await _tools_body()

    async def set_namespace_muted(namespace: str, muted: bool) -> dict:
        """Mute or unmute every tool of one child."""
        supervisor.set_namespace_muted(namespace, muted)
        return await _tools_body()

    async def set_tool_muted(namespace: str, tool: str, muted: bool) -> dict:
        """Mute or unmute one child tool. `tool` is the bare child tool name."""
        supervisor.set_tool_muted(namespace, tool, muted)
        return await _tools_body()

    async def write_source(namespace: str, files: dict[str, str]) -> dict:
        """Write inline source files for a child, then register it.

        Three-step agent flow: (1) call this to write the files under
        `DATA_DIR/servers/<namespace>`; (2) call `mcpflow_add_server` with kind
        `python` or `npm`, a `package`, and `source` set to the returned
        `path`; (3) the child's tools appear on `/mcp`. Limits: at most 200
        files, 512 KiB per file, 1 MiB total; keys are relative POSIX paths
        with no `.`/`..` segment. `restarted` is true when an existing running
        or failed child was bounced onto the new files. If this call fails at
        the restart step, the files are already written; call
        `mcpflow_restart_server`.
        """
        result = await supervisor.write_source(namespace, files)
        return {
            "namespace": result.namespace,
            "path": str(result.path),
            "files": result.files,
            "bytes": result.bytes,
            "restarted": result.restarted,
        }

    for fn in (
        list_servers,
        get_server,
        add_server,
        update_server,
        remove_server,
        enable_server,
        disable_server,
        restart_server,
        server_log,
        list_tools,
        set_root_muted,
        set_namespace_muted,
        set_tool_muted,
        write_source,
    ):
        admin.tool(_map_errors(fn))

    return admin
