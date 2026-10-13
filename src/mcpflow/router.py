"""The caller router: the one owner of the per-caller view on `/mcp` (D5).

`build_app` registers one `CallerRouter` on the gateway in place of
`supervisor.table`. Each provider operation reads the user and its `Reach`
once, in local variables, and asks only the providers that
`Supervisor.routed(reach)` returns, so a server outside the `Reach` is never
asked. The router holds no decision of its own: the keys and the grant
decision come from the `Reach`, the mute comes from the child chain. Nothing
survives the operation, so a rule, group, role, or token change applies to
the next request (D9).

TLA+ map (`specs/tla/multi_user_access.tla`): `_passes` is `Base` (the chain
mute is `MuteOK`, `Reach.allows_tool` is `Decision`), `_named` refuses
`Collides`, and every MCP path (list, call, hash, app) ends in `_passes` and
the collision check, so `Reach` agrees across the paths. The served kinds
(prompt, resource, template) follow the same shape: `_served` is the server
decision, `_servable` adds the mute (`MuteOK`) and `_owns` (`Owns`), and
`_unique` / `_single` refuse a shared identity (`PCollides` and `PReach` for
prompts, `RCollides` and `RReach` for resources). The list and the get filter
alike, so `PromptGetAgreesWithList` and `ResourceGetAgreesWithList` hold.

A provider failure only refuses: `_ask` returns the failed keys beside the
hits, and `_unique` / `_single` also refuse a name that a failed key may own
(`FailedBlocks`, so the name paths compute `TReachF` and `PReachF`). The hash
and app paths run through `_identity_call`, which refuses on a failed key in
any of its asks (`HashReachF`, `AppServed`).
"""

from __future__ import annotations

import logging
import re
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, Literal

from fastmcp.exceptions import NotFoundError, ToolError
from fastmcp.server.providers import Provider
from fastmcp.server.transforms import VersionSpec
from fastmcp.server.transforms.visibility import is_enabled
from fastmcp.utilities.async_utils import gather
from fastmcp.utilities.versions import version_sort_key

if TYPE_CHECKING:
    from fastmcp.tools.base import Tool

    from .policy import AccessPolicy, Reach
    from .registry import ServerKey
    from .supervisor import Supervisor

logger = logging.getLogger(__name__)

Routed = list[tuple["ServerKey", Provider]]
Kind = Literal["tool", "prompt", "resource", "template"]


def _with_identity(tools: Sequence[Tool], tool_hash: str) -> list[Tool]:
    """The tools that `ProxyProvider.get_tool_by_hash` matches: identity
    `tool_hash` (FastMCP's own reader) and app-visible. One per name, as the
    proxy counts distinct names, so two versions are not an ambiguity."""
    # Public since FastMCP 4.0.11. Import it here, not at module level: a rename
    # in an upgrade then fails only this rare path (closed, and
    # tests/test_router_hash_duplicate.py catches it), instead of stopping the
    # whole gateway at import time.
    from fastmcp.server.providers.addressing import is_app_tool_with_identity

    found: dict[str, Tool] = {}
    for tool in tools:
        if is_app_tool_with_identity(tool, tool_hash):
            found.setdefault(tool.name, tool)
    return list(found.values())


class CallerRouter(Provider):
    """Serve the child components of the caller's `Reach`, and nothing else."""

    def __init__(self, supervisor: Supervisor, policy: AccessPolicy) -> None:
        super().__init__()
        self._supervisor = supervisor
        self._policy = policy

    def __repr__(self) -> str:
        return "CallerRouter()"

    # --- one Reach per operation -------------------------------------------

    def _route(self) -> tuple[Reach | None, Routed]:
        """The `Reach` of the current user and its routed providers. No user
        (no token, or a token without a subject) routes nothing: default deny."""
        user = self._policy.current_user()
        if user is None:
            return None, []
        reach = self._policy.keys_for(user, "mcp")
        return reach, self._supervisor.routed(reach)

    @staticmethod
    async def _ask(
        routed: Routed,
        call: Callable[[Provider], Awaitable[Any]],
    ) -> tuple[list[tuple[ServerKey, Any]], list[ServerKey]]:
        """`AggregateProvider` gather semantics with the key kept beside each
        result: the hits, and the failed keys (D1). Any error but `NotFoundError`
        is a failure, `ToolError` and `CancelledError` included, and is logged."""
        results = await gather((call(p) for _, p in routed), return_exceptions=True)
        hits: list[tuple[ServerKey, Any]] = []
        failed: list[ServerKey] = []
        for (key, _), result in zip(routed, results, strict=True):
            if isinstance(result, BaseException):
                if not isinstance(result, NotFoundError):
                    logger.warning("provider of %s failed: %s", key.ref, result)
                    failed.append(key)
                continue
            hits.append((key, result))
        return hits, failed

    @staticmethod
    def _owns(key: ServerKey, kind: Kind, ident: str) -> bool:
        """TLA+ `Owns`: the namespace of `key` could have published `ident`.
        The `Namespace` transform publishes `<namespace>_<name>` for a tool or a
        prompt, and `proto://<namespace>/path` for a resource or a template. A
        URI without `://` passes it unchanged, so no get could read it back."""
        if kind in ("tool", "prompt"):
            return ident.startswith(f"{key.namespace}_")
        # The protocol part of `Namespace._URI_PATTERN` (`^([^:]+://)`).
        return re.match(rf"[^:]+://{key.namespace}/", ident) is not None

    @classmethod
    def _passes(cls, reach: Reach, key: ServerKey, tool: Tool) -> bool:
        """TLA+ `Base`: the child chain does not mute the tool, and the `Reach`
        allows it. The chain publishes `<namespace>_<tool>`; a name without
        that prefix fails closed."""
        return (
            is_enabled(tool)
            and cls._owns(key, "tool", tool.name)
            and reach.allows_tool(key, tool.name[len(key.namespace) + 1 :])
        )

    @staticmethod
    def _refuse(
        kind: str,
        ident: str,
        keys: Sequence[ServerKey],
        failed: Sequence[ServerKey] = (),
    ) -> None:
        """The one WARNING of a refusal: the clashing publishers `keys` (two or
        more, or none) and the `failed` keys that may own `ident`."""
        reasons = []
        if keys:
            reasons.append(f"is published by {', '.join(sorted(k.ref for k in keys))}")
        if failed:
            reasons.append(f"may be owned by failed {', '.join(sorted(k.ref for k in failed))}")
        logger.warning("%s %s %s; refusing it", kind, ident, " and ".join(reasons))

    @classmethod
    def _clash(
        cls, kind: Kind, ident: str, keys: set[ServerKey], failed: list[ServerKey]
    ) -> bool:
        """D5b and D2 for one identity: two distinct keys publish it, or a failed
        key may own it (`_owns`). Logs the refusal."""
        owned = [f for f in failed if cls._owns(f, kind, ident)]
        if len(keys) < 2 and not owned:
            return False
        cls._refuse(kind, ident, list(keys) if len(keys) > 1 else [], owned)
        return True

    @classmethod
    def _unique(
        cls,
        kind: Kind,
        passed: list[tuple[ServerKey, Any]],
        ident: Callable[[Any], str],
        failed: list[ServerKey],
    ) -> list[Any]:
        """List side of D5b: drop every component whose identity two distinct
        keys publish, or a failed key may own (D2). It counts keys, so two
        versions of one server never clash. One WARNING for each dropped
        identity."""
        owners: dict[str, set[ServerKey]] = {}
        for key, comp in passed:
            owners.setdefault(ident(comp), set()).add(key)
        refused = {i for i in sorted(owners) if cls._clash(kind, i, owners[i], failed)}
        return [c for _, c in passed if ident(c) not in refused]

    @classmethod
    def _single(
        cls,
        kind: Kind,
        name: str,
        passed: list[tuple[ServerKey, Any]],
        failed: list[ServerKey],
    ) -> Any | None:
        """Get side of D5b: the one passing component, or `None` when no key or
        two keys answer, or a failed key may own `name` (D2)."""
        if cls._clash(kind, name, {k for k, _ in passed}, failed):
            return None
        return passed[0][1] if passed else None

    async def _named(
        self,
        reach: Reach,
        routed: Routed,
        name: str,
        version: VersionSpec | None = None,
    ) -> tuple[Tool | None, list[ServerKey]]:
        """The named-path decision, which the hash and app paths reuse: the one
        passing tool that publishes `name`, or `None` when none or two do or a
        failed key may own it. The failed keys come back for `_identity_call`."""
        hits, failed = await self._ask(routed, lambda p: p.get_tool(name, version))
        passed = [(k, t) for k, t in hits if t is not None and self._passes(reach, k, t)]
        return self._single("tool", name, passed, failed), failed

    async def _identity_call(
        self,
        reach: Reach,
        routed: Routed,
        kind: str,
        ident: str,
        lookup: Callable[[Provider], Awaitable[Any]],
        pick: Callable[[list[tuple[ServerKey, Any]]], list[Tool]],
    ) -> Tool | None:
        """D4: an app identity holds no namespace, so any failed key may hold
        it. A failed key in the lookup ask (checked before `pick`, so a third
        failed key never turns "unknown" into the ambiguity verdict) or in any
        `_named` ask refuses the call, with no fall-through."""
        hits, failed = await self._ask(routed, lookup)
        if failed:
            self._refuse(kind, ident, [], failed)
            return None
        for candidate in pick(hits):
            tool, failed = await self._named(reach, routed, candidate.name)
            if failed:
                self._refuse(kind, ident, [], failed)
                return None
            if tool is not None:
                return tool
        return None

    # --- tools: list, named call, hashed call, app call ----------------------

    async def _list_tools(self) -> Sequence[Tool]:
        reach, routed = self._route()
        lists, failed = await self._ask(routed, lambda p: p.list_tools())
        passed = [
            (k, t) for k, tools in lists for t in tools if self._passes(reach, k, t)
        ]
        return self._unique("tool", passed, lambda t: t.name, failed)

    async def _get_tool(
        self, name: str, version: VersionSpec | None = None
    ) -> Tool | None:
        reach, routed = self._route()
        if reach is None:
            return None
        tool, _ = await self._named(reach, routed, name, version)
        return tool

    async def get_tool_by_hash(self, tool_hash: str, tool_name: str) -> Tool | None:
        reach, routed = self._route()

        async def by_hash(p: Provider) -> list[Tool]:
            try:
                hit = await p.get_tool_by_hash(tool_hash, tool_name)
            except ToolError:
                # The child decided "ambiguous" over its raw inventory, a
                # denied or muted duplicate included. Re-decide over the
                # caller's view: its listed tools with this identity, which
                # `_passes` filters below like any other hit.
                return _with_identity(await p.list_tools(), tool_hash)
            return [] if hit is None else [hit]

        def pick(hits: list[tuple[ServerKey, list[Tool]]]) -> list[Tool]:
            matches = [t for k, ts in hits for t in ts if self._passes(reach, k, t)]
            if len(matches) > 1:
                # The FastMCP verdict, as `AggregateProvider.get_tool_by_hash`.
                raise ToolError(
                    f"Ambiguous app tool {tool_name!r}: {len(matches)} components share "
                    f"the identity {tool_hash!r}. The same app is composed more than "
                    f"once, so this call cannot be routed to a single tool."
                )
            return matches

        return await self._identity_call(reach, routed, "hash", tool_hash, by_hash, pick)

    async def get_app_tool(self, app_name: str, tool_name: str) -> Tool | None:
        reach, routed = self._route()

        def pick(hits: list[tuple[ServerKey, Tool | None]]) -> list[Tool]:
            return [t for k, t in hits if t is not None and self._passes(reach, k, t)]

        return await self._identity_call(
            reach,
            routed,
            "app",
            f"{app_name}/{tool_name}",
            lambda p: p.get_app_tool(app_name, tool_name),
            pick,
        )

    # --- resources, resource templates, prompts: the server decision ---------

    def _served(self) -> Routed:
        """The routed pairs whose server the `Reach` allows (no user: none)."""
        reach, routed = self._route()
        return [] if reach is None else [(k, p) for k, p in routed if reach.allows_server(k)]

    @classmethod
    def _servable(cls, kind: Kind, key: ServerKey, comp: Any, ident: str) -> bool:
        """TLA+ `MuteOK` and `Owns`: the collision set of a served kind (D3).
        The server decision is already applied by `_served`."""
        if not is_enabled(comp):
            return False
        if not cls._owns(key, kind, ident):
            logger.debug("%s %s of %s is not namespaced; dropping it", kind, ident, key.ref)
            return False
        return True

    async def _served_list(
        self,
        kind: Kind,
        call: Callable[[Provider], Awaitable[Any]],
        ident: Callable[[Any], str],
    ) -> list[Any]:
        hits, failed = await self._ask(self._served(), call)
        passed = [
            (k, c)
            for k, comps in hits
            for c in comps
            if self._servable(kind, k, c, ident(c))
        ]
        return self._unique(kind, passed, ident, failed)

    async def _served_get(
        self,
        kind: Kind,
        name: str,
        call: Callable[[Provider], Awaitable[Any]],
        ident: Callable[[Any], str],
    ) -> Any | None:
        hits, failed = await self._ask(self._served(), call)
        passed = [
            (k, c)
            for k, c in hits
            if c is not None and self._servable(kind, k, c, ident(c))
        ]
        return self._single(kind, name, passed, failed)

    async def _list_resources(self):
        return await self._served_list(
            "resource", lambda p: p.list_resources(), lambda r: str(r.uri)
        )

    async def _get_resource(self, uri: str, version: VersionSpec | None = None):
        return await self._served_get(
            "resource", uri, lambda p: p.get_resource(uri, version), lambda r: str(r.uri)
        )

    async def _list_resource_templates(self):
        return await self._served_list(
            "template", lambda p: p.list_resource_templates(), lambda t: t.uri_template
        )

    async def _get_resource_template(
        self, uri: str, version: VersionSpec | None = None
    ):
        async def resolve(p: Provider):
            hit = await p.get_resource_template(uri, version)
            if hit is None or version is not None or is_enabled(hit):
                return hit
            # FastMCP's disabled fallback (`FastMCP.get_resource_template`),
            # kept inside one server so it cannot cross into another key (D5).
            enabled = [
                t
                for t in await p.list_resource_templates()
                if is_enabled(t) and t.matches(uri) is not None
            ]
            return max(enabled, key=version_sort_key) if enabled else None

        return await self._served_get(
            "template", uri, resolve, lambda t: t.uri_template
        )

    async def _list_prompts(self):
        return await self._served_list(
            "prompt", lambda p: p.list_prompts(), lambda p: p.name
        )

    async def _get_prompt(self, name: str, version: VersionSpec | None = None):
        return await self._served_get(
            "prompt", name, lambda p: p.get_prompt(name, version), lambda p: p.name
        )

    # --- lifecycle ------------------------------------------------------------

    @asynccontextmanager
    async def lifespan(self) -> AsyncIterator[None]:
        async with self._supervisor.table.lifespan():
            yield
