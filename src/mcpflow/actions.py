"""Child actions: tools a child tags for the admin, and the scope filter.

A child marks a tool as an action with `_meta["mcpflow"]["action"] = true`.
A tagged tool is an action only when it meets the action contract clause: no
`ui.visibility`, no `fastmcp.tool_hash`, and a flat input schema. A tool that
violates the clause is not an action and never reaches the page, because the
page cannot mask its secrets.

`ActionScopeFilter` sits innermost in every child chain and removes every
tagged tool from a session whose `AccessToken` lacks the `admin` scope, on the
named list and the named call. `AuthorizedHashProvider` sits outermost and
re-applies the same decision to the hashed and app dispatch paths, which
`get_tool_by_hash` and `get_app_tool` would otherwise take past every
transform. Together they fail closed for every tagged tool on every path.
`ActionScopeFilter` is not a copy of `admin_mcp.ScopeFilter`, which hides
every component: a child's untagged tools stay published.

This module owns the schema-subset grammar too, so the form the page renders
and the coercion the submit applies read one definition.

It imports `fastmcp` and the SDK only. `supervisor` and `web` import it, and
an import from either direction would form a cycle.
"""

from __future__ import annotations

import json
import math
from collections.abc import AsyncIterator, Iterable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from fastmcp import FastMCP
from fastmcp.server.auth.auth import AccessToken
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.providers import Provider
from fastmcp.server.transforms import GetToolNext, Transform, VersionSpec
from fastmcp.server.transforms.visibility import is_enabled
from fastmcp.tools.base import Tool, ToolResult
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser

ACTION_META_KEY: str = "mcpflow"
ADMIN_SCOPE: str = "admin"

# The effective types a flat property may have. A property with no effective
# type is flat too: it renders as a JSON textarea.
_FLAT_TYPES = {"string", "integer", "number", "boolean", "array"}


def _meta(tool: Tool) -> dict:
    meta = getattr(tool, "meta", None)
    return meta if isinstance(meta, dict) else {}


def _schema(tool: Tool) -> dict:
    # A FastMCP `Tool` carries `parameters`; the SDK tool that a raw
    # `Client.list_tools` returns carries `input_schema`. Both reach here.
    schema = getattr(tool, "parameters", None) or getattr(tool, "input_schema", None)
    return schema if isinstance(schema, dict) else {}


def is_tagged(tool: Tool) -> bool:
    ours = _meta(tool).get(ACTION_META_KEY)
    return isinstance(ours, dict) and ours.get("action") is True


# --- the flatness rule F0-F7 (design.md, "The schema-subset grammar") --------

# References and composition the clause refuses to resolve. `anyOf` is not
# here: one shape of it, the allowed `anyOf`, is flat.
REF_KEYS = frozenset({"$ref", "$dynamicRef", "$recursiveRef", "allOf", "oneOf", "not"})

_NULL = {"type": "null"}


def _dicts(value: object, *, skip_properties: bool = False):
    """Every dict in the walk of `value`, at every depth.

    Iterative, so a deep schema cannot exhaust the stack. With
    `skip_properties`, the walk is the outer schema: it skips the values of
    the top-level `properties` dict.
    """
    if skip_properties and isinstance(value, dict) and isinstance(
        value.get("properties"), dict
    ):
        # Visit the `properties` dict itself, not its values.
        yield value
        yield value["properties"]
        stack = [v for k, v in value.items() if k != "properties"]
    else:
        stack = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            yield node
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)


def _allowed_member(any_of: object) -> dict | None:
    """The non-null member of an allowed `anyOf`, else None."""
    if not isinstance(any_of, list) or len(any_of) != 2:
        return None
    if any_of[0] == _NULL:
        member = any_of[1]
    elif any_of[1] == _NULL:
        member = any_of[0]
    else:
        return None
    if isinstance(member, dict) and isinstance(member.get("type"), str):
        return member
    return None


def _head(prop: object) -> list[dict]:
    if not isinstance(prop, dict):
        return []
    member = _allowed_member(prop.get("anyOf"))
    return [prop] if member is None else [prop, member]


def _merged(head: list[dict]) -> dict:
    merged: dict = {}
    for d in head:
        merged.update(d)
    return merged


def _effective(prop: object) -> str | None:
    """The effective type: the one distinct type name of the head, else None."""
    names = set()
    for d in _head(prop):
        kind = d.get("type")
        members = [kind] if isinstance(kind, str) else kind if isinstance(kind, list) else []
        # A non-string member is not a type name, but it still counts as a
        # distinct one, so the property falls to no effective type.
        names.update(m if isinstance(m, str) else repr(m) for m in members)
    names.discard("null")
    return next(iter(names)) if len(names) == 1 else None


def is_secret(prop: object) -> bool:
    """The one secret test: some dict of the head holds `format: password`."""
    return any(d.get("format") == "password" for d in _head(prop))


def _properties(schema: dict) -> dict:
    props = schema.get("properties")
    return props if isinstance(props, dict) else {}


def _flat(prop: object) -> bool:
    """F1-F7 for one property."""
    if not isinstance(prop, dict):  # F1
        return False
    head = _head(prop)
    head_ids = {id(d) for d in head}
    if "anyOf" in prop and len(head) != 2:  # F3, this dict
        return False
    for d in _dicts(prop):
        if not REF_KEYS.isdisjoint(d):  # F2
            return False
        if d is not prop and "anyOf" in d:  # F3, every other dict
            return False
        if id(d) not in head_ids and d.get("format") == "password":  # F4
            return False
    kind = _effective(prop)
    if kind is not None and kind not in _FLAT_TYPES:  # F5
        return False
    if kind == "array":  # F6
        items = _merged(head).get("items")
        if not (isinstance(items, dict) and items.get("type") == "string"):
            return False
    return not is_secret(prop) or kind == "string"  # F7


def clause_violation(tool: Tool) -> str | None:
    meta = _meta(tool)
    # `tool_hash` first: it names the identity the hashed path matches on, so
    # a tool carrying both keys reports the term that opens that path.
    fastmcp_meta = meta.get("fastmcp")
    if isinstance(fastmcp_meta, dict) and "tool_hash" in fastmcp_meta:
        return "fastmcp.tool_hash"
    ui = meta.get("ui")
    if isinstance(ui, dict) and "visibility" in ui:
        return "ui.visibility"
    # F6: reject a malformed visibility-meta shape before any ActionView is
    # built, so `is_enabled` never dereferences a null `fastmcp`/`_internal`
    # (`fastmcp/server/transforms/visibility.py:300-303`). A non-dict `fastmcp`
    # or a non-dict `_internal` are the only shapes that crash it. Added
    # 2026-09-19 after codex review 3 (F6).
    if "fastmcp" in meta and not isinstance(fastmcp_meta, dict):
        return "meta"
    if isinstance(fastmcp_meta, dict) and "_internal" in fastmcp_meta and not isinstance(
        fastmcp_meta["_internal"], dict
    ):
        return "meta"
    schema = _schema(tool)
    # F7/F9: reject a malformed root grammar before any ActionView is built, so
    # the single guard here protects `form_fields`/`coerce_form` from
    # `set(required)` on an unhashable member. F9 (codex review 3) tests key
    # PRESENCE apart from the value type, so `properties: null` and
    # `required: null` are rejected while an absent key stays valid.
    if "properties" in schema and not isinstance(schema["properties"], dict):
        return "schema"
    if "required" in schema and not (
        isinstance(schema["required"], list)
        and all(isinstance(r, str) for r in schema["required"])
    ):
        return "schema"
    for d in _dicts(schema, skip_properties=True):  # F0
        if not REF_KEYS.isdisjoint(d) or "anyOf" in d or d.get("format") == "password":
            return "schema"
    for name, prop in _properties(schema).items():
        if not _flat(prop):
            return f"schema:{name}"
    return None


def is_action(tool: Tool) -> bool:
    return is_tagged(tool) and clause_violation(tool) is None


def action_enabled(tool: Tool, registry_visible: bool) -> bool:
    # Added 2026-09-19 after codex review 2 (F6). The effective-enabled state of
    # an action for the page and the direct call: the registry mute AND the
    # child's own fastmcp visibility mark. is_enabled(tool) reads
    # meta["fastmcp"]["_internal"]["visibility"], default True. The MCP chain
    # refuses a tool when either hides it, so the page and run_action must too.
    return registry_visible and is_enabled(tool)


class ActionScopeFilter(Transform):
    """Remove every tagged tool from a non-admin session on the named path.

    Fails closed: no token is not admin, and a clause violator is hidden like
    an action. `AuthorizedHashProvider` closes the hashed and app paths, so the
    filter no longer needs a hash-reachable exception: it hides every tagged
    tool. `_hides` is the one predicate of both seams; `get_tool` resolves
    first, because the verdict needs the tool's meta.
    """

    def __init__(self, scope: str = ADMIN_SCOPE) -> None:
        self.scope = scope

    def _is_admin(self) -> bool:
        token = get_access_token()
        return token is not None and self.scope in token.scopes

    def _hides(self, tool: Tool) -> bool:
        return is_tagged(tool)

    async def list_tools(self, tools: Sequence[Tool]) -> Sequence[Tool]:
        if self._is_admin():
            return tools
        return [t for t in tools if not self._hides(t)]

    async def get_tool(
        self, name: str, call_next: GetToolNext, *, version: VersionSpec | None = None
    ) -> Tool | None:
        tool = await call_next(name, version=version)
        if tool is not None and self._hides(tool) and not self._is_admin():
            return None
        return tool


class AuthorizedHashProvider(Provider):
    """Re-apply the child chain's authorization to the hashed and app paths.

    `FastMCP.call_tool` resolves a `<hash>_<name>` call through
    `get_tool_by_hash`, and an MCP-Apps client resolves through `get_app_tool`.
    Both read the raw tool and apply no transform (`Provider._get_tool`,
    `_WrappedProvider.get_tool_by_hash`), so the namespace transform, the
    visibility transform, and `ActionScopeFilter` never run on those paths.
    This provider wraps the whole child chain and delegates every ordinary
    method to it, so the named `list_tools` and `get_tool` are unchanged. It
    overrides the two transform-bypassing methods and re-runs the chain's named
    decision on the tool they resolve, so scope and mute guard those paths too.
    """

    def __init__(self, chain: Provider, namespace: str) -> None:
        super().__init__()
        self._chain = chain
        self._namespace = namespace

    def __repr__(self) -> str:
        return f"AuthorizedHashProvider({self._chain!r})"

    # Ordinary sourcing: delegate to the chain's public methods, which apply
    # the chain's transforms. This provider adds no transform of its own.
    async def _list_tools(self) -> Sequence[Tool]:
        return await self._chain.list_tools()

    async def _get_tool(self, name: str, version: VersionSpec | None = None):
        return await self._chain.get_tool(name, version)

    async def _list_resources(self):
        return await self._chain.list_resources()

    async def _get_resource(self, uri: str, version: VersionSpec | None = None):
        return await self._chain.get_resource(uri, version)

    async def _list_resource_templates(self):
        return await self._chain.list_resource_templates()

    async def _get_resource_template(self, uri: str, version: VersionSpec | None = None):
        return await self._chain.get_resource_template(uri, version)

    async def _list_prompts(self):
        return await self._chain.list_prompts()

    async def _get_prompt(self, name: str, version: VersionSpec | None = None):
        return await self._chain.get_prompt(name, version)

    async def get_tasks(self) -> Sequence[Any]:
        return await self._chain.get_tasks()

    @asynccontextmanager
    async def lifespan(self) -> AsyncIterator[None]:
        async with self._chain.lifespan():
            yield

    # The two transform-bypassing paths: authorize the tool they resolve.
    async def get_tool_by_hash(self, tool_hash: str, tool_name: str) -> Tool | None:
        raw = await self._chain.get_tool_by_hash(tool_hash, tool_name)
        return await self._authorize(raw)

    async def get_app_tool(self, app_name: str, tool_name: str) -> Tool | None:
        raw = await self._chain.get_app_tool(app_name, tool_name)
        return await self._authorize(raw)

    async def _authorize(self, raw: Tool | None) -> Tool | None:
        """Re-run the named-path decision on a hash- or app-resolved tool.

        `raw` carries the bare child name, so the named lookup uses the
        namespaced display name. `chain.get_tool` runs the namespace transform,
        the visibility transform (which marks a muted tool disabled), and
        `ActionScopeFilter` (which drops a tagged tool for a non-admin caller,
        reading `get_access_token()`). `is_enabled` closes the mute-bypass: the
        server runs a hash-resolved tool with no enabled check, and it is the
        same reader the named path uses (`server.get_tool`), so a mute marked
        on the visibility metadata refuses here too. A raw `Tool`/`ProxyTool`
        carries no `enabled` attribute, so the check must read the mark, not
        the field.
        """
        if raw is None:
            return None
        tool = await self._chain.get_tool(f"{self._namespace}_{raw.name}")
        if tool is None or not is_enabled(tool):
            return None
        return tool


async def call_tool_as_admin(
    gateway: FastMCP, name: str, arguments: dict[str, Any]
) -> ToolResult:
    """Call a gateway tool under an in-memory admin token.

    The UI routes sit on the outer Starlette app, outside any MCP request, so
    `get_access_token()` falls through to the SDK context variable this sets.
    The token lives for this call only, matches no stored digest, and is reset
    on every exit path.
    """
    user = AuthenticatedUser(
        AccessToken(token="", client_id="mcpflow-ui", scopes=[ADMIN_SCOPE])
    )
    reset = auth_context_var.set(user)
    try:
        return await gateway.call_tool(name, arguments)
    finally:
        auth_context_var.reset(reset)


@dataclass(frozen=True)
class ActionView:
    name: str
    title: str
    description: str
    schema: dict
    disabled: bool
    reason: str


# --- the schema-subset grammar: form controls and coercion -------------------


@dataclass(frozen=True)
class FormField:
    name: str
    # "text", "password", "enum", "integer", "number", "boolean", "array", "json"
    control: str
    required: bool
    enum: tuple[str, ...]
    default: str
    default_on: bool


def form_fields(schema: dict) -> list[FormField]:
    """One control per property of a clause-conforming schema, in order."""
    required = schema.get("required")
    required = set(required) if isinstance(required, list) else set()
    fields: list[FormField] = []
    for name, prop in _properties(schema).items():
        kind = _effective(prop)
        merged = _merged(_head(prop))
        enum = merged.get("enum")
        default = merged.get("default")
        if is_secret(prop):
            control = "password"
        elif kind == "string" and isinstance(enum, list) and all(
            isinstance(v, str) for v in enum
        ):
            control = "enum"
        elif kind == "string":
            control = "text"
        elif kind in ("integer", "number", "boolean", "array"):
            control = kind
        else:
            control = "json"
        if default is None or control == "password":
            shown = ""
        elif control == "array" and isinstance(default, list):
            shown = "\n".join(str(v) for v in default)
        elif control == "json":
            shown = json.dumps(default)
        else:
            shown = str(default)
        fields.append(
            FormField(
                name=name,
                control=control,
                required=name in required,
                enum=tuple(enum) if control == "enum" else (),
                default=shown,
                default_on=default is True,
            )
        )
    return fields


def _no_constant(token: str) -> float:
    raise ValueError(token)


def coerce_form(schema: dict, form: Mapping[str, Any]) -> dict[str, Any]:
    """Arguments from a posted form, by the coercion table in design.md.

    Raises `ValueError` whose text names the property. The text never holds
    the posted value, so it cannot carry a secret.
    """
    arguments: dict[str, Any] = {}
    for field in form_fields(schema):
        name = field.name
        if field.control == "boolean":
            arguments[name] = form.get(name) is not None
            continue
        raw = form.get(name)
        raw = raw if isinstance(raw, str) else ""
        if raw == "" and not field.required:
            continue
        if field.control == "enum":
            if raw not in field.enum:
                raise ValueError(f"{name}: not one of {', '.join(field.enum)}")
            arguments[name] = raw
        elif field.control == "integer":
            try:
                arguments[name] = int(raw.strip())
            except ValueError:
                raise ValueError(f"{name}: not an integer") from None
        elif field.control == "number":
            try:
                value = float(raw.strip())
            except ValueError:
                raise ValueError(f"{name}: not a number") from None
            if not math.isfinite(value):
                raise ValueError(f"{name}: not a finite number")
            arguments[name] = value
        elif field.control == "array":
            arguments[name] = [s.strip() for s in raw.splitlines() if s.strip()]
        elif field.control == "json":
            try:
                arguments[name] = json.loads(raw, parse_constant=_no_constant)
            except (ValueError, RecursionError):
                raise ValueError(f"{name}: not valid JSON") from None
        else:
            arguments[name] = raw
    return arguments


def _coerced_secret_literals(
    arguments: Mapping[str, Any], password_keys: frozenset[str]
) -> frozenset[str]:
    """Collect exact representations and constituents of secret arguments."""
    secrets: set[str] = set()

    def collect(value: Any) -> None:
        if isinstance(value, str):
            if value:
                secrets.add(value)
            return
        if value is not None and not isinstance(value, (bool, int, float, list, dict)):
            raise TypeError("invalid secret argument")
        secrets.add(
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        )
        if isinstance(value, bool):
            secrets.add("True" if value else "False")
        elif value is None:
            secrets.add("None")
        elif isinstance(value, list):
            for item in value:
                collect(item)
        elif isinstance(value, dict):
            for key, item in value.items():
                if not isinstance(key, str):
                    raise TypeError("invalid secret argument")
                if key:
                    secrets.add(key)
                collect(item)

    try:
        for key in password_keys:
            if key in arguments:
                collect(arguments[key])
    except Exception:  # noqa: BLE001 -- never expose secret traversal details
        raise ValueError("invalid secret argument") from None
    return frozenset(secrets)


# --- redaction: one owner for every result, error, and schema surface --------

_SECRET_DATA_KEYS = ("default", "const", "examples", "enum")


def _mask_str(text: str, secrets: Sequence[str]) -> str:
    """Replace every span of every secret in `text` with one mask.

    The interval-merge rule of `supervisor.scrub_secrets`: find every match span
    against the ORIGINAL string, merge overlapping or adjacent spans, and mask
    each merged span once. So two overlapping secrets (`abcd`, `cdefg` on
    `abcdefg`) mask whole, not `ab***`. Unlike `scrub_secrets`, this takes no
    minimum-length floor: the page must never echo a posted or configured
    secret, whatever its length. Added 2026-09-19 after codex review 2 (F3).
    """
    spans: list[tuple[int, int]] = []
    for value in secrets:
        start = text.find(value)
        while start != -1:
            spans.append((start, start + len(value)))
            start = text.find(value, start + 1)
    if not spans:
        return text
    spans.sort()
    merged = [spans[0]]
    for start, end in spans[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    out: list[str] = []
    prev = 0
    for start, end in merged:
        out.append(text[prev:start])
        out.append("***")
        prev = end
    out.append(text[prev:])
    return "".join(out)


def redact(value: Any, secrets: Iterable[str]) -> Any:
    """Mask every secret occurrence in `value`, including whole JSON nodes.

    Walks structured data BEFORE JSON serialization, so a secret embedded in a
    dict or list value masks whatever the serializer does. Masks a secret in a
    dict KEY and in a value alike, and merges overlapping spans (`_mask_str`).
    `actions.py` imports `fastmcp` and the SDK only, so it inlines the
    interval-merge rule rather than importing `scrub_secrets`.

    Compare non-string nodes with unescaped secrets using canonical JSON before
    descending. Strings also match both JSON-escaped inner forms.
    Collision-safe (F8): two dict keys that mask to the same string keep both
    entries, the later key disambiguated with a `"#<n>"` suffix.
    """
    base = {s for s in secrets if s}
    # JSON text can retain Unicode or escape it. Match both representations
    # against the original string before merging overlapping spans.
    ordered = list(
        base
        | {
            json.dumps(s, ensure_ascii=ascii_only)[1:-1]
            for s in base
            for ascii_only in (True, False)
        }
    )

    def walk(node: Any) -> Any:
        if isinstance(node, str):
            return _mask_str(node, ordered)
        try:
            canonical = json.dumps(
                node,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError, RecursionError):
            pass
        else:
            if canonical in base:
                return "***"
        if isinstance(node, dict):
            out: dict[Any, Any] = {}
            for k, v in node.items():
                key = _mask_str(k, ordered) if isinstance(k, str) else k
                if isinstance(key, str) and key in out:
                    n = 2
                    while f"{key}#{n}" in out:
                        n += 1
                    key = f"{key}#{n}"
                out[key] = walk(v)
            return out
        if isinstance(node, list):
            return [walk(v) for v in node]
        return node

    return walk(value)


def _drop_secret_data(prop: dict) -> dict:
    out = {k: v for k, v in prop.items() if k not in _SECRET_DATA_KEYS}
    member = _allowed_member(prop.get("anyOf"))
    if member is not None:
        out["anyOf"] = [
            {k: v for k, v in m.items() if k not in _SECRET_DATA_KEYS}
            if m is member
            else m
            for m in prop["anyOf"]
        ]
    return out


def redact_schema(schema: dict) -> dict:
    """A copy of `schema` with every declared secret data value removed.

    For each property where `is_secret` is true, drop `default`, `const`,
    `examples`, and `enum` from the property dict and from the non-null member
    of an allowed `anyOf`. The clause (F0, F4) forbids a password below the
    head, so a conforming action carries a secret data value only at a top-level
    secret property. `enum` added 2026-09-19 after codex review 2 (F4).
    """
    props = _properties(schema)
    if not props:
        return schema
    new_props = {
        name: _drop_secret_data(prop) if is_secret(prop) else prop
        for name, prop in props.items()
    }
    return {**schema, "properties": new_props}


def secret_literals(schema: dict) -> list[str]:
    # Added 2026-09-19 after codex review 2 (F4). For each property where
    # is_secret(prop) is true, collect every string in its "default", "const",
    # "examples", and "enum", at the property dict and at the non-null member of
    # an allowed anyOf. A list value contributes each string item. A non-string
    # value contributes nothing. The clause (F0, F4) forbids a password below the
    # head, so a conforming action carries a secret literal only at a top-level
    # secret property. The web handler unions the result into the secret set, so
    # a child-side default password that appears in a result is masked.
    out: list[str] = []
    for prop in _properties(schema).values():
        if not is_secret(prop):
            continue
        for d in _head(prop):
            for key in _SECRET_DATA_KEYS:
                value = d.get(key)
                if isinstance(value, str):
                    out.append(value)
                elif isinstance(value, list):
                    out.extend(v for v in value if isinstance(v, str))
    return out


def secret_keys(schema: dict) -> frozenset[str]:
    # Shared declaration test for execution and presentation schemas. Execution
    # unions these keys with rendered password keys; the page uses them to
    # derive controls and exclude password values from refills.
    return frozenset(
        name for name, prop in _properties(schema).items() if is_secret(prop)
    )
