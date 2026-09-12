"""Parse a child spec from a pasted JSON config block.

The parser only pre-fills the add form. The admin always confirms.
"""

from __future__ import annotations

import json
import re

from .registry import RegistryError, ServerSpec, spec_from_dict


# --- namespace and entry helpers --------------------------------------------


def _namespace_from_key(key: str) -> str:
    return re.sub(r"[^a-z0-9_]", "_", key.lower())


def _first_package(args: list[str]) -> tuple[str | None, list[str]]:
    """Return the first argument that does not start with `-` and the rest."""
    for i, arg in enumerate(args):
        if not arg.startswith("-"):
            return arg, args[i + 1 :]
    return None, []


_SOURCE_FLAGS = {"npx": ("--package", "-p"), "uvx": ("--from",)}


def _split_source(command: str, args: list[str]) -> tuple[str | None, list[str]]:
    """Pull the install-location flag out of an `npx`/`uvx` arg list.

    Handles `--package=<x>`, `--package <x>`, `-p <x>`, `-p=<x>` (npx) and
    `--from <x>`, `--from=<x>` (uvx). Reads flags only before the first
    positional token (the package): npx/uvx also stop option parsing there, so
    a later `-p`/`--from` is a child arg and stays. Takes the first value and
    drops every later source flag and its value. Returns `(source, rest)`.
    """
    flags = _SOURCE_FLAGS.get(command)
    if not flags:
        return None, args
    source: str | None = None
    rest: list[str] = []
    i = 0
    n = len(args)
    while i < n:
        tok = args[i]
        name = tok.split("=", 1)[0]
        if "=" in tok and name in flags:
            if source is None:
                source = tok.split("=", 1)[1]
            i += 1
            continue
        if tok in flags:
            if source is None and i + 1 < n:
                source = args[i + 1]
            i += 2  # drop the flag and its value
            continue
        if not tok.startswith("-"):
            rest.extend(args[i:])  # first positional token; stop here
            break
        rest.append(tok)  # a non-source flag such as `-y`
        i += 1
    return source, rest


def _spec_from_entry(name: str, entry: dict) -> ServerSpec:
    namespace = _namespace_from_key(name)
    env = entry.get("env", {}) or {}
    if entry.get("url"):
        data = {
            "namespace": namespace,
            "kind": "remote",
            "url": entry["url"],
            "transport": entry.get("transport", "http"),
            "headers": entry.get("headers", {}) or {},
        }
    else:
        command = entry.get("command", "")
        args = list(entry.get("args", []) or [])
        if command == "npx":
            source, tail = _split_source("npx", args)
            package, rest = _first_package(tail)
            data = {
                "namespace": namespace,
                "kind": "npm",
                "package": package,
                "source": source,
                "args": rest,
            }
        elif command == "uvx":
            source, tail = _split_source("uvx", args)
            package, rest = _first_package(tail)
            data = {
                "namespace": namespace,
                "kind": "python",
                "package": package,
                "source": source,
                "args": rest,
            }
        else:
            data = {
                "namespace": namespace,
                "kind": "custom",
                "command": command,
                "args": args,
            }
        data["env"] = env
    return spec_from_dict(data)


# --- public parser -----------------------------------------------------------


def parse_config_block(text: str) -> list[ServerSpec]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError) as exc:
        raise RegistryError(f"config: not valid JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise RegistryError("config: expected a JSON object")
    servers = data.get("mcpServers", data)
    if not isinstance(servers, dict) or not servers:
        raise RegistryError("config: no server entries found")
    specs: list[ServerSpec] = []
    for name, entry in servers.items():
        if not isinstance(entry, dict):
            raise RegistryError(f"config: entry {name} is not an object")
        specs.append(_spec_from_entry(name, entry))
    return specs
