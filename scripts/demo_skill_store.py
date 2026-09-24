"""Serve a persistent local demonstration of the independent skill-store child."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import sys
from pathlib import Path

import uvicorn
from fastmcp import Client
from fastmcp.client.transports import StdioTransport

from mcpflow.auth import TokenStore
from mcpflow.config import load_settings
from mcpflow.gateway import build_app
from mcpflow.registry import Registry, ServerSpec

WELCOME = """---
name: welcome
description: Verify the remote skill store demonstration.
---
Reply with REMOTE_SKILL_OK.
Read references/check.txt through the supporting resource URI.
"""


async def seed_child(root: Path, interpreter: str, libraries: list[str]) -> None:
    requested = {"demo": root / "library"}
    for definition in libraries:
        name, separator, raw = definition.partition("=")
        if not separator or name == "demo":
            raise ValueError("Use --library NAME=PATH with a name other than demo")
        path = Path(raw).expanduser().resolve(strict=True)
        if not path.is_dir() or name in requested:
            raise ValueError("Each library must name a unique existing directory")
        requested[name] = path
    transport = StdioTransport(
        command=interpreter, args=["-m", "skill_store"],
        env={"SKILLS_STATE_DIR": str(root / "child"), "SKILLS_NAMESPACE": "skills"},
    )
    async with Client(transport) as client:
        result = (await client.call_tool("list_stores")).data
        stores = {item["name"]: item for item in result["stores"]}
        for name, path in requested.items():
            if name in stores:
                if stores[name]["kind"] != "directory" or Path(stores[name]["path"]) != path:
                    raise ValueError("Existing demo registry has a different library definition")
                continue
            await client.call_tool("add_store", {"name": name, "kind": "directory", "path": str(path)})
        if not result["writable_store"]:
            await client.call_tool("set_writable", {"name": "demo"})
        if not (root / "library" / "welcome" / "SKILL.md").exists():
            current = (await client.call_tool("list_stores")).data
            if current["writable_store"] == "demo":
                await client.call_tool("write_skill", {
                    "name": "welcome",
                    "files": {"SKILL.md": WELCOME, "references/check.txt": "Persistent remote resource.\n"},
                    "message": "Local demonstration",
                })


def credentials(root: Path, gateway_dir: Path) -> dict[str, str]:
    path = root / "credentials.json"
    if path.exists():
        os.chmod(path, 0o600)
        return json.loads(path.read_text())
    tokens = TokenStore(gateway_dir / "tokens.json")
    tokens.load()
    result = {
        "admin_password": secrets.token_urlsafe(24),
        "mcp_token": tokens.create("local-demo-agent", "mcp")[1],
        "secret_key": secrets.token_hex(32),
    }
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/tmp/mcpflow-skill-demo"))
    parser.add_argument("--port", type=int, default=8791)
    parser.add_argument("--python", default=sys.executable, help="Interpreter with skill-store installed")
    parser.add_argument("--library", action="append", default=[], metavar="NAME=PATH")
    args = parser.parse_args()
    root = args.root.expanduser().resolve()
    marker = root / ".skill-store-demo"
    if root.exists() and any(root.iterdir()) and not marker.exists():
        parser.error("Use an empty directory or an existing skill-store demo directory")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    marker.touch(mode=0o600, exist_ok=True)
    gateway_dir = root / "gateway"
    for path in (gateway_dir, gateway_dir / "logs", root / "child", root / "library"):
        path.mkdir(mode=0o700, exist_ok=True)
    asyncio.run(seed_child(root, args.python, args.library))
    values = credentials(root, gateway_dir)
    registry = Registry(gateway_dir / "servers.json")
    registry.load()
    try:
        registry.get("skills")
    except KeyError:
        registry.add(ServerSpec(
            namespace="skills", kind="custom", command=args.python,
            args=["-m", "skill_store"], env={"SKILLS_STATE_DIR": str(root / "child")},
            actions=True, cache_ttl=0,
        ))
    settings = load_settings({
        "DATA_DIR": str(gateway_dir), "ADMIN_PASSWORD": values["admin_password"],
        "SECRET_KEY": values["secret_key"], "COOKIE_SECURE": "0",
        "PUBLIC_URL": f"http://127.0.0.1:{args.port}",
    })
    print(f"Admin UI: http://127.0.0.1:{args.port}/servers/skills/actions", flush=True)
    print(f"MCP endpoint: http://127.0.0.1:{args.port}/mcp", flush=True)
    print(f"Local credentials: {root / 'credentials.json'}", flush=True)
    print(f"Persistent demo state: {root}", flush=True)
    uvicorn.run(build_app(settings), host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
