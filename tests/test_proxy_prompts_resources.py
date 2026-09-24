"""The gateway forwards a child's prompts, resources, and resource templates.

Scenarios from `openspec/changes/proxy-prompts-resources/specs/**`. The child
runs the fake server in mode `skills`; a real MCP client over `/mcp` reads the
result. Every list assertion is a containment check, never an equality check
(design decision D6), so another child or the built-in server cannot break it.
"""

from __future__ import annotations

import asyncio

import pytest
from conftest import fake_child_spec
from fastmcp.exceptions import McpError
from test_visibility import (
    ROOT,
    _seed,
    admin,
    call_log,
    mute,
    ns_path,
    tool_names,
    tool_path,
    unmute,
)

PROMPT = "skills_diagnosing-bugs"
RESOURCE = "skill://skills/diagnosing-bugs/scripts/x.sh"
TEMPLATE = "skill://skills/{name}/SKILL.md"


def _with_client(base: str, token: str, fn):
    async def run():
        from fastmcp import Client
        from fastmcp.client.transports import StreamableHttpTransport

        transport = StreamableHttpTransport(
            base + "/mcp", headers={"Authorization": f"Bearer {token}"}
        )
        async with Client(transport) as c:
            return await fn(c)

    return asyncio.run(run())


def prompt_names(base: str, token: str) -> list[str]:
    async def fn(c):
        return [p.name for p in await c.list_prompts()]

    return _with_client(base, token, fn)


def resource_uris(base: str, token: str) -> list[str]:
    async def fn(c):
        return [str(r.uri) for r in await c.list_resources()]

    return _with_client(base, token, fn)


def template_uris(base: str, token: str) -> list[str]:
    async def fn(c):
        return [t.uriTemplate for t in await c.list_resource_templates()]

    return _with_client(base, token, fn)


def get_prompt(base: str, token: str, name: str) -> str:
    async def fn(c):
        return (await c.get_prompt(name)).messages[0].content.text

    return _with_client(base, token, fn)


def read_resource(base: str, token: str, uri: str) -> str:
    async def fn(c):
        return (await c.read_resource(uri))[0].text

    return _with_client(base, token, fn)


def _skills(server_factory):
    holder: dict = {}
    server = server_factory(_seed(fake_child_spec("skills", "skills"), holder=holder))
    server.wait(running=1)
    return server, server.base_url, holder["clear"]


# --- Namespaced prompts and resources ----------------------------------------


def test_lists_hold_namespaced_components(server_factory):
    _server, base, token = _skills(server_factory)

    assert PROMPT in prompt_names(base, token)
    assert RESOURCE in resource_uris(base, token)
    assert TEMPLATE in template_uris(base, token)


def test_template_is_absent_from_resources_list(server_factory):
    _server, base, token = _skills(server_factory)

    assert not any("{name}" in uri for uri in resource_uris(base, token))


def test_get_and_read_reach_child(server_factory):
    server, base, token = _skills(server_factory)

    assert get_prompt(base, token, PROMPT) == "# diagnosing-bugs\nbody"
    assert read_resource(base, token, RESOURCE) == "#!/bin/sh\necho x\n"
    log = call_log(server)
    assert "prompt:diagnosing-bugs" in log
    assert "resource:skill://diagnosing-bugs/scripts/x.sh" in log


def test_bare_uri_does_not_resolve(server_factory):
    server, base, token = _skills(server_factory)

    with pytest.raises(McpError):
        read_resource(base, token, "skill://diagnosing-bugs/scripts/x.sh")
    assert call_log(server) == []


# --- Visibility over every component kind ------------------------------------


def test_namespace_mute_empties_lists_and_refuses_read(server_factory):
    server, base, token = _skills(server_factory)

    with admin(server) as client:
        mute(client, ns_path("skills"))

        assert not any(p.startswith("skills_") for p in prompt_names(base, token))
        assert not any(
            u.startswith("skill://skills/") for u in resource_uris(base, token)
        )
        assert not any(
            t.startswith("skill://skills/") for t in template_uris(base, token)
        )
        with pytest.raises(McpError):
            get_prompt(base, token, PROMPT)
        with pytest.raises(McpError):
            read_resource(base, token, RESOURCE)
        assert call_log(server) == []

        unmute(client, ns_path("skills"))

    assert PROMPT in prompt_names(base, token)
    assert RESOURCE in resource_uris(base, token)
    assert TEMPLATE in template_uris(base, token)


def test_root_mute_hides_every_kind(server_factory):
    server, base, token = _skills(server_factory)

    with admin(server) as client:
        mute(client, ROOT)

    assert not any(p.startswith("skills_") for p in prompt_names(base, token))
    assert not any(u.startswith("skill://skills/") for u in resource_uris(base, token))
    assert not any(t.startswith("skill://skills/") for t in template_uris(base, token))
    with pytest.raises(McpError):
        read_resource(base, token, RESOURCE)
    assert call_log(server) == []


def test_tool_mute_hides_same_named_prompt(server_factory):
    server, base, token = _skills(server_factory)
    assert PROMPT in tool_names(base, token)

    with admin(server) as client:
        mute(client, tool_path("skills"), tool="diagnosing-bugs")

    assert PROMPT not in tool_names(base, token)
    assert PROMPT not in prompt_names(base, token)
    assert RESOURCE in resource_uris(base, token)
    assert TEMPLATE in template_uris(base, token)


def test_bare_uri_mute_hides_resource(server_factory):
    server, base, token = _skills(server_factory)

    with admin(server) as client:
        mute(client, tool_path("skills"), tool="skill://diagnosing-bugs/scripts/x.sh")

    assert RESOURCE not in resource_uris(base, token)
    assert PROMPT in prompt_names(base, token)
