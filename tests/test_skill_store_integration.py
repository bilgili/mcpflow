"""End-to-end tests for the separately installed, real skill-store child.

Install the sibling skill-store package in this test environment first.
Set SKILL_STORE_PYTHON when the child uses another virtual environment.
These tests never substitute fixture tools for the store implementation.
"""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import os
import sys
from contextlib import closing

import pytest
from action_browser import action_post
from fastmcp.exceptions import ToolError
from test_child_actions import call, cards, start
from test_child_instructions import _client

from mcpflow.registry import ServerSpec

ACTIONS = {
    "add_store", "update_store", "remove_store", "set_writable",
    "refresh_store", "migrate_skill", "migrate_store", "list_stores",
}
BODY = "---\nname: example\ndescription: Diagnose a failing test.\n---\nInspect the failing test.\n"
SUPPORT = b"#!/bin/sh\nprintf 'hello\\n'\n"
BINARY = bytes(range(256))


@pytest.fixture(params=["/", "__"])
def real_store(server_factory, tmp_path, request):
    interpreter = os.environ.get("SKILL_STORE_PYTHON")
    if not interpreter and importlib.util.find_spec("skill_store") is None:
        pytest.skip("Install the separate skill-store package or set SKILL_STORE_PYTHON")
    state = tmp_path / "state"
    state.mkdir()
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    target.mkdir()
    spec = ServerSpec(
        namespace="skills", kind="custom", command=interpreter or sys.executable,
        args=["-m", "skill_store"],
        env={"SKILLS_STATE_DIR": str(state), "SKILLS_PROMPT_SEPARATOR": request.param},
        actions=True, cache_ttl=0,
    )
    server, tokens = start(server_factory, spec)
    tokens["prompt_separator"] = request.param
    with closing(server.login()) as browser:
        page = browser.get("/servers/skills/actions")
        assert page.status_code == 200
        assert set(cards(page.text)) == ACTIONS
        for name, path in [("source", source), ("target", target)]:
            response = action_post(browser, "/servers/skills/actions/add_store", data={
                "name": name, "kind": "directory", "path": str(path),
            })
            assert response.status_code == 200, response.text
        response = action_post(browser, "/servers/skills/actions/set_writable", data={"name": "source"})
        assert response.status_code == 200
    yield server, tokens, state, source, target


def write_example(server, tokens):
    return call(server.base_url, tokens["mcp"], "skills_write_skill", {
        "name": "example",
        "files": {"SKILL.md": BODY, "scripts/check.sh": SUPPORT.decode()},
        "binary_files": {"assets/bytes.bin": base64.b64encode(BINARY).decode()},
        "message": "Integration acceptance example",
    })


def read_surfaces(server, tokens):
    async def run():
        async with _client(server.base_url, tokens["mcp"], mode="legacy") as client:
            assert "source/example" in client.initialize_result.instructions
            tools = {tool.name for tool in await client.list_tools()}
            assert {"skills_use_skill", "skills_write_skill", "skills_list_skills"} <= tools
            assert not {f"skills_{name}" for name in ACTIONS} & tools
            prompts = {prompt.name for prompt in await client.list_prompts()}
            prompt_name = f"skills_source{tokens['prompt_separator']}example"
            assert prompts == {prompt_name}
            prompt = await client.get_prompt(prompt_name)
            assert prompt.messages[0].content.text == BODY
            resources = {str(resource.uri) for resource in await client.list_resources()}
            uri = "skill://skills/source/example/scripts/check.sh"
            assert uri in resources
            content = await client.read_resource(uri)
            resource = content[0]
            actual = resource.text.encode() if hasattr(resource, "text") else base64.b64decode(resource.blob)
            assert actual == SUPPORT
            content = await client.read_resource("skill://skills/source/example/assets/bytes.bin")
            assert base64.b64decode(content[0].blob) == BINARY
            used = (await client.call_tool("skills_use_skill", {"name": "source/example"})).data
            assert used["body"] == BODY
            assert uri in {item["uri"] for item in used["resources"]}
        async with _client(server.base_url, tokens["mcp"]) as client:
            await client.list_tools()
            assert "source/example" in client.instructions
    asyncio.run(run())


def test_real_write_fresh_discovery_restart_and_mute(real_store):
    server, tokens, state, source, _target = real_store
    write_example(server, tokens)
    assert (source / "example/SKILL.md").read_text() == BODY
    assert (source / "example/assets/bytes.bin").read_bytes() == BINARY
    assert (state / "stores.json").stat().st_mode & 0o777 == 0o600
    read_surfaces(server, tokens)
    headers = {"Authorization": f"Bearer {tokens['admin']}"}
    response = server.post("/api/servers/skills/restart", headers=headers)
    assert response.status_code in (200, 202)
    assert server.wait(running=1)["running"] == 1
    read_surfaces(server, tokens)

    with closing(server.login()) as browser:
        response = browser.put("/api/visibility/namespaces/skills", json={"muted": True}, headers=headers)
        assert response.status_code == 200

    async def check_muted():
        async with _client(server.base_url, tokens["mcp"], mode="legacy") as client:
            assert "source/example" not in (client.initialize_result.instructions or "")
            assert not await client.list_prompts()
            assert not await client.list_resources()
    asyncio.run(check_muted())


def test_real_actions_scope_migration_and_remove_preserve_data(real_store):
    server, tokens, _state, source, target = real_store
    write_example(server, tokens)
    with pytest.raises(ToolError):
        call(server.base_url, tokens["mcp"], "skills_remove_store", {"name": "source"})
    assert (source / "example/SKILL.md").exists()
    still_registered = call(server.base_url, tokens["admin"], "skills_list_stores")
    assert "source" in str(still_registered)
    with closing(server.login()) as browser:
        response = action_post(browser, "/servers/skills/actions/set_writable", data={"name": "target"})
        assert response.status_code == 200
        response = action_post(browser, "/servers/skills/actions/migrate_skill", data={
            "from_store": "source", "name": "example", "to_store": "target",
        })
        assert response.status_code == 200, response.text
        assert (target / "example/SKILL.md").read_text() == BODY
        assert (target / "example/assets/bytes.bin").read_bytes() == BINARY
        assert not (source / "example").exists()
        response = action_post(browser, "/servers/skills/actions/remove_store", data={"name": "target"})
        assert response.status_code == 200
    assert (target / "example/SKILL.md").exists()
    with pytest.raises(ToolError):
        call(server.base_url, tokens["mcp"], "skills_write_skill", {"name": "blocked", "files": {"SKILL.md": BODY}})
    assert not (source / "blocked").exists()
    assert not (target / "blocked").exists()
