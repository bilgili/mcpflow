"""Verifier tests for scenarios of `proxy-prompts-resources` that the
implementer's module does not cover.

Each test names its scenario. Expectations come from
`openspec/changes/proxy-prompts-resources/specs/**`, not from the code.
"""

from __future__ import annotations

import pytest
from conftest import fake_child_spec
from fastmcp.exceptions import McpError
from test_admin_visibility import _seed as _scoped_seed
from test_admin_visibility import call_tool
from test_proxy_prompts_resources import (
    PROMPT,
    RESOURCE,
    TEMPLATE,
    _skills,
    get_prompt,
    prompt_names,
    read_resource,
    resource_uris,
    template_uris,
)
from test_visibility import (
    ROOT,
    _seed,
    admin,
    call_log,
    mute,
    ns_path,
    tool_path,
    unmute,
)

BARE_RESOURCE = "skill://diagnosing-bugs/scripts/x.sh"


# mcp-gateway / Namespaced prompts and resources: every prompt and resource is
# published under the namespace, so the bare identifiers are not listed.
# Closes the D6 hole: a containment check alone would pass if the gateway
# published both the bare and the namespaced identifier.
def test_bare_identifiers_are_not_listed(server_factory):
    _server, base, token = _skills(server_factory)

    assert "diagnosing-bugs" not in prompt_names(base, token)
    assert BARE_RESOURCE not in resource_uris(base, token)
    assert "skill://{name}/SKILL.md" not in template_uris(base, token)


# mcp-gateway / Scenario: Disabled child hides its prompts and resources
def test_disabled_child_hides_prompts_and_resources(server_factory):
    server, base, token = _skills(server_factory)
    assert PROMPT in prompt_names(base, token)

    with admin(server) as client:
        resp = client.post("/servers/skills/disable")
        assert resp.status_code in (200, 303), resp.text

    assert not any(p.startswith("skills_") for p in prompt_names(base, token))
    assert not any(u.startswith("skill://skills/") for u in resource_uris(base, token))
    assert not any(t.startswith("skill://skills/") for t in template_uris(base, token))


# mcp-gateway / Scenario: Failed child publishes no prompt or resource
def test_failed_child_publishes_no_prompt_or_resource(server_factory):
    holder: dict = {}
    server = server_factory(
        _seed(
            fake_child_spec("skills", "skills"),
            fake_child_spec("broken", "fail"),
            holder=holder,
        )
    )
    server.wait(running=1, failed=1)
    base, token = server.base_url, holder["clear"]

    prompts = prompt_names(base, token)
    uris = resource_uris(base, token)
    assert not any(p.startswith("broken_") for p in prompts)
    assert not any("://broken/" in u for u in uris)
    # The other running child is unaffected.
    assert PROMPT in prompts
    assert RESOURCE in uris


# tool-visibility / Scenario: Disabled root hides every child prompt and resource
# The spec says "empty" for an `mcp` session, so this is an equality check.
def test_root_mute_empties_prompt_and_resource_lists_for_mcp_session(server_factory):
    holder: dict = {}
    server = server_factory(_scoped_seed(holder, fake_child_spec("skills", "skills")))
    server.wait(running=1)
    base, token = server.base_url, holder["mcp"]
    assert PROMPT in prompt_names(base, token)

    with admin(server) as client:
        mute(client, ROOT)

    assert prompt_names(base, token) == []
    assert resource_uris(base, token) == []


# tool-visibility / Scenario: Re-enabling the namespace restores the prompts
# and resources -- "the child status stayed `running` throughout".
def test_namespace_mute_keeps_child_running(server_factory):
    server, base, token = _skills(server_factory)

    with admin(server) as client:
        mute(client, ns_path("skills"))
        assert server.health()["running"] == 1
        assert PROMPT not in prompt_names(base, token)
        assert server.health()["running"] == 1
        unmute(client, ns_path("skills"))

    assert server.health()["running"] == 1
    assert PROMPT in prompt_names(base, token)
    assert RESOURCE in resource_uris(base, token)
    assert TEMPLATE in template_uris(base, token)


# tool-visibility / Scenario: The stored name matches the bare URI, not the
# published URI -- driven over MCP by an `admin` session, as the scenario says.
def test_mcp_tool_mute_by_bare_uri_hides_resource(server_factory):
    holder: dict = {}
    server = server_factory(_scoped_seed(holder, fake_child_spec("skills", "skills")))
    server.wait(running=1)
    base, adm, mcp = server.base_url, holder["admin"], holder["mcp"]

    call_tool(
        base,
        adm,
        "mcpflow_set_tool_muted",
        {"namespace": "skills", "tool": BARE_RESOURCE, "muted": True},
    )

    assert RESOURCE not in resource_uris(base, mcp)
    assert PROMPT in prompt_names(base, mcp)


# tool-visibility / "A stored name `skill://skills/...` hides nothing" (design,
# The `_matches` finding): the published URI is not a match key.
def test_mute_by_published_uri_hides_nothing(server_factory):
    server, base, token = _skills(server_factory)

    with admin(server) as client:
        mute(client, tool_path("skills"), tool=RESOURCE)

    assert RESOURCE in resource_uris(base, token)
    assert read_resource(base, token, RESOURCE) == "#!/bin/sh\necho x\n"


# tool-visibility / A hidden prompt or resource is not readable: "The rule
# SHALL follow from the same mark that hides the component from the list" --
# so a name-level mute refuses the get and the read too, not only the
# namespace and root levels.
def test_name_mute_refuses_get_and_read(server_factory):
    server, base, token = _skills(server_factory)

    with admin(server) as client:
        mute(client, tool_path("skills"), tool="diagnosing-bugs")
        mute(client, tool_path("skills"), tool=BARE_RESOURCE)

    with pytest.raises(McpError):
        get_prompt(base, token, PROMPT)
    with pytest.raises(McpError):
        read_resource(base, token, RESOURCE)
    assert call_log(server) == []
