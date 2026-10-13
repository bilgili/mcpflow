"""10D: the caller router and the leak paths (multi-user-access, 10.10-10.12, 10.15).

Scenarios from `specs/access-policy/spec.md` (One decision on every MCP path,
Owner default, A global allow covers shared servers only, Admin bypass,
A published name resolves to one tool, Decisions are live) and
`specs/identity/spec.md` (Identity provider interface). Each docstring names the
TLA+ invariant of `specs/tla/multi_user_access.tla` that the test guards.

The fixture (`router_live.py`): admin-owned `time` (`get_current_time`,
`convert_time`, `cache_ttl` 300) and `github` (`x`, `create_issue`,
`shared_only`); user-owned `github@alice` (`x`, `alice_only`, `cache_ttl` 0)
and `github@bob` (`x`, `bob_only`). A tool returns `<ref>:<tool>`, so a test
sees which server a call reached. Each child logs every call it serves.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import contextmanager

import pytest
from conftest import ADMIN_ACTOR
from fastmcp.exceptions import NotFoundError, ToolError
from fastmcp.server.auth.auth import AccessToken
from fastmcp.server.providers.addressing import hash_tool
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from router_live import Child, start_live

from mcpflow.router import CallerRouter

TIME = {"time_get_current_time", "time_convert_time"}
ADMIN_GH = {"github_x", "github_create_issue", "github_shared_only"}
ALICE_GH = {"github_x", "github_alice_only"}
BOB_GH = {"github_x", "github_bob_only"}
EVERY_CHILD_TOOL = TIME | ADMIN_GH | ALICE_GH | BOB_GH
REFS = ("time", "github", "github@alice", "github@bob")


@pytest.fixture(scope="module")
def live(tmp_path_factory):
    lv, stop = start_live(tmp_path_factory.mktemp("router"))
    yield lv
    stop()


@pytest.fixture
def env(live):
    live.reset()
    yield live
    live.reset()


def refused(live, uid: str, name: str, args: dict | None = None) -> None:
    with pytest.raises(ToolError, match="Unknown tool"):
        live.call(uid, name, args)


def no_child_call(live) -> None:
    for ref in REFS:
        assert live.calls(ref) == [], ref


def child_names(names) -> set[str]:
    return {n for n in names if not n.startswith("mcpflow_")}


def as_token(subject: str | None, scopes=("mcp",)):
    """Set the in-process request context to an `AccessToken` (no HTTP)."""
    return auth_context_var.set(AuthenticatedUser(AccessToken(
        token="in-process", client_id="verifier", scopes=list(scopes),
        subject=subject)))


def router_of(live) -> CallerRouter:
    routers = [p for p in live.gateway.providers if isinstance(p, CallerRouter)]
    assert len(routers) == 1, live.gateway.providers
    return routers[0]


def hashed(app: str, tool: str) -> str:
    return f"{hash_tool(app, tool)}_{tool}"


# --- 10.10 The list path, the named call path, and the policy layers ----------


def test_default_deny_end_to_end_ac1(env):
    """Default deny, end to end (AC-1). Invariant: NoMcpLeak (list, call)."""
    import httpx

    with httpx.Client(base_url=env.base_url) as web:
        resp = web.post("/login", data={"user": "carol", "next": "/",
                                        "password": "pw-carol-0123456789"})
        assert resp.status_code == 303
    _rec, clear = env.policy.mint_token(env.user("carol"), "laptop", "mcp")
    env.tokens["carol-new"] = clear
    assert env.names("carol-new") == set()
    for name in sorted(EVERY_CHILD_TOOL):
        refused(env, "carol-new", name)
    no_child_call(env)


def test_a_denied_tool_on_the_named_path_ac8(env):
    """A denied tool on the named path (AC-8). Invariant: NoMcpLeak (list, call)."""
    env.grant("user", "alice", "server", "allow", "time")
    env.grant("user", "alice", "tool", "deny", "time", "convert_time")
    names = env.names("alice")
    assert "time_get_current_time" in names
    assert "time_convert_time" not in names
    refused(env, "alice", "time_convert_time")
    assert env.calls("time") == []
    assert env.call("alice", "time_get_current_time") == "time:get_current_time"


def test_a_server_outside_the_reach_is_not_asked(env):
    """A server outside the Reach is not asked. Invariant: NoMcpLeak (list).

    `github@alice` has `cache_ttl` 0, so every request to its provider reaches
    the child and shows as one `list` line in its log.
    """
    assert env.names("bob") == BOB_GH
    refused(env, "bob", "github_alice_only")
    assert env.log("github@alice") == []
    assert env.call("bob", "github_x") == "github@bob:x"
    assert env.log("github@alice") == []
    # Control: the owner's request does ask the provider.
    env.names("alice")
    assert "list" in env.log("github@alice")


def _components(env, uid: str):
    async def go():
        async with env.client(uid) as c:
            res = [str(r.uri) for r in await c.list_resources()]
            tpl = [r.uri_template for r in await c.list_resource_templates()]
            prm = [p.name for p in await c.list_prompts()]
            return res, tpl, prm
    return asyncio.run(go())


def test_resources_follow_the_server_decision(env):
    """Resources follow the server decision. Invariant: NoMcpLeak (list)."""
    env.grant("user", "alice", "tool", "allow", "time", "get_current_time")
    assert child_names(env.names("alice")) - ALICE_GH == {"time_get_current_time"}
    res, tpl, prm = _components(env, "alice")
    assert not [u for u in res + tpl if "time" in u], (res, tpl)
    assert not [p for p in prm if "time" in p], prm
    # Control: the admin view holds the resource, template, and prompt of time.
    res, tpl, prm = _components(env, "admin")
    assert [u for u in res if "time/info" in u], res
    assert [u for u in tpl if "time" in u], tpl
    assert [p for p in prm if p.endswith("time_prompt")], prm


def test_layered_rules_ac2(env):
    """Layered rules (AC-2). Invariant: NoMcpLeak (list)."""
    env.identity.set_groups("alice", ["eng"])
    env.grant("group", "eng", "server", "allow", "time")
    env.grant("group", "eng", "tool", "deny", "time", "convert_time")
    assert env.names("alice") & TIME == {"time_get_current_time"}


def test_the_owner_sees_their_own_server_ac5(env):
    """The owner sees their own server (AC-5). Invariant: OwnerSeesOwnStrict."""
    assert env.names("alice") == ALICE_GH
    assert env.call("alice", "github_x") == "github@alice:x"
    assert env.calls("github") == [] and env.calls("github@bob") == []


def test_an_admin_deny_hides_the_server_from_the_owner_ac5(env):
    """An admin deny hides the server from the owner (AC-5).
    Invariant: OwnerAllowNeverBeatsDeny, NoMcpLeak (list, call)."""
    env.grant("user", "alice", "server", "deny", "github@alice")
    assert env.names("alice") == set()
    for name in ALICE_GH:
        refused(env, "alice", name)
    no_child_call(env)


def test_a_group_deny_also_beats_the_owner_default(env):
    """A group deny also beats the owner default.
    Invariant: OwnerAllowNeverBeatsDeny, NoMcpLeak (list, call)."""
    env.identity.set_groups("alice", ["interns"])
    env.grant("group", "interns", "server", "deny", "github@alice")
    assert env.names("alice") == set()
    refused(env, "alice", "github_x")
    no_child_call(env)


def test_a_global_allow_keeps_private_servers_private(env):
    """A global allow keeps private servers private.
    Invariant: GlobalAllowNeverLeaksPrivate, NoMcpLeak (list, call).

    The scenario reads "every tool of the admin-owned servers", which holds
    only for a user who owns no `github`. `carol` (owns nothing) checks that
    form; `bob` (owns `github@bob`) checks that his own server keeps the
    namespace and that `github@alice` stays out.
    """
    env.identity.set_groups("carol", ["eng"])
    env.identity.set_groups("bob", ["eng"])
    env.grant("group", "eng", "global", "allow")
    assert env.names("carol") == TIME | ADMIN_GH
    assert env.call("carol", "github_x") == "github:x"
    assert env.names("bob") == TIME | BOB_GH
    refused(env, "carol", "github_alice_only")
    refused(env, "bob", "github_alice_only")
    assert env.calls("github@alice") == []


def test_the_admin_shares_a_user_server(env):
    """The admin shares a user server. Invariant: ForeignNeverShadowsShared,
    OneServerPerName. `carol` stands for the scenario's user who owns no
    `github` server (in the fixture `bob` owns `github@bob`)."""
    env.grant("user", "carol", "server", "allow", "github@alice")
    assert env.names("carol") == ALICE_GH
    assert env.call("carol", "github_x") == "github@alice:x"
    # The shared server keeps its namespace once it is granted too: a foreign
    # server never shadows a shared one.
    env.grant("user", "carol", "server", "allow", "github")
    assert env.names("carol") == ADMIN_GH
    assert env.call("carol", "github_x") == "github:x"
    assert env.calls("github@alice") == ["call:x"]


def test_a_global_deny_covers_the_owners_server(env):
    """A global deny covers the owner's server. Invariant: NoMcpLeak (list, call)."""
    env.grant("user", "alice", "global", "deny")
    assert env.names("alice") == set()
    refused(env, "alice", "github_alice_only")
    no_child_call(env)


def test_admin_view_over_mcp_ac4(env):
    """Admin view over MCP (AC-4). Invariant: AdminViewExcludesPrivate,
    AdminMcpExcludesPrivate, NoMcpLeak (list, call)."""
    for uid in ("admin", "root"):
        names = env.names(uid)
        assert child_names(names) == TIME | ADMIN_GH, uid
        assert any(n.startswith("mcpflow_") for n in names)
        assert env.call(uid, "github_x") == "github:x"
        refused(env, uid, "github_alice_only")
    assert env.calls("github@alice") == []


def test_a_non_admin_user_never_sees_an_admin_tool_ac4(env):
    """A non-admin user never sees an admin tool (AC-4). Invariant: NoMcpLeak."""
    env.grant("user", "alice", "global", "allow")
    names = env.names("alice")
    assert TIME <= names  # the global allow took effect
    assert not [n for n in names if n.startswith("mcpflow_")]
    refused(env, "alice", "mcpflow_list_servers")


def test_the_router_resolves_a_user_through_the_provider(env):
    """The router resolves a user through the provider. Invariant: NoMcpLeak
    (the Reach is the one of the resolved user)."""
    env.identity.set_groups("alice", ["eng"])
    reset = as_token("alice")
    try:
        user = env.policy.current_user()
    finally:
        auth_context_var.reset(reset)
    assert user == env.identity.get_user("alice")
    assert user.groups == frozenset({"eng"}) and user.is_admin is False
    env.identity.resolved.clear()
    assert env.names("alice") == ALICE_GH
    assert "alice" in env.identity.resolved


def test_a_token_without_a_subject_resolves_to_no_user(env):
    """A token without a subject resolves to no user. Invariant: NoMcpLeak
    (no user, no child component: default deny)."""
    token = AccessToken(token="t", client_id="c", scopes=["mcp"], subject=None)
    assert env.identity.resolve(token) is None

    async def listed(subject):
        reset = as_token(subject)
        try:
            assert (env.policy.current_user() is None) == (subject is None)
            return {t.name for t in await env.gateway.list_tools()}
        finally:
            auth_context_var.reset(reset)

    assert child_names(env.run(listed(None))) == set()
    # Control: the same in-process path lists the admin view for a subject.
    assert child_names(env.run(listed("admin"))) == TIME | ADMIN_GH


# --- 10.11 The hashed path and the app path: zero calls reach the child -------


def on_loop(live, fn, *args):
    async def go():
        return fn(*args)
    return live.run(go())


def in_process_call(live, subject, name):
    """`tools/call` through the live gateway with an in-process token."""
    async def go():
        reset = as_token(subject)
        try:
            return (await live.gateway.call_tool(name, {})).structured_content
        except Exception as exc:  # NotFoundError or ToolError: refused
            return exc
        finally:
            auth_context_var.reset(reset)
    return live.run(go())


def app_tool(live, subject, app, tool, run=False):
    """`CallerRouter.get_app_tool` for `subject`; run the tool when `run`."""
    async def go():
        reset = as_token(subject)
        try:
            found = await router_of(live).get_app_tool(app, tool)
            if found is not None and run:
                from fastmcp.server.context import Context

                async with Context(fastmcp=live.gateway):
                    return (await found.run({})).structured_content
            return found
        finally:
            auth_context_var.reset(reset)
    return live.run(go())


def test_a_denied_tool_on_the_hashed_path_ac8(env):
    """A denied tool on the hashed path (AC-8). Invariant: NoMcpLeak (hash)."""
    env.grant("user", "alice", "server", "allow", "time")
    env.grant("user", "alice", "tool", "deny", "time", "convert_time")
    refused(env, "alice", hashed("time", "convert_time"))
    # A server outside the Reach is not asked on the hashed path either.
    refused(env, "alice", hashed("gh", "bob_only"))
    assert env.calls("time") == [] and env.calls("github@bob") == []
    # A request with no user reaches no child on the hashed path.
    for name in (hashed("time", "get_current_time"), hashed("gh", "x")):
        assert isinstance(in_process_call(env, None, name), Exception)
    no_child_call(env)
    # Control: the allowed tool runs by hash, and `gh`/`x`, which three
    # servers publish, resolves inside the caller's Reach only.
    assert env.call("alice", hashed("time", "get_current_time")) == "time:get_current_time"
    assert env.call("bob", hashed("gh", "x")) == "github@bob:x"
    assert env.calls("github") == [] and env.calls("github@alice") == []


def test_an_allowed_tool_runs_by_hash_once(env):
    """fastmcp-4-0-11-hashed-lookup, "An allowed tool runs by hash".

    `alice` has a server allow on `time` and sends the hashed call name of
    `get_current_time`: the child runs the tool exactly once and the gateway
    returns its result. Invariant: CallAgreesWithList (hash).
    """
    env.grant("user", "alice", "server", "allow", "time")
    env.clear_logs()
    assert env.call("alice", hashed("time", "get_current_time")) == "time:get_current_time"
    assert env.calls("time") == ["call:get_current_time"]
    for ref in ("github", "github@alice", "github@bob"):
        assert env.calls(ref) == [], ref


def test_a_denied_tool_on_the_app_path_ac8(env):
    """A denied tool on the app path (AC-8). Invariant: NoMcpLeak (app)."""
    env.grant("user", "alice", "server", "allow", "time")
    env.grant("user", "alice", "tool", "deny", "time", "convert_time")
    assert app_tool(env, "alice", "time", "convert_time") is None
    # Outside the Reach: alice has no rule on `github@bob`.
    assert app_tool(env, "alice", "gh", "bob_only") is None
    # No user: nothing on the app path.
    for app, tool in (("time", "get_current_time"), ("gh", "x"), ("gh", "alice_only")):
        assert app_tool(env, None, app, tool) is None
    no_child_call(env)
    # Control: the allowed tool resolves and runs; `gh`/`x` resolves to the
    # caller's own server.
    assert app_tool(env, "alice", "time", "get_current_time") is not None
    assert app_tool(env, "bob", "gh", "x", run=True) == {"result": "github@bob:x"}
    assert env.calls("github") == [] and env.calls("github@alice") == []


def test_a_mute_covers_the_hashed_path_of_a_plain_child(env):
    """A mute covers the hashed path of a plain child.
    Invariant: MutedHiddenForAll, NoMcpLeak (hash)."""
    import httpx

    env.grant("user", "alice", "server", "allow", "time")
    name = hashed("time", "get_current_time")
    assert env.call("admin", name) == "time:get_current_time"  # control
    env.clear_logs()
    with httpx.Client(base_url=env.base_url) as web:
        assert web.post("/login", data={"password": "secret", "next": "/"}).status_code == 303
        path = "/visibility/namespaces/time/tool"
        assert web.post(path, data={"tool": "get_current_time"}).status_code == 200
        try:
            for uid in ("admin", "root", "alice"):
                refused(env, uid, name)
            assert app_tool(env, "admin", "time", "get_current_time") is None
            assert env.calls("time") == []
        finally:
            web.post(path, data={"tool": "get_current_time", "visible": "on"})


# --- 10.12 A published name resolves to one tool (the collision backstop) -----
#
# `github` with `create_issue` and `github_create` with `issue` both publish
# `github_create_issue` (D5b). Each owner writes alone, so the write-time check
# compares only with admin-owned and own namespaces and admits both; a grant
# later brings them into one Reach.

COLLIDE = (
    Child("github@bob", "gh", ("create_issue", "create_pr", "x", "z", "create_extra")),
    Child("github_create@alice", "gh", ("issue", "pr", "close", "z")),
    Child("github@carol", "gh", ("create_issue", "y")),
)
CLASH = {"github_create_issue", "github_create_pr"}
# What `alice` lists with `github@bob` granted and no failure. `z` is one app
# tool that both servers compose under names neither owns (`github_z`,
# `github_create_z`); `create_extra` gives `github@bob` a name that
# `github_create@alice` could own but does not publish (the failed-key tests).
ALICE_HEALTHY = {"github_x", "github_z", "github_create_extra",
                 "github_create_close", "github_create_z"}


@pytest.fixture(scope="module")
def collide_live(tmp_path_factory):
    lv, stop = start_live(tmp_path_factory.mktemp("collide"), COLLIDE)
    yield lv
    stop()


@pytest.fixture
def collide(collide_live):
    collide_live.reset()
    yield collide_live
    collide_live.reset()


def warnings_for(caplog, name: str) -> list[logging.LogRecord]:
    return [r for r in caplog.records
            if r.levelno == logging.WARNING and name in r.getMessage()]


def test_a_granted_foreign_server_collides(collide, caplog):
    """A granted foreign server collides. Invariant: OneServerPerToolName,
    OneServerPerName, NoMcpLeak (call)."""
    env = collide
    env.grant("user", "alice", "server", "allow", "github@bob")
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        names = env.names("alice")
    assert names == ALICE_HEALTHY, names
    for name in CLASH:
        assert len(warnings_for(caplog, name)) == 1, (name, caplog.records)
    for name in CLASH:
        refused(env, "alice", name)
    for ref in env.children:
        assert env.calls(ref) == [], ref
    # The refusal covers the names only, not the servers.
    assert env.call("alice", "github_x") == "github@bob:x"
    assert env.call("alice", "github_create_close") == "github_create@alice:close"


def test_a_muted_tool_causes_no_refusal_c2(collide, caplog):
    """A muted tool causes no refusal (C2). Invariant: OneServerPerToolName
    (the collision set holds only tools that pass the mute and the Reach),
    OwnerSeesOwnStrict. `carol` plays the scenario's `alice` (owns `github`);
    `github_create@alice` plays the granted `github_create@bob`."""
    env = collide
    env.grant("user", "carol", "server", "allow", "github_create@alice")
    assert "github_create_issue" not in env.names("carol")  # control: it clashes
    key = env.children["github_create@alice"].key
    on_loop(env, env.supervisor.set_tool_muted, key, "issue", True, ADMIN_ACTOR)
    try:
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            names = env.names("carol")
        assert "github_create_issue" in names
        assert warnings_for(caplog, "github_create_issue") == []
        assert env.call("carol", "github_create_issue") == "github@carol:create_issue"
        assert env.calls("github_create@alice") == []
    finally:
        on_loop(env, env.supervisor.set_tool_muted, key, "issue", False, ADMIN_ACTOR)


def test_the_app_path_refuses_a_colliding_name_c2(collide, caplog):
    """The app path refuses a colliding name (C2). Invariant:
    OneServerPerToolName, NoMcpLeak (app)."""
    env = collide
    env.grant("user", "alice", "server", "allow", "github@bob")
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        for tool in ("issue", "create_issue", "pr", "create_pr"):
            assert app_tool(env, "alice", "gh", tool) is None, tool
    for name in CLASH:
        assert warnings_for(caplog, name), name
    for ref in env.children:
        assert env.calls(ref) == [], ref
    # Control: a name that does not clash resolves on the app path.
    assert app_tool(env, "alice", "gh", "close", run=True) == {
        "result": "github_create@alice:close"}


# --- Served kinds: a published prompt or resource resolves to one server ------
#
# The fake child also publishes a prompt for each tool (same name) and the
# resources `res://gh/info` and `urn:gh:shared`. On `COLLIDE`, `github@bob`
# and `github_create@alice` both publish the prompts `github_create_issue` and
# `github_create_pr`, as they do the tools.

PROMPT_CLASH = CLASH


def served(env, uid: str):
    """The prompt names and resource URIs that `uid` lists."""
    async def go():
        async with env.client(uid) as c:
            return ({p.name for p in await c.list_prompts()},
                    {str(r.uri) for r in await c.list_resources()})
    return asyncio.run(go())


def prompt_text(env, uid: str, name: str) -> str:
    async def go():
        async with env.client(uid) as c:
            return (await c.get_prompt(name)).messages[0].content.text
    return asyncio.run(go())


def read_text(env, uid: str, uri: str) -> str:
    async def go():
        async with env.client(uid) as c:
            return (await c.read_resource(uri))[0].text
    return asyncio.run(go())


def template_name(env, subject: str, uri: str):
    """The name of the template that the router resolves `uri` to."""
    async def go():
        reset = as_token(subject)
        try:
            found = await router_of(env).get_resource_template(uri)
            return None if found is None else found.name
        finally:
            auth_context_var.reset(reset)
    return env.run(go())


def test_a_muted_template_falls_back_inside_one_server(collide):
    """A muted template falls back to the next enabled template of the same
    server. Invariant: PassingResourceReachable (FastMCP's disabled fallback
    stays, per server). `carol` owns `github@carol`, the only server in view;
    its templates `tpl` and `tpl_alt` match the same URI.

    The proxy template reads the child by the concrete URI, and the child then
    picks its own first match (`tpl`), so the read text cannot tell the two
    apart. The router answer is checked by the name of the resolved template.
    """
    env = collide
    uri = "tpl://github/gh/hello"
    assert template_name(env, "carol", uri) == "tpl"  # control: `tpl` is first
    assert read_text(env, "carol", uri) == "hello"
    key = env.children["github@carol"].key
    on_loop(env, env.supervisor.set_tool_muted, key, "tpl", True, ADMIN_ACTOR)
    try:
        assert template_name(env, "carol", uri) == "tpl_alt"
        assert read_text(env, "carol", uri) == "hello"  # a read still resolves
    finally:
        on_loop(env, env.supervisor.set_tool_muted, key, "tpl", False, ADMIN_ACTOR)
    assert template_name(env, "carol", uri) == "tpl"


def test_unique_and_single_count_keys_not_versions(caplog):
    """The clash helper counts keys. Invariant: OneServerPerResourceURI,
    OneServerPerPromptName. Two distinct keys that publish one resource
    identity are refused with one WARNING that names the kind; two versions
    under one key are kept."""
    from mcpflow.registry import ServerKey

    a, b = ServerKey.parse("github@alice"), ServerKey.parse("github@bob")
    uri = "res://github/info"
    ident = str
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        assert CallerRouter._unique("resource", [(a, uri), (b, uri)], ident, []) == []
        assert CallerRouter._single("resource", uri, [(a, "va"), (b, "vb")], []) is None
    messages = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(messages) == 2, messages
    for m in messages:
        assert "resource" in m and uri in m and "github@alice, github@bob" in m, m
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        assert CallerRouter._unique("resource", [(a, uri), (a, uri)], ident, []) == [uri, uri]
        assert CallerRouter._single("resource", uri, [(a, "v1")], []) == "v1"
    assert caplog.records == []


def test_a_granted_foreign_server_collides_on_a_prompt(collide, caplog):
    """A granted foreign server collides on a prompt. Invariant:
    OneServerPerPromptName, PromptGetAgreesWithList."""
    env = collide
    env.grant("user", "alice", "server", "allow", "github@bob")
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        prompts, _ = served(env, "alice")
    assert prompts == ALICE_HEALTHY | {"github_gh_prompt",
                                       "github_create_gh_prompt"}, prompts
    for name in PROMPT_CLASH:
        found = [r for r in warnings_for(caplog, name) if "prompt" in r.getMessage()]
        assert len(found) == 1, (name, caplog.records)
    # The get agrees with the list: a refused name is unknown, and no child ran it.
    for name in PROMPT_CLASH:
        with pytest.raises(Exception, match="(?i)unknown prompt"):
            prompt_text(env, "alice", name)
    for ref in env.children:
        assert not [x for x in env.log(ref) if x.startswith("prompt:")], ref
    # The refusal covers the names only, not the servers.
    assert prompt_text(env, "alice", "github_x") == "github@bob:x"
    assert prompt_text(env, "alice", "github_create_close") == "github_create@alice:close"


def test_a_muted_prompt_causes_no_refusal_c2(collide, caplog):
    """A muted prompt causes no refusal (C2). Invariant: PassingPromptReachable
    (list), PromptGetAgreesWithList (get: the collision set holds only prompts
    that pass the mute), PassingResourceReachable. `carol` plays the scenario's
    user who owns `github`."""
    env = collide
    env.grant("user", "carol", "server", "allow", "github_create@alice")
    prompts, resources = served(env, "carol")
    assert "github_create_issue" not in prompts  # control: it clashes
    assert "res://github_create/gh/info" in resources  # control: listed
    key = env.children["github_create@alice"].key
    on_loop(env, env.supervisor.set_namespace_muted, key, True, ADMIN_ACTOR)
    try:
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            prompts, resources = served(env, "carol")
            text = prompt_text(env, "carol", "github_create_issue")
        assert "github_create_issue" in prompts
        assert warnings_for(caplog, "github_create_issue") == []
        assert text == "github@carol:create_issue"
        assert "res://github_create/gh/info" not in resources
        assert "res://github/gh/info" in resources
        assert not [x for x in env.log("github_create@alice") if x.startswith("prompt:")]
    finally:
        on_loop(env, env.supervisor.set_namespace_muted, key, False, ADMIN_ACTOR)


def test_an_unnamespaced_resource_uri_is_not_listed(collide, caplog):
    """An unnamespaced resource URI is not listed. Invariant:
    ResourceGetAgreesWithList (no get reads `urn:gh:shared`),
    PassingResourceReachable (the namespaced resources stay)."""
    env = collide
    for grant in (False, True):
        if grant:
            env.grant("user", "alice", "server", "allow", "github@bob")
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            _, resources = served(env, "alice")
        assert not [u for u in resources if "urn:gh:shared" in u], resources
        assert warnings_for(caplog, "urn:gh:shared") == []
        assert "res://github_create/gh/info" in resources
        assert ("res://github/gh/info" in resources) is grant
        # The get agrees with the list: no server answers the raw URI.
        with pytest.raises(Exception, match="(?i)not found|unknown resource"):
            read_text(env, "alice", "urn:gh:shared")


# --- A failed provider only refuses (router-failed-key-backstop) --------------
#
# `failing` makes the live provider of one routed key raise, as a child that
# errors on a request. The router asks `Supervisor.routed(reach)` providers on
# every request and reads the method off the provider object, so an attribute
# set on that object is the hook the gateway really uses; `del` restores it.
# Healthy, `alice` (with `github@bob` granted) lists `ALICE_HEALTHY`; a name
# is owned by a failed key when it starts with `<namespace>_` of that key.

PROVIDER_METHODS = ("list_tools", "get_tool", "get_tool_by_hash", "get_app_tool",
                    "list_prompts", "get_prompt")
ROUTER_LOG = "mcpflow.router"


@contextmanager
def failing(env, ref, only=PROVIDER_METHODS, exc=None):
    """Make the provider of `ref` raise `exc` on the methods `only`; restore."""
    provider = env.supervisor.get(env.children[ref].key).provider
    error = exc if exc is not None else RuntimeError(f"{ref} is down")

    async def boom(*args, **kwargs):
        raise error

    for method in only:
        setattr(provider, method, boom)
    try:
        yield
    finally:
        for method in only:
            provider.__dict__.pop(method, None)
        assert not [m for m in only if m in provider.__dict__]


def router_warnings(caplog, *needles: str) -> list[logging.LogRecord]:
    """The WARNINGs of the router whose message holds every needle."""
    return [r for r in caplog.records
            if r.levelno == logging.WARNING and r.name == ROUTER_LOG
            and all(n in r.getMessage() for n in needles)]


def no_child_ran(env) -> None:
    """No child ran a tool or rendered a prompt."""
    for ref in env.children:
        assert env.calls(ref) == [], ref
        assert not [x for x in env.log(ref) if x.startswith("prompt:")], ref


def unknown_prompt(env, uid: str, name: str) -> None:
    with pytest.raises(Exception, match="(?i)unknown prompt"):
        prompt_text(env, uid, name)


def test_a_failed_provider_does_not_hand_its_name_to_a_prefix_namespace(collide, caplog):
    """A failed provider does not hand its name to a prefix namespace.
    Invariant: FailureOnlyRefuses (tool list, named call, prompt list, prompt
    get), FailureRefusesOnlyOwned (`github_x` stays).

    `github_create_extra` is the name that tells the fix from the clash: only
    `github@bob` publishes it, so it is served while `github_create@alice` is
    up. `github_create_issue` is the scenario's name; it clashes when healthy.
    """
    env = collide
    env.grant("user", "alice", "server", "allow", "github@bob")
    owned = ("github_create_issue", "github_create_extra")
    # Control: the healthy request serves the name that only `github@bob` publishes.
    assert "github_create_extra" in env.names("alice")
    assert "github_create_extra" in served(env, "alice")[0]
    assert env.call("alice", "github_create_extra") == "github@bob:create_extra"
    assert prompt_text(env, "alice", "github_create_extra") == "github@bob:create_extra"
    env.clear_logs()
    caplog.clear()
    with failing(env, "github_create@alice"), caplog.at_level(logging.WARNING):
        names = env.names("alice")
        prompts, _ = served(env, "alice")
        for name in owned:
            refused(env, "alice", name)
            unknown_prompt(env, "alice", name)
        no_child_ran(env)
        # Not owned by the failed key: the name and the prompt stay.
        assert env.call("alice", "github_x") == "github@bob:x"
        assert prompt_text(env, "alice", "github_x") == "github@bob:x"
    assert names == {"github_x", "github_z"}, names
    assert prompts == {"github_x", "github_z", "github_gh_prompt"}, prompts
    for kind in ("tool", "prompt"):
        for name in owned:
            assert router_warnings(caplog, kind, name, "github_create@alice"), (kind, name)
    # The failed key recovers: the next request serves every name again.
    assert env.names("alice") == ALICE_HEALTHY


def test_a_failed_shorter_namespace_hides_the_names_it_may_own(collide, caplog):
    """A failed shorter namespace hides the names it may own. Invariant:
    FailureOnlyRefuses, FailureRefusesOnlyOwned (the failed `github` owns every
    `github_*` name, so each name of `github_create@alice` goes, and returns
    with the provider)."""
    env = collide
    env.grant("user", "alice", "server", "allow", "github@bob")
    assert env.call("alice", "github_create_close") == "github_create@alice:close"  # control
    env.clear_logs()
    caplog.clear()
    mine = ("github_create_close", "github_create_z")
    with failing(env, "github@bob"), caplog.at_level(logging.WARNING):
        assert env.names("alice") == set()
        assert served(env, "alice")[0] == set()
        for name in mine:
            refused(env, "alice", name)
            unknown_prompt(env, "alice", name)
        no_child_ran(env)
    for kind in ("tool", "prompt"):
        for name in mine:
            assert router_warnings(caplog, kind, name, "github@bob"), (kind, name)
    # Every name returns when the provider answers again.
    assert env.names("alice") == ALICE_HEALTHY
    assert env.call("alice", "github_create_close") == "github_create@alice:close"
    assert prompt_text(env, "alice", "github_create_close") == "github_create@alice:close"


def test_a_failed_key_stops_the_app_identity_lookup(collide, caplog):
    """A failed key stops the app-identity lookup. Invariant:
    HashFailureOnlyRefuses (hashed path), AppFailureOnlyRefuses (app path),
    FailureRefusesOnlyOwned (the named `github_x` still runs).

    `github_create@alice` cannot own `github_x`, yet the identity `gh`/`x` holds
    no namespace, so a failure of any key refuses it.
    """
    env = collide
    env.grant("user", "alice", "server", "allow", "github@bob")
    ident = hash_tool("gh", "x")
    # Control: healthy, both paths resolve to the one server that composes `x`.
    assert env.call("alice", hashed("gh", "x")) == "github@bob:x"
    assert app_tool(env, "alice", "gh", "x") is not None
    env.clear_logs()
    caplog.clear()
    with failing(env, "github_create@alice"), caplog.at_level(logging.WARNING):
        refused(env, "alice", hashed("gh", "x"))
        assert app_tool(env, "alice", "gh", "x") is None
        no_child_ran(env)
        assert router_warnings(caplog, "hash", ident, "github_create@alice")
        assert router_warnings(caplog, "app", "gh/x", "github_create@alice")
        # The name path still serves the tool of `github@bob`.
        assert env.call("alice", "github_x") == "github@bob:x"
    assert env.call("alice", hashed("gh", "x")) == "github@bob:x"  # recovered
    # A failure of the lookup ask alone (the named ask of `github_x` answers).
    caplog.clear()
    env.clear_logs()
    with caplog.at_level(logging.WARNING):
        with failing(env, "github_create@alice", only=("get_tool_by_hash",)):
            refused(env, "alice", hashed("gh", "x"))
        with failing(env, "github_create@alice", only=("get_app_tool",)):
            assert app_tool(env, "alice", "gh", "x") is None
    no_child_ran(env)
    assert router_warnings(caplog, "hash", ident, "github_create@alice")
    assert router_warnings(caplog, "app", "gh/x", "github_create@alice")


def test_a_key_answers_the_lookup_and_fails_the_named_ask(collide, caplog):
    """A key answers the lookup and fails the named ask. Invariant:
    AppFailureOnlyRefuses (no fall-through to another candidate).

    Both servers compose `gh`/`z`. `github_create@alice` answers
    `get_app_tool` and raises on `get_tool`, so its own name `github_create_z`
    and the named ask of `github_z` both meet the failure. A lookup-only guard
    would serve `github_z` of `github@bob` after `github_create_z` is refused.
    """
    env = collide
    env.grant("user", "alice", "server", "allow", "github@bob")
    assert app_tool(env, "alice", "gh", "z") is not None  # control: healthy resolves
    env.clear_logs()
    caplog.clear()
    with failing(env, "github_create@alice", only=("get_tool",)), \
            caplog.at_level(logging.WARNING):
        assert app_tool(env, "alice", "gh", "z") is None
        no_child_ran(env)
        assert router_warnings(caplog, "app", "gh/z", "github_create@alice")
        # `github_z` is not owned by the failed key: the named path serves it.
        assert env.call("alice", "github_z") == "github@bob:z"


class _Reach:
    def allows_tool(self, key, bare):
        return True


class _Fake:
    """A provider that publishes `tools` (all of identity `ident`), or raises."""

    def __init__(self, *tools, get=None, by_hash=None, listing=None, get_once=False):
        self.tools, self.get, self.by_hash, self.listing = tools, get, by_hash, listing
        self.get_once, self.gets = get_once, []

    async def get_tool(self, name, version=None):
        self.gets.append(name)
        if self.get:
            error = self.get
            if self.get_once:
                self.get = None
            raise error
        return next((t for t in self.tools if t.name == name), None)

    async def get_app_tool(self, app_name, tool_name):
        return self.tools[0] if self.tools else None

    async def get_tool_by_hash(self, tool_hash, tool_name):
        if self.by_hash:
            raise self.by_hash
        return self.tools[0] if self.tools else None

    async def list_tools(self):
        if self.listing:
            raise self.listing
        return list(self.tools)


def _fake_tool(name: str):
    from fastmcp.tools import Tool

    def run() -> str:
        return name

    return Tool.from_function(run, name=name, meta={"ui": {"visibility": ["app"]}})


def _router(**providers):
    """A router over fake providers `ref=_Fake(...)`, in the keyword order."""
    from mcpflow.registry import ServerKey

    routed = [(ServerKey.parse(ref), p) for ref, p in providers.items()]
    router = CallerRouter(None, None)  # type: ignore[arg-type]
    router._route = lambda: (_Reach(), routed)
    return router


def test_a_failed_third_key_answers_unknown_not_ambiguous(caplog):
    """Two passing tools share the identity and a third key fails: the answer
    is unknown, not the ambiguity verdict (N3). Invariant: HashFailureOnlyRefuses.
    Tested on `get_tool_by_hash` with fake providers: the `collide` fixture has
    no two keys that compose one tool under one hash name."""
    def pair(**third):
        return _router(
            ga=_Fake(_fake_tool("ga_x")), gb=_Fake(_fake_tool("gb_x")), gc=_Fake(**third))

    # Control: with no failure, the two passing tools are the ambiguity verdict.
    with pytest.raises(ToolError, match="Ambiguous app tool"):
        asyncio.run(pair().get_tool_by_hash("h", "x"))
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        found = asyncio.run(pair(by_hash=RuntimeError("down")).get_tool_by_hash("h", "x"))
    assert found is None
    assert router_warnings(caplog, "hash", "h", "gc")


def test_a_tool_error_from_get_tool_by_hash_then_a_raising_list_makes_the_key_failed(caplog):
    """A `ToolError` of `get_tool_by_hash` is the child verdict "ambiguous"; the
    router re-decides over `list_tools`. A raising `list_tools` then makes the
    key failed (D4). Invariant: HashFailureOnlyRefuses."""
    def hashed_pair(**second):
        return _router(ga=_Fake(_fake_tool("ga_x")),
                       gb=_Fake(by_hash=ToolError("ambiguous"), **second))

    # Control: the verdict is absorbed when the list answers; `ga` is served.
    found = asyncio.run(hashed_pair().get_tool_by_hash("h", "x"))
    assert found is not None and found.name == "ga_x"
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        found = asyncio.run(
            hashed_pair(listing=RuntimeError("down")).get_tool_by_hash("h", "x"))
    assert found is None
    assert router_warnings(caplog, "hash", "h", "gb")


class _Versioned(_Fake):
    """A provider that publishes two versions of one name with two identities:
    `by_hash` finds the lower one, `get_tool` of the name answers the highest."""

    def __init__(self, lower, higher):
        super().__init__(lower, higher)
        self.lower, self.higher = lower, higher

    async def get_tool(self, name, version=None):
        self.gets.append(name)
        if name != self.lower.name:
            return None
        return self.higher if version is None else next(
            (t for t in self.tools if version.matches(t.version)), None)

    async def get_tool_by_hash(self, tool_hash, tool_name):
        return self.lower


def test_a_tool_sharing_the_listed_name_does_not_replace_the_found_tool():
    """fastmcp-4-0-11-hashed-lookup, "A tool that shares the listed name does
    not replace the found tool" (gate finding 5), through the router.

    The hashed lookup finds the LOWER version `T` (identity `h`); the HIGHER
    version under the same name has another identity. The gateway runs `T` or
    answers unknown-tool; the higher version never runs. Invariant: NoMcpLeak
    (hash), CallAgreesWithList.

    FastMCP owns this rule (design D1): the gateway template's identity check
    (step 4) rejects the higher version. The fake providers sit directly under
    `CallerRouter`, so this pins FastMCP's rule at the router seam, not the
    child chain or `AuthorizedHashProvider`.
    """
    from fastmcp import FastMCP
    from fastmcp.tools import Tool

    ident = hash_tool("app", "x")
    ran: list[str] = []

    def tool(label: str, version: str, identity: str):
        def run() -> str:
            ran.append(label)
            return label

        return Tool.from_function(
            run, name="ga_x", version=version,
            meta={"fastmcp": {"tool_hash": identity}, "ui": {"visibility": ["app"]}})

    lower = tool("lower", "1", ident)
    higher = tool("higher", "2", hash_tool("app", "other"))

    async def hashed_call(provider):
        gateway = FastMCP("gw")
        gateway.add_provider(_router(ga=provider))
        try:
            return (await gateway.call_tool(f"{ident}_x", {})).structured_content
        except (NotFoundError, ToolError) as exc:
            assert "Unknown tool" in str(exc), exc
            return None

    # Control: the lower version alone runs by hash, once.
    assert asyncio.run(hashed_call(_Fake(lower))) == {"result": "lower"}
    assert ran == ["lower"]
    ran.clear()
    # The higher version under the same name never runs.
    outcome = asyncio.run(hashed_call(_Versioned(lower, higher)))
    assert "higher" not in ran
    assert outcome in (None, {"result": "lower"}), outcome
    assert ran == ([] if outcome is None else ["lower"])


def test_a_failed_first_candidate_does_not_fall_through(caplog):
    """The first app candidate answers the lookup and fails its named ask: the
    call answers unknown and asks no second candidate, although the second
    would answer (D4, codex pre-merge finding 1). Invariant:
    AppFailureOnlyRefuses. `ga` fails only its first `get_tool`, so a
    fall-through would serve `gb_z`."""
    def two(**first):
        return _router(ga=_Fake(_fake_tool("ga_z"), **first), gb=_Fake(_fake_tool("gb_z")))

    # Control: healthy, the first candidate in routed order is served.
    found = asyncio.run(two().get_app_tool("gh", "z"))
    assert found is not None and found.name == "ga_z"
    router = two(get=RuntimeError("down"), get_once=True)
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        found = asyncio.run(router.get_app_tool("gh", "z"))
    assert found is None
    assert router_warnings(caplog, "app", "gh/z", "ga")
    gb = router._route()[1][1][1]
    assert gb.gets == ["ga_z"], gb.gets  # one named ask; no second candidate


class _Gone(NotFoundError):
    """A `NotFoundError` subclass is still "not published"."""


@pytest.mark.parametrize(
    "error, is_failure",
    [
        (NotFoundError("no"), False),
        (_Gone("no"), False),
        (ToolError("boom"), True),
        (RuntimeError("down"), True),
        (asyncio.CancelledError(), True),
    ],
    ids=["not-found", "not-found-subclass", "tool-error", "runtime", "cancelled"],
)
def test_ask_excludes_only_not_found_error(error, is_failure):
    """Only `NotFoundError` (and its subclasses) is no failure; every other
    error a provider raises is one, a child-level `CancelledError` included
    (D1, codex pre-merge finding 3). Invariant: FailureRefusesOnlyOwned (a
    `NotFoundError` refuses nothing), FailureOnlyRefuses (any other error
    refuses). `KeyboardInterrupt` and `SystemExit` leave the event loop, so
    the router never classifies them."""
    from mcpflow.registry import ServerKey

    ga, gc = ServerKey.parse("ga"), ServerKey.parse("gc")
    routed = [(ga, _Fake(get=error)), (gc, _Fake(_fake_tool("gc_x")))]
    hits, failed = asyncio.run(CallerRouter._ask(routed, lambda p: p.get_tool("gc_x")))
    assert failed == ([ga] if is_failure else [])
    assert [k for k, _ in hits] == [gc]


def test_a_not_found_error_is_not_a_failure(collide, caplog):
    """A `NotFoundError` is not a failure. Invariant: FailureRefusesOnlyOwned
    (no refusal without a failed key; `github@bob` would own
    `github_create_close` if it had failed)."""
    env = collide
    env.grant("user", "alice", "server", "allow", "github@bob")
    env.clear_logs()
    caplog.clear()
    with failing(env, "github@bob", only=("get_tool",), exc=NotFoundError("no tool")), \
            caplog.at_level(logging.WARNING):
        assert env.call("alice", "github_create_close") == "github_create@alice:close"
    assert env.calls("github_create@alice") == ["call:close"]
    # No failure WARNING (a healthy clash on `github_create_issue` still logs).
    assert router_warnings(caplog, "failed") == []
    assert router_warnings(caplog, "github_create_close") == []


def test_a_tool_error_from_get_tool_is_a_failure(collide, caplog):
    """A `ToolError` from `get_tool` is a failure (D1). Invariant:
    FailureOnlyRefuses. `github_create_extra` is served when healthy, so the
    refusal comes from the failure, not from a clash."""
    env = collide
    env.grant("user", "alice", "server", "allow", "github@bob")
    assert env.call("alice", "github_create_extra") == "github@bob:create_extra"  # control
    env.clear_logs()
    caplog.clear()
    with failing(env, "github_create@alice", only=("get_tool",), exc=ToolError("boom")), \
            caplog.at_level(logging.WARNING):
        refused(env, "alice", "github_create_extra")
        no_child_ran(env)
        assert env.call("alice", "github_x") == "github@bob:x"
    assert router_warnings(caplog, "tool", "github_create_extra", "github_create@alice")


# --- 10.15 Decisions are live: one session, `time` with `cache_ttl` 300 -------


def in_one_session(env, uid, steps):
    """Run `steps(client)` in one live MCP session of `uid`."""
    async def go():
        async with env.client(uid) as c:
            return await steps(c)
    return asyncio.run(go())


def test_the_fixture_caches_time_for_300_seconds(env):
    """Precondition of 10.15: `time` has `cache_ttl` 300."""
    assert env.supervisor.get(env.children["time"].key).spec.cache_ttl == 300


def test_a_revoked_grant_stops_the_next_call(env):
    """A revoked grant stops the next call. Invariant: NoMcpLeak (stale)."""
    rule = env.grant("user", "alice", "tool", "allow", "time", "get_current_time")

    async def steps(c):
        assert "time_get_current_time" in {t.name for t in await c.list_tools()}
        assert (await c.call_tool("time_get_current_time", {})).data == "time:get_current_time"
        env.revoke(rule)
        with pytest.raises(ToolError, match="Unknown tool"):
            await c.call_tool("time_get_current_time", {})

    in_one_session(env, "alice", steps)
    assert env.calls("time") == ["call:get_current_time"]


def test_a_group_change_applies_at_once(env):
    """A group change applies at once. Invariant: NoMcpLeak (stale)."""
    env.identity.set_groups("alice", ["eng"])
    env.grant("group", "eng", "server", "allow", "time")

    async def steps(c):
        assert TIME <= {t.name for t in await c.list_tools()}
        env.identity.set_groups("alice", [])
        assert not TIME & {t.name for t in await c.list_tools()}
        with pytest.raises(ToolError, match="Unknown tool"):
            await c.call_tool("time_get_current_time", {})

    in_one_session(env, "alice", steps)
    assert env.calls("time") == []


def test_a_cached_child_list_grants_nothing(env):
    """A cached child list grants nothing. Invariant: NoMcpLeak (stale)."""
    env.grant("user", "alice", "server", "allow", "time")

    async def steps(c):
        assert TIME <= {t.name for t in await c.list_tools()}
        env.grant("user", "alice", "tool", "deny", "time", "get_current_time")
        with pytest.raises(ToolError, match="Unknown tool"):
            await c.call_tool("time_get_current_time", {})
        names = {t.name for t in await c.list_tools()}
        assert "time_get_current_time" not in names
        assert "time_convert_time" in names

    in_one_session(env, "alice", steps)
    assert env.calls("time") == []


def test_a_global_allow_keeps_private_servers_private_unique_namespace(collide):
    """A global allow keeps private servers private, where no shared server
    holds the namespace. Invariant: GlobalAllowNeverLeaksPrivate.

    In the main fixture an admin-owned `github` would shadow a leaked
    `github@alice`. Here `github_create@alice` is the only server of its
    namespace, so a global allow that covered it would show at once.
    """
    env = collide
    env.identity.set_groups("carol", ["eng"])
    env.grant("group", "eng", "global", "allow")
    names = env.names("carol")
    assert names == {"github_create_issue", "github_y"}, names
    refused(env, "carol", "github_create_close")
    assert env.calls("github_create@alice") == []
