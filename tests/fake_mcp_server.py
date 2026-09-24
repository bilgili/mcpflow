"""A fake child MCP server for the verifier suite.

The supervisor spawns this over stdio as a `custom` child:
`<python> fake_mcp_server.py <mode> [arg]`.

Modes:
- `good`   : serve one tool `get_current_time(timezone: string)`.
- `two`    : serve `get_current_time` and `convert_time`, so a test can mute
             one tool and assert the sibling survives.
- `slow`   : like `two`, but wait for the file named by `MCPFLOW_RELEASE`
             before serving, so a test can act while the child status is
             still `starting` without racing a fixed sleep.
- `fail`   : write an error to stderr and exit non-zero (probe failure).
- `hang`   : sleep without speaking MCP (probe timeout).
- `skills` : serve one tool `diagnosing-bugs`, one prompt of the same name,
             one resource `skill://diagnosing-bugs/scripts/x.sh`, and one
             resource template `skill://{name}/SKILL.md`, so a test can see
             how the gateway publishes and hides every component kind.
- `grow`   : serve tool and prompt `get_current_time`. While the file named
             by `MCPFLOW_GROW` exists, every list also shows tool and prompt
             `extra`, so a test adds components with no restart.
- `instructions` : serve `get_current_time` and a concrete resource
             `instructions://self` whose body is the file named by
             `INSTRUCTIONS_FILE`, read on each request.
- `slowres` : serve `get_current_time` and an `instructions://self` whose
             read never returns. The start is normal.
- `bigres` : serve `get_current_time` and an `instructions://self` that
             returns 20000 bytes.
- `action` : serve tools under `_meta["mcpflow"]["action"]`. Conforming
             actions `set_writable(name)` (raises `ToolError` for `git1`) and
             `add_store` (every control kind, a `format: password` field, a
             result that echoes the secret, a `ToolError` that echoes it for
             the name `fail`); ordinary `list_stores`; the
             hashed variant `hashed` (tagged, with `ui.visibility` and
             `fastmcp.tool_hash`); `yes_tag` (tag value `"yes"`);
             `nested` (an `object` property); `nested_pw` (a password
             property of type `array`). While the file named by
             `MCPFLOW_BREAK` exists, `tools/list` fails.

`MCPFLOW_CALL_LOG` names a file the child appends one line to per tool call.
A test reads it to prove a refused call never reached the child.

`MCPFLOW_PID_FILE` names a file the child appends its process id to at start.
A test reads it to prove a child was not respawned.

`MCPFLOW_HANG_LIST` (action mode) names a file. While it exists, `tools/list`
never returns, so a lease holder keeps its lease open. A test creates the file
after the child is running, then cancels a read or holds a lease past the
teardown drain bound.
"""

import os
import sys
import time

_MODE = sys.argv[1] if len(sys.argv) > 1 else "good"
_ARG = sys.argv[2] if len(sys.argv) > 2 else None
_CALL_LOG = os.environ.get("MCPFLOW_CALL_LOG")

# Amendment 4 (codex review 3) fixture secrets. Static strings a test configures
# as the child's `env` secrets (F4) or that a child echoes back (F1). Distinct
# from the shared verifier SECRET so they never collide with other tests.
R3_LEAK_DEFAULT = "ZZR3-LEAK-hush-dd-01"
R3_TITLE_SECRET = "ZZR3-TITLE-hush-aa-02"
R3_DESC_SECRET = "ZZR3-DESC-hush-bb-03"
R3_DEFAULT_SECRET = "ZZR3-DFLT-hush-cc-04"


def _record(name: str) -> None:
    if not _CALL_LOG:
        return
    with open(_CALL_LOG, "a") as f:
        f.write(name + "\n")


def _main() -> None:
    pid_file = os.environ.get("MCPFLOW_PID_FILE")
    if pid_file:
        with open(pid_file, "a") as f:
            f.write(f"{os.getpid()}\n")
    if _MODE == "fail":
        sys.stderr.write("child boom: could not start the server\n")
        sys.stderr.flush()
        sys.exit(1)
    if _MODE == "hang":
        time.sleep(300)
        return
    if _MODE == "slow":
        # Block until the test releases us. A fixed sleep would race a slow
        # CI box or a slow login hash.
        release = os.environ.get("MCPFLOW_RELEASE")
        deadline = time.time() + 60
        while release and not os.path.exists(release) and time.time() < deadline:
            time.sleep(0.05)

    from fastmcp import FastMCP

    mcp = FastMCP("fake")

    if _MODE == "skills":
        # The tool and the prompt share a name, so one mute shows its reach
        # over both kinds; the resource and the template must survive it.
        @mcp.tool(name="diagnosing-bugs")
        def diagnosing_bugs_tool() -> str:
            "A tool named like the prompt."
            _record("diagnosing-bugs")
            return "tool"

        @mcp.prompt(name="diagnosing-bugs")
        def diagnosing_bugs_prompt() -> str:
            "A skill prompt."
            _record("prompt:diagnosing-bugs")
            return "# diagnosing-bugs\nbody"

        @mcp.resource(
            "skill://diagnosing-bugs/scripts/x.sh", mime_type="text/x-shellscript"
        )
        def script() -> str:
            _record("resource:skill://diagnosing-bugs/scripts/x.sh")
            return "#!/bin/sh\necho x\n"

        @mcp.resource("skill://{name}/SKILL.md")
        def skill_md(name: str) -> str:
            _record(f"template:skill://{name}/SKILL.md")
            return "# " + name

        mcp.run()
        return

    @mcp.tool
    def get_current_time(timezone: str = "UTC") -> str:
        "Return the current time in a timezone."
        _record("get_current_time")
        return "2026-01-01T00:00:00Z"

    if _MODE == "grow":
        from fastmcp.server.middleware import Middleware

        grow = os.environ.get("MCPFLOW_GROW")

        def grown() -> bool:
            return bool(grow) and os.path.exists(grow)

        class Grow(Middleware):
            # Checked on every list, so the catalog grows the moment the file
            # appears. A lookup by name on the child itself always resolves.
            async def on_list_tools(self, context, call_next):
                tools = await call_next(context)
                return tools if grown() else [t for t in tools if t.name != "extra"]

            async def on_list_prompts(self, context, call_next):
                prompts = await call_next(context)
                return (
                    prompts if grown() else [p for p in prompts if p.name != "extra"]
                )

        mcp.add_middleware(Grow())

        @mcp.tool
        def extra() -> str:
            "A tool that appears when the child grows."
            _record("extra")
            return "extra"

        @mcp.prompt(name="get_current_time")
        def time_prompt() -> str:
            "A prompt present from the start."
            return "time"

        @mcp.prompt(name="extra")
        def extra_prompt() -> str:
            "A prompt that appears when the child grows."
            return "extra"

    if _MODE == "instructions":

        @mcp.resource("instructions://self", mime_type="text/markdown")
        def instructions() -> str:
            with open(os.environ["INSTRUCTIONS_FILE"]) as f:
                return f.read()

    if _MODE == "slowres":
        import asyncio

        @mcp.resource("instructions://self", mime_type="text/markdown")
        async def instructions_hang() -> str:
            await asyncio.sleep(3600)
            return "never"

    if _MODE == "bigres":

        @mcp.resource("instructions://self", mime_type="text/plain")
        def instructions_big() -> str:
            return "x" * 20000

    if _MODE == "action":
        from typing import Annotated, Any, Literal

        from fastmcp.exceptions import ToolError
        from fastmcp.server.providers.addressing import hash_tool
        from pydantic import Field

        tag = {"mcpflow": {"action": True}}

        brk = os.environ.get("MCPFLOW_BREAK")
        if brk:
            from fastmcp.server.middleware import Middleware

            class Break(Middleware):
                # While the file exists, `tools/list` fails, so the actions
                # page renders its probe-failure frame on a running child.
                async def on_list_tools(self, context, call_next):
                    if os.path.exists(brk):
                        raise RuntimeError("transport closed")
                    return await call_next(context)

            mcp.add_middleware(Break())

        hang = os.environ.get("MCPFLOW_HANG_LIST")
        if hang:
            import asyncio as _asyncio

            from fastmcp.server.middleware import Middleware

            class HangList(Middleware):
                # While the file exists, `tools/list` never returns, so a lease
                # holder (a probe or the actions read) keeps its lease open. A
                # test uses it to cancel a read mid-flight or to hold a lease
                # past the teardown drain bound. The child process stays alive;
                # only the one list call hangs.
                async def on_list_tools(self, context, call_next):
                    while os.path.exists(hang):
                        await _asyncio.sleep(0.05)
                    return await call_next(context)

            mcp.add_middleware(HangList())
        password = Field(json_schema_extra={"format": "password"})

        @mcp.tool(meta=tag)
        def set_writable(name: str) -> str:
            "Make one read/write-capable store the writable one."
            _record("set_writable")
            if name == "git1":
                raise ToolError("git1 is read-only")
            return f"writable: {name}"

        @mcp.tool(meta=tag)
        def add_store(
            name: str,
            kind: Literal["git", "directory", "s3"],
            secret_key: Annotated[str, password],
            port: int | None = None,
            ratio: float | None = None,
            tags: list[str] | None = None,
            path_style: bool = False,
            extra: Any = None,
        ) -> dict:
            "Register a git, directory, or s3 store."
            _record("add_store")
            if name == "fail":
                raise ToolError(f"rejected secret {secret_key}")
            return {
                "name": name,
                "kind": kind,
                "secret_key": secret_key,
                "port": port,
                "ratio": ratio,
                "tags": tags,
                "path_style": path_style,
                "extra": extra,
            }

        @mcp.tool
        def list_stores() -> str:
            "List stores."
            _record("list_stores")
            return "git1, dir1"

        @mcp.tool(
            meta={
                **tag,
                "ui": {"visibility": ["app"]},
                "fastmcp": {"tool_hash": hash_tool("fake", "hashed")},
            }
        )
        def hashed() -> str:
            "A tagged tool on the hashed path."
            _record("hashed")
            return "hashed"

        @mcp.tool(meta={"mcpflow": {"action": "yes"}})
        def yes_tag() -> str:
            "A tag that is not the boolean true."
            _record("yes_tag")
            return "yes"

        @mcp.tool(meta=tag)
        def nested(cfg: dict) -> str:
            "A tagged tool with an object property."
            _record("nested")
            return "nested"

        @mcp.tool(meta=tag)
        def nested_pw(keys: Annotated[list[str], password]) -> str:
            "A tagged tool with an array password."
            _record("nested_pw")
            return "nested_pw"

        @mcp.tool(meta={**tag, "fastmcp": {"tool_hash": hash_tool("fake", "half")}})
        def half() -> str:
            "A tagged tool with a tool_hash and no ui key."
            _record("half")
            return "half"

        @mcp.tool(
            meta={
                **tag,
                "ui": {"visibility": ["app"]},
                "fastmcp": {"tool_hash": "ABCDEF012345"},
            }
        )
        def fake() -> str:
            "A tagged tool with an uppercase tool_hash."
            _record("fake")
            return "fake"

        # `MCPFLOW_RETAG` names a file. While it exists, the child re-tags the
        # ordinary tool `rotate_keys` as a conforming action, with no restart.
        # A test uses it to prove that an action-capable child (`cache_ttl=0`)
        # classifies the live tool: an mcp session that lists or calls
        # `rotate_keys` after the tag reads the tag, never a stale ordinary form.
        retag = os.environ.get("MCPFLOW_RETAG")
        if retag:
            from fastmcp.server.middleware import Middleware

            class Retag(Middleware):
                async def on_list_tools(self, context, call_next):
                    tools = await call_next(context)
                    if os.path.exists(retag):
                        for t in tools:
                            if t.name == "rotate_keys":
                                t.meta = {**(t.meta or {}), "mcpflow": {"action": True}}
                    return tools

            mcp.add_middleware(Retag())

            @mcp.tool
            def rotate_keys() -> str:
                "An ordinary tool a test re-tags as an action at runtime."
                _record("rotate_keys")
                return "rotated"

        if _ARG == "more":
            from fastmcp.tools.base import ToolResult
            from mcp.types import TextContent
            from pydantic import WithJsonSchema

            @mcp.tool(meta=tag)
            def report(name: str) -> ToolResult:
                "Structured content, its JSON mirror, and one real text block."
                _record("report")
                return ToolResult(
                    content=[
                        TextContent(type="text", text=f'{{"name":"{name}"}}'),
                        TextContent(type="text", text="store added"),
                    ],
                    structured_content={"name": name},
                )

            @mcp.tool(meta=tag)
            def differ() -> ToolResult:
                "A text block that differs from the structured content."
                _record("differ")
                return ToolResult(
                    content=[TextContent(type="text", text='{"ok":1}')],
                    structured_content={"ok": True},
                )

            @mcp.tool(meta=tag)
            def count() -> int:
                "A wrapped int."
                _record("count")
                return 3

            @mcp.tool(meta=tag)
            def finish() -> str:
                "A wrapped str."
                _record("finish")
                return "done"

            member_pw = WithJsonSchema(
                {"type": "string", "anyOf": [{"type": "string", "format": "password"},
                                             {"type": "null"}]}
            )
            beside_pw = WithJsonSchema(
                {"format": "password", "anyOf": [{"type": "string", "format": "date"},
                                                 {"type": "null"}]}
            )

            @mcp.tool(meta=tag)
            def member_secret(key: Annotated[str | None, member_pw] = None) -> str:
                "A password in the anyOf member."
                _record("member_secret")
                return f"got {key}"

            @mcp.tool(meta=tag)
            def beside_secret(key: Annotated[str | None, beside_pw] = None) -> str:
                "A password beside a member format."
                _record("beside_secret")
                return f"got {key}"

            default_pw = Field(
                default="D3FAULT-SECRET-9",
                json_schema_extra={"format": "password"},
            )

            @mcp.tool(meta=tag)
            def defaulted(secret_key: Annotated[str, default_pw] = "D3FAULT-SECRET-9") -> str:
                "A conforming action whose password property carries a default."
                _record("defaulted")
                return "ok"

            # Amendment 3 (codex review 2) fixtures.
            from fastmcp.tools.base import Tool

            # F2: echo the posted secret in an output field declared
            # `format: date-time`, which the FastMCP structured-result parser
            # rejects. The raw result API (`call_tool_mcp`) runs no parser.
            @mcp.tool(
                meta=tag,
                output_schema={
                    "type": "object",
                    "properties": {"when": {"type": "string", "format": "date-time"}},
                    "required": ["when"],
                },
            )
            def parse_fail(secret_key: Annotated[str, password]) -> dict:
                "Return the posted secret in a field the structured parser rejects."
                _record("parse_fail")
                return {"when": secret_key}

            # F3: return the posted secret as a dict KEY, not a value.
            @mcp.tool(meta=tag)
            def keyed(secret_key: Annotated[str, password]) -> dict:
                "Return the posted secret as a structured-content key."
                _record("keyed")
                return {secret_key: "ok"}

            # F4: a conforming password property that carries an `enum` literal.
            # An omitted optional value takes the child-side default `S3CRET`.
            def enumed(secret_key: str = "S3CRET") -> str:
                _record("enumed")
                return f"stored {secret_key}"

            mcp.add_tool(
                Tool.from_function(enumed, meta=tag).model_copy(
                    update={
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "secret_key": {
                                    "type": "string",
                                    "format": "password",
                                    "enum": ["S3CRET"],
                                }
                            },
                        }
                    }
                )
            )

            # F7: a tagged tool with a malformed root schema (`required` is not a
            # list of strings). It must fail the clause and never build a view.
            def bad_root(name: str = "") -> str:
                _record("bad_root")
                return "x"

            mcp.add_tool(
                Tool.from_function(bad_root, meta=tag).model_copy(
                    update={
                        "parameters": {
                            "type": "object",
                            "properties": {"name": {"type": "string"}},
                            "required": [{}],
                        }
                    }
                )
            )

            # --- Amendment 4 (codex review 3) fixtures ------------------------
            from fastmcp import Context

            # F1 (mask binds to the execution listing): an optional password
            # property whose child-side default is echoed in the result. When the
            # admin submits the field empty, the child runs with the default and
            # returns it. `run_action` collects the default through
            # `secret_literals` on its OWN listing, so the mask covers it.
            leak_pw = Field(
                default=R3_LEAK_DEFAULT, json_schema_extra={"format": "password"}
            )

            @mcp.tool(meta=tag)
            def echo_default(
                secret_key: Annotated[str, leak_pw] = R3_LEAK_DEFAULT,
            ) -> str:
                "Echo the password argument, which defaults to a child-side secret."
                _record("echo_default")
                return f"used {secret_key}"

            # F2 (sink 2): echo the posted secret in a child LOG notification. The
            # supervisor's child `Client` uses a drop `log_handler`, so no log line
            # holds the secret. Without the drop handler the default handler would
            # log it.
            @mcp.tool(meta=tag)
            async def log_secret(
                secret_key: Annotated[str, password], ctx: Context
            ) -> str:
                "Send the posted secret in a child log notification."
                _record("log_secret")
                await ctx.info(f"received {secret_key}")
                return "logged"

            # F4 (display sanitation): a configured secret in a property title, a
            # property description, and an ordinary property default. The page and
            # the schema disclosure must mask each. The values are static; the test
            # configures them as `env` secrets of the child.
            titled_field = Field(
                description=R3_DESC_SECRET,
                json_schema_extra={"title": R3_TITLE_SECRET},
            )

            @mcp.tool(meta=tag)
            def titled(
                label: Annotated[str, titled_field] = "",
                region: str = R3_DEFAULT_SECRET,
            ) -> str:
                "A tool whose schema carries configured secrets in display fields."
                _record("titled")
                return "ok"

            # F5 (numeric scalar): the posted password comes back as a numeric
            # scalar in the structured content.
            @mcp.tool(meta=tag)
            def numeric(secret_key: Annotated[str, password]) -> dict:
                "Return the posted password as an integer scalar."
                _record("numeric")
                return {"n": int(secret_key)}

            # F8 (collision-safe keys): two configured secrets as dict keys. Both
            # entries must survive, the masked keys disambiguated.
            @mcp.tool(meta=tag)
            def two_keys() -> dict:
                "Return two configured secrets as colliding dict keys."
                _record("two_keys")
                return {"SECRET_A": "failed", "SECRET_B": "succeeded"}

        mcp.run()
        return

    if _MODE in ("two", "slow"):

        @mcp.tool
        def convert_time(timezone: str = "UTC") -> str:
            "Convert a time to a timezone."
            _record("convert_time")
            return "2026-01-01T12:00:00Z"

    mcp.run()


if __name__ == "__main__":
    _main()
