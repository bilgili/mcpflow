"""A verifier child for change `child-actions-page`: schema and result sweeps.

Spawned as a `custom` child: `<python> fake_actions_sweep_child.py`.
Every tool carries `_meta["mcpflow"]["action"] = true`. Three groups:

- `pw_*`   : real pydantic secrets that the clause must keep flat. Each echoes
             its secret in a text block and in structured content.
- `bad_*`  : shapes that the clause must reject: real pydantic nesting, and raw
             input schemas that hold `$ref`, composition, or a secret outside
             `properties`. The raw schema replaces the generated one.
- `res_*`  : result shapes for the mirror rule.

`MCPFLOW_CALL_LOG` names a file the child appends one line to per tool call.
"""

import os
from typing import Annotated

from fastmcp import FastMCP
from fastmcp.tools.base import Tool, ToolResult
from mcp.types import TextContent
from pydantic import BaseModel, Field, SecretStr

TAG = {"mcpflow": {"action": True}}
PW = Field(json_schema_extra={"format": "password"})
_CALL_LOG = os.environ.get("MCPFLOW_CALL_LOG")

mcp = FastMCP("sweep")


def _record(name: str) -> None:
    if _CALL_LOG:
        with open(_CALL_LOG, "a") as f:
            f.write(name + "\n")


def _echo(name: str, secret: str) -> ToolResult:
    _record(name)
    return ToolResult(
        content=[TextContent(type="text", text=f"saw {secret}")],
        structured_content={"secret": secret},
    )


def _raw(fn, schema: dict) -> None:
    mcp.add_tool(Tool.from_function(fn, meta=TAG).model_copy(update={"parameters": schema}))


# --- pw_*: flat secrets --------------------------------------------------------


@mcp.tool(meta=TAG)
def pw_secretstr(key: SecretStr) -> ToolResult:
    return _echo("pw_secretstr", key.get_secret_value())


@mcp.tool(meta=TAG)
def pw_opt_secretstr(key: SecretStr | None = None) -> ToolResult:
    return _echo("pw_opt_secretstr", key.get_secret_value() if key else "")


@mcp.tool(meta=TAG)
def pw_annotated(key: Annotated[str, PW]) -> ToolResult:
    return _echo("pw_annotated", key)


@mcp.tool(meta=TAG)
def pw_opt_annotated(key: Annotated[str | None, PW] = None) -> ToolResult:
    return _echo("pw_opt_annotated", key or "")


def pw_opt_string(secret_key: str | None = None) -> ToolResult:
    return _echo("pw_opt_string", secret_key or "")


# Scenario "An optional password string stays flat", the exact property shape.
_raw(pw_opt_string, {"type": "object", "properties": {"secret_key": {
    "anyOf": [{"type": "string", "format": "password"}, {"type": "null"}]}}})


def pw_mirror(key: str) -> ToolResult:
    # Structured content, its exact JSON mirror, and a real text block that
    # echoes the secret: the mirror goes, the kept text is masked.
    _record("pw_mirror")
    import json

    structured = {"secret": key}
    return ToolResult(
        content=[
            TextContent(type="text", text=json.dumps(structured)),
            TextContent(type="text", text=f"stored {key}"),
        ],
        structured_content=structured,
    )


_raw(pw_mirror, {"type": "object", "properties": {"key": {"type": "string", "format": "password"}},
                 "required": ["key"]})


# --- bad_*: clause violators ------------------------------------------------------


class Cfg(BaseModel):
    user: str
    key: SecretStr


@mcp.tool(meta=TAG)
def bad_list_secretstr(keys: list[SecretStr]) -> str:
    _record("bad_list_secretstr")
    return "x"


@mcp.tool(meta=TAG)
def bad_dict_secretstr(keys: dict[str, SecretStr]) -> str:
    _record("bad_dict_secretstr")
    return "x"


@mcp.tool(meta=TAG)
def bad_model(cfg: Cfg) -> str:
    _record("bad_model")
    return "x"


@mcp.tool(meta=TAG)
def bad_opt_model(cfg: Cfg | None = None) -> str:
    _record("bad_opt_model")
    return "x"


@mcp.tool(meta=TAG)
def bad_tuple_secret(pair: tuple[str, SecretStr]) -> str:
    _record("bad_tuple_secret")
    return "x"


_DEFS = {"Cfg": {"type": "object", "properties": {"user": {"type": "string"}}}}


def _cfg_tool(name: str, prop: dict, defs: bool = True) -> None:
    def fn(cfg: str | None = None) -> str:
        _record(name)
        return "x"

    fn.__name__ = name
    schema = {"type": "object", "properties": {"cfg": prop}}
    if defs:
        schema["$defs"] = _DEFS
    _raw(fn, schema)


_cfg_tool("bad_ref", {"$ref": "#/$defs/Cfg"})
_cfg_tool("bad_allof", {"allOf": [{"$ref": "#/$defs/Cfg"}]})
_cfg_tool("bad_oneof", {"oneOf": [{"type": "string"}, {"type": "integer"}]}, defs=False)
_cfg_tool("bad_deep_not", {"type": "array", "items": {"type": "string", "not": {"const": ""}}},
          defs=False)
_cfg_tool("bad_opt_ref", {"anyOf": [{"$ref": "#/$defs/Cfg"}, {"type": "null"}]})
_cfg_tool("bad_items_pw", {"type": "array", "items": {"type": "string", "format": "password"}},
          defs=False)


def bad_outer(token: str | None = None) -> str:
    _record("bad_outer")
    return "x"


# Scenario "A secret declared outside properties is not flat", verbatim.
_raw(bad_outer, {"type": "object", "properties": {"token": {"type": "string"}},
                 "allOf": [{"properties": {"token": {"format": "password"}}}]})


# --- res_*: result shapes for the mirror rule -------------------------------------


def _result(name: str, texts: list[str], structured) -> None:
    def fn() -> ToolResult:
        _record(name)
        return ToolResult(
            content=[TextContent(type="text", text=t) for t in texts],
            structured_content=structured,
        )

    fn.__name__ = name
    mcp.add_tool(Tool.from_function(fn, meta=TAG))


_result("res_key_order", ['{"b":2,"a":1}'], {"a": 1, "b": 2})
_result("res_unicode", ['{"n":"\\u00fc\\u2603"}'], {"n": "ü☃"})
_result("res_float_int", ['{"n":1}'], {"n": 1.0})
_result("res_multi_mirror", ['{"a":1}', "real one", '{ "a" : 1 }', "real two"], {"a": 1})
_result("res_parses_other", ['{"name":"y"}'], {"name": "x"})
_result("res_str_quoted", ['"3"', "3"], {"result": "3"})
_result("res_int_as_float", ["3.0"], {"result": 3})
_result("res_two_keys", ["3"], {"result": 3, "x": 1})
_result("res_no_structured", ['{"a":1}', "plain"], None)
_result("res_deep_text", ["[" * 100_000], {"a": 1})


@mcp.tool(meta=TAG)
def res_list() -> list[int]:
    _record("res_list")
    return [1, 2]


@mcp.tool(meta=TAG)
def res_none() -> None:
    _record("res_none")


@mcp.tool(meta=TAG)
def res_bool() -> bool:
    _record("res_bool")
    return True


@mcp.tool
def plain() -> str:
    _record("plain")
    return "plain"


if __name__ == "__main__":
    mcp.run()
