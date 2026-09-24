"""Verifier tests for the 2026-09-17 amendment of change `child-actions-page`.

Derived from `specs/mcp-gateway/spec.md` (Action contract clause, Admin tools
are visible to admin sessions only), `specs/web-ui/spec.md` (Actions page,
mirror rule), and the frozen `is_secret`, `is_hash_reachable`, and mirror
contracts in `design.md`. Expectations come from the spec text, not from the
implementation:

- the secret invariant: a flat tool holds `format: password` only in the head
  of a top-level property, and that property renders a password control;
- the hash predicate: agreement with the real FastMCP 4.0.4
  `parse_hashed_backend_name` and `ProxyProvider.get_tool_by_hash`;
- list/call agreement per caller and tool class on one real provider chain;
- the mirror rule on real result shapes, and masking after the mirror drop.

Fixture child: `fake_actions_sweep_child.py`.
"""

from __future__ import annotations

import html
import json
import logging
import re
import sys
from pathlib import Path
from typing import Annotated

import pytest
from action_browser import action_post, control
from fastmcp import Client, FastMCP
from fastmcp.exceptions import NotFoundError, ToolError
from fastmcp.server.providers.addressing import hash_tool
from fastmcp.server.providers.proxy import ProxyProvider
from fastmcp.server.transforms import Namespace, Visibility
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from pydantic import BaseModel, Field, SecretStr
from test_child_actions import SECRET, call, cards, list_names, password_inputs, start
from test_visibility import admin, call_log

from mcpflow import web
from mcpflow.actions import (
    ActionScopeFilter,
    AuthorizedHashProvider,
    clause_violation,
    form_fields,
    is_secret,
)
from mcpflow.registry import ServerSpec

TAG = {"mcpflow": {"action": True}}
PW = {"type": "string", "format": "password"}
NULL = {"type": "null"}


# --- the secret invariant, from the spec text ----------------------------------


def _spec_head(prop: dict) -> list[dict]:
    """The head per the amended clause: `P`, plus the non-null member of an
    allowed `anyOf` (exactly two members, one `{"type": "null"}`, one dict with
    a string `type`)."""
    any_of = prop.get("anyOf")
    if isinstance(any_of, list) and len(any_of) == 2 and NULL in any_of:
        other = any_of[1] if any_of[0] == NULL else any_of[0]
        if isinstance(other, dict) and isinstance(other.get("type"), str):
            return [prop, other]
    return [prop]


def _password_dicts(value) -> list[int]:
    out, stack = [], [value]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if node.get("format") == "password":
                out.append(id(node))
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return out


def assert_secret_invariant(schema: dict) -> str:
    """Either the tool violates the clause, or every declared secret sits in a
    property head that renders a password control. Returns the verdict."""

    class T:
        meta = TAG
        input_schema = schema

    term = clause_violation(T())
    if term is not None:
        return "violator"
    props = schema.get("properties") or {}
    allowed = {}
    for name, prop in props.items():
        for d in _spec_head(prop):
            allowed[id(d)] = name
    controls = {f.name: f.control for f in form_fields(schema)}
    for pid in _password_dicts(schema):
        assert pid in allowed, f"declared secret outside a property head: {schema}"
        name = allowed[pid]
        assert controls[name] == "password", (name, controls, schema)
        assert is_secret(props[name]), (name, schema)
    return "password" if "password" in controls.values() else "flat"


def obj(props: dict, **outer) -> dict:
    return {"type": "object", "properties": props, **outer}


# Construct -> (schema, expected verdict). "password" means flat with a
# password control; "violator" means the clause rejects the tool.
SWEEP = {
    "prefixItems": (obj({"p": {"type": "array", "items": {"type": "string"},
                               "prefixItems": [PW]}}), "violator"),
    "items list": (obj({"p": {"type": "array", "items": [PW]}}), "violator"),
    "contains": (obj({"p": {"type": "array", "items": {"type": "string"},
                            "contains": PW}}), "violator"),
    "additionalProperties in prop": (obj({"p": {"additionalProperties": PW}}), "violator"),
    "additionalProperties outer": (obj({"p": {"type": "string"}}, additionalProperties=PW),
                                   "violator"),
    "patternProperties in prop": (obj({"p": {"patternProperties": {".*": PW}}}), "violator"),
    "patternProperties outer": (obj({"p": {"type": "string"}},
                                    patternProperties={"^p$": PW}), "violator"),
    "dependentSchemas outer": (obj({"p": {"type": "string"}, "q": {"type": "string"}},
                                   dependentSchemas={"q": {"properties": {"p": PW}}}),
                               "violator"),
    "dependentRequired + definitions": (obj({"p": {"type": "string"}},
                                            dependentRequired={"p": ["q"]},
                                            definitions={"x": PW}), "violator"),
    "if/then outer": (obj({"p": {"type": "string"}}, **{
        "if": {"required": ["p"]}, "then": {"properties": {"p": {"format": "password"}}}}),
        "violator"),
    "if/then in prop": (obj({"p": {"type": "string", "if": {"minLength": 1},
                                   "then": {"format": "password"}}}), "violator"),
    "else in prop": (obj({"p": {"type": "string", "if": {"minLength": 1},
                                "else": {"format": "password"}}}), "violator"),
    "unevaluatedProperties": (obj({"p": {"type": "string"}}, unevaluatedProperties=PW),
                              "violator"),
    "propertyNames": (obj({"p": {"type": "string"}}, propertyNames=PW), "violator"),
    "$defs + $ref": (obj({"p": {"$ref": "#/$defs/S"}}, **{"$defs": {"S": PW}}), "violator"),
    "$ref to a plain string": (obj({"p": {"$ref": "#/$defs/S"}},
                                   **{"$defs": {"S": {"type": "string"}}}), "violator"),
    "$defs secret unused": (obj({"p": {"type": "string"}}, **{"$defs": {"S": PW}}), "violator"),
    "$dynamicAnchor + $dynamicRef": (obj({"p": {"$dynamicRef": "#s"}}, **{
        "$defs": {"S": {**PW, "$dynamicAnchor": "s"}}}), "violator"),
    "$anchor on the property": (obj({"p": {**PW, "$anchor": "s"}}), "password"),
    "type [string, null]": (obj({"p": {"type": ["string", "null"], "format": "password"}}),
                            "password"),
    "type [null, string, integer]": (obj({"p": {"type": ["null", "string", "integer"],
                                                "format": "password"}}), "violator"),
    "enum + format": (obj({"p": {"type": "string", "enum": ["a"], "format": "password"}}),
                      "password"),
    "const + format, no type": (obj({"p": {"const": "x", "format": "password"}}), "violator"),
    "const + format + type": (obj({"p": {"type": "string", "const": "x",
                                         "format": "password"}}), "password"),
    "nested anyOf": (obj({"p": {"anyOf": [{"anyOf": [PW, NULL]}, NULL]}}), "violator"),
    "anyOf swapped": (obj({"p": {"anyOf": [NULL, PW]}}), "password"),
    "anyOf member without type": (obj({"p": {"anyOf": [{"format": "password"}, NULL]}}),
                                  "violator"),
    "anyOf three members": (obj({"p": {"anyOf": [PW, NULL, {"type": "integer"}]}}),
                            "violator"),
    "anyOf two non-null": (obj({"p": {"anyOf": [PW, {"type": "string"}]}}), "violator"),
    "optional array, items secret": (obj({"p": {"anyOf": [{"type": "array", "items": PW},
                                                          NULL]}}), "violator"),
    "format on an array": (obj({"p": {"type": "array", "items": {"type": "string"},
                                      "format": "password"}}), "violator"),
    "format, no type": (obj({"p": {"format": "password"}}), "violator"),
    "member type list": (obj({"p": {"anyOf": [{"type": ["string", "null"],
                                               "format": "password"}, NULL]}}), "violator"),
    "P integer, member secret string": (obj({"p": {"type": "integer",
                                                   "anyOf": [PW, NULL]}}), "violator"),
    "secret in default": (obj({"p": {"type": "string", "default": {"format": "password"}}}),
                          "violator"),
    "secret in examples": (obj({"p": {"type": "string",
                                      "examples": [{"format": "password"}]}}), "violator"),
    "not outer": (obj({"p": {"type": "string"}}, **{"not": {"properties": {"p": PW}}}),
                  "violator"),
    "inline properties secret": (obj({"p": {"properties": {"x": PW}}}), "violator"),
    "items of object with secret": (obj({"p": {"type": "array", "items": {
        "type": "object", "properties": {"k": PW}}}}), "violator"),
    "secret beside member format": (obj({"p": {"format": "password", "anyOf": [
        {"type": "string", "format": "date"}, NULL]}}), "password"),
    "secret in member beside string": (obj({"p": {"type": "string", "anyOf": [PW, NULL]}}),
                                       "password"),
}


@pytest.mark.parametrize("case", sorted(SWEEP))
def test_adversarial_schema_never_puts_a_secret_in_a_plain_control(case):
    schema, expected = SWEEP[case]
    assert assert_secret_invariant(schema) == expected


_PW_FIELD = Field(json_schema_extra={"format": "password"})


def test_is_secret_reads_only_the_head():
    # design.md: true iff some dict of the head holds `format: password`.
    assert is_secret(PW)
    assert is_secret({"anyOf": [NULL, PW]})
    assert is_secret({"format": "password", "anyOf": [{"type": "string", "format": "date"}, NULL]})
    assert not is_secret({"type": "array", "items": PW})
    assert not is_secret({"type": "string", "default": {"format": "password"}})
    assert not is_secret({"anyOf": [PW, NULL, {"type": "integer"}]})  # not allowed: head is [P]
    assert not is_secret({"anyOf": [{"format": "password"}, NULL]})  # member lacks a str type
    assert not is_secret({"anyOf": [{"anyOf": [PW, NULL]}, NULL]})
    for value in ("password", None, ["password"], {"format": "Password"}):
        assert not is_secret(value)


class _Cfg(BaseModel):
    user: str
    key: SecretStr


def _pydantic_server() -> FastMCP:
    s = FastMCP("sweep")


    @s.tool(meta=TAG)
    def secretstr(key: SecretStr) -> str: ...

    @s.tool(meta=TAG)
    def opt_secretstr(key: SecretStr | None = None) -> str: ...

    @s.tool(meta=TAG)
    def list_secretstr(keys: list[SecretStr]) -> str: ...

    @s.tool(meta=TAG)
    def set_secretstr(keys: set[SecretStr]) -> str: ...

    @s.tool(meta=TAG)
    def tuple_secretstr(pair: tuple[str, SecretStr]) -> str: ...

    @s.tool(meta=TAG)
    def dict_secretstr(keys: dict[str, SecretStr]) -> str: ...

    @s.tool(meta=TAG)
    def model_secretstr(cfg: _Cfg) -> str: ...

    @s.tool(meta=TAG)
    def opt_model(cfg: _Cfg | None = None) -> str: ...

    @s.tool(meta=TAG)
    def annotated_pw(key: Annotated[str, _PW_FIELD]) -> str: ...

    @s.tool(meta=TAG)
    def opt_annotated_pw(key: Annotated[str | None, _PW_FIELD] = None) -> str: ...

    return s


PYDANTIC = {
    "secretstr": "password", "opt_secretstr": "password", "annotated_pw": "password",
    "opt_annotated_pw": "password", "list_secretstr": "violator", "set_secretstr": "violator",
    "tuple_secretstr": "violator", "dict_secretstr": "violator",
    "model_secretstr": "violator", "opt_model": "violator",
}


@pytest.mark.asyncio
async def test_real_pydantic_secrets_are_password_controls_or_violators():
    async with Client(_pydantic_server()) as c:
        schemas = {t.name: t.input_schema for t in await c.list_tools()}
    assert set(schemas) == set(PYDANTIC)
    got = {name: assert_secret_invariant(schema) for name, schema in schemas.items()}
    assert got == PYDANTIC


# --- list/call agreement per caller and tool class ------------------------------

APP = {"visibility": ["app"]}

# Tool classes of one child, and the per-caller outcome the F1 model gives.
UPPER = "ABCDEF012345"


def _classes_child(log: list[str]) -> FastMCP:
    child = FastMCP("child")

    def add(name, meta, fn_arg=False):
        if fn_arg:
            def fn(cfg: dict) -> str:
                log.append(name)
                return name
        else:
            def fn() -> str:
                log.append(name)
                return name
        fn.__name__ = name
        child.tool(meta=meta)(fn)

    hashed = {"fastmcp": {"tool_hash": hash_tool("child", "hashed")}, "ui": APP}
    add("plain", None)
    add("action", TAG)
    add("hashed", {**TAG, **hashed})
    add("violator", TAG, fn_arg=True)
    add("fakehash", {**TAG, "fastmcp": {"tool_hash": UPPER}, "ui": APP})
    real = hash_tool("child", "nonhex")
    add("nonhex", {**TAG, "fastmcp": {"tool_hash": "g" + real[1:]}, "ui": APP})
    add("short", {**TAG, "fastmcp": {"tool_hash": hash_tool("child", "short")[:11]}, "ui": APP})
    add("long", {**TAG, "fastmcp": {"tool_hash": hash_tool("child", "long") + "0"}, "ui": APP})
    add("half", {**TAG, "fastmcp": {"tool_hash": hash_tool("child", "half")}})
    add("muted_action", TAG)
    add("muted_hashed", {**TAG, "fastmcp": {"tool_hash": hash_tool("child", "muted_hashed")},
                         "ui": APP})
    return child


def _gateway(child: FastMCP) -> FastMCP:
    # F1/F2 revised: the real capable chain. ActionScopeFilter innermost, then
    # the visibility and namespace transforms, then AuthorizedHashProvider
    # outermost so the hashed path re-runs the named decision.
    provider = ProxyProvider(lambda: Client(child))
    provider.add_transform(ActionScopeFilter())
    vis = Visibility(False, names={"muted_action", "muted_hashed"})
    chain = provider.wrap_transform(vis).wrap_transform(Namespace("c"))
    gateway = FastMCP("gw")
    gateway.add_provider(AuthorizedHashProvider(chain, "c"))
    return gateway


def _as(scopes):
    if scopes is None:
        return auth_context_var.set(None)
    return auth_context_var.set(
        AuthenticatedUser(AccessToken(token="", client_id="verifier", scopes=scopes))
    )


async def _runs(gateway, name, args) -> bool:
    try:
        await gateway.call_tool(name, args)
        return True
    except (NotFoundError, ToolError) as exc:
        assert "Unknown tool" in str(exc), exc
        return False


LISTED = {
    # tool: (non-admin listed, admin listed). F1: every tagged tool, the
    # hash-reachable `hashed` included, is now hidden from a non-admin session.
    "plain": (True, True), "action": (False, True), "hashed": (False, True),
    "violator": (False, True), "fakehash": (False, True), "half": (False, True),
    "nonhex": (False, True), "short": (False, True), "long": (False, True),
    "muted_action": (False, False), "muted_hashed": (False, False),
}
HASHED_NAMES = {
    "action": [f"{hash_tool('child', 'action')}_action", f"{'0' * 12}_action"],
    "hashed": [f"{hash_tool('child', 'hashed')}_hashed"],
    "fakehash": [f"{UPPER}_fakehash", f"{UPPER.lower()}_fakehash"],
    "half": [f"{hash_tool('child', 'half')}_half"],
    "nonhex": [f"{hash_tool('child', 'nonhex')}_nonhex"],
    "short": [f"{hash_tool('child', 'short')}_short"],
    "long": [f"{hash_tool('child', 'long')}_long"],
    "muted_hashed": [f"{hash_tool('child', 'muted_hashed')}_muted_hashed"],
}


@pytest.mark.asyncio
@pytest.mark.parametrize("scopes", [None, ["mcp"], ["admin"], ["mcp", "admin"], []])
async def test_list_and_call_agree_per_caller_and_tool_class(scopes):
    log: list[str] = []
    gateway = _gateway(_classes_child(log))
    is_admin = scopes is not None and "admin" in scopes
    reset = _as(scopes)
    try:
        listed = {t.name for t in await gateway.list_tools()}
        for tool, (other, adm) in LISTED.items():
            want = adm if is_admin else other
            assert (f"c_{tool}" in listed) is want, (tool, scopes)
            args = {"cfg": {}} if tool == "violator" else {}
            log.clear()
            ran = await _runs(gateway, f"c_{tool}", args)
            # Named call agrees with the list, for every class and caller.
            assert ran is want, (tool, scopes)
            assert (log == [tool]) is want
        for tool, names in HASHED_NAMES.items():
            for name in names:
                log.clear()
                ran = await _runs(gateway, name, {})
                # F1: the AuthorizedHashProvider re-runs the named decision on
                # the tool the hashed path resolves. A non-admin caller reaches
                # NO tagged tool by hash. An admin reaches only a
                # hash-addressable, unmuted tool (here `hashed`); a muted tool
                # (`muted_hashed`) never runs by hash for any scope.
                expected = is_admin and tool == "hashed"
                assert ran is expected, (name, scopes)
                assert (log == [tool]) is expected
                if ran:
                    assert f"c_{tool}" in listed  # admin lists what it runs by hash
    finally:
        auth_context_var.reset(reset)
    assert auth_context_var.get() is None


# --- the mirror rule: condition matrix -------------------------------------------

MIRROR = [
    # (text, structured, is mirror)
    ('{"name":"s3main"}', {"name": "s3main"}, True),
    ('{"b":2,"a":1}', {"a": 1, "b": 2}, True),
    ('{"n":"\\u00fc"}', {"n": "ü"}, True),
    ('{"n":"ü"}', {"n": "ü"}, True),
    (' {"a" : 1}\n', {"a": 1}, True),
    ('{"ok":1}', {"ok": True}, False),
    ('{"ok":true}', {"ok": 1}, False),
    ('{"n":1}', {"n": 1.0}, False),
    ('{"n":1.0}', {"n": 1}, False),
    ('{"name":"y"}', {"name": "x"}, False),
    ('{"a":1}', None, False),
    ("done", {"result": "done"}, True),
    ('"done"', {"result": "done"}, False),
    ("3", {"result": "3"}, True),
    ("3", {"result": 3}, True),
    ("3.0", {"result": 3}, False),
    ("true", {"result": True}, True),
    ("1", {"result": True}, False),
    ("null", {"result": None}, True),
    ("[1,2]", {"result": [1, 2]}, True),
    ("[2,1]", {"result": [1, 2]}, False),
    ('{"result":3}', {"result": 3}, True),
    ("3", {"result": 3, "x": 1}, False),
    ("not json", {"a": 1}, False),
    ("[" * 100_000, {"a": 1}, False),
    ("[" * 100_000, {"result": [1]}, False),
    ("NaN", {"result": "NaN"}, True),
    ("", {"result": ""}, True),
]


@pytest.mark.parametrize(("text", "structured", "mirror"), MIRROR)
def test_mirror_condition_matrix(text, structured, mirror):
    assert web._is_mirror(text, structured) is mirror


# --- live: the sweep child through the page and /mcp ------------------------------

SWEEP_CHILD = str(Path(__file__).parent / "fake_actions_sweep_child.py")
PAGE = "/servers/sweep/actions"
PW_TOOLS = ["pw_secretstr", "pw_opt_secretstr", "pw_annotated", "pw_opt_annotated",
            "pw_opt_string", "pw_mirror"]
BAD_TERMS = {
    "bad_list_secretstr": "schema:keys", "bad_dict_secretstr": "schema:keys",
    "bad_model": "schema:cfg", "bad_opt_model": "schema:cfg",
    "bad_tuple_secret": "schema:pair", "bad_ref": "schema:cfg", "bad_allof": "schema:cfg",
    "bad_oneof": "schema:cfg", "bad_deep_not": "schema:cfg", "bad_opt_ref": "schema:cfg",
    "bad_items_pw": "schema:cfg", "bad_outer": "schema",
}


def sweep_spec() -> ServerSpec:
    # F2 revised: the sweep child is action-capable, so mcpflow honours its tags.
    return ServerSpec(namespace="sweep", kind="custom", command=sys.executable,
                      args=[SWEEP_CHILD], actions=True)


def _field(tool: str) -> str:
    return "secret_key" if tool == "pw_opt_string" else "key"


def _result_pres(body: str) -> list[str]:
    m = re.search(r'<div class="result">(.*?)</div>', body, re.DOTALL)
    if not m:
        return []
    return [html.unescape(p) for p in re.findall(r"<pre>(.*?)</pre>", m.group(1), re.DOTALL)]


def _variants(secret: str) -> set[str]:
    raw = {secret, json.dumps(secret)[1:-1], json.dumps(secret, ensure_ascii=False)[1:-1]}
    return raw | {html.escape(v) for v in raw} | {html.escape(v, quote=False) for v in raw}


def test_violators_hidden_from_mcp_listed_for_admin_absent_from_page(server_factory, caplog):
    caplog.set_level(logging.WARNING, logger="mcpflow.supervisor")
    server, h = start(server_factory, sweep_spec())
    caplog.clear()
    with admin(server) as client:
        page = cards(client.get(PAGE).text)
    assert not set(BAD_TERMS) & set(page)
    assert set(PW_TOOLS) <= set(page)
    warnings = [r.getMessage() for r in caplog.records
                if r.name == "mcpflow.supervisor" and r.levelno == logging.WARNING]
    for tool, term in BAD_TERMS.items():
        assert warnings.count(f"sweep: tool {tool} is not an action: {term}") == 1, tool
    mcp = set(list_names(server.base_url, h["mcp"]))
    adm = set(list_names(server.base_url, h["admin"]))
    assert "sweep_plain" in mcp
    for tool in [*BAD_TERMS, *PW_TOOLS]:
        assert f"sweep_{tool}" not in mcp, tool
        assert f"sweep_{tool}" in adm, tool
    for tool in BAD_TERMS:
        with pytest.raises(ToolError, match="Unknown tool"):
            call(server.base_url, h["mcp"], f"sweep_{tool}", {})
    assert call_log(server) == []


def test_every_real_secret_renders_a_password_control_and_is_masked(server_factory, caplog):
    caplog.set_level(logging.DEBUG)
    server, _h = start(server_factory, sweep_spec())
    with admin(server) as client:
        page = cards(client.get(PAGE).text)
        for tool in PW_TOOLS:
            inputs = password_inputs(page[tool])
            assert len(inputs) == 1 and "value=" not in inputs[0], tool
            assert inputs[0] == control(page[tool], _field(tool)), tool
            resp = action_post(client, f"{PAGE}/{tool}", data={_field(tool): SECRET})
            assert resp.status_code == 200, (tool, resp.text)
            assert SECRET not in resp.text, tool
            assert "***" in "".join(_result_pres(resp.text)), tool
            rerender = password_inputs(cards(resp.text)[tool])
            assert len(rerender) == 1 and "value=" not in rerender[0]
    assert sorted(call_log(server)) == sorted(PW_TOOLS)
    assert not [r for r in caplog.records if SECRET in r.getMessage()]


def test_mask_runs_after_the_mirror_drop(server_factory):
    server, _h = start(server_factory, sweep_spec())
    with admin(server) as client:
        resp = action_post(client, f"{PAGE}/pw_mirror", data={"key": SECRET})
    assert resp.status_code == 200
    # The JSON mirror of the structured content is dropped on the raw text;
    # the kept text block still has its secret masked.
    assert _result_pres(resp.text) == ['{\n  "secret": "***"\n}', "stored ***"]


@pytest.mark.parametrize("secret", ['ü"S3CRET-5', "ü\\S3CRET-6", "é\tS3CRET-7"])
def test_non_ascii_secret_with_a_json_escape_is_masked(server_factory, secret):
    # Requirement: every posted `format: password` value reads `***` in the
    # rendered result. The structured content renders as JSON with
    # `ensure_ascii=False`, so the secret appears as `ü\"S3CRET` there.
    server, _h = start(server_factory, sweep_spec())
    with admin(server) as client:
        resp = action_post(client, f"{PAGE}/pw_annotated", data={"key": secret})
    assert resp.status_code == 200
    block = "".join(_result_pres(resp.text))
    raw_block = re.search(r'<div class="result">(.*?)</div>', resp.text, re.DOTALL).group(1)
    for v in _variants(secret):
        assert v not in block and v not in raw_block, v


def _pretty(value) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False)


RESULTS = {
    "res_key_order": [_pretty({"a": 1, "b": 2})],
    "res_unicode": [_pretty({"n": "ü☃"})],
    "res_float_int": [_pretty({"n": 1.0}), '{"n":1}'],
    "res_multi_mirror": [_pretty({"a": 1}), "real one", "real two"],
    "res_parses_other": [_pretty({"name": "x"}), '{"name":"y"}'],
    "res_str_quoted": [_pretty({"result": "3"}), '"3"'],
    "res_int_as_float": [_pretty({"result": 3}), "3.0"],
    "res_two_keys": [_pretty({"result": 3, "x": 1}), "3"],
    "res_no_structured": ['{"a":1}', "plain"],
    "res_list": [_pretty({"result": [1, 2]})],
    "res_bool": [_pretty({"result": True})],
    "res_none": [],
    "res_deep_text": [_pretty({"a": 1}), "[" * 100_000],
}


def test_result_shapes_follow_the_mirror_rule(server_factory):
    server, _h = start(server_factory, sweep_spec())
    with admin(server) as client:
        got = {}
        for tool in RESULTS:
            resp = action_post(client, f"{PAGE}/{tool}")
            assert resp.status_code == 200, (tool, resp.text[:500])
            got[tool] = _result_pres(resp.text)
    assert got == RESULTS
