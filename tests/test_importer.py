"""The JSON paste importer.

Scenarios from `specs/web-ui/spec.md` (JSON paste import). No test touches the
network: the importer parses pasted text only.
"""

from __future__ import annotations

import pytest

from mcpflow.importer import parse_config_block
from mcpflow.registry import RegistryError


def _one(text: str):
    specs = parse_config_block(text)
    assert len(specs) == 1
    return specs[0]


def test_valid_mcpservers_block():
    spec = _one(
        '{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@scope/pkg", "/data"]}}}'
    )
    assert spec.kind == "npm"
    # The package is the first argument that does not start with "-".
    assert spec.package == "@scope/pkg"
    assert spec.args == ["/data"]
    assert spec.namespace == "fs"


@pytest.mark.parametrize(
    "args",
    [
        ["-y", "--package=github:o/r", "bin", "/data"],
        ["-y", "--package", "github:o/r", "bin", "/data"],
        ["-y", "-p", "github:o/r", "bin", "/data"],
        ["-y", "-p=github:o/r", "bin", "/data"],
    ],
)
def test_npx_source_forms(args):
    import json

    spec = _one(json.dumps({"mcpServers": {"t": {"command": "npx", "args": args}}}))
    assert spec.kind == "npm"
    assert spec.package == "bin"
    assert spec.source == "github:o/r"
    assert spec.args == ["/data"]


def test_npx_two_package_flags_keep_first_no_flag_left():
    spec = _one(
        '{"mcpServers": {"t": {"command": "npx", "args": '
        '["-y", "--package", "github:a/one", "--package", "github:b/two", "bin"]}}}'
    )
    assert spec.source == "github:a/one"
    assert spec.package == "bin"
    assert "--package" not in spec.args and "-p" not in spec.args


def test_npx_flag_after_package_stays_an_arg():
    spec = _one(
        '{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@scope/pkg", "-p", "3000"]}}}'
    )
    assert spec.package == "@scope/pkg"
    assert spec.source is None
    assert spec.args == ["-p", "3000"]


@pytest.mark.parametrize(
    "args",
    [
        ["--from", "git+https://host/o/r", "pkg"],
        ["--from=git+https://host/o/r", "pkg"],
    ],
)
def test_uvx_source_forms(args):
    import json

    spec = _one(json.dumps({"mcpServers": {"t": {"command": "uvx", "args": args}}}))
    assert spec.kind == "python"
    assert spec.package == "pkg"
    assert spec.source == "git+https://host/o/r"


def test_reserved_entry_raises():
    # A block with a reserved entry (mcpflow_x) is rejected by spec_from_dict.
    with pytest.raises(RegistryError):
        parse_config_block(
            '{"mcpServers": {"mcpflow_x": {"command": "uvx", "args": ["x"]}}}'
        )


def test_unparsable_json_raises():
    with pytest.raises(RegistryError):
        parse_config_block("this is not json")
