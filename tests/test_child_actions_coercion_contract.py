"""Pure coercion and redaction contracts from the Amendment 5 correction candidate."""

import math
from copy import deepcopy
from types import MappingProxyType

import pytest

from mcpflow import actions


def collect(arguments, password_keys=frozenset({"secret"})):
    helper = getattr(actions, "_coerced_secret_literals", None)
    assert callable(helper), "actions._coerced_secret_literals is not implemented"
    result = helper(arguments, password_keys)
    assert isinstance(result, frozenset)
    return result


@pytest.mark.parametrize(
    "value,expected",
    [
        pytest.param(" 00123 ", {" 00123 "}, id="string-is-not-recoerced"),
        pytest.param("x", {"x"}, id="one-character-string"),
        pytest.param('ü"\\tail', {'ü"\\tail'}, id="exact-unicode-string"),
        pytest.param("", set(), id="empty-string"),
        pytest.param(0, {"0"}, id="integer-zero"),
        pytest.param(-42, {"-42"}, id="negative-integer"),
        pytest.param(1.0, {"1.0"}, id="integral-float"),
        pytest.param(-0.0, {"-0.0"}, id="negative-float-zero"),
        pytest.param(1e20, {"1e+20"}, id="float-exponent"),
        pytest.param(True, {"true", "True"}, id="boolean-true"),
        pytest.param(False, {"false", "False"}, id="boolean-false"),
        pytest.param(None, {"null", "None"}, id="null"),
        pytest.param([], {"[]"}, id="empty-list"),
        pytest.param({}, {"{}"}, id="empty-dictionary"),
        pytest.param(["", "x", "x"], {'["","x","x"]', "x"}, id="list-and-leaves"),
    ],
)
def test_coerced_literals_match_exact_value_contract(value, expected):
    assert collect({"secret": value}) == frozenset(expected)


def test_coerced_literals_include_canonical_nested_containers_keys_and_leaves():
    value = {"z": [True, None, "ü"], "a": {"": [], "token": "x"}}
    expected = {
        '{"a":{"":[],"token":"x"},"z":[true,null,"ü"]}',
        '{"":[],"token":"x"}',
        '[true,null,"ü"]',
        "a",
        "z",
        "token",
        "[]",
        "x",
        "true",
        "True",
        "null",
        "None",
        "ü",
    }
    assert collect({"secret": value}) == frozenset(expected)


def test_coerced_literals_visit_only_selected_top_level_argument_values():
    unsupported = object()
    arguments = MappingProxyType(
        {
            "secret": "selected",
            "other_secret": False,
            "public": {"secret": "unselected", "invalid": unsupported},
        }
    )
    selected = frozenset({"secret", "other_secret", "absent"})
    assert collect(arguments, selected) == {"selected", "false", "False"}
    assert arguments["public"]["invalid"] is unsupported


@pytest.mark.parametrize("selected", [frozenset(), frozenset({"absent"})])
def test_absent_selected_arguments_do_not_collect_or_validate_other_values(selected):
    assert collect({"public": object()}, selected) == frozenset()


def test_coerced_literals_do_not_mutate_arguments_or_mix_calls():
    arguments = {
        "secret": {"z": ["value", {"leaf": 2}], "a": []},
        "public": ["untouched"],
    }
    before = deepcopy(arguments)
    selected_value = arguments["secret"]
    selected_list = selected_value["z"]
    result = collect(arguments)
    assert arguments == before
    assert arguments["secret"] is selected_value
    assert selected_value["z"] is selected_list
    assert list(selected_value) == ["z", "a"]
    assert "value" in result
    assert collect({"secret": "next-call"}) == frozenset({"next-call"})
    assert "next-call" not in result


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(float("nan"), id="nan"),
        pytest.param(float("inf"), id="positive-infinity"),
        pytest.param(float("-inf"), id="negative-infinity"),
        pytest.param([1, float("nan")], id="nested-nan"),
        pytest.param({"key": float("inf")}, id="nested-infinity"),
        pytest.param(object(), id="unsupported-object"),
        pytest.param(("value",), id="tuple"),
        pytest.param({"value"}, id="set"),
        pytest.param(b"value", id="bytes"),
        pytest.param({1: "value"}, id="integer-key"),
        pytest.param({True: "value"}, id="boolean-key"),
        pytest.param({None: "value"}, id="null-key"),
        pytest.param({"valid": [{"nested": {2: "value"}}]}, id="nested-invalid-key"),
    ],
)
def test_coerced_literals_reject_invalid_values_with_fixed_error(value):
    with pytest.raises(ValueError, match=r"^invalid secret argument$"):
        collect({"secret": value})


@pytest.mark.parametrize("kind", ["list", "dictionary"])
def test_coerced_literals_reject_cycles_without_mutating_them(kind):
    if kind == "list":
        value = []
        value.append(value)
        child_key = 0
    else:
        value = {}
        value["self"] = value
        child_key = "self"
    with pytest.raises(ValueError, match=r"^invalid secret argument$"):
        collect({"secret": value})
    assert len(value) == 1 and value[child_key] is value


def test_coerced_literals_replace_traversal_failure_with_fixed_error():
    class UnreadableList(list):
        def __iter__(self):
            raise RuntimeError("PRIVATE-traversal-detail")

    with pytest.raises(ValueError, match=r"^invalid secret argument$"):
        collect({"secret": UnreadableList(["value"])})


@pytest.mark.parametrize(
    "value,secret,expected",
    [
        pytest.param(True, "true", "***", id="mask-true"),
        pytest.param(False, "false", "***", id="mask-false"),
        pytest.param(None, "null", "***", id="mask-null"),
        pytest.param(True, "1", True, id="true-is-not-one"),
        pytest.param(False, "0", False, id="false-is-not-zero"),
        pytest.param(1, "true", 1, id="one-is-not-true"),
        pytest.param(0, "false", 0, id="zero-is-not-false"),
        pytest.param(True, "True", True, id="true-needs-json-spelling"),
        pytest.param(False, "False", False, id="false-needs-json-spelling"),
        pytest.param(None, "None", None, id="null-needs-json-spelling"),
        pytest.param(1, "1", "***", id="mask-integer"),
        pytest.param(1.0, "1.0", "***", id="mask-float"),
        pytest.param(1, "1.0", 1, id="integer-is-not-float"),
        pytest.param(1.0, "1", 1.0, id="float-is-not-integer"),
        pytest.param(-0.0, "-0.0", "***", id="mask-negative-zero"),
        pytest.param(0.0, "-0.0", 0.0, id="zero-sign-is-significant"),
        pytest.param(True, "unrelated", True, id="ordinary-true"),
        pytest.param(False, "unrelated", False, id="ordinary-false"),
        pytest.param(None, "unrelated", None, id="ordinary-null"),
    ],
)
def test_redact_compares_canonical_scalars_without_type_conflation(
    value, secret, expected
):
    actual = actions.redact(value, {secret})
    assert type(actual) is type(expected)
    assert actual == expected


@pytest.mark.parametrize(
    "value,canonical",
    [
        pytest.param([], "[]", id="empty-list"),
        pytest.param({}, "{}", id="empty-dictionary"),
        pytest.param(
            [{"key": "token"}, True, None],
            '[{"key":"token"},true,null]',
            id="nonempty-list",
        ),
        pytest.param(
            {"z": 1, "a": "ü"}, '{"a":"ü","z":1}', id="sorted-unicode-dictionary"
        ),
    ],
)
def test_redact_masks_whole_container_before_descending(value, canonical):
    before = deepcopy(value)
    assert actions.redact(value, {canonical}) == "***"
    assert value == before


@pytest.mark.parametrize(
    "noncanonical",
    [
        pytest.param('{"z":1,"a":"ü"}', id="unsorted"),
        pytest.param('{"a": "ü", "z": 1}', id="whitespace"),
        pytest.param('{"a":"\\u00fc","z":1}', id="ascii-escaped"),
    ],
)
def test_redact_container_equality_uses_only_canonical_unescaped_secret(noncanonical):
    value = {"z": 1, "a": "ü"}
    assert actions.redact(value, {noncanonical}) == value


def test_redact_descends_when_parent_does_not_match_and_preserves_input():
    value = {
        "containers": [[], {}, {"z": 1, "a": "ü"}],
        "leaves": [True, False, None, 1, 0],
        "plain": "ordinary",
    }
    before = deepcopy(value)
    secrets = {"[]", "{}", '{"a":"ü","z":1}', "true", "null"}
    assert actions.redact(value, secrets) == {
        "containers": ["***", "***", "***"],
        "leaves": ["***", False, "***", 1, 0],
        "plain": "ordinary",
    }
    assert value == before


@pytest.mark.parametrize(
    "value,noncanonical",
    [
        pytest.param(float("nan"), "NaN", id="nan"),
        pytest.param(float("inf"), "Infinity", id="positive-infinity"),
        pytest.param(float("-inf"), "-Infinity", id="negative-infinity"),
    ],
)
def test_redact_nonfinite_nodes_skip_canonical_equality(value, noncanonical):
    result = actions.redact({"number": value, "text": "private"}, {noncanonical, "private"})
    assert result["text"] == "***"
    assert isinstance(result["number"], float)
    if math.isnan(value):
        assert math.isnan(result["number"])
    else:
        assert result["number"] == value


def test_redact_unserializable_container_still_masks_supported_children():
    unsupported = object()
    value = {"opaque": unsupported, "text": "private", "nested": ["private"]}
    result = actions.redact(value, {"private"})
    assert result == {"opaque": unsupported, "text": "***", "nested": ["***"]}
    assert result["opaque"] is unsupported
    assert value == {"opaque": unsupported, "text": "private", "nested": ["private"]}


def test_redact_boolean_null_and_empty_container_text_spellings():
    text = "true True false False null None [] {} | 1 0"
    secrets = {"true", "True", "false", "False", "null", "None", "[]", "{}"}
    assert actions.redact(text, secrets) == "*** *** *** *** *** *** *** *** | 1 0"
