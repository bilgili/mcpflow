"""Frozen interfaces of usage-stats (design.md "Proposed interfaces", item 9.13).

Each assertion comes from the design text, not from the implementation.
"""

from __future__ import annotations

import dataclasses
import inspect
import typing
from contextvars import ContextVar

from mcpflow import policy, router, usage, web
from mcpflow.usage import (
    Attribution,
    Counts,
    Series,
    Totals,
    UsageAttribution,
    UsageMiddleware,
    UsageRange,
    UsageStore,
)


def _params(func) -> list[str]:
    return list(inspect.signature(func).parameters)


def _kind(func, name):
    return inspect.signature(func).parameters[name].kind


def _fields(cls) -> list[str]:
    return [f.name for f in dataclasses.fields(cls)]


def _frozen(cls) -> bool:
    return cls.__dataclass_params__.frozen


def test_the_six_constants():
    assert usage.FLUSH_INTERVAL == 30.0
    assert isinstance(usage.FLUSH_INTERVAL, float)
    assert usage.RETENTION_DAYS == 400
    assert usage.MAX_RANGE_DAYS == 400
    assert usage.DEFAULT_RANGE_DAYS == 30
    assert usage.TOP_SERVERS == 7
    assert usage.SCHEMA_VERSION == 1


def test_bucket_literal():
    assert typing.get_args(usage.Bucket) == ("day", "week", "month")


def test_attribution_and_its_context_var():
    assert _fields(Attribution) == ["ref", "tool"]
    assert not _frozen(Attribution)
    assert Attribution() == Attribution(ref=None, tool=None)
    assert isinstance(usage.CALL_ATTRIBUTION, ContextVar)
    assert usage.CALL_ATTRIBUTION.name == "mcpflow_call_attribution"
    assert usage.CALL_ATTRIBUTION.get() is None
    assert _params(usage.attribute) == ["ref", "tool"]
    assert not inspect.iscoroutinefunction(usage.attribute)


def test_the_frozen_data_classes():
    assert _fields(Counts) == ["calls", "errors"] and _frozen(Counts)
    assert Counts() == Counts(calls=0, errors=0)
    assert _fields(UsageRange) == ["start", "end", "bucket"] and _frozen(UsageRange)
    assert _fields(Totals) == ["by_tool", "by_server", "degraded"] and _frozen(Totals)
    assert _fields(Series) == ["buckets", "by_server", "degraded"] and _frozen(Series)
    assert dataclasses.is_dataclass(usage.ChartView) and _frozen(usage.ChartView)


def test_usage_store_signatures():
    assert _params(UsageStore.__init__) == ["self", "path"]
    assert _params(UsageStore.record) == ["self", "ref", "tool", "user", "ok", "ms"]
    for name in ("ok", "ms"):
        assert _kind(UsageStore.record, name) is inspect.Parameter.KEYWORD_ONLY
    for name in ("ref", "tool", "user"):
        assert _kind(UsageStore.record, name) is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert _params(UsageStore.forget_user) == ["self", "user_id"]
    # record and forget_user are synchronous; the rest are coroutines.
    assert not inspect.iscoroutinefunction(UsageStore.record)
    assert not inspect.iscoroutinefunction(UsageStore.forget_user)
    for name in ("start", "stop"):
        meth = getattr(UsageStore, name)
        assert _params(meth) == ["self"]
        assert inspect.iscoroutinefunction(meth)
    for name in ("totals", "series"):
        meth = getattr(UsageStore, name)
        assert _params(meth) == ["self", "rng", "reach"]
        assert inspect.iscoroutinefunction(meth)


def test_parse_range_and_chart_view_signatures():
    assert _params(usage.parse_range) == ["params", "today"]
    assert _params(usage.chart_view) == ["series", "top"]
    assert _kind(usage.chart_view, "top") is inspect.Parameter.KEYWORD_ONLY
    assert (
        inspect.signature(usage.chart_view).parameters["top"].default
        == usage.TOP_SERVERS
    )


def test_transform_and_middleware_signatures():
    from fastmcp.server.middleware import Middleware
    from fastmcp.server.transforms import Transform

    assert issubclass(UsageAttribution, Transform)
    assert _params(UsageAttribution.get_tool) == [
        "self",
        "name",
        "call_next",
        "version",
    ]
    assert _kind(UsageAttribution.get_tool, "version") is inspect.Parameter.KEYWORD_ONLY
    assert (
        inspect.signature(UsageAttribution.get_tool).parameters["version"].default
        is None
    )
    assert inspect.iscoroutinefunction(UsageAttribution.get_tool)

    assert issubclass(UsageMiddleware, Middleware)
    assert _params(UsageMiddleware.__init__) == ["self", "store", "policy"]
    assert _params(UsageMiddleware.on_call_tool) == ["self", "context", "call_next"]
    assert inspect.iscoroutinefunction(UsageMiddleware.on_call_tool)


def test_router_bare_is_a_static_method():
    raw = inspect.getattr_static(router.CallerRouter, "_bare")
    assert isinstance(raw, staticmethod)
    assert _params(router.CallerRouter._bare) == ["key", "name"]


def test_access_policy_signatures():
    params = _params(policy.AccessPolicy.__init__)
    assert params[-2:] == ["registry", "usage"]
    assert _params(policy.AccessPolicy.is_current) == ["self", "user"]
    assert not inspect.iscoroutinefunction(policy.AccessPolicy.is_current)


def test_web_signatures():
    assert _params(web.usage_range) == ["request"]
    assert _params(web.build_routes)[-1] == "usage"
