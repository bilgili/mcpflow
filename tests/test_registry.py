"""The persisted registry.

Scenarios from `specs/server-registry/spec.md` (Persistent registry file,
Persisted and in-memory registries agree) and `specs/mcp-gateway/spec.md`
(Child kinds, Unique namespaces).
"""

from __future__ import annotations

import hashlib
import json

import pytest
from pydantic import ValidationError

from mcpflow.registry import (
    REVISION_FIELDS,
    Registry,
    RegistryError,
    ServerKey,
    ServerSpec,
    revision,
    spec_from_dict,
)


def _npm(namespace: str, **extra) -> ServerSpec:
    return ServerSpec(namespace=namespace, kind="npm", package="@scope/pkg", **extra)


# --- Source field (git-source-packages) --------------------------------------


def test_source_rejected_on_remote():
    with pytest.raises(ValidationError) as exc:
        ServerSpec(
            namespace="r", kind="remote", url="https://x/mcp", source="https://s"
        )
    assert "source" in str(exc.value)


def test_source_rejected_on_custom():
    with pytest.raises(ValidationError) as exc:
        ServerSpec(namespace="c", kind="custom", command="x", source="https://s")
    assert "source" in str(exc.value)


def test_source_bad_prefix_rejected():
    with pytest.raises(ValidationError) as exc:
        ServerSpec(namespace="p", kind="python", package="p", source="ftp://x")
    assert "source" in str(exc.value)


@pytest.mark.parametrize(
    "src",
    ["git+https://h/o/r", "https://h/t.tgz", "github:o/r", "/srv/tool"],
)
def test_source_prefixes_pass(src):
    spec = ServerSpec(namespace="p", kind="python", package="p", source=src)
    assert spec.source == src


def test_source_empty_string_is_none():
    spec = ServerSpec(namespace="p", kind="python", package="p", source="   ")
    assert spec.source is None


def test_file_without_source_loads_as_none(tmp_path):
    path = tmp_path / "servers.json"
    path.write_text(
        '{"version": 1, "servers": ['
        '{"namespace": "time", "kind": "npm", "package": "@scope/pkg"}]}'
    )
    reg = Registry(path, path.with_name("user_servers.json"))
    reg.load()
    assert reg.get(ServerKey(None, "time")).source is None


def test_redact_source():
    from mcpflow.registry import redact_source

    assert (
        redact_source("git+https://oauth2:TOKEN@gitlab.example/o/r")
        == "git+https://***@gitlab.example/o/r"
    )
    # A @ref after the path is not user information.
    assert redact_source("git+https://host/o/r@ref") == "git+https://host/o/r@ref"
    assert redact_source("github:o/r") == "github:o/r"
    assert redact_source("/srv/tool") == "/srv/tool"
    assert redact_source(None) is None


def test_source_secrets():
    from mcpflow.registry import source_secrets

    # user:pass — the whole user information and the bare password both mask.
    assert source_secrets("git+https://oauth2:SEKRETTOKEN123@host/o/r") == [
        "oauth2:SEKRETTOKEN123",
        "SEKRETTOKEN123",
    ]
    # A bare-token user information (no colon) yields only itself.
    assert source_secrets("https://SEKRETTOKEN123@host/o/r") == ["SEKRETTOKEN123"]
    # A `@` in a query does not stretch the userinfo past the authority; the
    # bare password still masks (urlsplit bounds it to the netloc).
    assert source_secrets("https://user:SEKRETTOKEN123@host/o/r?x=a@b") == [
        "user:SEKRETTOKEN123",
        "SEKRETTOKEN123",
    ]
    # No credential: nothing to mask.
    assert source_secrets("git+https://host/o/r@ref") == []
    assert source_secrets("github:o/r") == []
    assert source_secrets("/srv/tool") == []
    assert source_secrets(None) == []


# --- spec_command (unify-dashboard-servers) ----------------------------------


def test_spec_command():
    from mcpflow.registry import spec_command

    python = ServerSpec(
        namespace="time",
        kind="python",
        package="mcp-server-time",
        args=["--local-timezone", "UTC"],
    )
    assert spec_command(python) == "uvx mcp-server-time --local-timezone UTC"

    npm = ServerSpec(
        namespace="fs", kind="npm", package="my-bin", source="github:o/r"
    )
    assert spec_command(npm) == "npx -y --package=github:o/r my-bin"

    remote = ServerSpec(
        namespace="r", kind="remote", url="https://host/mcp", transport="sse"
    )
    assert spec_command(remote) == "SSE https://host/mcp"

    # `args` overrides the spec's own list, so the preview and the command
    # line show the same arguments.
    assert spec_command(python, ["--tz", "CET"]) == "uvx mcp-server-time --tz CET"
    assert spec_command(python, []) == "uvx mcp-server-time"

    # The source is redacted, so a credential never reaches a page.
    secret = ServerSpec(
        namespace="tool",
        kind="python",
        package="my-tool",
        source="git+https://oauth2:TOKEN@host/o/r",
    )
    out = spec_command(secret)
    assert out == "uvx --from git+https://***@host/o/r my-tool"
    assert "TOKEN" not in out


def test_update_keeps_source_on_redacted_echo(tmp_path):
    from mcpflow.registry import redact_source

    reg = Registry(tmp_path / "servers.json", tmp_path / "user_servers.json")
    reg.load()
    raw = "git+https://oauth2:TOKEN@host/o/r"
    reg.add(ServerSpec(namespace="p", kind="python", package="p", source=raw))
    # A client echoes the redacted GET body back to PUT: keep the credential.
    echoed = ServerSpec(
        namespace="p", kind="python", package="p", source=redact_source(raw)
    )
    reg.update(echoed)
    assert reg.get(ServerKey(None, "p")).source == raw
    # A new credential is adopted.
    new = "git+https://oauth2:NEW@host/o/r"
    reg.update(ServerSpec(namespace="p", kind="python", package="p", source=new))
    assert reg.get(ServerKey(None, "p")).source == new


# --- Reserved namespaces (admin-mcp-provider) --------------------------------


def test_reserved_namespace_mcpflow_rejected():
    with pytest.raises(RegistryError) as exc:
        spec_from_dict({"namespace": "mcpflow", "kind": "custom", "command": "x"})
    assert str(exc.value).startswith("namespace:")
    assert "namespace mcpflow is reserved" in str(exc.value)


def test_reserved_prefix_mcpflow_underscore_rejected():
    with pytest.raises(RegistryError) as exc:
        spec_from_dict({"namespace": "mcpflow_list", "kind": "custom", "command": "x"})
    assert str(exc.value).startswith("namespace:")
    assert "namespace mcpflow_list is reserved" in str(exc.value)


def test_prefix_without_underscore_passes():
    spec = spec_from_dict({"namespace": "mcpflower", "kind": "custom", "command": "x"})
    assert spec.namespace == "mcpflower"


def test_load_refuses_reserved_namespace(tmp_path):
    path = tmp_path / "servers.json"
    path.write_text(
        '{"version": 1, "servers": ['
        '{"namespace": "mcpflow", "kind": "npm", "package": "@scope/pkg"}]}'
    )
    reg = Registry(path, path.with_name("user_servers.json"))
    with pytest.raises(ValidationError):
        reg.load()


# --- Persistent registry file (12.4) -----------------------------------------


def test_missing_file(tmp_path):
    path = tmp_path / "servers.json"
    reg = Registry(path, path.with_name("user_servers.json"))
    reg.load()
    assert reg.list() == []
    assert not path.exists()
    reg.add(_npm("time"))
    assert path.exists()


def test_restart_keeps_children(tmp_path):
    path = tmp_path / "servers.json"
    reg = Registry(path, path.with_name("user_servers.json"))
    reg.load()
    reg.add(_npm("time"))
    # A fresh process loads the same file.
    reloaded = Registry(path, path.with_name("user_servers.json"))
    reloaded.load()
    assert [s.namespace for s in reloaded.list()] == ["time"]


def test_duplicate_namespace_rejected(tmp_path):
    path = tmp_path / "servers.json"
    reg = Registry(path, path.with_name("user_servers.json"))
    reg.load()
    reg.add(_npm("time"))
    before = path.read_bytes()
    with pytest.raises(RegistryError):
        reg.add(_npm("time"))
    # The file is unchanged.
    assert path.read_bytes() == before


def test_load_rejects_duplicate_namespace(tmp_path):
    # A hand-edited file with two entries under one namespace must not load.
    path = tmp_path / "servers.json"
    path.write_text(
        '{"version": 1, "servers": ['
        '{"namespace": "time", "kind": "npm", "package": "@scope/pkg"},'
        '{"namespace": "time", "kind": "npm", "package": "@scope/pkg2"}]}'
    )
    reg = Registry(path, path.with_name("user_servers.json"))
    with pytest.raises(RegistryError):
        reg.load()


def test_invalid_namespace_rejected(tmp_path):
    # The admin adds a child with namespace "My-Server".
    with pytest.raises(RegistryError) as exc:
        spec_from_dict(
            {"namespace": "My-Server", "kind": "npm", "package": "@scope/pkg"}
        )
    assert "namespace" in str(exc.value)


def test_quiescent_state(tmp_path):
    path = tmp_path / "servers.json"
    reg = Registry(path, path.with_name("user_servers.json"))
    reg.load()
    reg.add(_npm("a"))
    reg.add(_npm("b"))
    reg.set_enabled(ServerKey(None, "a"), False)
    # With no operation in flight, the file equals the in-memory list.
    fresh = Registry(path, path.with_name("user_servers.json"))
    fresh.load()
    assert [s.model_dump() for s in fresh.list()] == [
        s.model_dump() for s in reg.list()
    ]


# --- Child kinds and atomic write (12.5) -------------------------------------


def test_per_kind_required_fields():
    # python and npm require package.
    with pytest.raises(ValidationError):
        ServerSpec(namespace="p", kind="python")
    with pytest.raises(ValidationError):
        ServerSpec(namespace="n", kind="npm")
    # remote requires url.
    with pytest.raises(ValidationError):
        ServerSpec(namespace="r", kind="remote")
    # custom requires command.
    with pytest.raises(ValidationError):
        ServerSpec(namespace="c", kind="custom")
    # Valid specs for each kind construct without error.
    ServerSpec(namespace="p", kind="python", package="mcp-server-time")
    ServerSpec(namespace="n", kind="npm", package="@scope/pkg")
    ServerSpec(namespace="r", kind="remote", url="https://x.test/mcp")
    ServerSpec(namespace="c", kind="custom", command="/bin/echo")


def test_atomic_write_on_every_mutator(tmp_path):
    path = tmp_path / "servers.json"
    reg = Registry(path, path.with_name("user_servers.json"))
    reg.load()

    def on_disk() -> list[str]:
        fresh = Registry(path, path.with_name("user_servers.json"))
        fresh.load()
        return [s.namespace for s in fresh.list()]

    reg.add(_npm("time"))
    assert on_disk() == ["time"]

    reg.add(_npm("fs"))
    assert on_disk() == ["time", "fs"]

    reg.update(_npm("time", args=["--x"]))
    fresh = Registry(path, path.with_name("user_servers.json"))
    fresh.load()
    assert fresh.get(ServerKey(None, "time")).args == ["--x"]

    reg.set_enabled(ServerKey(None, "fs"), False)
    fresh = Registry(path, path.with_name("user_servers.json"))
    fresh.load()
    assert fresh.get(ServerKey(None, "fs")).enabled is False

    reg.remove(ServerKey(None, "time"))
    assert on_disk() == ["fs"]


# --- Per-child cache TTL (child-catalog-freshness) ---------------------------


def test_cache_ttl_default_inherits():
    assert _npm("time").cache_ttl is None


def test_cache_ttl_zero_persists(tmp_path):
    path = tmp_path / "servers.json"
    reg = Registry(path, path.with_name("user_servers.json"))
    reg.load()
    reg.add(_npm("skills", cache_ttl=0))
    assert '"cache_ttl": 0.0' in path.read_text()
    reloaded = Registry(path, path.with_name("user_servers.json"))
    reloaded.load()
    assert reloaded.get(ServerKey(None, "skills")).cache_ttl == 0.0


def test_negative_cache_ttl_rejected():
    with pytest.raises(RegistryError, match="cache_ttl"):
        spec_from_dict(
            {"namespace": "skills", "kind": "npm", "package": "p", "cache_ttl": -1}
        )


def test_file_without_cache_ttl_loads_none(tmp_path):
    path = tmp_path / "servers.json"
    reg = Registry(path, path.with_name("user_servers.json"))
    reg.load()
    reg.add(_npm("time"))
    data = json.loads(path.read_text())
    for server in data["servers"]:
        del server["cache_ttl"]
    path.write_text(json.dumps(data))
    reloaded = Registry(path, path.with_name("user_servers.json"))
    reloaded.load()
    assert reloaded.get(ServerKey(None, "time")).cache_ttl is None


def test_update_takes_the_caller_cache_ttl(tmp_path):
    reg = Registry(tmp_path / "servers.json", tmp_path / "user_servers.json")
    reg.load()
    reg.add(_npm("skills", cache_ttl=0))
    reg.update(_npm("skills"))
    assert reg.get(ServerKey(None, "skills")).cache_ttl is None


# --- Multi-user keys (multi-user-access, task 10.2) --------------------------
# Scenarios from `specs/server-registry/spec.md` (Persistent registry file,
# Server key and reference) and `specs/mcp-gateway/spec.md` (Unique namespaces).


def _pinned(namespace: str, owner: str | None = None, **extra) -> ServerSpec:
    return ServerSpec(
        namespace=namespace,
        kind="npm",
        package="@acme/mcp@1.2.3",
        owner=owner,
        **extra,
    )


def _two_files(tmp_path):
    path = tmp_path / "servers.json"
    user_path = tmp_path / "user_servers.json"
    reg = Registry(path, user_path)
    reg.load()
    return reg, path, user_path


def _owner_records(node):
    if isinstance(node, dict):
        if "namespace" in node:
            yield node
        for v in node.values():
            yield from _owner_records(v)
    elif isinstance(node, list):
        for v in node:
            yield from _owner_records(v)


def test_a_user_server_stays_out_of_servers_json(tmp_path):
    reg, path, user_path = _two_files(tmp_path)
    reg.add(_npm("time"))
    before = path.read_bytes()
    reg.add(_pinned("github", owner="alice"))
    assert path.read_bytes() == before
    recs = list(_owner_records(json.loads(user_path.read_text())))
    assert [(r["namespace"], r["owner"]) for r in recs] == [("github", "alice")]
    # No record of servers.json carries `owner` or `approved_revision`.
    for rec in _owner_records(json.loads(path.read_text())):
        assert "owner" not in rec and "approved_revision" not in rec
    # A fresh process loads both classes.
    fresh = Registry(path, user_path)
    fresh.load()
    assert {s.key for s in fresh.list()} == {
        ServerKey(None, "time"),
        ServerKey("alice", "github"),
    }


def test_a_user_record_without_owner_stops_the_load(tmp_path):
    reg, path, user_path = _two_files(tmp_path)
    reg.add(_pinned("github", owner="alice"))
    data = json.loads(user_path.read_text())
    for rec in _owner_records(data):
        del rec["owner"]
    user_path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        Registry(path, user_path).load()


def test_an_existing_file_loads_as_admin_owned(tmp_path):
    path = tmp_path / "servers.json"
    path.write_text(
        '{"version": 1, "servers": ['
        '{"namespace": "time", "kind": "npm", "package": "@scope/pkg"}]}'
    )
    reg = Registry(path, tmp_path / "user_servers.json")
    reg.load()
    spec = reg.get(ServerKey(None, "time"))
    assert spec.owner is None
    assert spec.approval == "approved"
    assert spec.enabled is True


def test_two_users_own_the_same_namespace(tmp_path):
    reg, path, user_path = _two_files(tmp_path)
    reg.add(_pinned("github", owner="alice"))
    reg.add(_pinned("github", owner="bob"))
    assert {s.key for s in reg.list()} == {
        ServerKey("alice", "github"),
        ServerKey("bob", "github"),
    }
    assert ServerKey("alice", "github").ref == "github@alice"
    assert ServerKey("bob", "github").ref == "github@bob"
    assert reg.get(ServerKey("alice", "github")).owner == "alice"
    assert reg.get(ServerKey("bob", "github")).owner == "bob"


def test_a_body_cannot_change_the_owner_or_the_approval(tmp_path):
    reg, path, user_path = _two_files(tmp_path)
    reg.add(_pinned("github", owner="alice"))
    key = ServerKey("alice", "github")
    stored = reg.get(key)
    reg.set_approved_revision(key, revision(stored))
    approved = reg.get(key).approved_revision
    assert approved == revision(stored)
    # An update that carries a forged approval keeps the stored value.
    forged = _pinned("github", owner="alice", approved_revision="f" * 64, args=["--x"])
    reg.update(forged)
    kept = reg.get(key)
    assert kept.owner == "alice"
    assert kept.approved_revision == approved
    assert kept.args == ["--x"]
    # An update that names owner `bob` never touches the child of `alice`.
    before = user_path.read_bytes()
    try:
        reg.update(_pinned("github", owner="bob", approved_revision="e" * 64))
    except (RegistryError, KeyError):  # an unknown key may raise either
        pass
    assert user_path.read_bytes() == before
    assert reg.get(key).owner == "alice"
    assert ServerKey("bob", "github") not in {s.key for s in reg.list()}


def test_duplicate_namespace_of_one_user_rejected(tmp_path):
    reg, path, user_path = _two_files(tmp_path)
    reg.add(_pinned("github", owner="alice"))
    before = user_path.read_bytes()
    with pytest.raises(RegistryError) as exc:
        reg.add(_pinned("github", owner="alice"))
    assert "github" in str(exc.value)
    assert user_path.read_bytes() == before


def test_two_owners_share_a_namespace(tmp_path):
    reg, path, user_path = _two_files(tmp_path)
    reg.add(_npm("github"))
    reg.add(_pinned("github", owner="alice"))
    assert {s.key for s in reg.list()} == {
        ServerKey(None, "github"),
        ServerKey("alice", "github"),
    }


# --- Interface: ServerKey and revision ---------------------------------------


@pytest.mark.parametrize(
    "ref,expected",
    [
        ("time", ServerKey(None, "time")),
        ("github@alice", ServerKey("alice", "github")),
        ("my_srv2@bob-1", ServerKey("bob-1", "my_srv2")),
    ],
)
def test_server_key_parse_roundtrip(ref, expected):
    key = ServerKey.parse(ref)
    assert key == expected
    assert key.ref == ref


@pytest.mark.parametrize(
    "ref",
    ["", "@alice", "github@", "a@b@c", "Github", "git hub@alice", "github@Alice"],
)
def test_server_key_parse_refuses_a_bad_shape(ref):
    with pytest.raises(ValueError):
        ServerKey.parse(ref)


_FIELD_CHANGES = {
    "kind": "python",
    "package": "other==2.0.0",
    "args": ["--changed"],
    "url": "https://other.test/mcp",
    "transport": "sse",
    "headers": {"X-Other": "1"},
    "command": "/bin/other",
    "env": {"OTHER": "1"},
    "source": "git+https://h/o/other",
}


def _full_spec() -> ServerSpec:
    base = ServerSpec(namespace="x", kind="npm", package="@s/p@1.0.0")
    # `model_copy(update=...)` skips the per-kind check, so one spec can hold
    # a value in every field of the revision.
    return base.model_copy(
        update={
            "args": ["--a"],
            "url": "https://x.test/mcp",
            "transport": "http",
            "headers": {"X-A": "1"},
            "command": "/bin/x",
            "env": {"A": "1"},
            "source": "git+https://h/o/r",
        }
    )


def test_revision_fields_are_the_frozen_tuple():
    assert REVISION_FIELDS == (
        "kind",
        "package",
        "args",
        "url",
        "transport",
        "headers",
        "command",
        "env",
        "source",
    )


def test_revision_is_the_sha256_of_canonical_json():
    spec = _full_spec()
    canonical = json.dumps(
        {f: getattr(spec, f) for f in REVISION_FIELDS},
        sort_keys=True,
        separators=(",", ":"),
    )
    assert revision(spec) == hashlib.sha256(canonical.encode()).hexdigest()


@pytest.mark.parametrize("field", REVISION_FIELDS)
def test_each_revision_field_changes_the_revision(field):
    spec = _full_spec()
    changed = spec.model_copy(update={field: _FIELD_CHANGES[field]})
    assert getattr(changed, field) != getattr(spec, field)
    assert revision(changed) != revision(spec)


def test_a_description_does_not_change_the_revision():
    spec = _full_spec()
    assert revision(spec.model_copy(update={"description": "new text"})) == revision(
        spec
    )


# --- ServerKey validates its shape (1317096) ---------------------------------
#
# Requirement "Server key and reference": the key and the reference map one to
# one. Guarded invariant: OpTouchesOnlyOwnPaths - a key that could hold `@` in
# its namespace would share a reference, and so every store path, with
# another key.


@pytest.mark.parametrize(
    "owner,namespace",
    [
        (None, "github@alice"),   # `@` in the namespace
        ("alice", "github@bob"),
        (None, "Bad"),            # bad namespace
        (None, "../x"),
        (None, ""),
        (None, "github\n"),
        ("Alice", "github"),      # bad owner
        ("al/ice", "github"),
        ("..", "github"),
        (".", "github"),
        ("a@b", "github"),
        ("", "github"),
        ("alice\n", "github"),
    ],
)
def test_server_key_refuses_a_bad_shape_at_construction(owner, namespace):
    with pytest.raises(ValueError):
        ServerKey(owner, namespace)


def test_no_two_keys_share_a_reference():
    keys = [ServerKey(None, "github"), ServerKey("alice", "github"),
            ServerKey("bob", "github"), ServerKey(None, "gh"),
            ServerKey("alice", "gh"), ServerKey("bob-1", "my_srv2")]
    refs = [k.ref for k in keys]
    assert len(set(refs)) == len(refs)
    assert all(ServerKey.parse(k.ref) == k for k in keys)


# --- 10.27 Unique namespaces: the write-time prefix rule (D5b) ---------------
#
# Scenarios from `specs/mcp-gateway/spec.md`, requirement "Unique namespaces".
# The rule binds a USER write only (user decision 2026-10-02); an admin write
# is exempt, and the router backstop refuses a name two tools really share.
# Guarded invariant: `OneServerPerToolName` (`multi_user_access.tla`) through
# the backstop, which the write-time check cannot replace.


def _files(tmp_path) -> dict:
    return {p.name: p.read_bytes() for p in tmp_path.glob("*.json")}


@pytest.mark.parametrize("existing,added,other", [
    ((None, "github"), "github_create", "github"),       # N starts with M_
    ((None, "github_create"), "github", "github_create"),  # M starts with N_
    (("alice", "github"), "github_create", "github"),    # own namespace
])
def test_a_prefix_collision_is_refused_at_write_time(tmp_path, existing, added, other):
    reg, _p, _u = _two_files(tmp_path)
    owner, ns = existing
    reg.add(_pinned(ns, owner=owner))
    before = _files(tmp_path)
    with pytest.raises(RegistryError) as exc:
        reg.add(_pinned(added, owner="alice"))
    assert f"namespace {added} conflicts with {other}" in str(exc.value)
    assert "a tool name could resolve to both" in str(exc.value)
    assert _files(tmp_path) == before


@pytest.mark.parametrize("first,second", [("gmail", "gmail_work"),
                                          ("github", "github_create"),
                                          ("github_create", "github")])
def test_an_admin_prefix_pair_is_accepted(tmp_path, first, second):
    reg, _p, _u = _two_files(tmp_path)
    reg.add(_npm(first))
    reg.add(_npm(second))
    assert {s.key for s in reg.list()} == {ServerKey(None, first),
                                           ServerKey(None, second)}
    fresh = Registry(tmp_path / "servers.json", tmp_path / "user_servers.json")
    fresh.load()
    assert len(fresh.list()) == 2


@pytest.mark.asyncio
async def test_prefix_rule_binds_the_user_write_through_the_supervisor(tmp_path):
    """Both directions through `Supervisor.add`: `alice` is refused
    `github_create` against admin `github`; the admin is not."""
    from user_servers import ADMIN, ALICE, Env

    env = Env(tmp_path / "data")
    try:
        await env.sup.add(_npm("github", enabled=False), ADMIN)
        before = _files(env.dir)
        with pytest.raises(RegistryError, match="conflicts with github"):
            await env.sup.add(_pinned("github_create"), ALICE)
        assert _files(env.dir) == before
        await env.sup.add(_npm("github_create", enabled=False), ADMIN)
        assert ServerKey(None, "github_create") in {s.key for s in env.reg.list()}
    finally:
        await env.close()


def test_a_user_write_does_not_reveal_a_foreign_namespace(tmp_path):
    reg, _p, _u = _two_files(tmp_path)
    reg.add(_pinned("github", owner="bob"))
    reg.add(_pinned("github_create", owner="alice"))   # bob's github is not compared
    assert ServerKey("alice", "github_create") in {s.key for s in reg.list()}
    errors = []
    for ns in ("github_create_x", "github_create"):     # own collision, duplicate
        with pytest.raises(RegistryError) as exc:
            reg.add(_pinned(ns, owner="alice"))
        errors.append(str(exc.value))
    for msg in errors:
        assert "github@bob" not in msg
        assert "bob" not in msg
    assert "conflicts with github_create" in errors[0]


def test_an_existing_collision_still_loads(tmp_path, caplog):
    import logging

    path = tmp_path / "servers.json"
    path.write_text(json.dumps({"version": 1, "servers": [
        {"namespace": "github", "kind": "npm", "package": "@scope/pkg"},
        {"namespace": "github_create", "kind": "npm", "package": "@scope/pkg"},
    ]}))
    reg = Registry(path, tmp_path / "user_servers.json")
    with caplog.at_level(logging.WARNING):
        reg.load()
    assert {s.namespace for s in reg.list()} == {"github", "github_create"}
    warns = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    hits = [m for m in warns if "github_create" in m and "github" in m.replace(
        "github_create", "", 1)]
    assert len(hits) == 1, warns


@pytest.mark.parametrize("owner", [None, "alice"])
def test_invalid_namespace_rejected_for_every_owner(owner):
    with pytest.raises(RegistryError) as exc:
        spec_from_dict({"namespace": "My-Server", "kind": "npm",
                        "package": "@acme/mcp@1.2.3", "owner": owner})
    assert "namespace" in str(exc.value)
    for reserved in ("mcpflow", "mcpflow_list"):
        with pytest.raises(RegistryError, match=f"namespace {reserved} is reserved"):
            spec_from_dict({"namespace": reserved, "kind": "npm",
                            "package": "@acme/mcp@1.2.3", "owner": owner})


def test_an_admin_prefix_pair_is_accepted_and_the_router_refuses_the_shared_name(
        tmp_path):
    """`gmail` publishes `work_send` and `gmail_work` publishes `send`: both
    publish `gmail_work_send`. The registry holds both; the router refuses
    only that name, and every other tool of both servers stays reachable."""
    from router_live import Child, start_live

    pair = (Child("gmail", "gm", ("work_send", "inbox")),
            Child("gmail_work", "gm", ("send", "drafts")))
    lv, stop = start_live(tmp_path, pair)
    try:
        assert {s.namespace for s in lv.supervisor.registry.list()} \
            == {"gmail", "gmail_work"}
        names = lv.names("admin")
        assert {"gmail_inbox", "gmail_work_drafts"} <= names
        assert "gmail_work_send" not in names
        with pytest.raises(Exception):
            lv.call("admin", "gmail_work_send")
        assert lv.calls("gmail") == [] and lv.calls("gmail_work") == []
        assert lv.call("admin", "gmail_inbox") == "gmail:inbox"
    finally:
        stop()


# --- 10.27 Reserved namespace on the three adapters --------------------------


def test_reserved_namespace_rejected_on_the_rest_api(server_factory):
    from test_admin_mcp import _seed as seed_tokens

    holder: dict = {}
    server = server_factory(seed_tokens(holder, _npm("time")))
    before = (server.data_dir / "servers.json").read_bytes()
    resp = server.post("/api/servers",
                       headers={"Authorization": f"Bearer {holder['admin']}"},
                       json={"namespace": "mcpflow", "kind": "python", "package": "x"})
    assert resp.status_code == 400
    assert "namespace" in resp.json()["error"]
    assert "namespace mcpflow is reserved" in resp.json()["error"]
    assert (server.data_dir / "servers.json").read_bytes() == before


def test_reserved_namespace_rejected_on_the_web_form(server_factory):
    from test_admin_mcp import _seed as seed_tokens

    server = server_factory(seed_tokens({}))
    client = server.login()
    resp = client.post("/servers", data={"namespace": "mcpflow", "kind": "python",
                                         "package": "x"})
    client.close()
    assert resp.status_code == 400
    assert "namespace mcpflow is reserved" in resp.text
    assert 'name="namespace"' in resp.text  # the form is rendered again


@pytest.mark.parametrize("ns", ["mcpflow", "mcpflow_list"])
def test_reserved_namespace_rejected_over_mcp(server_factory, ns):
    from test_admin_mcp import _seed as seed_tokens
    from test_admin_mcp import call_tool, list_tools

    holder: dict = {}
    server = server_factory(seed_tokens(holder, _npm("time")))
    before = (server.data_dir / "servers.json").read_bytes()
    with pytest.raises(Exception) as exc:
        call_tool(server.base_url, holder["admin"], "mcpflow_add_server",
                  {"spec": {"namespace": ns, "kind": "custom", "command": "x"}})
    assert f"namespace {ns} is reserved" in str(exc.value)
    assert (server.data_dir / "servers.json").read_bytes() == before
    assert "mcpflow_list_servers" not in list_tools(server.base_url, holder["mcp"])
