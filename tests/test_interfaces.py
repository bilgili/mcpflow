"""Interface contract tests (12.22).

Every public signature under `design.md` "Public interfaces" is frozen. These
tests assert each one with `inspect.signature`, plus the frozen dataclass /
model field lists and the error-type contracts.
"""

from __future__ import annotations

import dataclasses
import inspect
import typing

import pydantic
from conftest import fake_child_spec

from mcpflow import (
    auth,
    catalog,
    cli,
    config,
    gateway,
    importer,
    oauth,
    registry,
    supervisor,
    web,
)


def _params(func) -> list[str]:
    return list(inspect.signature(func).parameters)


def _default(func, name):
    return inspect.signature(func).parameters[name].default


def _kind(func, name):
    return inspect.signature(func).parameters[name].kind


# --- config.py ---------------------------------------------------------------


def test_settings_fields_frozen():
    fields = [f.name for f in dataclasses.fields(config.Settings)]
    assert fields == [
        "data_dir",
        "host",
        "port",
        "admin_password_hash",
        "secret_key",
        "cookie_secure",
        "session_ttl",
        "child_start_timeout",
        "child_cache_ttl",
        "log_level",
        "public_url",
        "max_user_servers",
        "max_user_tokens",
    ]
    assert config.Settings.__dataclass_params__.frozen is True
    defaults = {f.name: f.default for f in dataclasses.fields(config.Settings)}
    assert defaults["max_user_servers"] == 20
    assert defaults["max_user_tokens"] == 10


def test_load_settings_signature():
    assert _params(config.load_settings) == ["overrides"]
    assert _default(config.load_settings, "overrides") is None


# --- registry.py -------------------------------------------------------------


def test_serverspec_fields():
    expected = {
        "namespace",
        "kind",
        "package",
        "args",
        "url",
        "transport",
        "headers",
        "command",
        "env",
        "enabled",
        "muted",
        "disabled_tools",
        "description",
        "cache_ttl",
        "source",
        "catalog",
        "oauth_pending",
        "created_at",
        "actions",
        "owner",
        "approved_revision",
    }
    assert set(registry.ServerSpec.model_fields) == expected
    # Registry-owned; no field defaults to an approval (F7a).
    assert registry.ServerSpec.model_fields["owner"].default is None
    assert registry.ServerSpec.model_fields["approved_revision"].default is None
    # F2 revised: the action-capability trust grant, opt-in per child.
    assert registry.ServerSpec.model_fields["actions"].default is False
    # A child added by hand has no catalog provenance.
    assert registry.ServerSpec.model_fields["catalog"].default is None
    # A header-sink child awaiting its token; default off for every other child.
    assert registry.ServerSpec.model_fields["oauth_pending"].default is False
    assert registry.ServerSpec.model_fields["transport"].default == "http"
    assert registry.ServerSpec.model_fields["enabled"].default is True
    assert registry.ServerSpec.model_fields["description"].default == ""
    # A spec from a build before tool-visibility must load fully visible.
    assert registry.ServerSpec.model_fields["muted"].default is False
    spec = registry.ServerSpec(namespace="n", kind="custom", command="c")
    assert spec.disabled_tools == []


def test_registry_error_is_value_error():
    assert issubclass(registry.RegistryError, ValueError)


def test_registry_methods():
    assert _params(registry.Registry.__init__) == [
        "self", "path", "user_path", "max_user_servers",
    ]
    assert _kind(registry.Registry.__init__, "max_user_servers") == (
        inspect.Parameter.KEYWORD_ONLY
    )
    assert _default(registry.Registry.__init__, "max_user_servers") == 20
    assert _params(registry.Registry.load) == ["self"]
    assert _params(registry.Registry.list) == ["self"]
    assert _params(registry.Registry.get) == ["self", "key"]
    assert _params(registry.Registry.add) == ["self", "spec"]
    assert _params(registry.Registry.update) == ["self", "spec"]
    assert _params(registry.Registry.remove) == ["self", "key"]
    assert _params(registry.Registry.set_enabled) == ["self", "key", "enabled"]
    assert _params(registry.Registry.set_oauth_header) == [
        "self", "key", "name", "value",
    ]
    assert _params(registry.Registry.set_approved_revision) == [
        "self", "key", "revision",
    ]
    assert _params(registry.Registry.set_muted) == ["self", "key", "muted"]
    assert _params(registry.Registry.set_tool_muted) == [
        "self", "key", "tool", "muted",
    ]


def test_serverspec_memo_interface():
    """bound-user-writes (round 4, G15): the snapshot memo, no copy hooks."""
    spec = registry.ServerSpec
    assert _params(spec._current_revision) == ["self"]
    assert spec.model_copy is pydantic.BaseModel.model_copy
    assert "__setattr__" not in spec.__dict__  # no override, whatever pydantic wraps
    assert "_revision_memo" not in spec.__dict__
    assert "_revision_memo" not in spec.model_fields
    assert "_revision_memo" not in spec.__private_attributes__


def test_server_key_and_revision():
    assert [f.name for f in dataclasses.fields(registry.ServerKey)] == [
        "owner", "namespace",
    ]
    params = registry.ServerKey.__dataclass_params__
    assert params.frozen is True and params.order is True
    assert registry.REVISION_FIELDS == (
        "kind", "package", "args", "url", "transport",
        "headers", "command", "env", "source",
    )
    assert _params(registry.revision) == ["spec"]
    assert _params(registry.ServerKey.parse) == ["ref"]


# --- supervisor.py -----------------------------------------------------------


def test_child_fields():
    assert [f.name for f in dataclasses.fields(supervisor.Child)] == [
        "spec",
        "status",
        "last_error",
        "tool_count",
        "started_at",
        "transport",
        "provider",
        "visibility",
        "lock",
        "task",
        "session",
        "grant",
        "refresh_rejected",
        "refresh_transient",
    ]


STATES = {"starting", "running", "failed", "stopped"}


def test_status_holds_exactly_the_four_real_states():
    """`configured` was a member no code ever assigned, so a reader had to
    handle a case that could not occur. Nothing may reintroduce one."""
    assert set(typing.get_args(supervisor.Status)) == STATES


def test_a_new_child_is_stopped():
    child = supervisor._new_child(fake_child_spec("time", "good"))
    assert child.status == "stopped"
    assert child.status in STATES


def test_toolview_fields_frozen():
    assert [f.name for f in dataclasses.fields(supervisor.ToolView)] == [
        "namespace",
        "name",
        "description",
        "schema_summary",
        "status",
        "tool",
        "visible",
        "pinned",
        "ref",
        "owner",
    ]
    assert supervisor.ToolView.__dataclass_params__.frozen is True


def test_supervisor_table_attribute(tmp_path):
    from conftest import make_policy, make_settings
    from fastmcp.server.providers import AggregateProvider

    reg = registry.Registry(tmp_path / "servers.json", tmp_path / "user_servers.json")
    reg.load()
    sup = supervisor.Supervisor(
        reg,
        make_settings(tmp_path),
        oauth.CredStore(tmp_path),
        oauth.PendingFlows(),
        make_policy(tmp_path, reg),
    )
    assert isinstance(sup.table, AggregateProvider)


def test_supervisor_methods():
    S = supervisor.Supervisor
    assert _params(S.__init__) == [
        "self", "registry", "settings", "creds", "flows", "policy",
    ]
    for name in ("startup", "shutdown", "add", "update", "remove", "enable",
                 "disable", "restart", "_run_start", "_teardown", "tools",
                 "write_source", "finish_oauth"):
        assert inspect.iscoroutinefunction(getattr(S, name)), name
    assert _params(S.finish_oauth) == [
        "self", "flow", "token_fmt", "tokens", "client_fmt", "reauth", "header",
    ]
    assert _default(S.finish_oauth, "client_fmt") is None
    assert _default(S.finish_oauth, "reauth") is False
    assert _default(S.finish_oauth, "header") is None
    assert _params(S.children) == ["self"]
    assert _params(S.get) == ["self", "key"]
    assert _params(S.add) == ["self", "spec", "actor", "client_fmt", "client"]
    assert _default(S.add, "client_fmt") is None
    assert _default(S.add, "client") is None
    assert _params(S.update) == ["self", "key", "spec", "actor"]
    assert _params(S.approve) == ["self", "key", "revision", "actor"]
    assert _params(S.remove) == ["self", "key", "actor"]
    assert _params(S.enable) == ["self", "key", "actor"]
    assert _params(S.disable) == ["self", "key", "actor"]
    assert _params(S.restart) == ["self", "key", "actor"]
    assert _params(S.write_source) == ["self", "key", "files", "actor"]
    assert _params(S.log_tail) == ["self", "key", "lines"]
    assert _default(S.log_tail, "lines") == 100
    assert _params(S.set_root_muted) == ["self", "muted", "actor"]
    assert _params(S.set_namespace_muted) == ["self", "key", "muted", "actor"]
    assert _params(S.set_tool_muted) == ["self", "key", "tool", "muted", "actor"]
    assert _params(S.actions) == ["self", "key"]
    assert _params(S.run_action)[:3] == ["self", "key", "name"]
    assert _params(S.run_action)[:5] == ["self", "key", "name", "form", "actor"]
    for kw in ("rendered_password_keys", "rendered_secrets"):
        assert _kind(S.run_action, kw) == inspect.Parameter.KEYWORD_ONLY, kw
        assert _default(S.run_action, kw) == frozenset(), kw
    assert inspect.iscoroutinefunction(S.instructions_blocks)
    # The Reach is required: no default, so no caller can skip the filter.
    for name in ("tools", "instructions_blocks"):
        assert _default(getattr(S, name), "reach") is inspect.Parameter.empty, name
    assert _params(S.instructions_blocks) == ["self", "reach"]
    # `probe` is keyword-only, so every existing positional call keeps its
    # meaning (dashboard-tool-snapshot D3).
    assert _params(S.tools) == ["self", "reach", "probe"]
    assert _kind(S.tools, "probe") == inspect.Parameter.KEYWORD_ONLY
    assert _default(S.tools, "probe") is True
    assert _params(S.children_of) == ["self", "owner"]
    assert _params(S.routed) == ["self", "reach"]


# --- identity.py -------------------------------------------------------------


def test_identity_interface():
    from mcpflow import identity

    assert identity.BOOTSTRAP_ADMIN_ID == "admin"
    assert identity.USER_ID_RE.pattern == r"^[a-z0-9][a-z0-9_-]{0,63}$"
    assert identity.GROUP_RE.pattern == r"^[a-z][a-z0-9_-]{0,31}$"
    assert [f.name for f in dataclasses.fields(identity.User)] == [
        "id", "name", "groups", "provider", "pending", "incarnation",
    ]
    incarnation = identity.User.__dataclass_fields__["incarnation"]
    assert incarnation.default == 0
    assert incarnation.kw_only is True
    assert identity.ADMINS_GROUP == "admins"
    assert identity.User.__dataclass_params__.frozen is True
    L = identity.LocalIdentityProvider
    assert L.kind == "local"
    assert _params(L.__init__) == ["self", "path", "admin_password_hash", "clock"]
    assert _params(L._create_user) == [
        "self", "user_id", "name", "admin", "groups",
    ]
    for name in ("name", "admin", "groups"):
        assert _kind(L._create_user, name) == inspect.Parameter.KEYWORD_ONLY
        assert _kind(L.check_create_user, name) == inspect.Parameter.KEYWORD_ONLY
    for name, params in (
        ("authenticate", ["self", "user_id", "password"]),
        ("get_user", ["self", "user_id"]),
        ("resolve", ["self", "token"]),
        ("list_users", ["self"]),
        ("list_groups", ["self"]),
        ("session_binding", ["self", "user_id"]),
        ("_issue_setup_code", ["self", "user_id"]),
        ("check_reset", ["self", "user_id"]),
        ("check_setup_code", ["self", "user_id", "code"]),
        ("replace_credential", ["self", "user_id", "expected_state", "new_hash"]),
        ("set_admin", ["self", "user_id", "admin"]),
        ("set_groups", ["self", "user_id", "groups", "admin"]),
        ("change_groups", ["self", "user_id", "add", "remove"]),
        ("remove_member", ["self", "group", "user_id"]),
        ("change_members", ["self", "group", "add", "remove"]),
        ("_create_user", ["self", "user_id", "name", "admin", "groups"]),
        ("_create_group", ["self", "name"]),
        ("_delete_group", ["self", "name"]),
        ("check_create_user", ["self", "user_id", "name", "admin", "groups"]),
        ("check_create_group", ["self", "name"]),
        ("_delete_user", ["self", "user_id"]),
        ("load", ["self"]),
    ):
        assert _params(getattr(L, name)) == params, name
        if not name.startswith("_") and name not in ("load",) and not name.startswith(
            ("set_", "check_", "replace_", "change_", "remove_")
        ):
            assert hasattr(identity.IdentityProvider, name), name
    # The cascade halves are private: `AccessPolicy` is the public owner.
    for name in ("create_user", "create_group", "delete_group"):
        assert not hasattr(L, name), name
    # The create pre-checks are Local only, as `check_reset` is.
    for name in ("check_create_user", "check_create_group"):
        assert not hasattr(identity.IdentityProvider, name), name
    assert not hasattr(L, "issue_setup_code")
    assert not hasattr(L, "set_password")  # removed by user-self-service-password
    # `check_reset` is Local only: the policy reaches it through `local_identity()`.
    assert not hasattr(identity.IdentityProvider, "check_reset")


def test_the_provider_has_no_public_cascade_half():
    """private-cascade-halves T12, scenario "The provider has no public create
    or group delete": the halves are private, the pre-checks are Local only."""
    from mcpflow import identity

    L = identity.LocalIdentityProvider
    for name in ("create_user", "create_group", "delete_group", "issue_setup_code"):
        assert not hasattr(L, name), name
    for name, params in (
        ("_create_user", ["self", "user_id", "name", "admin", "groups"]),
        ("_create_group", ["self", "name"]),
        ("_delete_group", ["self", "name"]),
        ("check_create_user", ["self", "user_id", "name", "admin", "groups"]),
        ("check_create_group", ["self", "name"]),
    ):
        assert _params(getattr(L, name)) == params, name
    for name in ("name", "admin", "groups"):
        assert _kind(L._create_user, name) == inspect.Parameter.KEYWORD_ONLY
        assert _kind(L.check_create_user, name) == inspect.Parameter.KEYWORD_ONLY
    for name in ("check_create_user", "check_create_group"):
        assert not hasattr(identity.IdentityProvider, name), name
    assert not inspect.iscoroutinefunction(L.check_create_user)
    assert not inspect.iscoroutinefunction(L.check_create_group)


# --- auth.py -----------------------------------------------------------------


def test_hash_password_signature():
    assert _params(auth.hash_password) == ["password", "iterations"]
    assert _kind(auth.hash_password, "iterations") == inspect.Parameter.KEYWORD_ONLY
    assert _default(auth.hash_password, "iterations") == 600_000


def test_password_and_session_signatures():
    assert _params(auth.verify_password) == ["password", "encoded"]
    assert _params(auth.sign_session) == ["secret", "user_id", "binding", "expires_at"]
    assert _params(auth.verify_session) == ["secret", "value", "binding_of", "now"]


def test_session_gate_signature():
    params = inspect.signature(auth.SessionGate.__init__).parameters
    assert list(params) == [
        "self", "app", "secret", "identity", "public_prefixes", "user_routes",
        "bearer_prefixes",
    ]
    for kw in ("secret", "identity", "public_prefixes", "user_routes",
               "bearer_prefixes"):
        assert params[kw].kind == inspect.Parameter.KEYWORD_ONLY
    assert params["bearer_prefixes"].default == ()


def test_token_record_fields_frozen():
    assert [f.name for f in dataclasses.fields(auth.TokenRecord)] == [
        "id",
        "name",
        "sha256",
        "created_at",
        "last_used_at",
        "scope",
        "user_id",
    ]
    assert auth.TokenRecord.__dataclass_params__.frozen is True
    # A record without a user_id in tokens.json loads as the bootstrap admin.
    assert auth.TokenRecord.__dataclass_fields__["user_id"].default == "admin"
    # A record without a scope in an old file must load as `mcp`.
    assert auth.TokenRecord.__dataclass_fields__["scope"].default == "mcp"


def test_token_store_methods():
    T = auth.TokenStore
    assert _params(T.__init__) == ["self", "path", "user_path", "max_user_tokens"]
    assert _kind(T.__init__, "max_user_tokens") == inspect.Parameter.KEYWORD_ONLY
    assert _default(T.__init__, "max_user_tokens") == 10
    assert _params(T.load) == ["self"]
    assert _params(T.list) == ["self"]
    assert _params(T.create) == ["self", "name", "scope", "user_id", "exempt"]
    assert _kind(T.create, "exempt") == inspect.Parameter.KEYWORD_ONLY
    assert _default(T.create, "exempt") is False
    assert _params(T.list_for) == ["self", "user_id"]
    assert _params(T.revoke_user) == ["self", "user_id"]
    assert _params(T.revoke) == ["self", "token_id"]
    assert _params(T.lookup) == ["self", "token", "scopes"]


def test_admin_token_gate_signature():
    params = inspect.signature(auth.AdminTokenGate.__init__).parameters
    assert list(params) == ["self", "app", "store", "identity"]
    for kw in ("store", "identity"):
        assert params[kw].kind == inspect.Parameter.KEYWORD_ONLY


def test_hashed_token_verifier():
    assert issubclass(auth.HashedTokenVerifier, auth.TokenVerifier)
    assert _params(auth.HashedTokenVerifier.__init__) == ["self", "store", "identity"]
    assert _params(auth.HashedTokenVerifier.verify_token) == ["self", "token"]
    assert inspect.iscoroutinefunction(auth.HashedTokenVerifier.verify_token)


# --- importer.py -------------------------------------------------------------


def test_importer_signatures():
    assert _params(importer.parse_config_block) == ["text"]


# --- web.py, gateway.py, cli.py ----------------------------------------------


def test_build_routes_signature():
    assert _params(web.build_routes) == [
        "supervisor",
        "tokens",
        "settings",
        "creds",
        "flows",
        "identity",
    ]


# --- catalog.py and oauth.py (oauth-connect frozen interfaces) ---------------


def test_catalog_load_signature():
    params = inspect.signature(catalog.Catalog.load).parameters
    assert list(params) == [
        "builtin_dir",
        "local_dir",
        "providers",
        "client_formats",
        "token_formats",
    ]
    for kw in ("providers", "client_formats", "token_formats"):
        assert params[kw].kind == inspect.Parameter.KEYWORD_ONLY
        assert params[kw].default == ()


def test_build_spec_signature():
    assert _params(catalog.build_spec) == [
        "entry",
        "namespace",
        "values",
        "args",
        "cred_paths",
    ]
    assert _default(catalog.build_spec, "cred_paths") is None


def test_credstore_methods():
    C = oauth.CredStore
    assert _params(C.__init__) == ["self", "data_dir"]
    assert _params(C.paths) == ["self", "ref"]
    assert _params(C.write_client) == ["self", "ref", "fmt", "creds"]
    assert _params(C.write_token) == ["self", "ref", "fmt", "tokens"]
    assert _params(C.has_client) == ["self", "ref"]
    assert _params(C.has_token) == ["self", "ref"]
    assert _params(C.awaiting) == ["self", "ref"]
    assert _params(C.remove) == ["self", "ref"]


def test_pending_flows_methods():
    P = oauth.PendingFlows
    assert _params(P.__init__) == ["self", "ttl"]
    assert _default(P.__init__, "ttl") == 600.0
    assert _params(P.create) == ["self", "ref", "entry_id", "client", "actor", "reauth"]
    assert _kind(P.create, "reauth") == inspect.Parameter.KEYWORD_ONLY
    assert _default(P.create, "reauth") is False
    assert _params(P.peek) == ["self", "state"]
    assert _params(P.has_open) == ["self", "ref"]
    assert _params(P.begin_exchange) == ["self", "state"]
    assert _params(P.end_exchange) == ["self", "state"]
    assert _params(P.pop) == ["self", "state"]
    assert _params(P.discard) == ["self", "ref"]
    assert "reauth" in [f.name for f in dataclasses.fields(oauth.PendingFlow)]
    # PendingFlow.namespace became PendingFlow.ref (keyed stores, F2).
    fields = [f.name for f in dataclasses.fields(oauth.PendingFlow)]
    assert "ref" in fields
    assert "namespace" not in fields
    assert oauth.PendingFlow.__dataclass_fields__["reauth"].default is False
    # PendingFlow.actor is the opener's snapshot: after `created`, before `reauth`.
    assert "actor" in fields
    assert fields.index("created") < fields.index("actor") < fields.index("reauth")


def test_oauth_url_builder_signatures():
    assert _params(oauth.authorize_url) == ["provider", "block", "redirect_uri", "flow"]
    assert _params(oauth.token_request) == ["provider", "redirect_uri", "code", "flow"]


def test_provider_registry_methods():
    R = oauth.ProviderRegistry
    assert _params(R.load) == ["builtin_dir", "local_dir"]
    assert _params(R.get) == ["self", "provider_id"]
    assert _params(R.ids) == ["self"]


def test_header_sink_and_spec():
    from mcpflow import catalog
    assert catalog.HeaderSink().name == "Authorization"
    assert catalog.HeaderSink().scheme == "Bearer"
    assert [f.name for f in dataclasses.fields(oauth.HeaderSpec)] == [
        "name", "scheme", "refresh_token_url",
    ]
    assert catalog.OAuthBlock.model_fields["client_file"].default is None
    assert catalog.OAuthBlock.model_fields["token_file"].default is None
    assert catalog.OAuthBlock.model_fields["header"].default is None
    assert oauth.Provider.model_fields["scope_separator"].default == " "


def test_build_app_signature():
    assert _params(gateway.build_app) == ["settings"]


def test_cli_main_signature():
    assert _params(cli.main) == ["argv"]
    assert _default(cli.main, "argv") is None


def test_the_provider_has_no_public_reset():
    """identity-error-ownership, Test 15: `AccessPolicy.issue_setup_code` is
    the only public reset; the provider half is private."""
    from mcpflow.identity import LocalIdentityProvider as L

    assert not hasattr(L, "issue_setup_code")
    assert _params(L._issue_setup_code) == ["self", "user_id"]
