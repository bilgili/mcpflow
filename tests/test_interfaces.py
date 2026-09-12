"""Interface contract tests (12.22).

Every public signature under `design.md` "Public interfaces" is frozen. These
tests assert each one with `inspect.signature`, plus the frozen dataclass /
model field lists and the error-type contracts.
"""

from __future__ import annotations

import dataclasses
import inspect
import typing

from conftest import fake_child_spec

from mcpflow import auth, catalog, cli, config, gateway, importer, oauth, registry, supervisor, web


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
        "log_level",
        "public_url",
    ]
    assert config.Settings.__dataclass_params__.frozen is True


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
        "source",
        "catalog",
        "oauth_pending",
        "created_at",
    }
    assert set(registry.ServerSpec.model_fields) == expected
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
    assert _params(registry.Registry.__init__) == ["self", "path"]
    assert _params(registry.Registry.load) == ["self"]
    assert _params(registry.Registry.list) == ["self"]
    assert _params(registry.Registry.get) == ["self", "namespace"]
    assert _params(registry.Registry.add) == ["self", "spec"]
    assert _params(registry.Registry.update) == ["self", "spec"]
    assert _params(registry.Registry.remove) == ["self", "namespace"]
    assert _params(registry.Registry.set_enabled) == ["self", "namespace", "enabled"]
    assert _params(registry.Registry.set_oauth_header) == [
        "self", "namespace", "name", "value",
    ]


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
    ]
    assert supervisor.ToolView.__dataclass_params__.frozen is True


def test_supervisor_table_attribute(tmp_path):
    from conftest import make_settings
    from fastmcp.server.providers import AggregateProvider

    reg = registry.Registry(tmp_path / "servers.json")
    reg.load()
    sup = supervisor.Supervisor(
        reg,
        make_settings(tmp_path),
        oauth.CredStore(tmp_path),
        oauth.PendingFlows(),
    )
    assert isinstance(sup.table, AggregateProvider)


def test_supervisor_methods():
    S = supervisor.Supervisor
    assert _params(S.__init__) == ["self", "registry", "settings", "creds", "flows"]
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
    assert _params(S.get) == ["self", "namespace"]
    assert _params(S.add) == ["self", "spec", "client_fmt", "client"]
    assert _default(S.add, "client_fmt") is None
    assert _default(S.add, "client") is None
    assert _params(S.update) == ["self", "spec"]
    assert _params(S.remove) == ["self", "namespace"]
    assert _params(S.enable) == ["self", "namespace"]
    assert _params(S.disable) == ["self", "namespace"]
    assert _params(S.restart) == ["self", "namespace"]
    assert _params(S.write_source) == ["self", "namespace", "files"]
    assert _params(S.log_tail) == ["self", "namespace", "lines"]
    assert _default(S.log_tail, "lines") == 100


# --- auth.py -----------------------------------------------------------------


def test_hash_password_signature():
    assert _params(auth.hash_password) == ["password", "iterations"]
    assert _kind(auth.hash_password, "iterations") == inspect.Parameter.KEYWORD_ONLY
    assert _default(auth.hash_password, "iterations") == 600_000


def test_password_and_session_signatures():
    assert _params(auth.verify_password) == ["password", "encoded"]
    assert _params(auth.sign_session) == ["secret", "password_hash", "expires_at"]
    assert _params(auth.verify_session) == [
        "secret",
        "password_hash",
        "value",
        "now",
    ]


def test_session_gate_signature():
    params = inspect.signature(auth.SessionGate.__init__).parameters
    assert list(params) == ["self", "app", "secret", "password_hash", "public_prefixes"]
    for kw in ("secret", "password_hash", "public_prefixes"):
        assert params[kw].kind == inspect.Parameter.KEYWORD_ONLY


def test_token_record_fields_frozen():
    assert [f.name for f in dataclasses.fields(auth.TokenRecord)] == [
        "id",
        "name",
        "sha256",
        "created_at",
        "last_used_at",
        "scope",
    ]
    assert auth.TokenRecord.__dataclass_params__.frozen is True
    # A record without a scope in an old file must load as `mcp`.
    assert auth.TokenRecord.__dataclass_fields__["scope"].default == "mcp"


def test_token_store_methods():
    T = auth.TokenStore
    assert _params(T.__init__) == ["self", "path"]
    assert _params(T.load) == ["self"]
    assert _params(T.list) == ["self"]
    assert _params(T.create) == ["self", "name", "scope"]
    assert _default(T.create, "scope") == "mcp"
    assert _params(T.revoke) == ["self", "token_id"]
    assert _params(T.lookup) == ["self", "token", "scopes"]


def test_admin_token_gate_signature():
    params = inspect.signature(auth.AdminTokenGate.__init__).parameters
    assert list(params) == ["self", "app", "store"]
    assert params["store"].kind == inspect.Parameter.KEYWORD_ONLY


def test_hashed_token_verifier():
    assert issubclass(auth.HashedTokenVerifier, auth.TokenVerifier)
    assert _params(auth.HashedTokenVerifier.__init__) == ["self", "store"]
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
    assert _params(C.paths) == ["self", "namespace"]
    assert _params(C.write_client) == ["self", "namespace", "fmt", "creds"]
    assert _params(C.write_token) == ["self", "namespace", "fmt", "tokens"]
    assert _params(C.has_client) == ["self", "namespace"]
    assert _params(C.has_token) == ["self", "namespace"]
    assert _params(C.awaiting) == ["self", "namespace"]
    assert _params(C.remove) == ["self", "namespace"]


def test_pending_flows_methods():
    P = oauth.PendingFlows
    assert _params(P.__init__) == ["self", "ttl"]
    assert _default(P.__init__, "ttl") == 600.0
    assert _params(P.create) == ["self", "namespace", "entry_id", "client", "reauth"]
    assert _kind(P.create, "reauth") == inspect.Parameter.KEYWORD_ONLY
    assert _default(P.create, "reauth") is False
    assert _params(P.peek) == ["self", "state"]
    assert _params(P.has_open) == ["self", "namespace"]
    assert _params(P.begin_exchange) == ["self", "state"]
    assert _params(P.end_exchange) == ["self", "state"]
    assert _params(P.pop) == ["self", "state"]
    assert _params(P.discard) == ["self", "namespace"]
    assert "reauth" in [f.name for f in dataclasses.fields(oauth.PendingFlow)]
    assert oauth.PendingFlow.__dataclass_fields__["reauth"].default is False


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
    assert [f.name for f in dataclasses.fields(oauth.HeaderSpec)] == ["name", "scheme"]
    assert catalog.OAuthBlock.model_fields["client_file"].default is None
    assert catalog.OAuthBlock.model_fields["token_file"].default is None
    assert catalog.OAuthBlock.model_fields["header"].default is None
    assert oauth.Provider.model_fields["scope_separator"].default == " "


def test_build_app_signature():
    assert _params(gateway.build_app) == ["settings"]


def test_cli_main_signature():
    assert _params(cli.main) == ["argv"]
    assert _default(cli.main, "argv") is None
