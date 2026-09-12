"""The marketplace catalog module.

Scenarios from `specs/marketplace/spec.md` (Catalog sources and precedence,
Invalid catalog files are skipped, Catalog entry schema, Search and
categories, Connect action — the `build_spec` half, Built-in catalog
coverage).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from mcpflow.catalog import BUILTIN_DIR, CATEGORIES, Catalog, CatalogEntry, build_spec
from mcpflow.oauth import CLIENT_FORMATS, TOKEN_FORMATS, CredPaths
from mcpflow.registry import RegistryError

# The known names the web layer passes at load so the built-in `gmail` oauth
# entry is not skipped. A bad provider or format name still skips its file.
KNOWN = {
    "providers": frozenset({"google", "linear"}),
    "client_formats": CLIENT_FORMATS,
    "token_formats": TOKEN_FORMATS,
}


def _oauth_file(**over) -> dict:
    data = {
        "id": "gmail",
        "name": "Gmail",
        "vendor": "Google",
        "category": "google",
        "description": "Mail.",
        "auth": "oauth",
        "tools": ["search_emails"],
        "spec": {"kind": "npm", "package": "pkg"},
        "oauth": {
            "provider": "google",
            "scopes": ["https://example/scope"],
            "client_file": {"env": "GMAIL_OAUTH_PATH", "format": "google-client"},
            "token_file": {"env": "GMAIL_CREDENTIALS_PATH", "format": "google-auth-library"},
        },
    }
    data.update(over)
    return data

MINIMAL = {
    "id": "time",
    "name": "Time",
    "vendor": "Anthropic",
    "category": "util",
    "description": "Clock.",
    "spec": {"kind": "python", "package": "mcp-server-time"},
}


def _write(directory: Path, name: str, data) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(data if isinstance(data, str) else json.dumps(data))
    return path


def _catalog(tmp_path: Path, builtin: dict[str, dict] | None = None, local=None) -> Catalog:
    bdir, ldir = tmp_path / "builtin", tmp_path / "local"
    for name, data in (builtin or {}).items():
        _write(bdir, name, data)
    for name, data in (local or {}).items():
        _write(ldir, name, data)
    return Catalog.load(bdir, ldir if local is not None else tmp_path / "missing")


# --- Catalog sources and precedence ------------------------------------------


def test_builtin_entries_load(tmp_path):
    cat = _catalog(tmp_path, {"gmail.json": {**MINIMAL, "id": "gmail"}})
    entry = cat.get("gmail")
    assert entry is not None and entry.origin == "builtin"
    assert cat.errors == []


def test_local_overrides_builtin(tmp_path):
    cat = _catalog(
        tmp_path,
        {"gmail.json": {**MINIMAL, "id": "gmail"}},
        {"my-gmail.json": {**MINIMAL, "id": "gmail", "spec": {"kind": "npm", "package": "other"}}},
    )
    assert len(cat.entries()) == 1
    entry = cat.get("gmail")
    assert entry.spec.package == "other" and entry.origin == "local"


def test_local_adds_new_entry(tmp_path):
    cat = _catalog(
        tmp_path,
        {"gmail.json": {**MINIMAL, "id": "gmail"}},
        {"acme.json": {**MINIMAL, "id": "acme"}},
    )
    assert cat.get("acme").origin == "local"
    assert cat.get("gmail").origin == "builtin"


def test_keyed_by_id_not_file_name(tmp_path):
    cat = _catalog(tmp_path, {"whatever.json": {**MINIMAL, "id": "clock"}})
    assert cat.get("clock") is not None and cat.get("whatever") is None


def test_file_cannot_claim_origin(tmp_path):
    cat = _catalog(tmp_path, {}, {"x.json": {**MINIMAL, "origin": "builtin"}})
    assert cat.entries() == []
    assert "origin" in cat.errors[0][1]


def test_load_is_a_snapshot(tmp_path):
    cat = _catalog(tmp_path, {"t.json": MINIMAL})
    _write(tmp_path / "builtin", "u.json", {**MINIMAL, "id": "later"})
    assert cat.get("later") is None
    assert Catalog.load(tmp_path / "builtin", None).get("later") is not None


# --- Invalid catalog files are skipped ---------------------------------------


def test_invalid_json_skipped(tmp_path):
    cat = _catalog(tmp_path, {}, {"bad.json": "{not json", "acme.json": {**MINIMAL, "id": "acme"}})
    assert cat.get("acme") is not None
    assert len(cat.errors) == 1
    assert cat.errors[0][0].name == "bad.json"


def test_reserved_id_skipped(tmp_path):
    cat = _catalog(tmp_path, {}, {"x.json": {**MINIMAL, "id": "mcpflow_x"}})
    assert cat.entries() == []
    assert "reserved" in cat.errors[0][1]


def test_bad_local_does_not_remove_builtin(tmp_path):
    cat = _catalog(
        tmp_path,
        {"gmail.json": {**MINIMAL, "id": "gmail"}},
        {"gmail.json": {**MINIMAL, "id": "gmail", "spec": {"kind": "remote"}}},
    )
    assert cat.get("gmail").origin == "builtin"
    assert "url" in cat.errors[0][1]


def test_misspelled_key_skipped(tmp_path):
    data = {k: v for k, v in MINIMAL.items() if k != "description"}
    data["descripton"] = "Clock."
    cat = _catalog(tmp_path, {}, {"x.json": data})
    assert cat.entries() == []
    assert "descripton" in cat.errors[0][1]


# --- Catalog entry schema ----------------------------------------------------


def test_minimal_entry_defaults(tmp_path):
    cat = _catalog(tmp_path, {"t.json": MINIMAL})
    e = cat.get("time")
    assert e.auth == "none" and e.tools == [] and e.setup == [] and e.color == "#4c8bf5"


def test_header_on_npm_rejected(tmp_path):
    bad = {
        **MINIMAL,
        "spec": {"kind": "npm", "package": "x"},
        "setup": [{"key": "Authorization", "where": "header"}],
    }
    cat = _catalog(tmp_path, {"t.json": bad})
    assert cat.entries() == []
    assert "header" in cat.errors[0][1] and "remote" in cat.errors[0][1]


def test_remote_without_url_rejected(tmp_path):
    cat = _catalog(tmp_path, {"t.json": {**MINIMAL, "spec": {"kind": "remote"}}})
    assert "url" in cat.errors[0][1]


def test_bad_color_rejected(tmp_path):
    cat = _catalog(tmp_path, {"t.json": {**MINIMAL, "color": "red"}})
    assert "color" in cat.errors[0][1]


# --- Search and categories ---------------------------------------------------


def _three(tmp_path):
    return _catalog(
        tmp_path,
        {
            "gmail.json": {
                **MINIMAL,
                "id": "gmail",
                "name": "Gmail",
                "vendor": "Google",
                "category": "google",
                "tools": ["search_emails", "send_email"],
            },
            "github.json": {
                **MINIMAL,
                "id": "github",
                "name": "GitHub",
                "vendor": "GitHub",
                "category": "dev",
                "tools": ["create_issue"],
            },
            "git.json": {**MINIMAL, "id": "git", "name": "Git", "category": "dev"},
        },
    )


def test_search_by_tool_name(tmp_path):
    assert [e.id for e in _three(tmp_path).search("send_email", None)] == ["gmail"]


def test_category_filter(tmp_path):
    assert [e.id for e in _three(tmp_path).search("", "google")] == ["gmail"]


def test_search_and_category_combine(tmp_path):
    assert [e.id for e in _three(tmp_path).search("git", "dev")] == ["git", "github"]


def test_counts_ignore_query(tmp_path):
    cat = _three(tmp_path)
    counts = cat.counts()
    assert counts["google"] == 1 and counts["dev"] == 2 and counts["util"] == 0
    assert set(counts) == set(CATEGORIES)
    assert cat.search("send_email", None) and cat.counts() == counts


# --- build_spec (the connect half that needs no server) ----------------------


def _entry(**over) -> CatalogEntry:
    return CatalogEntry.model_validate({**MINIMAL, **over, "origin": "builtin"})


def test_build_spec_minimal():
    spec = build_spec(_entry(), "time", {}, None)
    assert spec.kind == "python" and spec.package == "mcp-server-time"
    assert spec.catalog == "time" and spec.description == "Clock."
    assert spec.env == {} and spec.headers == {}


def test_build_spec_missing_required_names_key():
    e = _entry(spec={"kind": "npm", "package": "x"}, setup=[{"key": "SLACK_BOT_TOKEN", "where": "env"}])
    with pytest.raises(RegistryError) as exc:
        build_spec(e, "slack", {"SLACK_BOT_TOKEN": ""}, None)
    assert "SLACK_BOT_TOKEN" in str(exc.value)


def test_build_spec_optional_empty_left_out():
    e = _entry(
        spec={"kind": "npm", "package": "x"},
        setup=[{"key": "A", "where": "env"}, {"key": "B", "where": "env", "required": False}],
    )
    spec = build_spec(e, "x", {"A": "1", "B": ""}, None)
    assert spec.env == {"A": "1"}


def test_build_spec_header_lands_in_headers():
    e = _entry(
        spec={"kind": "remote", "url": "https://x/mcp"},
        setup=[{"key": "Authorization", "where": "header"}],
    )
    spec = build_spec(e, "x", {"Authorization": "Bearer x"}, None)
    assert spec.headers == {"Authorization": "Bearer x"} and spec.env == {}


def test_build_spec_args_posted_win_verbatim():
    e = _entry(spec={"kind": "npm", "package": "x", "args": ["/data"]})
    assert build_spec(e, "x", {}, None).args == ["/data"]
    assert build_spec(e, "x", {}, ["/mnt"]).args == ["/mnt"]
    assert build_spec(e, "x", {}, []).args == []


def test_build_spec_bad_namespace_is_registry_error():
    with pytest.raises(RegistryError) as exc:
        build_spec(_entry(), "Bad Name", {}, None)
    assert "namespace" in str(exc.value)


def test_run_command_follows_args():
    e = _entry(spec={"kind": "npm", "package": "x", "args": ["/data"]})
    assert e.run_command() == "npx -y x /data"
    assert e.run_command(["/mnt"]) == "npx -y x /mnt"
    assert e.run_command([]) == "npx -y x"


def test_run_command_names_the_source():
    """The detail must not show a command that would fail.

    `gdrive` sets `package` to a bin name that does not exist on npm; without
    the source the detail would read `npx -y mcp-server-gdrive` beside a child
    that runs fine.
    """
    e = _entry(spec={"kind": "npm", "package": "bin", "source": "github:o/r"})
    assert e.run_command() == "npx -y --package=github:o/r bin"


def test_run_command_and_preview_redact_the_source():
    """The detail shows the source twice, so both are masked.

    `build_command` returns what it is given and the detail renders it into a
    `<pre>`, so redacting only the preview would still leak through the
    command.
    """
    raw = "git+https://oauth2:TOKEN@host/o/r"
    e = _entry(spec={"kind": "npm", "package": "bin", "source": raw})
    # `redact_source` replaces the whole user information, user name included,
    # not only the secret half.
    assert e.run_command() == "npx -y --package=git+https://***@host/o/r bin"
    assert e.preview("ns")["source"] == "git+https://***@host/o/r"
    assert "TOKEN" not in e.run_command()
    assert "TOKEN" not in str(e.preview("ns"))


def test_run_command_keeps_its_remote_branch():
    e = _entry(spec={"kind": "remote", "url": "https://example.test/mcp"})
    assert e.run_command() == "HTTP https://example.test/mcp"


def test_a_source_on_a_remote_entry_is_rejected():
    with pytest.raises(ValidationError) as exc:
        _entry(spec={
            "kind": "remote",
            "url": "https://example.test/mcp",
            "source": "github:o/r",
        })
    assert "source" in str(exc.value)


def test_a_source_with_an_unknown_prefix_is_rejected():
    with pytest.raises(ValidationError) as exc:
        _entry(spec={"kind": "npm", "package": "bin", "source": "ftp://x"})
    assert "source" in str(exc.value)


def test_build_spec_carries_the_source():
    e = _entry(spec={"kind": "npm", "package": "bin", "source": "github:o/r#abc"})
    assert build_spec(e, "ns", {}, None).source == "github:o/r#abc"


def test_preview_masks_secrets_and_tags():
    e = _entry(spec={"kind": "npm", "package": "x"}, setup=[{"key": "TOKEN", "where": "env"}])
    p = e.preview("ns")
    assert p["env"] == {"TOKEN": "•••"} and p["catalog"] == "time" and p["namespace"] == "ns"


# --- Built-in catalog coverage -----------------------------------------------


def test_builtin_catalog_all_valid():
    cat = Catalog.load(BUILTIN_DIR, None, **KNOWN)
    assert cat.errors == []
    assert len(cat.entries()) == len(list(BUILTIN_DIR.glob("*.json")))
    assert all(n > 0 for n in cat.counts().values())
    for e in cat.entries():
        assert e.tools, e.id
        if e.spec.kind == "remote":
            assert e.spec.url.startswith("https://"), e.id


def test_every_builtin_git_source_is_pinned():
    """A git source has no tarball hash: npm prints `skipping integrity check
    for git dependency`, so the commit pin is its only integrity control.

    An unpinned `github:owner/repo` re-resolves the default branch at every
    cold npx cache, which runs upstream code the project never reviewed.
    """
    import re as _re

    cat = Catalog.load(BUILTIN_DIR, None, **KNOWN)
    for e in cat.entries():
        src = e.spec.source
        if src and src.startswith(("github:", "git+https://")):
            assert _re.search(r"#[0-9a-f]{40}$", src), f"{e.id} is not pinned: {src}"


def test_gdrive_is_an_oauth_entry_with_a_pinned_source():
    cat = Catalog.load(BUILTIN_DIR, None, **KNOWN)
    e = cat.get("gdrive")
    assert e.auth == "oauth"
    assert e.setup == []
    assert e.oauth.provider == "google"
    assert e.oauth.scopes == ["https://www.googleapis.com/auth/drive.readonly"]
    assert e.oauth.client_file.env == "GDRIVE_OAUTH_PATH"
    assert e.oauth.client_file.format == "google-client"
    assert e.oauth.token_file.env == "GDRIVE_CREDENTIALS_PATH"
    assert e.oauth.token_file.format == "google-auth-library"
    assert e.spec.kind == "npm"
    assert e.spec.package == "mcp-server-gdrive"  # the bin, not the npm name
    assert e.spec.source.startswith("github:dylancaponi/gdrive-mcp-server#")
    # Only what the child publishes with no extra env. `upload` and
    # `sheets_read` sit behind GDRIVE_ENABLE_UPLOAD / GDRIVE_ENABLE_SHEETS,
    # and `build_spec` sets only the two credential paths.
    assert e.tools == ["search", "read", "download", "list_folder", "export_pdf"]


def test_gcal_is_an_oauth_entry_with_the_two_formats_it_needs():
    """Neither Google format `gmail` and `gdrive` use works for this child.

    Measured against `@cocal/google-calendar-mcp` 2.6.3: `google-client` writes
    the client under `web` and the child's loader has no `web` branch, so it
    exits at start; `google-auth-library` writes a flat token object that the
    child accepts only through a migration branch and rewrites at first read.
    """
    cat = Catalog.load(BUILTIN_DIR, None, **KNOWN)
    e = cat.get("gcal")
    assert e.auth == "oauth"
    assert e.setup == []
    assert e.oauth.provider == "google"
    assert e.oauth.scopes == ["https://www.googleapis.com/auth/calendar"]
    assert e.oauth.client_file.env == "GOOGLE_OAUTH_CREDENTIALS"
    assert e.oauth.client_file.format == "google-client-flat"
    assert e.oauth.token_file.env == "GOOGLE_CALENDAR_MCP_TOKEN_PATH"
    assert e.oauth.token_file.format == "google-calendar"
    assert e.spec.kind == "npm"


def test_gcal_pins_its_package_version():
    """This entry encodes two facts about the child's private on-disk layout:
    the token map key, and the absence of a `web` branch. Neither is a
    published interface, so an unpinned entry would break every Calendar
    connection at once on the next cold npx cache.
    """
    import re as _re

    cat = Catalog.load(BUILTIN_DIR, None, **KNOWN)
    e = cat.get("gcal")
    assert _re.fullmatch(r"@cocal/google-calendar-mcp@\d+\.\d+\.\d+", e.spec.package)
    # The pin has to survive into the command, or it pins nothing.
    assert e.run_command() == f"npx -y {e.spec.package}"


def test_gcal_names_the_account_management_tool():
    """`manage-accounts` is registered outside the child's filtered tool
    registry and force-added to its available set, so `ENABLED_TOOLS` cannot
    withhold it. It removes accounts and starts a consent flow of the child's
    own, so the card names it rather than hiding it.
    """
    cat = Catalog.load(BUILTIN_DIR, None, **KNOWN)
    e = cat.get("gcal")
    assert e.tools == [
        "list-calendars", "list-events", "search-events", "get-event",
        "list-colors", "create-event", "create-events", "update-event",
        "delete-event", "get-freebusy", "get-current-time", "respond-to-event",
        "manage-accounts",
    ]


def test_connecting_gcal_registers_only_the_two_credential_paths():
    cat = Catalog.load(BUILTIN_DIR, None, **KNOWN)
    paths = CredPaths(
        client=Path("/data/creds/gcal/client.json"),
        token=Path("/data/creds/gcal/token.json"),
    )
    spec = build_spec(cat.get("gcal"), "gcal", {}, None, paths)
    assert spec.enabled is False
    assert spec.env == {
        "GOOGLE_OAUTH_CREDENTIALS": "/data/creds/gcal/client.json",
        "GOOGLE_CALENDAR_MCP_TOKEN_PATH": "/data/creds/gcal/token.json",
    }
    assert spec.catalog == "gcal"


def test_builtin_named_entries_present():
    cat = Catalog.load(BUILTIN_DIR, None, **KNOWN)
    for id in (
        "gmail", "gcal", "gdrive", "m365", "slack", "linear", "asana", "atlassian",
        "notion", "github", "gitlab", "sentry", "stripe", "zapier", "figma", "fs",
        "postgres", "time", "fetch", "memory",
    ):
        assert cat.get(id) is not None, id


# --- OAuth entries (oauth-connect, 3.1 to 3.4) -------------------------------


def test_gmail_is_oauth_entry():
    cat = Catalog.load(BUILTIN_DIR, None, **KNOWN)
    e = cat.get("gmail")
    assert e is not None and e.auth == "oauth"
    assert e.oauth is not None and e.oauth.provider == "google"
    assert e.oauth.client_file.env == "GMAIL_OAUTH_PATH"
    assert e.oauth.token_file.env == "GMAIL_CREDENTIALS_PATH"
    assert e.setup == []


def test_oauth_block_without_oauth_auth_rejected(tmp_path):
    _write(tmp_path / "b", "x.json", _oauth_file(auth="env"))
    cat = Catalog.load(tmp_path / "b", None, **KNOWN)
    assert cat.entries() == []
    assert "oauth" in cat.errors[0][1]


def test_oauth_block_with_setup_rejected(tmp_path):
    data = _oauth_file(setup=[{"key": "EXTRA", "where": "env"}])
    _write(tmp_path / "b", "x.json", data)
    cat = Catalog.load(tmp_path / "b", None, **KNOWN)
    assert cat.entries() == []
    assert "oauth" in cat.errors[0][1]


def test_oauth_auth_without_block_valid(tmp_path):
    # An `auth: "oauth"` entry with no block is a remote vendor MCP Flow
    # cannot sign in to yet. It stays valid and needs no known provider.
    data = {k: v for k, v in _oauth_file().items() if k != "oauth"}
    data["spec"] = {"kind": "remote", "url": "https://x/mcp"}
    _write(tmp_path / "b", "x.json", data)
    cat = Catalog.load(tmp_path / "b", None)
    assert cat.get("gmail") is not None
    assert cat.errors == []


def test_unknown_provider_skipped(tmp_path):
    _write(tmp_path / "b", "x.json", _oauth_file(oauth={
        "provider": "acme",
        "scopes": ["s"],
        "client_file": {"env": "E1", "format": "google-client"},
        "token_file": {"env": "E2", "format": "google-auth-library"},
    }))
    cat = Catalog.load(tmp_path / "b", None, **KNOWN)
    assert cat.entries() == []
    assert "acme" in cat.errors[0][1]


def test_unknown_format_skipped(tmp_path):
    _write(tmp_path / "b", "x.json", _oauth_file(oauth={
        "provider": "google",
        "scopes": ["s"],
        "client_file": {"env": "E1", "format": "google-client"},
        "token_file": {"env": "E2", "format": "acme-v9"},
    }))
    cat = Catalog.load(tmp_path / "b", None, **KNOWN)
    assert cat.entries() == []
    assert "acme-v9" in cat.errors[0][1]


def test_provider_files_are_not_entries():
    # `providers/google.json` ships inside the package, in a subdirectory the
    # non-recursive glob never reads, so no catalog entry has id `google`.
    cat = Catalog.load(BUILTIN_DIR, None, **KNOWN)
    assert cat.get("google") is None


def _oauth_entry(**over) -> CatalogEntry:
    return CatalogEntry.model_validate({**_oauth_file(), **over, "origin": "builtin"})


def test_build_spec_oauth():
    e = _oauth_entry()
    paths = CredPaths(
        client=Path("/data/creds/gmail/client.json"),
        token=Path("/data/creds/gmail/token.json"),
    )
    spec = build_spec(e, "gmail", {"ignored": "x"}, None, paths)
    assert spec.enabled is False
    assert spec.headers == {}
    assert spec.env == {
        "GMAIL_OAUTH_PATH": "/data/creds/gmail/client.json",
        "GMAIL_CREDENTIALS_PATH": "/data/creds/gmail/token.json",
    }
    assert spec.catalog == "gmail"


def test_build_spec_oauth_carries_the_source():
    """The oauth branch of `build_spec` is a second `data` dict.

    This is the path `gdrive` takes, and it is the one that must carry the
    source: without it the child would run `npx -y mcp-server-gdrive`, a
    package that does not exist on npm.
    """
    e = _oauth_entry(spec={
        "kind": "npm",
        "package": "mcp-server-gdrive",
        "source": "github:o/r#abc",
    })
    paths = CredPaths(
        client=Path("/data/creds/gmail/client.json"),
        token=Path("/data/creds/gmail/token.json"),
    )
    spec = build_spec(e, "gmail", {}, None, paths)
    assert spec.source == "github:o/r#abc"
    assert spec.package == "mcp-server-gdrive"


def test_build_spec_oauth_needs_cred_paths():
    with pytest.raises(RegistryError) as exc:
        build_spec(_oauth_entry(), "gmail", {}, None)
    assert "cred_paths" in str(exc.value)


# --- header sink (remote-oauth) ----------------------------------------------


def _header_file(**over) -> dict:
    data = {
        "id": "linear",
        "name": "Linear",
        "vendor": "Linear",
        "category": "projects",
        "description": "Linear.",
        "auth": "oauth",
        "tools": ["list_issues"],
        "spec": {"kind": "remote", "url": "https://mcp.linear.app/sse", "transport": "sse"},
        "oauth": {
            "provider": "linear",
            "scopes": ["read", "write"],
            "header": {"name": "Authorization", "scheme": "Bearer"},
        },
    }
    data.update(over)
    return data


def _header_entry(**over) -> CatalogEntry:
    return CatalogEntry.model_validate({**_header_file(), **over, "origin": "builtin"})


def test_linear_is_header_sink_entry():
    cat = Catalog.load(BUILTIN_DIR, None, **KNOWN)
    e = cat.get("linear")
    assert e is not None and e.auth == "oauth"
    assert e.oauth is not None and e.oauth.provider == "linear"
    assert e.oauth.header is not None
    assert e.oauth.header.name == "Authorization"
    assert e.oauth.header.scheme == "Bearer"
    assert e.oauth.client_file is None and e.oauth.token_file is None


def test_one_sink_per_block(tmp_path):
    data = _header_file()
    data["oauth"]["client_file"] = {"env": "E1", "format": "google-client"}
    data["oauth"]["token_file"] = {"env": "E2", "format": "google-auth-library"}
    _write(tmp_path / "b", "x.json", data)
    cat = Catalog.load(tmp_path / "b", None, **KNOWN)
    assert cat.entries() == []
    assert "header" in cat.errors[0][1] or "client_file" in cat.errors[0][1]


def test_block_needs_a_sink(tmp_path):
    data = _header_file()
    del data["oauth"]["header"]
    _write(tmp_path / "b", "x.json", data)
    cat = Catalog.load(tmp_path / "b", None, **KNOWN)
    assert cat.entries() == []
    assert "header" in cat.errors[0][1] or "client_file" in cat.errors[0][1]


def test_header_sink_requires_remote(tmp_path):
    data = _header_file(spec={"kind": "npm", "package": "x"})
    _write(tmp_path / "b", "x.json", data)
    cat = Catalog.load(tmp_path / "b", None, **KNOWN)
    assert cat.entries() == []
    assert "remote" in cat.errors[0][1]


def test_file_sink_requires_local(tmp_path):
    data = _oauth_file(spec={"kind": "remote", "url": "https://x/mcp"})
    _write(tmp_path / "b", "x.json", data)
    cat = Catalog.load(tmp_path / "b", None, **KNOWN)
    assert cat.entries() == []
    assert "python" in cat.errors[0][1] or "npm" in cat.errors[0][1]


def test_build_spec_header_sink():
    spec = build_spec(_header_entry(), "linear", {"ignored": "x"}, None)
    assert spec.kind == "remote" and spec.enabled is False
    assert spec.headers == {} and spec.env == {}
    assert spec.oauth_pending is True
    assert spec.catalog == "linear"
