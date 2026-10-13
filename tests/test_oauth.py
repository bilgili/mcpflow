"""The OAuth client module: provider registry, credential store, file
formats, pending flows, and the two URL builders.

Scenarios from `specs/oauth-client/spec.md`. Tests use `tmp_path` for the
provider directories and the store, and `BUILTIN_DIR / "providers"` for the
built-in Google provider.
"""

from __future__ import annotations

import json
import stat
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from mcpflow.catalog import BUILTIN_DIR, FileSink, OAuthBlock
from mcpflow.oauth import (
    CLIENT_FORMATS,
    GCAL_ACCOUNT_MODE,
    TOKEN_FORMATS,
    ClientCreds,
    CredStore,
    OAuthTokenError,
    PendingFlows,
    Provider,
    ProviderRegistry,
    authorize_url,
    token_request,
)

PROVIDERS_DIR = BUILTIN_DIR / "providers"


def _write(directory: Path, name: str, data) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(data if isinstance(data, str) else json.dumps(data))
    return path


# --- Provider registry (4.1) -------------------------------------------------


def test_builtin_google_provider_loads():
    reg = ProviderRegistry.load(PROVIDERS_DIR, None)
    p = reg.get("google")
    assert p is not None and p.pkce is True
    assert p.authorize_params == {"access_type": "offline", "prompt": "consent"}
    assert reg.skipped == []
    assert "google" in reg.ids()


def test_local_provider_overrides_builtin(tmp_path):
    local = tmp_path / "local"
    _write(local, "google.json", {
        "id": "google",
        "name": "Google",
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "help": "local help",
    })
    reg = ProviderRegistry.load(PROVIDERS_DIR, local)
    # Built-in ships google, linear, and moomoo; the local file overrides google.
    assert reg.ids() == frozenset({"google", "linear", "moomoo"})
    assert reg.get("google").help == "local help"


def test_http_token_url_rejected(tmp_path):
    b = tmp_path / "b"
    _write(b, "bad.json", {
        "id": "bad",
        "name": "Bad",
        "authorize_url": "https://example.com/auth",
        "token_url": "http://example.com/token",
    })
    reg = ProviderRegistry.load(b, None)
    assert reg.get("bad") is None
    assert "token_url" in reg.skipped[0][1]


def test_unknown_provider_key_skipped(tmp_path):
    b = tmp_path / "b"
    _write(b, "x.json", {
        "id": "x",
        "name": "X",
        "authorize_url": "https://e/auth",
        "token_url": "https://e/token",
        "bogus": 1,
    })
    reg = ProviderRegistry.load(b, None)
    assert reg.get("x") is None
    assert "bogus" in reg.skipped[0][1]


def test_missing_local_provider_dir(tmp_path):
    reg = ProviderRegistry.load(PROVIDERS_DIR, tmp_path / "nope")
    assert reg.get("google") is not None
    assert reg.skipped == []


# --- Credential store (4.2) --------------------------------------------------


def test_client_file_is_private(tmp_path):
    store = CredStore(tmp_path)
    store.write_client("gmail", "google-client", ClientCreds("abc", "xyz"))
    path = store.paths("gmail").client
    assert path.parent == tmp_path / "creds" / "gmail"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_write_replaces_atomically(tmp_path):
    store = CredStore(tmp_path)
    store.write_client("gmail", "google-client", ClientCreds("a", "1"))
    store.write_client("gmail", "google-client", ClientCreds("b", "2"))
    path = store.paths("gmail").client
    assert json.loads(path.read_text())["web"]["client_id"] == "b"
    # No temporary file is left behind in the namespace directory.
    assert [p.name for p in path.parent.glob("*.tmp")] == []


def test_remove_absent_ok(tmp_path):
    store = CredStore(tmp_path)
    store.remove("never_existed")  # no error


def test_has_client_has_token_awaiting(tmp_path):
    store = CredStore(tmp_path)
    assert not store.has_client("gmail")
    assert not store.awaiting("gmail")
    store.write_client("gmail", "google-client", ClientCreds("a", "1"))
    assert store.has_client("gmail") and not store.has_token("gmail")
    assert store.awaiting("gmail") is True
    store.write_token("gmail", "google-auth-library", {
        "access_token": "a", "refresh_token": "r", "scope": "s",
        "token_type": "Bearer", "expires_in": 3600,
    })
    assert store.has_token("gmail") and store.awaiting("gmail") is False
    store.remove("gmail")
    assert not store.has_client("gmail") and not store.has_token("gmail")


# --- File formats (4.3) ------------------------------------------------------


def test_google_client_shape():
    text = CLIENT_FORMATS["google-client"](ClientCreds("abc", "xyz"))
    assert json.loads(text) == {"web": {"client_id": "abc", "client_secret": "xyz"}}


def test_google_token_shape():
    before = int(time.time() * 1000)
    text = TOKEN_FORMATS["google-auth-library"]({
        "access_token": "a", "refresh_token": "r", "scope": "s",
        "token_type": "Bearer", "expires_in": 3600,
    })
    out = json.loads(text)
    assert out["access_token"] == "a" and out["refresh_token"] == "r"
    assert out["scope"] == "s" and out["token_type"] == "Bearer"
    assert "expires_in" not in out
    expected = before + 3600 * 1000
    assert abs(out["expiry_date"] - expected) <= 1000


def test_google_token_no_expiry_omits_the_field():
    """A response with no `expires_in` is a valid non-expiring token: omit
    `expiry_date`, keep the rest, do not raise."""
    text = TOKEN_FORMATS["google-auth-library"]({
        "access_token": "a", "refresh_token": "r", "scope": "s",
        "token_type": "Bearer",
    })
    out = json.loads(text)
    assert out["access_token"] == "a" and out["refresh_token"] == "r"
    assert "expiry_date" not in out and "expires_in" not in out


def test_google_token_null_expiry_omits_the_field():
    """A JSON null `expires_in` reads as `None`, the same as absent: omit."""
    text = TOKEN_FORMATS["google-auth-library"]({
        "access_token": "a", "token_type": "Bearer", "expires_in": None,
    })
    out = json.loads(text)
    assert "expiry_date" not in out


def test_google_token_numeric_string_expiry_is_kept():
    """`int("3600")` succeeds; some providers send the field as a string, and
    the shipped code connects them. Keep it, do not refuse it."""
    before = int(time.time() * 1000)
    text = TOKEN_FORMATS["google-auth-library"]({
        "access_token": "a", "token_type": "Bearer", "expires_in": "3600",
    })
    out = json.loads(text)
    assert abs(out["expiry_date"] - (before + 3600 * 1000)) <= 1000


def test_google_token_zero_expiry_is_kept_not_omitted():
    """Integer `0` is a present, valid, zero-second expiry, not an omission.
    A truthiness guard would drop it; the `is None` test keeps it."""
    before = int(time.time() * 1000)
    text = TOKEN_FORMATS["google-auth-library"]({
        "access_token": "a", "token_type": "Bearer", "expires_in": 0,
    })
    out = json.loads(text)
    assert "expiry_date" in out
    assert abs(out["expiry_date"] - before) <= 1000


def test_google_token_non_numeric_expiry_is_refused():
    """A present-but-unparseable value is a malformed response, not a
    non-expiring token: raise `OAuthTokenError`, do not coerce."""
    with pytest.raises(OAuthTokenError):
        TOKEN_FORMATS["google-auth-library"]({
            "access_token": "a", "token_type": "Bearer", "expires_in": "later",
        })


def test_google_token_overflowing_expiry_is_refused():
    """JSON `1e400` parses to a float infinity and `int(inf)` overflows. The
    builder turns that `OverflowError` into `OAuthTokenError`, so the response
    never escapes as a bare 500."""
    assert json.loads("1e400") == float("inf")  # what the JSON parser yields
    with pytest.raises(OAuthTokenError):
        TOKEN_FORMATS["google-auth-library"]({
            "access_token": "a", "token_type": "Bearer", "expires_in": float("inf"),
        })


def test_google_client_flat_shape():
    """The Calendar child's loader has no `web` branch.

    Measured against `@cocal/google-calendar-mcp` 2.6.3: a `web` file makes it
    exit with `Invalid credentials file format`, and an `installed` file with
    no `redirect_uris` crashes on `redirect_uris[0]`. Only the top-level shape
    starts the child.
    """
    text = CLIENT_FORMATS["google-client-flat"](ClientCreds("abc", "xyz"))
    assert json.loads(text) == {"client_id": "abc", "client_secret": "xyz"}


def test_google_calendar_wraps_under_the_account_mode():
    text = TOKEN_FORMATS["google-calendar"]({
        "access_token": "a", "refresh_token": "r", "scope": "s",
        "token_type": "Bearer", "expires_in": 3600,
    })
    out = json.loads(text)
    assert list(out) == [GCAL_ACCOUNT_MODE] == ["normal"]
    inner = out["normal"]
    assert inner["access_token"] == "a" and inner["refresh_token"] == "r"
    assert "expires_in" not in inner and "expiry_date" in inner


def test_google_calendar_key_is_a_valid_account_id():
    """`loadAllAccounts` validates every key against
    `^[a-z0-9_-]{1,64}$` and skips the ones that fail, which is why the
    account email the earlier proposal wanted cannot be the key.
    """
    import re

    assert re.fullmatch(r"[a-z0-9_-]{1,64}", GCAL_ACCOUNT_MODE)
    assert GCAL_ACCOUNT_MODE not in {".", "..", "con", "prn", "aux", "nul"}


def test_the_two_token_formats_share_one_credentials_owner(monkeypatch):
    """The `expires_in` to `expiry_date` conversion has one owner.

    Both formats are re-read through the shared builder, so replacing it moves
    both. A copy in either format would leave that format on the real clock and
    fail this test.
    """
    monkeypatch.setattr(
        "mcpflow.oauth._google_credentials", lambda tokens: {"sentinel": 1}
    )
    response = {"access_token": "a", "expires_in": 3600}
    assert json.loads(TOKEN_FORMATS["google-auth-library"](response)) == {"sentinel": 1}
    assert json.loads(TOKEN_FORMATS["google-calendar"](response)) == {
        "normal": {"sentinel": 1}
    }


def test_calendar_format_holds_exactly_what_the_flat_format_holds():
    """The wrapper adds a key and changes nothing inside it."""
    response = {
        "access_token": "a", "refresh_token": "r", "scope": "s",
        "token_type": "Bearer", "expires_in": 3600,
    }
    flat = json.loads(TOKEN_FORMATS["google-auth-library"](response))
    wrapped = json.loads(TOKEN_FORMATS["google-calendar"](response))["normal"]
    # Both read the clock, so the two values differ by the call gap.
    assert abs(flat.pop("expiry_date") - wrapped.pop("expiry_date")) <= 1000
    assert flat == wrapped


# --- Pending flows (4.4) -----------------------------------------------------


def _client() -> ClientCreds:
    return ClientCreds("abc", "secret")


def test_state_has_128_bits():
    flows = PendingFlows()
    flow = flows.create("gmail", "gmail", _client(), ADMIN_ACTOR)
    # token_urlsafe(32) is 32 random bytes, well over 128 bits; its text is
    # at least 22 base64url characters.
    assert len(flow.state) >= 22
    assert len(flow.code_verifier) >= 43


def test_pop_returns_once():
    flows = PendingFlows()
    flow = flows.create("gmail", "gmail", _client(), ADMIN_ACTOR)
    assert flows.pop(flow.state) is flow
    assert flows.pop(flow.state) is None


def test_pop_expired_is_none():
    flows = PendingFlows(ttl=0.0)
    flow = flows.create("gmail", "gmail", _client(), ADMIN_ACTOR)
    time.sleep(0.01)
    assert flows.pop(flow.state) is None


def test_discard_drops_namespace_flows():
    flows = PendingFlows()
    a = flows.create("gmail", "gmail", _client(), ADMIN_ACTOR)
    b = flows.create("gmail", "gmail", _client(), ADMIN_ACTOR)
    c = flows.create("slack", "slack", _client(), ADMIN_ACTOR)
    flows.discard("gmail")
    assert flows.pop(a.state) is None and flows.pop(b.state) is None
    assert flows.pop(c.state) is c


def test_peek_does_not_consume():
    flows = PendingFlows()
    flow = flows.create("gmail", "gmail", _client(), ADMIN_ACTOR)
    assert flows.peek(flow.state) is flow
    assert flows.peek(flow.state) is flow  # still there
    assert flows.pop(flow.state) is flow   # pop still consumes
    assert flows.peek(flow.state) is None


def test_create_reauth_flow():
    flows = PendingFlows()
    connect = flows.create("gmail", "gmail", _client(), ADMIN_ACTOR)
    reauth = flows.create("slack", "slack", _client(), ADMIN_ACTOR, reauth=True)
    assert connect.reauth is False
    assert reauth.reauth is True


def test_has_open():
    flows = PendingFlows()
    assert flows.has_open("gmail") is False
    flow = flows.create("gmail", "gmail", _client(), ADMIN_ACTOR, reauth=True)
    assert flows.has_open("gmail") is True
    assert flows.has_open("slack") is False
    flows.pop(flow.state)
    assert flows.has_open("gmail") is False


def test_begin_exchange_is_exclusive():
    flows = PendingFlows()
    flow = flows.create("gmail", "gmail", _client(), ADMIN_ACTOR)
    assert flows.begin_exchange(flow.state) is True
    assert flows.begin_exchange(flow.state) is False  # already in flight
    flows.end_exchange(flow.state)
    assert flows.begin_exchange(flow.state) is True   # freed
    flows.discard("gmail")
    assert flows.begin_exchange(flow.state) is True    # discard cleared the mark


def test_sweep_evicts_abandoned_flow():
    # An abandoned flow leaves memory at the next flow operation, not only on
    # its own pop.
    flows = PendingFlows(ttl=0.0)
    a = flows.create("gmail", "gmail", _client(), ADMIN_ACTOR)
    time.sleep(0.01)
    flows.create("slack", "slack", _client(), ADMIN_ACTOR)  # sweeps `a`
    assert flows.peek(a.state) is None


# --- Authorization request and token exchange (4.5) --------------------------


def _provider(pkce: bool = True) -> Provider:
    return Provider(
        id="google",
        name="Google",
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        authorize_params={"access_type": "offline", "prompt": "consent"},
        pkce=pkce,
    )


def _block() -> OAuthBlock:
    return OAuthBlock(
        provider="google",
        scopes=["https://x/gmail.modify", "https://x/gmail.settings.basic"],
        client_file=FileSink(env="GMAIL_OAUTH_PATH", format="google-client"),
        token_file=FileSink(env="GMAIL_CREDENTIALS_PATH", format="google-auth-library"),
    )


def test_authorize_url_google():
    flows = PendingFlows()
    flow = flows.create("gmail", "gmail", _client(), ADMIN_ACTOR)
    url = authorize_url(
        _provider(), _block(), "https://mcp.example/oauth/callback", flow
    )
    split = urlsplit(url)
    assert f"{split.scheme}://{split.netloc}{split.path}" == (
        "https://accounts.google.com/o/oauth2/v2/auth"
    )
    q = parse_qs(split.query)
    assert q["response_type"] == ["code"]
    assert q["client_id"] == ["abc"]
    assert q["redirect_uri"] == ["https://mcp.example/oauth/callback"]
    assert q["scope"] == ["https://x/gmail.modify https://x/gmail.settings.basic"]
    assert q["state"] == [flow.state]
    assert q["access_type"] == ["offline"] and q["prompt"] == ["consent"]
    assert q["code_challenge_method"] == ["S256"] and q["code_challenge"][0]


def test_authorize_url_without_pkce():
    flows = PendingFlows()
    flow = flows.create("gmail", "gmail", _client(), ADMIN_ACTOR)
    url = authorize_url(_provider(pkce=False), _block(), "https://mcp.example/oauth/callback", flow)
    q = parse_qs(urlsplit(url).query)
    assert "code_challenge" not in q and "code_challenge_method" not in q


def test_token_request_body():
    flows = PendingFlows()
    flow = flows.create("gmail", "gmail", _client(), ADMIN_ACTOR)
    url, body = token_request(
        _provider(), "https://mcp.example/oauth/callback", "the-code", flow
    )
    assert url == "https://oauth2.googleapis.com/token"
    assert body["grant_type"] == "authorization_code"
    assert body["code"] == "the-code"
    assert body["redirect_uri"] == "https://mcp.example/oauth/callback"
    assert body["client_id"] == "abc" and body["client_secret"] == "secret"
    assert body["code_verifier"] == flow.code_verifier


def test_token_request_without_pkce():
    flows = PendingFlows()
    flow = flows.create("gmail", "gmail", _client(), ADMIN_ACTOR)
    _url, body = token_request(_provider(pkce=False), "https://mcp.example/oauth/callback", "c", flow)
    assert "code_verifier" not in body


# --- 10E (10.18): existing scenarios under a server reference ---------------
#
# Guarded invariant: OpTouchesOnlyOwnPaths
# (specs/tla/multi_user_access_lifecycle.tla, negative config
# multi_user_access_lifecycle_nskeyed.cfg). Every scenario runs under the
# user reference `gmail@alice`, beside an admin-owned `gmail` whose
# credential tree must stay byte-identical.


from keyed_stores import (
    BAD_REFS,
    TOKENS,
    build,
    drain,
    tree,
    user_add,
    user_spec,
)

from mcpflow.oauth import HeaderSpec
from mcpflow.registry import RegistryError, ServerKey

GMAIL_ALICE = ServerKey("alice", "gmail")


def _admin_gmail_creds(store: CredStore) -> None:
    store.write_client("gmail", "google-client", ClientCreds("admin-id", "admin-s"))
    store.write_token("gmail", "google-auth-library", TOKENS)


def test_client_file_is_private_under_a_user_reference(tmp_path):
    """Client file is private, for reference `gmail@alice`.
    Invariant: OpTouchesOnlyOwnPaths."""
    store = CredStore(tmp_path)
    store.write_client("gmail@alice", "google-client", ClientCreds("a", "1"))
    path = store.paths("gmail@alice").client
    assert path.parent == tmp_path / "creds" / "gmail@alice"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not (tmp_path / "creds" / "gmail").exists()


def test_abandoned_flow_is_evicted_under_a_user_reference():
    """Abandoned flow is evicted: the sweep runs on any later operation."""
    flows = PendingFlows(ttl=0.0)
    old = flows.create("gmail@alice", "gmail", _client(), ADMIN_ACTOR)
    assert old.ref == "gmail@alice"
    time.sleep(0.01)
    flows.create("gmail", "gmail", _client(), ADMIN_ACTOR)
    assert flows.peek(old.state) is None
    assert flows.has_open("gmail@alice") is False


def test_state_is_consumed_once_under_a_user_reference():
    """State is consumed once: a second pop of the same state finds nothing."""
    flows = PendingFlows()
    flow = flows.create("gmail@alice", "gmail", _client(), ADMIN_ACTOR)
    assert flows.pop(flow.state) is flow
    assert flows.pop(flow.state) is None


def test_expired_flow_under_a_user_reference_writes_no_token(tmp_path):
    """Expired flow: the callback finds no flow, so no token file appears."""
    flows = PendingFlows(ttl=0.0)
    store = CredStore(tmp_path)
    flow = flows.create("gmail@alice", "gmail", _client(), ADMIN_ACTOR)
    time.sleep(0.01)
    assert flows.peek(flow.state) is None and flows.pop(flow.state) is None
    assert not store.has_token("gmail@alice")


def test_the_connect_path_writes_through_the_supervisor_only():
    """The connect path writes through the supervisor: no module outside
    `Supervisor` (and the store itself) calls `CredStore.write_client`,
    `write_token`, or `remove`."""
    src = Path(__file__).resolve().parents[1] / "src" / "mcpflow"
    offenders = []
    for path in src.rglob("*.py"):
        if path.name in ("oauth.py", "supervisor.py"):
            continue
        text = path.read_text()
        for call in ("creds.write_client(", "creds.write_token(", "creds.remove("):
            if call in text:
                offenders.append(f"{path.name}: {call}")
    assert offenders == []


@pytest.mark.asyncio
async def test_remove_deletes_the_credential_directory_of_a_user_reference(tmp_path):
    """Remove deletes the credential directory, for `gmail@alice`; the admin
    `gmail` tree does not change. Invariant: OpTouchesOnlyOwnPaths."""
    sup = build(tmp_path, user_spec("gmail", "alice", enabled=False))
    _admin_gmail_creds(sup.creds)
    admin_before = tree(tmp_path / "creds" / "gmail")
    sup.creds.write_client("gmail@alice", "google-client", ClientCreds("a", "1"))
    sup.creds.write_token("gmail@alice", "google-auth-library", TOKENS)
    try:
        await sup.remove(GMAIL_ALICE, ADMIN_ACTOR)
        assert not (tmp_path / "creds" / "gmail@alice").exists()
        assert tree(tmp_path / "creds" / "gmail") == admin_before
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_remove_of_a_user_child_without_credentials(tmp_path):
    """Remove of a child without credentials completes with no error."""
    sup = build(tmp_path, user_spec("gmail", "alice", enabled=False))
    try:
        await sup.remove(GMAIL_ALICE, ADMIN_ACTOR)
        assert GMAIL_ALICE not in {s.key for s in sup.registry.list()}
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_callback_after_delete_of_a_user_child(tmp_path):
    """Callback after delete: the late callback writes nothing for the
    removed reference, and the registry holds no `gmail@alice`."""
    sup = build(tmp_path, user_spec("gmail", "alice", enabled=False))
    sup.creds.write_client("gmail@alice", "google-client", ClientCreds("a", "1"))
    flow = sup.flows.create("gmail@alice", "gmail", ClientCreds("a", "1"), ADMIN_ACTOR)
    try:
        await sup.remove(GMAIL_ALICE, ADMIN_ACTOR)
        assert await sup.finish_oauth(flow, "google-auth-library", TOKENS) is False
        assert not (tmp_path / "creds" / "gmail@alice").exists()
        assert GMAIL_ALICE not in {s.key for s in sup.registry.list()}
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_hand_enable_of_a_pending_user_child(tmp_path):
    """Hand enable of a pending child: refused, naming the reference."""
    sup = build(tmp_path, user_spec("gmail", "alice", enabled=False))
    sup.creds.write_client("gmail@alice", "google-client", ClientCreds("a", "1"))
    try:
        with pytest.raises(RegistryError) as exc:
            await sup.enable(GMAIL_ALICE, ADMIN_ACTOR)
        assert "gmail@alice" in str(exc.value)
        assert "authoriz" in str(exc.value)
        assert sup.get(GMAIL_ALICE).status == "stopped"
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_rest_enable_of_a_pending_user_child(tmp_path):
    """REST enable of a pending child: `update` with `enabled` true is
    refused and the registry keeps `enabled` false."""
    sup = build(tmp_path, user_spec("gmail", "alice", enabled=False))
    sup.creds.write_client("gmail@alice", "google-client", ClientCreds("a", "1"))
    try:
        with pytest.raises(RegistryError):
            await sup.update(GMAIL_ALICE, user_spec("gmail", "alice", enabled=True), ADMIN_ACTOR)
        assert sup.registry.get(GMAIL_ALICE).enabled is False
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_enable_after_the_token_exists_for_a_user_child(tmp_path):
    """Enable after the token exists: the child starts."""
    sup = build(tmp_path, user_spec("gmail", "alice", enabled=False))
    sup.creds.write_client("gmail@alice", "google-client", ClientCreds("a", "1"))
    sup.creds.write_token("gmail@alice", "google-auth-library", TOKENS)
    try:
        await sup.enable(GMAIL_ALICE, ADMIN_ACTOR)
        assert sup.get(GMAIL_ALICE).status == "starting"
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_a_deleted_user_child_leaves_no_credential_behind(tmp_path):
    """A deleted child leaves no credential behind: the second delete after
    the teardown drops a token the child wrote again. Invariant:
    OpTouchesOnlyOwnPaths (the admin `gmail` tree stays)."""
    sup = build(tmp_path, user_spec("gmail", "alice", enabled=False))
    _admin_gmail_creds(sup.creds)
    admin_before = tree(tmp_path / "creds" / "gmail")
    own = tmp_path / "creds" / "gmail@alice"
    sup.creds.write_client("gmail@alice", "google-client", ClientCreds("a", "1"))

    async def child_rewrites_token(_child):
        own.mkdir(parents=True, exist_ok=True)
        (own / "token.json").write_text('{"refresh_token": "r"}')

    sup._teardown = child_rewrites_token
    try:
        await sup.remove(GMAIL_ALICE, ADMIN_ACTOR)
        assert not own.exists()
        assert tree(tmp_path / "creds" / "gmail") == admin_before
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_a_removal_interrupted_by_a_restart_under_a_user_reference(tmp_path):
    """A removal interrupted by a restart leaves no usable credential: the
    next add of `gmail@alice` purges the residue, and `awaiting` is true once
    the connect wrote `client.json`. The admin `gmail` tree stays."""
    sup = build(tmp_path)
    _admin_gmail_creds(sup.creds)
    admin_before = tree(tmp_path / "creds" / "gmail")
    sup.creds.write_client("gmail@alice", "google-client", ClientCreds("old", "1"))
    sup.creds.write_token("gmail@alice", "google-auth-library", TOKENS)  # residue
    try:
        await user_add(sup, user_spec("gmail", "alice", enabled=False),
                       client_fmt="google-client", client=ClientCreds("new", "2"))
        assert sup.creds.awaiting("gmail@alice") is True
        assert not sup.creds.has_token("gmail@alice")
        assert tree(tmp_path / "creds" / "gmail") == admin_before
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_a_duplicate_add_keeps_the_live_user_childs_credential(tmp_path):
    """A duplicate add keeps the live child's credential, for `gmail@alice`."""
    sup = build(tmp_path, user_spec("gmail", "alice", enabled=False))
    sup.creds.write_client("gmail@alice", "google-client", ClientCreds("a", "1"))
    sup.creds.write_token("gmail@alice", "google-auth-library", TOKENS)
    before = tree(tmp_path / "creds" / "gmail@alice")
    try:
        with pytest.raises(RegistryError, match="gmail"):
            await user_add(sup, user_spec("gmail", "alice", enabled=False))
        assert tree(tmp_path / "creds" / "gmail@alice") == before
    finally:
        await drain(sup)


_NEW = {"access_token": "new-access", "refresh_token": "new-refresh", "scope": "s",
        "token_type": "Bearer", "expires_in": 3600}


def _reauth_sup(tmp_path, *, enabled: bool):
    """`gmail@alice` with an old grant, beside admin `gmail`; a recorder logs
    the teardown and the two credential writes in order."""
    sup = build(tmp_path, user_spec("gmail", "alice", enabled=enabled))
    _admin_gmail_creds(sup.creds)
    sup.creds.write_client("gmail@alice", "google-client", ClientCreds("old", "o"))
    sup.creds.write_token("gmail@alice", "google-auth-library", TOKENS)
    sup.get(GMAIL_ALICE).status = "running" if enabled else "stopped"
    events: list[str] = []
    real_teardown = sup._teardown

    async def teardown(child):
        events.append("teardown")
        await real_teardown(child)

    sup._teardown = teardown
    for name in ("write_client", "write_token"):
        real = getattr(sup.creds, name)

        def wrapped(*a, _real=real, _name=name, **kw):
            events.append(f"{_name}:{a[0]}")
            return _real(*a, **kw)

        setattr(sup.creds, name, wrapped)
    return sup, events


async def _reauth(sup):
    flow = sup.flows.create("gmail@alice", "gmail", ClientCreds("new", "n"), ADMIN_ACTOR, reauth=True)
    return await sup.finish_oauth(flow, "google-auth-library", _NEW,
                                  client_fmt="google-client", reauth=True)


@pytest.mark.asyncio
async def test_reauthorization_tears_the_user_child_down_before_it_writes(tmp_path):
    """Re-authorization tears the child down before it writes, then restarts
    it. Every write names `gmail@alice`. Invariant: OpTouchesOnlyOwnPaths."""
    sup, events = _reauth_sup(tmp_path, enabled=True)
    admin_before = tree(tmp_path / "creds" / "gmail")
    try:
        assert await _reauth(sup) is True
        assert events[:3] == ["teardown", "write_client:gmail@alice",
                              "write_token:gmail@alice"]
        assert sup.get(GMAIL_ALICE).task is not None  # the restart
        assert tree(tmp_path / "creds" / "gmail") == admin_before
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_reauthorization_lands_one_grant_in_the_user_token_file(tmp_path):
    """Re-authorization lands one grant in the token file of `gmail@alice`."""
    sup, _events = _reauth_sup(tmp_path, enabled=True)
    try:
        assert await _reauth(sup) is True
        token = json.loads(sup.creds.paths("gmail@alice").token.read_text())
        assert token["access_token"] == "new-access"
        assert token["refresh_token"] == "new-refresh"
        admin = json.loads(sup.creds.paths("gmail").token.read_text())
        assert admin["access_token"] == "a"
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_reauthorization_of_a_disabled_user_child_still_stops_it_first(tmp_path):
    """Re-authorization of a disabled child still stops it first, writes
    both files, and leaves the child stopped with no restart task."""
    sup, events = _reauth_sup(tmp_path, enabled=False)
    try:
        assert await _reauth(sup) is True
        assert events[:3] == ["teardown", "write_client:gmail@alice",
                              "write_token:gmail@alice"]
        child = sup.get(GMAIL_ALICE)
        assert child.status == "stopped"
        assert child.task is None or child.task.done()
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_a_header_sink_reauthorization_keeps_its_order_for_a_user_child(tmp_path):
    """A header sink re-authorization keeps its order: one registry write of
    the header, then the teardown, for `linear@alice`."""
    key = ServerKey("alice", "linear")
    sup = build(tmp_path, user_spec("linear", "alice", enabled=True,
                                    headers={"Authorization": "Bearer old"}))
    sup.get(key).status = "running"
    seen: list[tuple] = []
    real_teardown = sup._teardown

    async def teardown(child):
        spec = sup.registry.get(key)
        seen.append((spec.headers.get("Authorization"), spec.oauth_pending))
        await real_teardown(child)

    sup._teardown = teardown
    flow = sup.flows.create("linear@alice", "linear", _client(), ADMIN_ACTOR, reauth=True)
    try:
        ok = await sup.finish_oauth(flow, None, {"access_token": "tok-xyz"},
                                    reauth=True,
                                    header=HeaderSpec("Authorization", "Bearer"))
        assert ok is True
        assert seen and seen[0] == ("Bearer tok-xyz", False)
        assert sup.registry.get(key).headers["Authorization"] == "Bearer tok-xyz"
    finally:
        await drain(sup)


# --- 10E (10.19): store isolation between owners -----------------------------
#
# Guarded invariant: OpTouchesOnlyOwnPaths
# (specs/tla/multi_user_access_lifecycle.tla; the negative config
# multi_user_access_lifecycle_nskeyed.cfg keys the stores by namespace and
# violates it).

from conftest import ADMIN_ACTOR, fake_child_spec

GITHUB = ServerKey(None, "github")
GITHUB_ALICE = ServerKey("alice", "github")


async def _running_admin_github(tmp_path, *more):
    sup = build(tmp_path, fake_child_spec("github", "good", enabled=False), *more)
    sup.creds.write_client("github", "google-client", ClientCreds("admin", "s"))
    sup.creds.write_token("github", "google-auth-library", TOKENS)
    await sup.enable(GITHUB, ADMIN_ACTOR)
    await sup.get(GITHUB).task
    assert sup.get(GITHUB).status == "running"
    return sup


def test_a_user_add_never_touches_the_admin_credential_store_purge(tmp_path):
    """A user add never touches the admin credential (F2), at the store: the
    residue purge of `github@alice` touches only `creds/github@alice/`.
    Invariant: OpTouchesOnlyOwnPaths."""
    store = CredStore(tmp_path)
    store.write_token("github", "google-auth-library", TOKENS)
    store.write_client("github@alice", "google-client", ClientCreds("a", "1"))
    admin_before = tree(tmp_path / "creds" / "github")
    store.remove("github@alice")
    assert not (tmp_path / "creds" / "github@alice").exists()
    assert tree(tmp_path / "creds" / "github") == admin_before


@pytest.mark.asyncio
async def test_a_user_add_never_touches_the_admin_credential(tmp_path):
    """A user add never touches the admin credential (F2): `alice` adds
    `github` and `creds/github/token.json` keeps its content.
    Invariant: OpTouchesOnlyOwnPaths."""
    sup = build(tmp_path)
    sup.creds.write_token("github", "google-auth-library", TOKENS)
    before = tree(tmp_path / "creds")
    try:
        await user_add(sup, user_spec("github", "alice", enabled=False))
        assert tree(tmp_path / "creds") == before
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_a_user_remove_never_touches_the_admin_credential(tmp_path):
    """A user remove never touches the admin credential (F2): the admin token
    file stays and admin-owned `github` keeps running.
    Invariant: OpTouchesOnlyOwnPaths."""
    sup = await _running_admin_github(tmp_path, user_spec("github", "alice",
                                                          enabled=False))
    sup.creds.write_token("github@alice", "google-auth-library", TOKENS)
    admin_before = tree(tmp_path / "creds" / "github")
    try:
        await sup.remove(GITHUB_ALICE, ADMIN_ACTOR)
        assert tree(tmp_path / "creds" / "github") == admin_before
        assert not (tmp_path / "creds" / "github@alice").exists()
        assert sup.get(GITHUB).status == "running"
        assert GITHUB in {s.key for s in sup.registry.list()}
    finally:
        await drain(sup)


def _plant(tmp_path):
    for rel in ("creds/github/token.json", "creds/x/token.json",
                "creds/github@alice/x/token.json", "creds/%2f/token.json",
                "tokens/keep.json"):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rel)


@pytest.mark.parametrize("ref", BAD_REFS)
def test_a_bad_reference_is_refused(tmp_path, ref):
    """A bad reference is refused: every store call raises `ValueError` and
    no path under or above `creds/` changes. Invariant: OpTouchesOnlyOwnPaths."""
    store = CredStore(tmp_path)
    _plant(tmp_path)
    before = tree(tmp_path)
    calls = [
        lambda: store.remove(ref),
        lambda: store.write_client(ref, "google-client", ClientCreds("a", "1")),
        lambda: store.write_token(ref, "google-auth-library", TOKENS),
        lambda: store.paths(ref),
        lambda: store.has_client(ref),
        lambda: store.has_token(ref),
        lambda: store.awaiting(ref),
    ]
    for call in calls:
        with pytest.raises(ValueError):
            call()
    assert tree(tmp_path) == before


def test_discard_keeps_the_flow_of_another_owner_in_the_flow_table():
    """Discard keeps the flow of another owner (F2): `discard("github@alice")`
    keeps the flows of `github` and `github@bob`."""
    flows = PendingFlows()
    admin = flows.create("github", "github", _client(), ADMIN_ACTOR)
    bob = flows.create("github@bob", "github", _client(), ADMIN_ACTOR)
    alice = flows.create("github@alice", "github", _client(), ADMIN_ACTOR)
    flows.discard("github@alice")
    assert flows.has_open("github") and flows.has_open("github@bob")
    assert not flows.has_open("github@alice")
    assert flows.pop(alice.state) is None
    assert flows.pop(admin.state) is admin and flows.pop(bob.state) is bob


@pytest.mark.asyncio
async def test_discard_keeps_the_flow_of_another_owner(tmp_path):
    """Discard keeps the flow of another owner (F2): the supervisor removes
    `github@alice`, and the callback of the open `github` flow still
    completes. Invariant: OpTouchesOnlyOwnPaths."""
    sup = build(tmp_path, fake_child_spec("github", "good", enabled=False),
                user_spec("github", "alice", enabled=False))
    sup.creds.write_client("github", "google-client", ClientCreds("admin", "s"))
    flow = sup.flows.create("github", "github", ClientCreds("admin", "s"), ADMIN_ACTOR)
    try:
        await sup.remove(GITHUB_ALICE, ADMIN_ACTOR)
        assert sup.flows.has_open("github")
        assert await sup.finish_oauth(flow, "google-auth-library", TOKENS) is True
        assert sup.creds.has_token("github")
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_another_owners_credential_does_not_decide(tmp_path):
    """Another owner's credential does not decide (C1): admin `gmail` awaits
    its token, and approved `gmail@alice` with no credential starts."""
    sup = build(tmp_path, fake_child_spec("gmail", "good", enabled=False),
                user_spec("gmail", "alice", enabled=False))
    sup.creds.write_client("gmail", "google-client", ClientCreds("a", "1"))
    assert sup.creds.awaiting("gmail")
    try:
        await sup.enable(GMAIL_ALICE, ADMIN_ACTOR)
        assert sup.get(GMAIL_ALICE).status == "starting"
        assert not (tmp_path / "creds" / "gmail@alice").exists()
        # The mirror: alice's pending credential does not block the admin.
        await sup.remove(GMAIL_ALICE, ADMIN_ACTOR)
        sup.creds.remove("gmail")
        sup.creds.write_client("gmail@alice", "google-client", ClientCreds("a", "1"))
        await sup.enable(ServerKey(None, "gmail"), ADMIN_ACTOR)
        assert sup.get(ServerKey(None, "gmail")).status == "starting"
    finally:
        await drain(sup)


@pytest.mark.asyncio
async def test_an_add_under_a_shared_namespace_purges_only_its_own_reference(tmp_path):
    """An add under a shared namespace purges only its own reference (C1):
    `alice` adds `gmail`, the purge deletes `creds/gmail@alice` residue, and
    `creds/gmail` keeps both files. Invariant: OpTouchesOnlyOwnPaths."""
    sup = build(tmp_path, fake_child_spec("gmail", "good", enabled=False))
    _admin_gmail_creds(sup.creds)
    sup.creds.write_token("gmail@alice", "google-auth-library", TOKENS)  # residue
    admin_before = tree(tmp_path / "creds" / "gmail")
    try:
        await user_add(sup, user_spec("gmail", "alice", enabled=False))
        assert GMAIL_ALICE in {s.key for s in sup.registry.list()}
        assert not (tmp_path / "creds" / "gmail@alice").exists()
        assert tree(tmp_path / "creds" / "gmail") == admin_before
    finally:
        await drain(sup)
