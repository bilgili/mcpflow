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
    # Built-in ships google + linear; the local file overrides google.
    assert reg.ids() == frozenset({"google", "linear"})
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
    store.remove("never-existed")  # no error


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
    flow = flows.create("gmail", "gmail", _client())
    # token_urlsafe(32) is 32 random bytes, well over 128 bits; its text is
    # at least 22 base64url characters.
    assert len(flow.state) >= 22
    assert len(flow.code_verifier) >= 43


def test_pop_returns_once():
    flows = PendingFlows()
    flow = flows.create("gmail", "gmail", _client())
    assert flows.pop(flow.state) is flow
    assert flows.pop(flow.state) is None


def test_pop_expired_is_none():
    flows = PendingFlows(ttl=0.0)
    flow = flows.create("gmail", "gmail", _client())
    time.sleep(0.01)
    assert flows.pop(flow.state) is None


def test_discard_drops_namespace_flows():
    flows = PendingFlows()
    a = flows.create("gmail", "gmail", _client())
    b = flows.create("gmail", "gmail", _client())
    c = flows.create("slack", "slack", _client())
    flows.discard("gmail")
    assert flows.pop(a.state) is None and flows.pop(b.state) is None
    assert flows.pop(c.state) is c


def test_peek_does_not_consume():
    flows = PendingFlows()
    flow = flows.create("gmail", "gmail", _client())
    assert flows.peek(flow.state) is flow
    assert flows.peek(flow.state) is flow  # still there
    assert flows.pop(flow.state) is flow   # pop still consumes
    assert flows.peek(flow.state) is None


def test_create_reauth_flow():
    flows = PendingFlows()
    connect = flows.create("gmail", "gmail", _client())
    reauth = flows.create("slack", "slack", _client(), reauth=True)
    assert connect.reauth is False
    assert reauth.reauth is True


def test_has_open():
    flows = PendingFlows()
    assert flows.has_open("gmail") is False
    flow = flows.create("gmail", "gmail", _client(), reauth=True)
    assert flows.has_open("gmail") is True
    assert flows.has_open("slack") is False
    flows.pop(flow.state)
    assert flows.has_open("gmail") is False


def test_begin_exchange_is_exclusive():
    flows = PendingFlows()
    flow = flows.create("gmail", "gmail", _client())
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
    a = flows.create("gmail", "gmail", _client())
    time.sleep(0.01)
    flows.create("slack", "slack", _client())  # sweeps `a`
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
    flow = flows.create("gmail", "gmail", _client())
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
    flow = flows.create("gmail", "gmail", _client())
    url = authorize_url(_provider(pkce=False), _block(), "https://mcp.example/oauth/callback", flow)
    q = parse_qs(urlsplit(url).query)
    assert "code_challenge" not in q and "code_challenge_method" not in q


def test_token_request_body():
    flows = PendingFlows()
    flow = flows.create("gmail", "gmail", _client())
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
    flow = flows.create("gmail", "gmail", _client())
    _url, body = token_request(_provider(pkce=False), "https://mcp.example/oauth/callback", "c", flow)
    assert "code_verifier" not in body
