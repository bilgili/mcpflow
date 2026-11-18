"""Frozen signatures and constants of admin-password-file (design, Proposed interfaces)."""

from __future__ import annotations

import dataclasses
import inspect

from mcpflow import auth, config, identity


def params(f):
    return list(inspect.signature(f).parameters)


def test_auth_and_config_signatures():
    assert params(auth.is_password_hash) == ["value"]
    assert params(config.data_dir_path) == ["overrides"]
    assert inspect.signature(config.data_dir_path).parameters["overrides"].default is None
    assert config.LEGACY_ADMIN_ENV == ("ADMIN_PASSWORD", "ADMIN_PASSWORD_HASH")


def test_settings_fields():
    fields = dataclasses.fields(config.Settings)
    assert [f.name for f in fields][-2:] == ["max_user_tokens", "ignored_admin_env"]
    assert "admin_password_hash" not in [f.name for f in fields]
    assert {f.name: f.default for f in fields}["ignored_admin_env"] == ()


def test_identity_signatures():
    assert params(identity.write_admin_password_file) == ["data_dir", "password_hash"]
    init = inspect.signature(identity.LocalIdentityProvider.__init__).parameters
    assert list(init) == ["self", "path", "clock"]
    assert init["clock"].kind is inspect.Parameter.KEYWORD_ONLY
    cls = identity.LocalIdentityProvider
    assert params(cls.replace_credential) == ["self", "user_id", "expected_state", "new_hash"]
    assert params(cls._credential_state) == ["self", "user_id"]


def test_identity_constants():
    assert identity.ADMIN_PASSWORD_FILE == "admin-password.hash"
    assert identity.ADMIN_PASSWORD_CLAIM == "admin-password.hash.applying"
    assert identity.ADMIN_PENDING_NOTE == (
        "No admin password yet. Run `mcpflow set-admin-password` on the server, then restart."
    )
