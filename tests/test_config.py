"""Settings from the environment.

Scenarios from `specs/auth/spec.md`: Admin password source, Secret key.
"""

from __future__ import annotations

import pytest

from mcpflow.auth import hash_password, verify_password
from mcpflow.config import ConfigError, load_settings


def test_no_password_configured(tmp_path):
    # Neither ADMIN_PASSWORD nor ADMIN_PASSWORD_HASH given.
    with pytest.raises(ConfigError):
        load_settings({"DATA_DIR": str(tmp_path)})


def test_hash_wins_over_clear_text(tmp_path):
    # Both set; the login must accept only the password behind the hash.
    hashed = hash_password("real-password")
    settings = load_settings(
        {
            "DATA_DIR": str(tmp_path),
            "ADMIN_PASSWORD": "decoy-password",
            "ADMIN_PASSWORD_HASH": hashed,
        }
    )
    assert settings.admin_password_hash == hashed
    assert verify_password("real-password", settings.admin_password_hash) is True
    assert verify_password("decoy-password", settings.admin_password_hash) is False


def test_generated_key_persists(tmp_path):
    # Two starts without SECRET_KEY reuse DATA_DIR/secret_key.
    first = load_settings({"DATA_DIR": str(tmp_path), "ADMIN_PASSWORD": "pw"})
    second = load_settings({"DATA_DIR": str(tmp_path), "ADMIN_PASSWORD": "pw"})
    assert first.secret_key == second.secret_key
    key_file = tmp_path / "secret_key"
    assert key_file.exists()
    assert len(key_file.read_text().strip()) == 64


def test_bad_hash_format(tmp_path):
    with pytest.raises(ConfigError):
        load_settings(
            {"DATA_DIR": str(tmp_path), "ADMIN_PASSWORD_HASH": "totally-invalid"}
        )


@pytest.mark.parametrize(
    "bad",
    [
        "pbkdf2_sha256$0$00$00",  # zero iterations, short salt and digest
        "pbkdf2_sha256$1$aa$bb",  # salt and digest too short
        "pbkdf2_sha256$1$" + "a" * 16 + "$" + "b" * 63,  # digest one char short
        "pbkdf2_sha256$-1$" + "a" * 16 + "$" + "b" * 64,  # negative iterations
        "pbkdf2_sha256$1$" + "a" * 16 + "$" + "b" * 64 + "x",  # trailing char
    ],
)
def test_unusable_hash_rejected(tmp_path, bad):
    # The tightened rule rejects placeholders and truncated fields at load time.
    with pytest.raises(ConfigError):
        load_settings({"DATA_DIR": str(tmp_path), "ADMIN_PASSWORD_HASH": bad})


def test_real_hash_accepted(tmp_path):
    hashed = hash_password("pw")
    settings = load_settings({"DATA_DIR": str(tmp_path), "ADMIN_PASSWORD_HASH": hashed})
    assert settings.admin_password_hash == hashed
