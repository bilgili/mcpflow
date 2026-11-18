"""Settings from the environment.

Scenarios from `specs/auth/spec.md`: Admin password source, Secret key.
"""

from __future__ import annotations

import pytest

from mcpflow.config import ConfigError, load_settings


def test_generated_key_persists(tmp_path):
    # Two starts without SECRET_KEY reuse DATA_DIR/secret_key.
    first = load_settings({"DATA_DIR": str(tmp_path)})
    second = load_settings({"DATA_DIR": str(tmp_path)})
    assert first.secret_key == second.secret_key
    key_file = tmp_path / "secret_key"
    assert key_file.exists()
    assert len(key_file.read_text().strip()) == 64


# --- Child catalog freshness (child-catalog-freshness) -----------------------


def test_child_cache_ttl_default(tmp_path):
    settings = load_settings({"DATA_DIR": str(tmp_path)})
    assert settings.child_cache_ttl == 300.0


def test_child_cache_ttl_parses(tmp_path):
    settings = load_settings(
        {"DATA_DIR": str(tmp_path), "CHILD_CACHE_TTL": "2"}
    )
    assert settings.child_cache_ttl == 2.0


def test_negative_child_cache_ttl_rejected(tmp_path):
    with pytest.raises(ConfigError, match="CHILD_CACHE_TTL"):
        load_settings(
            {"DATA_DIR": str(tmp_path), "CHILD_CACHE_TTL": "-1"}
        )
