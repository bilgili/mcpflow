"""Catalog installation preserves the registry's cache duration contract."""

import math
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_catalog import KNOWN, _entry, _oauth_entry

from mcpflow.catalog import BUILTIN_DIR, Catalog, CatalogEntry, build_spec
from mcpflow.oauth import CredPaths


@pytest.mark.parametrize("duration", [None, 0, 12.5])
@pytest.mark.parametrize("oauth", [False, True])
def test_install_preserves_catalog_cache_duration(duration, oauth):
    entry = _oauth_entry() if oauth else _entry()
    data = entry.model_dump()
    data["spec"]["cache_ttl"] = duration
    entry = CatalogEntry.model_validate(data)
    paths = CredPaths(client=Path("/data/client.json"), token=Path("/data/token.json"))
    spec = build_spec(entry, "test", {}, None, paths)
    assert spec.cache_ttl == duration


@pytest.mark.parametrize("duration", [-1, math.inf, -math.inf, math.nan])
def test_catalog_rejects_invalid_cache_duration(duration):
    data = _entry().model_dump()
    data["spec"]["cache_ttl"] = duration
    with pytest.raises(ValidationError, match="finite number"):
        CatalogEntry.model_validate(data)


def test_skill_store_catalog_grants_live_actions_and_state_path():
    catalog = Catalog.load(BUILTIN_DIR, None, **KNOWN)
    entry = catalog.get("skills")
    assert entry is not None
    assert entry.spec.kind == "python"
    assert entry.spec.package == "skill-store"
    spec = build_spec(entry, "skills", {"SKILLS_STATE_DIR": "/data/skills"}, None)
    assert spec.actions is True
    assert spec.cache_ttl == 0
    assert spec.env == {"SKILLS_STATE_DIR": "/data/skills"}
    assert spec.source.startswith("git+https://github.com/bilgili/skill-store.git@")
