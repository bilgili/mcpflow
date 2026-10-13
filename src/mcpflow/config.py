"""Process settings from environment variables and CLI overrides.

`config.py` imports `hash_password` and the cap defaults from `auth.py` and
`registry.py`. Neither takes a `Settings`, so there is no import cycle.
"""

from __future__ import annotations

import math
import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path

from .auth import DEFAULT_MAX_USER_TOKENS, hash_password
from .registry import DEFAULT_MAX_USER_SERVERS

# A usable hash needs a positive iteration count, a salt of at least 16 hex
# chars, and a full 64-hex-char SHA-256 digest. Checked with fullmatch, so a
# placeholder like `pbkdf2_sha256$0$00$00` is rejected.
_HASH_RE = re.compile(r"pbkdf2_sha256\$[1-9]\d*\$[0-9a-f]{16,}\$[0-9a-f]{64}")


class ConfigError(Exception):
    """Raised when the environment cannot produce a valid `Settings`."""


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    host: str
    port: int
    admin_password_hash: str
    secret_key: bytes
    cookie_secure: bool
    session_ttl: int
    child_start_timeout: float
    child_cache_ttl: float
    log_level: str
    public_url: str | None = None
    # Per-user caps on stored servers and tokens; the admin is exempt (D2).
    max_user_servers: int = DEFAULT_MAX_USER_SERVERS
    max_user_tokens: int = DEFAULT_MAX_USER_TOKENS


def _get(overrides: dict[str, str], name: str, default: str | None) -> str | None:
    if name in overrides and overrides[name] is not None:
        return overrides[name]
    return os.environ.get(name, default)


def _resolve_secret_key(data_dir: Path, env_value: str | None) -> bytes:
    if env_value:
        return env_value.encode()
    path = data_dir / "secret_key"
    if path.exists():
        return path.read_text().strip().encode()
    key = secrets.token_hex(32)  # 64 hex characters
    tmp = path.with_suffix(".tmp")
    # Create the file already-private (0600); avoid the 0644 window that a
    # write_text + chmod leaves open on the signing key.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key)
    os.replace(tmp, path)
    return key.encode()


def _get_limit(overrides: dict[str, str], name: str, default: int) -> int:
    """A per-user cap: an integer >= 0. `0` allows no write."""
    raw = _get(overrides, name, str(default))
    # ASCII digits only: `int()` alone also takes "+5", " 5 ", "1_0", and
    # non-ASCII digits, and its 4300-digit limit raises for a huge value.
    if raw is None or not re.fullmatch(r"[0-9]{1,9}", raw):
        raise ConfigError(f"{name} must be an integer >= 0")
    return int(raw)


def load_settings(overrides: dict[str, str] | None = None) -> Settings:
    """Read the environment, apply CLI overrides, and prepare the data dir."""
    overrides = overrides or {}

    data_dir = Path(_get(overrides, "DATA_DIR", "./data"))
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "logs").mkdir(parents=True, exist_ok=True)

    host = _get(overrides, "HOST", "127.0.0.1")
    port = int(_get(overrides, "PORT", "8000"))

    password_hash = _get(overrides, "ADMIN_PASSWORD_HASH", None)
    if password_hash:
        if not _HASH_RE.fullmatch(password_hash):
            raise ConfigError("ADMIN_PASSWORD_HASH is not a valid pbkdf2_sha256 hash")
    else:
        clear = _get(overrides, "ADMIN_PASSWORD", None)
        if not clear:
            raise ConfigError("set ADMIN_PASSWORD or ADMIN_PASSWORD_HASH")
        password_hash = hash_password(clear)

    secret_key = _resolve_secret_key(data_dir, _get(overrides, "SECRET_KEY", None))

    cookie_secure = _get(overrides, "COOKIE_SECURE", "0") in ("1", "true", "True")
    session_ttl = int(_get(overrides, "SESSION_TTL_SECONDS", "604800"))
    child_start_timeout = float(_get(overrides, "CHILD_START_TIMEOUT", "60"))
    child_cache_ttl = float(_get(overrides, "CHILD_CACHE_TTL", "300"))
    if not (math.isfinite(child_cache_ttl) and child_cache_ttl >= 0):
        raise ConfigError("CHILD_CACHE_TTL must be a finite number >= 0")
    log_level = _get(overrides, "LOG_LEVEL", "INFO")
    public_url = _get(overrides, "PUBLIC_URL", None)
    public_url = public_url.rstrip("/") if public_url else None
    max_user_servers = _get_limit(
        overrides, "MAX_USER_SERVERS", DEFAULT_MAX_USER_SERVERS
    )
    max_user_tokens = _get_limit(overrides, "MAX_USER_TOKENS", DEFAULT_MAX_USER_TOKENS)

    return Settings(
        data_dir=data_dir,
        host=host,
        port=port,
        admin_password_hash=password_hash,
        secret_key=secret_key,
        cookie_secure=cookie_secure,
        session_ttl=session_ttl,
        child_start_timeout=child_start_timeout,
        child_cache_ttl=child_cache_ttl,
        log_level=log_level,
        public_url=public_url,
        max_user_servers=max_user_servers,
        max_user_tokens=max_user_tokens,
    )
