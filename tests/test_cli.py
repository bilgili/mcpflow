"""The `mcpflow` console entry point.

Scenarios from `specs/packaging/spec.md` (Console entry point, Single-sourced
version) and `specs/auth/spec.md` (Admin password source).
"""

from __future__ import annotations

import pytest

from mcpflow import __version__
from mcpflow.auth import verify_password
from mcpflow.cli import main


def _patch_uvicorn(monkeypatch):
    """Capture uvicorn.run instead of binding a socket."""
    captured: dict = {}

    def fake_run(app, *, host, port, log_level):
        captured["host"] = host
        captured["port"] = port

    import uvicorn

    monkeypatch.setattr(uvicorn, "run", fake_run)
    return captured


def test_serve_with_flags(monkeypatch, tmp_path):
    captured = _patch_uvicorn(monkeypatch)
    monkeypatch.setenv("ADMIN_PASSWORD", "pw")
    rc = main(
        [
            "serve",
            "--host",
            "0.0.0.0",
            "--port",
            "9000",
            "--data-dir",
            str(tmp_path),
        ]
    )
    assert rc == 0
    assert captured["host"] == "0.0.0.0"
    assert captured["port"] == 9000


def test_serve_with_environment(monkeypatch, tmp_path):
    captured = _patch_uvicorn(monkeypatch)
    monkeypatch.setenv("ADMIN_PASSWORD", "pw")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("PORT", "9001")
    rc = main(["serve"])
    assert rc == 0
    assert captured["port"] == 9001


def test_hash_password(capsys):
    rc = main(["hash-password", "hunter2"])
    assert rc == 0
    line = capsys.readouterr().out.strip()
    assert line.startswith("pbkdf2_sha256$")
    assert verify_password("hunter2", line) is True


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == __version__


def test_exit_code_2(monkeypatch, tmp_path, capsys):
    # Neither ADMIN_PASSWORD nor ADMIN_PASSWORD_HASH set.
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("ADMIN_PASSWORD_HASH", raising=False)
    rc = main(["serve", "--data-dir", str(tmp_path)])
    assert rc == 2
    assert capsys.readouterr().err.strip() != ""
