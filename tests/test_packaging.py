"""The distributable wheel (12.21).

Scenario from `specs/packaging/spec.md` (Distributable package): `uv build`
produces a wheel that contains the templates and the vendored static files.
"""

from __future__ import annotations

import os
import subprocess
import zipfile
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_PYPI = "https://pypi.org/simple/"


def test_wheel_contains_package_data(tmp_path):
    env = dict(os.environ)
    env["UV_INDEX_URL"] = _PYPI
    env["PIP_INDEX_URL"] = _PYPI
    result = subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(tmp_path)],
        cwd=str(_ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(f"uv build failed:\n{result.stdout}\n{result.stderr}")

    wheels = list(tmp_path.glob("mcpflow-*-py3-none-any.whl"))
    assert wheels, "no wheel produced"
    with zipfile.ZipFile(wheels[0]) as zf:
        names = zf.namelist()
    assert any(n.startswith("mcpflow/templates/") for n in names)
    assert "mcpflow/static/htmx.min.js" in names
    assert "mcpflow/catalog/gmail.json" in names
    assert "mcpflow/catalog/providers/google.json" in names


def test_image_installs_git_for_git_sources():
    """Scenario from `specs/docker-deploy/spec.md` (Git is on PATH).

    A child whose spec names a git `source` is started by `npx --package=` or
    `uvx --from`, and both clone with `git`. The base image has none, so the
    Dockerfile must install it or such a child cannot run. Read statically: the
    in-image check needs a running daemon, this one guards the regression in
    any environment.
    """
    dockerfile = (_ROOT / "Dockerfile").read_text()
    # Comments name git too, so read the package list of the install command
    # itself: everything between `apt-get install` and the next `&&`.
    body = " ".join(
        line for line in dockerfile.splitlines() if not line.lstrip().startswith("#")
    )
    assert "apt-get install" in body, "Dockerfile has no apt-get install layer"
    packages = body.split("apt-get install", 1)[1].split("&&", 1)[0].split()
    assert "git" in packages, f"git is not installed; packages are {packages}"
    assert "ca-certificates" in packages, (
        f"git needs ca-certificates for an https remote; packages are {packages}"
    )
