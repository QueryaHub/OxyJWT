from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("mypy", reason="install dev extras: pip install -e '.[dev]'")


def test_mypy_public_stubs() -> None:
    repo = Path(__file__).resolve().parents[2]
    cmd = [
        sys.executable,
        "-m",
        "mypy",
        "python/oxyjwt",
        "tests/typing/test_public_api.py",
        "--config-file",
        str(repo / "pyproject.toml"),
    ]
    proc = subprocess.run(
        cmd,
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
