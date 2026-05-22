"""Performance smoke tests using `scripts/compare_jwt_libraries.py` logic.

The full manual benchmark remains:

    python scripts/compare_jwt_libraries.py --algorithms all --iterations 1000 ...

CI runs the fast HS256 smoke test below. Set ``OXYJWT_BENCHMARK=1`` and use
``pytest -m benchmark`` for a wider algorithm sweep (slower).
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_COMPARE_SCRIPT = _REPO / "scripts" / "compare_jwt_libraries.py"


def _load_compare_module() -> object:
    name = "compare_jwt_libraries"
    spec = importlib.util.spec_from_file_location(name, _COMPARE_SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_benchmark_hs256_smoke_vs_competitors() -> None:
    """Run the shared benchmark harness for HS256; assert OxyJWT is healthy."""
    pytest.importorskip("oxyjwt._oxyjwt")
    pytest.importorskip("jwt")

    mod = _load_compare_module()
    results, skipped = mod.run_benchmark(
        iterations=50,
        rounds=1,
        warmup=8,
        selected_algorithms={"HS256"},
        competitor_key_mode="pem",
    )
    assert results, "expected at least one benchmark result"

    oxy = [r for r in results if r.library == "OxyJWT"]
    assert len(oxy) == 2, "OxyJWT should report encode + decode"
    for r in oxy:
        assert r.ops_per_second > 500, f"{r.operation} too slow: {r.ops_per_second}"

    libs = {r.library for r in results}
    assert "OxyJWT" in libs
    # PyJWT is the main reference; others may be absent in minimal installs.
    if "PyJWT" in libs:
        py_enc = next(r.ops_per_second for r in results if r.library == "PyJWT" and r.operation == "encode")
        ox_enc = next(r.ops_per_second for r in results if r.library == "OxyJWT" and r.operation == "encode")
        assert ox_enc >= py_enc * 0.25, (
            f"OxyJWT HS256 encode ({ox_enc:.0f} ops/s) should stay within 4x of PyJWT ({py_enc:.0f} ops/s)"
        )


@pytest.mark.benchmark
@pytest.mark.skipif(
    os.environ.get("OXYJWT_BENCHMARK") != "1",
    reason="set OXYJWT_BENCHMARK=1 to run extended benchmark (slower)",
)
def test_benchmark_multi_algorithm_extended() -> None:
    """Broader sweep: HS256, RS256, EdDSA — opt-in to avoid slowing default CI."""
    pytest.importorskip("oxyjwt._oxyjwt")
    pytest.importorskip("jwt")

    mod = _load_compare_module()
    results, _skipped = mod.run_benchmark(
        iterations=120,
        rounds=2,
        warmup=20,
        selected_algorithms={"HS256", "RS256", "EdDSA"},
        competitor_key_mode="pem",
    )
    by_algo = {(r.algorithm, r.library, r.operation): r.ops_per_second for r in results}
    for algo in ("HS256", "RS256", "EdDSA"):
        assert (algo, "OxyJWT", "encode") in by_algo
        assert (algo, "OxyJWT", "decode") in by_algo
        assert by_algo[algo, "OxyJWT", "encode"] > 100
        assert by_algo[algo, "OxyJWT", "decode"] > 100
