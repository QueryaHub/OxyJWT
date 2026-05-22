"""Performance smoke tests using `scripts/compare_jwt_libraries.py` logic.

**CI smoke (default pytest):** ``test_benchmark_hs256_smoke_vs_competitors`` — fast HS256
check with tightened OxyJWT vs PyJWT ratio gates (see ``_MIN_OXY_VS_PYJWT_*``).

**Extended (opt-in):** ``OXYJWT_BENCHMARK=1 pytest -m benchmark`` — HS256, RS256, EdDSA.

**Full comparison (scheduled / manual):** ``.github/workflows/benchmarks.yml`` and
``scripts/compare_jwt_libraries.py`` with higher iteration counts; artifact Markdown only.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_COMPARE_SCRIPT = _REPO / "scripts" / "compare_jwt_libraries.py"

# HS256 smoke: minimum OxyJWT/PyJWT throughput ratio (tightened from 0.25 = 4× slack).
_MIN_OXY_VS_PYJWT_ENCODE_RATIO = 0.75
_MIN_OXY_VS_PYJWT_DECODE_RATIO = 0.75
_MIN_OXYJWT_OPS_PER_SECOND = 500

# Extended sweep: looser floor vs PyJWT when present (asymmetric crypto is noisier in CI).
_MIN_OXY_VS_PYJWT_EXTENDED_RATIO = 0.5


def _load_compare_module() -> object:
    name = "compare_jwt_libraries"
    spec = importlib.util.spec_from_file_location(name, _COMPARE_SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _ops_for(
    results: list[object], library: str, operation: str, *, mod: object
) -> float | None:
    for r in results:
        if r.library == library and r.operation == operation:  # type: ignore[attr-defined]
            return float(r.ops_per_second)  # type: ignore[attr-defined]
    return None


def _assert_oxyjwt_hs256_smoke(results: list[object], *, mod: object) -> None:
    oxy_enc = _ops_for(results, "OxyJWT", "encode", mod=mod)
    oxy_dec = _ops_for(results, "OxyJWT", "decode", mod=mod)
    assert oxy_enc is not None and oxy_dec is not None
    assert oxy_enc > _MIN_OXYJWT_OPS_PER_SECOND, f"encode too slow: {oxy_enc:.0f} ops/s"
    assert oxy_dec > _MIN_OXYJWT_OPS_PER_SECOND, f"decode too slow: {oxy_dec:.0f} ops/s"

    py_enc = _ops_for(results, "PyJWT", "encode", mod=mod)
    py_dec = _ops_for(results, "PyJWT", "decode", mod=mod)
    if py_enc is not None and py_enc > 0:
        assert oxy_enc >= py_enc * _MIN_OXY_VS_PYJWT_ENCODE_RATIO, (
            f"HS256 encode: OxyJWT {oxy_enc:.0f} ops/s vs PyJWT {py_enc:.0f} ops/s "
            f"(need >={_MIN_OXY_VS_PYJWT_ENCODE_RATIO:.0%} of PyJWT)"
        )
    if py_dec is not None and py_dec > 0:
        assert oxy_dec >= py_dec * _MIN_OXY_VS_PYJWT_DECODE_RATIO, (
            f"HS256 decode: OxyJWT {oxy_dec:.0f} ops/s vs PyJWT {py_dec:.0f} ops/s "
            f"(need >={_MIN_OXY_VS_PYJWT_DECODE_RATIO:.0%} of PyJWT)"
        )


def test_benchmark_hs256_smoke_vs_competitors() -> None:
    """Run the shared benchmark harness for HS256; assert OxyJWT vs PyJWT ratios."""
    pytest.importorskip("oxyjwt._oxyjwt")
    pytest.importorskip("jwt")

    mod = _load_compare_module()
    results, _skipped = mod.run_benchmark(
        iterations=50,
        rounds=1,
        warmup=8,
        selected_algorithms={"HS256"},
        competitor_key_mode="pem",
    )
    assert results, "expected at least one benchmark result"
    assert len([r for r in results if r.library == "OxyJWT"]) == 2  # type: ignore[attr-defined]
    _assert_oxyjwt_hs256_smoke(results, mod=mod)


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
    by_algo = {
        (r.algorithm, r.library, r.operation): r.ops_per_second  # type: ignore[attr-defined]
        for r in results
    }
    for algo in ("HS256", "RS256", "EdDSA"):
        assert (algo, "OxyJWT", "encode") in by_algo
        assert (algo, "OxyJWT", "decode") in by_algo
        assert by_algo[algo, "OxyJWT", "encode"] > 100
        assert by_algo[algo, "OxyJWT", "decode"] > 100
        py_enc = by_algo.get((algo, "PyJWT", "encode"))
        py_dec = by_algo.get((algo, "PyJWT", "decode"))
        ox_enc = by_algo[algo, "OxyJWT", "encode"]
        ox_dec = by_algo[algo, "OxyJWT", "decode"]
        if py_enc and py_enc > 0:
            assert ox_enc >= py_enc * _MIN_OXY_VS_PYJWT_EXTENDED_RATIO, algo
        if py_dec and py_dec > 0:
            assert ox_dec >= py_dec * _MIN_OXY_VS_PYJWT_EXTENDED_RATIO, algo
