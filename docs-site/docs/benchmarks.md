# Benchmarks

OxyJWT is optimized for throughput on typical JWT workloads. Numbers depend on CPU, compiler flags, Python version, and the cryptographic backend (see the root [README](https://github.com/QueryaHub/OxyJWT/blob/main/README.md) for the default `aws_lc_rs` backend and the `rust_crypto` alternative on some Linux aarch64 wheels).

## Three levels of benchmarking

| Level | How to run | Purpose |
|-------|------------|---------|
| **Smoke** | Default `pytest` (`tests/test_benchmark_jwt_libraries.py::test_benchmark_hs256_smoke_vs_competitors`) | Fast HS256 regression gate in every CI run; OxyJWT must stay ≥75% of PyJWT encode/decode throughput (was 25% / 4× slack). |
| **Extended** | `OXYJWT_BENCHMARK=1 pytest -m benchmark` | HS256, RS256, EdDSA with moderate iterations; optional locally or before release. |
| **Full** | Weekly [Benchmarks workflow](https://github.com/QueryaHub/OxyJWT/blob/main/.github/workflows/benchmarks.yml) or the script below | Higher iteration counts; Markdown artifact for trend spotting, not a hard gate. |

## Reference ratios (HS256 smoke parameters)

Measured on a typical Linux dev machine with `maturin develop --release`, 50 iterations, 1 round, warmup 8 (same as CI smoke):

| Operation | OxyJWT (ops/s) | PyJWT (ops/s) | OxyJWT / PyJWT |
|-----------|----------------|---------------|----------------|
| encode | ~400k+ | ~130k+ | ~3× |
| decode | ~160k+ | ~115k+ | ~1.4× |

CI asserts **≥75%** of PyJWT for both operations so large regressions fail without requiring absolute ops/s parity across runners.

## Running comparisons locally

The repository includes [`scripts/compare_jwt_libraries.py`](https://github.com/QueryaHub/OxyJWT/blob/main/scripts/compare_jwt_libraries.py), which benchmarks OxyJWT against PyJWT, Authlib, and python-jose where supported.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -U pip maturin ".[bench]"
.venv/bin/maturin develop --release
.venv/bin/python scripts/compare_jwt_libraries.py \
  --algorithms HS256,RS256,EdDSA \
  --iterations 1000 \
  --rounds 3 \
  --warmup 100 \
  --markdown benchmark-results/local.bench.md
```

Raw JSON/Markdown outputs are gitignored; keep them local or attach them to release notes as needed.

## CI artifacts

The [Benchmarks workflow](https://github.com/QueryaHub/OxyJWT/blob/main/.github/workflows/benchmarks.yml) runs on a weekly schedule and on `workflow_dispatch`. It uploads `benchmark-results/ci-bench.md` (HS256, RS256, EdDSA; 200 iterations × 2 rounds). Use it to spot large regressions over time, not as absolute performance guarantees.

Main [CI](https://github.com/QueryaHub/OxyJWT/blob/main/.github/workflows/ci.yml) enforces the HS256 smoke ratios on every push/PR.

## Methodology

- **Metric:** operations per second (encode and decode measured separately).
- **Warmup:** reduces JIT and allocator noise; see script defaults.
- **Fairness:** each library uses its supported key types; unsupported pairs are recorded as zero throughput in the script output.

Always compare on your own target hardware before choosing a library for production latency budgets.
