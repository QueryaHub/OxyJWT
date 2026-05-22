# Benchmarks

OxyJWT is optimized for throughput on typical JWT workloads. Numbers depend on CPU, compiler flags, Python version, and the cryptographic backend (see the root [README](https://github.com/QueryaHub/OxyJWT/blob/main/README.md) for the default `aws_lc_rs` backend and the `rust_crypto` alternative on some Linux aarch64 wheels).

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

The [Benchmarks workflow](https://github.com/QueryaHub/OxyJWT/blob/main/.github/workflows/benchmarks.yml) runs on a weekly schedule and on manual dispatch. It uploads a Markdown summary as a workflow artifact (smaller iteration counts than a full local run). Use it to spot large regressions over time, not as absolute performance guarantees.

## Methodology

- **Metric:** operations per second (encode and decode measured separately).
- **Warmup:** reduces JIT and allocator noise; see script defaults.
- **Fairness:** each library uses its supported key types; unsupported pairs are recorded as zero throughput in the script output.

Always compare on your own target hardware before choosing a library for production latency budgets.
