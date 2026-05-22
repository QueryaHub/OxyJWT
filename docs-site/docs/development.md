# Development

This page explains how to build and test OxyJWT locally.

## Requirements

- Python 3.10 or newer
- Rust stable
- `maturin`
- `pytest` (optional: `pytest-cov` for coverage reports)

Use a virtual environment. `maturin develop` expects one.

```bash
python -m venv .venv
.venv/bin/python -m pip install -U pip maturin pytest pytest-cov cryptography pyjwt
```

## Install The Extension Locally

```bash
.venv/bin/maturin develop --release
```

This compiles the Rust extension and installs it into `.venv`.

## Type checking

OxyJWT ships inline stubs (`python/oxyjwt/*.pyi`) and a `py.typed` marker. After installing dev dependencies:

```bash
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/python -m mypy python/oxyjwt tests/typing/test_public_api.py
```

CI runs the same check in a dedicated **Type check (mypy)** job. With `mypy` installed (`pip install -e ".[dev]"`), `tests/typing/test_mypy.py` runs the same command under pytest; without it, that test is skipped.

## Run Tests

Pytest is configured with `pythonpath = ["python"]` in `pyproject.toml` so the editable tree under `python/oxyjwt/` (including the compiled `_oxyjwt` module) is exercised.

```bash
cargo fmt --manifest-path rust/Cargo.toml --check
cargo clippy --manifest-path rust/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path rust/Cargo.toml
.venv/bin/python -m pytest
.venv/bin/python -m pytest --cov=oxyjwt --cov-report=term-missing
```

## Contributing

See [`CONTRIBUTING.md`](https://github.com/QueryaHub/OxyJWT/blob/main/CONTRIBUTING.md) in the repository root for PR expectations and security reporting (`SECURITY.md`).

## Releasing

Maintainers publish with a `v*` git tag; see [`RELEASING.md`](https://github.com/QueryaHub/OxyJWT/blob/main/RELEASING.md) for the full checklist (version sync, tests, PyPI Trusted Publishing).

## Build A Wheel

```bash
maturin build --release
```

Wheels are written under `rust/target/wheels/`.

## Build The Documentation

Install docs dependencies:

```bash
.venv/bin/python -m pip install -U -r docs-site/requirements.txt
```

Build docs strictly:

```bash
.venv/bin/mkdocs build --strict -f docs-site/mkdocs.yml
```

Serve docs locally:

```bash
.venv/bin/mkdocs serve -f docs-site/mkdocs.yml
```

Build and run a static Docker image for server deployment:

```bash
docker compose -f docs-site/docker-compose.yml up -d --build
```

The static Docker build is available at `http://127.0.0.1:8001` (see `OXYJWT_DOCS_PORT` in `docs-site/docker-compose.yml`). Local `mkdocs serve` also uses **port 8001** (`dev_addr` in `docs-site/mkdocs.yml`).

## Compare JWT Libraries

Install optional benchmark dependencies and the local OxyJWT extension:

```bash
.venv/bin/python -m pip install -U ".[bench]"
.venv/bin/maturin develop --release
```

Run the comparison script:

```bash
.venv/bin/python scripts/compare_jwt_libraries.py \
  --algorithms all \
  --iterations 1000 \
  --rounds 3 \
  --warmup 100 \
  --json benchmark-results/all-algorithms.bench.json \
  --markdown benchmark-results/all-algorithms.bench.md
```

The script covers HMAC, RSA, RSA-PSS, ECDSA, and EdDSA. It compares installed libraries and reports unsupported library/algorithm combinations as `0` throughput.

For a quick smoke test:

```bash
.venv/bin/python scripts/compare_jwt_libraries.py --algorithms HS256,RS256,EdDSA --iterations 100 --rounds 1
```

The test suite also runs a small **HS256** benchmark against the same harness (`tests/test_benchmark_jwt_libraries.py`). For a slower multi-algorithm pytest sweep:

```bash
OXYJWT_BENCHMARK=1 .venv/bin/python -m pytest -m benchmark -q
```

Results are written under `benchmark-results/`, which is ignored by git because benchmark numbers are machine-specific.

The default Rust crypto backend is `aws_lc_rs`. It was selected because local benchmarks showed much better RSA and ECDSA performance than `rust_crypto`. Linux **aarch64** wheels are built with `rust_crypto` because `aws-lc-sys` cross-compilation is unreliable in manylinux; expect different relative performance on that platform. To compare the pure RustCrypto backend locally:

```bash
PYO3_BUILD_EXTENSION_MODULE=1 maturin build --release --no-default-features --features rust_crypto
```

## Project Layout

```text
pyproject.toml
docs-site/mkdocs.yml
docs-site/docs/
docs-site/Dockerfile
docs-site/docker-compose.yml
python/oxyjwt/
rust/
tests/
scripts/
```

The Python package exposes the public API. The Rust crate implements the native extension as `oxyjwt._oxyjwt`. The documentation site is self-contained under `docs-site/` so it can be moved into a separate repository later.
