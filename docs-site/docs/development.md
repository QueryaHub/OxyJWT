# Development

This page explains how to build and test OxyJWT locally.

## Requirements

- Python 3.10 or newer
- Rust stable
- `maturin`
- `pytest`

Use a virtual environment. `maturin develop` expects one.

```bash
python -m venv .venv
.venv/bin/python -m pip install -U pip maturin pytest cryptography pyjwt
```

## Install The Extension Locally

```bash
.venv/bin/maturin develop --release
```

This compiles the Rust extension and installs it into `.venv`.

## Run Tests

```bash
cargo fmt --manifest-path rust/Cargo.toml --check
cargo clippy --manifest-path rust/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path rust/Cargo.toml
.venv/bin/python -m pytest
```

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

Results are written under `benchmark-results/`, which is ignored by git because benchmark numbers are machine-specific.

The default Rust crypto backend is `aws_lc_rs`. It was selected because local benchmarks showed much better RSA and ECDSA performance than `rust_crypto`. To compare the pure RustCrypto backend:

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
