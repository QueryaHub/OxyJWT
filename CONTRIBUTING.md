# Contributing to OxyJWT

Thanks for your interest in improving OxyJWT.

## Development setup

From the repository root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -U pip maturin pytest pytest-cov cryptography pyjwt
.venv/bin/maturin develop --release
.venv/bin/python -m pytest
```

The Python package lives under `python/`. Pytest is configured to prefer that tree via `pythonpath` in `pyproject.toml`, so local edits and the built `_oxyjwt` extension are exercised together.

## Checks before opening a PR

- `cargo fmt --manifest-path rust/Cargo.toml --check`
- `cargo clippy --manifest-path rust/Cargo.toml --all-targets -- -D warnings`
- `cargo test --manifest-path rust/Cargo.toml`
- `pytest` (with optional `pytest --cov=oxyjwt`)
- `mkdocs build --strict -f docs-site/mkdocs.yml` if you change documentation

## Branching (0.4.0)

Integration branch is **`dev`**. Feature work uses one branch per issue from `dev`, PRs target `dev`.

Always sync before branching: `git fetch --all --prune` then `git pull --ff-only origin dev`. Run the full Rust + pytest suite before opening a PR.

Use `gh` to set **labels** (`p0`/`p1`/`p2`, `security`, …) and milestone **0.4.0** on issues and PRs. See [docs/GITFLOW.md](docs/GITFLOW.md) and [milestone 0.4.0](https://github.com/QueryaHub/OxyJWT/milestone/1).

## Pull requests

- Keep changes focused and match existing style (formatting, typing, minimal comments).
- Add or update tests when behavior changes.
- Update `docs-site/docs/changelog.md` for user-visible changes.

## Releasing

Maintainers: follow [RELEASING.md](RELEASING.md) before tagging `v*` and triggering the PyPI workflow.

## Security

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities.
