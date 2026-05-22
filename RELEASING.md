# Releasing OxyJWT

This checklist is for maintainers publishing **0.4.x** (and later) to PyPI via the GitHub Actions [Release workflow](.github/workflows/release.yml).

## Before tagging

1. **Version alignment** — these must match:
   - `pyproject.toml` → `[project].version`
   - `rust/Cargo.toml` → `[package].version`
   - `python/oxyjwt/__init__.py` → `__version__`
2. **Changelog** — update [`docs-site/docs/changelog.md`](docs-site/docs/changelog.md) (section for the release; add release date when publishing).
3. **Tests** (from repo root):

   ```bash
   cargo fmt --manifest-path rust/Cargo.toml --check
   cargo clippy --manifest-path rust/Cargo.toml --all-targets -- -D warnings
   cargo test --manifest-path rust/Cargo.toml
   maturin develop --release --pip-path "$(command -v pip3)"
   python -m pytest
   mkdocs build --strict -f docs-site/mkdocs.yml
   ```

4. **Smoke import** (after `maturin develop`):

   ```bash
   python -c "import oxyjwt; print(oxyjwt.__version__)"
   ```

5. **Optional wheel check**:

   ```bash
   maturin build --release --out dist
   ```

## Publish

1. Commit all release-prep changes on `main`.
2. Merge `dev` → `main`, then create and push an annotated tag (example for **0.4.0**):

   ```bash
   git tag -a v0.4.0 -m "Release 0.4.0"
   git push origin v0.4.0
   ```

3. The **Release** workflow builds wheels (Linux x86_64/aarch64, macOS, Windows) + sdist and publishes to PyPI (requires the `pypi` environment and [Trusted Publishing](https://docs.pypi.org/trusted-publishers/)).

4. On GitHub, create a **Release** from the tag. Use [`.github/RELEASE_NOTES_v0.4.0.md`](.github/RELEASE_NOTES_v0.4.0.md) or the **0.4.0** section in `docs-site/docs/changelog.md` as the release notes body.

## After release

- Confirm the new version on [PyPI](https://pypi.org/project/oxyjwt/).
- Verify `pip install oxyjwt==<version>` on a clean venv.
- Update supported-version wording in [`SECURITY.md`](SECURITY.md) if a new line is current.

## Notes

- **Linux aarch64** wheels use the `rust_crypto` feature (see `release.yml`); x86_64 uses default `aws_lc_rs`.
- Benchmark artifacts are optional; see [`docs-site/docs/benchmarks.md`](docs-site/docs/benchmarks.md).
