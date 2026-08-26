# Versioning and API stability

OxyJWT follows [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`).

## Public API

The supported public surface is the names exported in `oxyjwt.__all__` in [`python/oxyjwt/__init__.py`](https://github.com/QueryaHub/OxyJWT/blob/main/python/oxyjwt/__init__.py), plus the type stubs in `python/oxyjwt/_oxyjwt.pyi` for native symbols. Treat anything not exported there as internal.

## What counts as breaking

Typical **major** (breaking) changes include:

- Removing or renaming public symbols in `__all__`
- Changing function signatures in incompatible ways
- Changing exception types for a given failure mode when that type is part of the public contract (for example, aligning with PyJWT)
- Changing default security behavior (for example, turning verification on when it was off)

**Minor** releases may add algorithms, options, documentation, or performance improvements without breaking existing callers.

**Patch** releases are for bug fixes and documentation corrections that preserve behavior.

## Maturity

Releases `0.x` are pre-1.0. Minor bumps in `0.x` may include small API adjustments while PyJWT parity hardens. After **1.0.0**, breaking changes are reserved for major versions.

The PyPI `Development Status` classifier tracks maturity (Beta on the `0.7.x` line; **Stable** is planned for `1.0.0`).

## Rust crate version

The Rust crate under `rust/` uses the same version number as the Python package for releases built with maturin.
