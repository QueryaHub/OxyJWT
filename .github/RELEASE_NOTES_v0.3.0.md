# OxyJWT 0.3.0

**Beta** release — PyJWT parity improvements, documentation, and operational tooling. No new breaking changes beyond [0.2.0](https://github.com/QueryaHub/OxyJWT/blob/main/docs-site/docs/changelog.md#020) (exception hierarchy).

## Highlights

- **`subject`** on `decode` / `decode_complete`, wired to native verification
- **`PyJWKClient`** LRU cache for signing keys by `kid`
- Runtime dependency on **orjson** (installed automatically via `pip`)
- Docs: versioning, benchmarks, FastAPI cookbook, corrected API reference for `verify_signature` / `options`
- CI: coverage report, benchmark smoke test, optional weekly benchmark workflow
- `SECURITY.md` and `CONTRIBUTING.md`

## Install

```bash
pip install oxyjwt==0.3.0
```

## Upgrade from 0.2.0

```bash
pip install -U oxyjwt
```

See the full [changelog](https://github.com/QueryaHub/OxyJWT/blob/main/docs-site/docs/changelog.md#030) for details.
