# Migrating from PyJWT

OxyJWT exposes a **PyJWT-shaped** module API: `encode`, `decode`, `decode_complete`, `PyJWT`, `PyJWK`, `PyJWKSet`, and `PyJWKClient` (see the package `__all__` for the current list). Wheels are **abi3** (stable ABI) and are intended to work on **CPython 3.10 through 3.14**; install the matching wheel or build the extension from source with a supported toolchain.

## Exception hierarchy (breaking change)

OxyJWT’s native errors are aligned with **PyJWT** for `try` / `except` patterns:

- `InvalidTokenError` is the base class for “bad token or claims” (under the library root `OxyJWTError`, similar to PyJWT’s `PyJWTError`).
- `DecodeError` inherits from `InvalidTokenError`.
- `InvalidSignatureError` inherits from `DecodeError`.

If you previously caught `OxyJWTError` for signature failures, you may need to catch `InvalidTokenError` or `InvalidSignatureError` instead, matching PyJWT.

## Differences to expect

- **Detached payloads** (`b64: false` / `detached_payload=`) are not supported yet; `decode` / `decode_complete` raise `NotImplementedError` if you pass `detached_payload`.
- **Plugin / `register_algorithm` workflows** (full `PyJWS` plugin model) are not a goal of v1; use the supported algorithm set from the Rust `jsonwebtoken` stack.
- **`sort_headers`**: for encoding, the boolean applies to **JSON** serialization of the payload (stable key order via `json.dumps`); header handling follows the same rules as the Rust `encode` path for supported header fields.

For behavior questions, run the test suite or compare a specific call with `import jwt` and `import oxyjwt` on the same inputs (tests under `tests/` include parity-style checks when PyJWT is installed).
