# Git flow (OxyJWT 0.4.0)

Integration branch: **`dev`**. Production releases merge `dev` → `main` and tag `v*`.

## Branches

| Branch | Purpose |
|--------|---------|
| `main` | Stable; PyPI releases from tags on `main` only |
| `dev` | Integration for 0.4.0 work; all feature PRs target here |
| `issue/<number>-<short-slug>` | One issue, one branch, from latest `dev` |

## Workflow per issue

1. Pick the highest-priority open issue (labels `p0` → `p1` → `p2`, then `security` before `performance`).
2. Update local `dev`:
   ```bash
   git checkout dev
   git pull origin dev
   ```
3. Create a branch:
   ```bash
   git checkout -b issue/42-jwks-refresh-on-miss
   ```
4. Implement the issue scope only. Prefer **atomic commits** (one logical change per commit; split by file when sensible):
   ```bash
   git add python/oxyjwt/jwks_client.py
   git commit -m "feat(jwks): refresh JWKS once when kid is missing"
   git add tests/test_jwks_client.py
   git commit -m "test(jwks): cover key rotation refresh on unknown kid"
   ```
5. Push and open a PR **into `dev`** (not `main`):
   ```bash
   git push -u origin issue/42-jwks-refresh-on-miss
   gh pr create --base dev --title "feat(jwks): refresh JWKS on unknown kid (#42)" --body "Closes #42"
   ```
6. After review and green CI, squash-merge or merge commit into `dev`.
7. Delete the feature branch.

## Commits

- Use [Conventional Commits](https://www.conventionalcommits.org/): `feat`, `fix`, `perf`, `docs`, `test`, `ci`, `chore`.
- Scope examples: `jwks`, `api`, `rust`, `docs`, `bench`.
- One PR should not mix unrelated issues.

## Release 0.4.0 (later)

When `dev` is ready:

1. Finalize changelog and version bump on `dev`.
2. PR `dev` → `main` (release PR).
3. Tag `v0.4.0` on `main` → [Release workflow](.github/workflows/release.yml) publishes to PyPI.
4. Merge `main` back into `dev` if needed.

## Issue labels

| Label | Meaning |
|-------|---------|
| `p0` | Must ship in 0.4.0 |
| `p1` | Should ship in 0.4.0 |
| `p2` | Nice to have / post-1.0 |
| `security` | Security hardening |
| `performance` | Throughput / latency |
| `enhancement` | Feature or parity |
| `documentation` | Docs only |
| `testing` | Tests / CI |

Milestone: **[0.4.0](https://github.com/QueryaHub/OxyJWT/milestone/1)** (27 issues).

## Recommended work order (by priority)

Take the next open issue from the top; branch name pattern: `issue/<num>-<short-slug>`.

### P0 — do first

| # | Title |
|---|--------|
| [#1](https://github.com/QueryaHub/OxyJWT/issues/1) | JWKS refresh on unknown `kid` |
| [#3](https://github.com/QueryaHub/OxyJWT/issues/3) | Issuer list validation fix |
| [#2](https://github.com/QueryaHub/OxyJWT/issues/2) | Warnings for `verify_signature=False` |
| [#4](https://github.com/QueryaHub/OxyJWT/issues/4) | Encode: single JSON path |
| [#5](https://github.com/QueryaHub/OxyJWT/issues/5) | Decode: single-parse `decode_complete` |
| [#6](https://github.com/QueryaHub/OxyJWT/issues/6) | Drop claims orjson round-trips |

### P1 — security & JWKS

| # | Title |
|---|--------|
| [#7](https://github.com/QueryaHub/OxyJWT/issues/7)–[#12](https://github.com/QueryaHub/OxyJWT/issues/12) | JWKS limits, alg check, validation unify, leeway, JWK set/enc |
| [#15](https://github.com/QueryaHub/OxyJWT/issues/15)–[#18](https://github.com/QueryaHub/OxyJWT/issues/18) | `ssl_context`, `headers`, `lifespan`, `strict_aud`, `cache_keys` |
| [#13](https://github.com/QueryaHub/OxyJWT/issues/13)–[#14](https://github.com/QueryaHub/OxyJWT/issues/14) | JWKS perf index, GIL release |
| [#19](https://github.com/QueryaHub/OxyJWT/issues/19)–[#22](https://github.com/QueryaHub/OxyJWT/issues/22) | Security tests, bench CI, docs, `.pyi` |

### P2 — stretch / post-1.0

[#23](https://github.com/QueryaHub/OxyJWT/issues/23)–[#27](https://github.com/QueryaHub/OxyJWT/issues/27)

## CLI shortcuts

```bash
# New issue branch
ISSUE=42
SLUG=jwks-refresh-on-miss
git checkout dev && git pull origin dev
git checkout -b "issue/${ISSUE}-${SLUG}"

# PR to dev
gh pr create --base dev --assignee @me
```
