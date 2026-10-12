# AI Agent Guidelines for auth0-api-python

## Your Role

You are a Python SDK engineer on auth0-api-python, the async library APIs use to verify Auth0 access tokens (Bearer and DPoP) and perform server-side token exchange.

---

## Working Principles

- **Think before coding.** State assumptions. When a request is ambiguous, surface the interpretations and ask before building.
- **Simplicity first.** Write the minimum code that solves the stated problem. No speculative options, single-use abstractions, or error handling for impossible states.
- **Surgical changes.** Every changed line traces to the request. Clean up imports your change orphaned, leave pre-existing dead code alone.
- **Verify before done.** Turn the request into a checkable criterion (e.g. "reject X" becomes a failing test for X, then a fix) and run it before claiming success.

---

## Project Structure

```
src/auth0_api_python/
  __init__.py      # Public API: everything in __all__ is the supported surface
  api_client.py    # ApiClient: verify_request, verify_access_token, verify_dpop_proof,
                   #   get_access_token_for_connection, get_token_by_exchange_profile,
                   #   get_token_on_behalf_of; private helpers (_discover, _fetch_jwks, ...) at the end,
                   #   except _resolve_allowed_domains, which sits above verify_request (leave it there)
  config.py        # ApiClientOptions (all constructor options and defaults)
  errors.py        # BaseAuthError hierarchy (status code, OAuth error code, WWW-Authenticate headers)
  cache.py         # CacheAdapter ABC + InMemoryCache (LRU + TTL) for discovery/JWKS
  utils.py         # normalize_domain, OIDC/JWKS fetch, unverified header/payload decode, htu normalization
  act.py           # get_current_actor / get_delegation_chain (RFC 8693 act claim)
  types.py         # TypedDicts: DomainsResolverContext, OnBehalfOfTokenResult, ActClaim
  token_utils.py   # Test helpers (token/DPoP proof generators) with a synthetic test key. Not in __all__, but packaged and importable
tests/
  conftest.py      # Shared fixtures (api_client_confidential, mock_discovery) and httpx mock helpers
  test_api_client.py, test_cache.py, test_utils.py, test_act.py
docs/              # Caching.md, MultipleCustomDomain.md (hand-written guides, linked from README)
README.md, EXAMPLES.md
pyproject.toml     # Poetry manifest; source of truth for dependencies
requirements.txt   # Hand-maintained runtime + dev dep list for the Snyk SCA workflow (pins can differ from pyproject.toml)
.version, .shiprc  # Release version source (.shiprc keeps .version and pyproject.toml in sync)
.ruff.toml         # Lint config (CI-enforced)
```

Before changing a flow (Bearer/DPoP verification, token exchange, MCD, caching), read its row in [references/flow-map.md](references/flow-map.md) for entry points, supporting helpers, tests, and docs.

---

## Boundaries

### Always Do

- Run `poetry run pytest` and `poetry run ruff check .` before committing (both run in CI on Python 3.9 to 3.12).
- Make surgical changes: touch only what the request requires. Do not refactor or reformat adjacent code.
- Follow existing style and naming. Add new public `ApiClient` methods after the existing public methods, above the `# ===== Private Methods =====` banner in `api_client.py`. Add new private helpers below it. Never reorder existing declarations.
- Add unit tests for new functionality, marked `@pytest.mark.asyncio` when async, mocking HTTP with `pytest-httpx` (no real network calls).
- Raise typed errors from `errors.py` (subclasses of `BaseAuthError` with `get_status_code()` / `get_error_code()`). Wrap third-party failures in a typed error with `raise ... from e`. Inside a catch-all, re-raise this SDK's own errors first (`except VerifyAccessTokenError: raise`, as `verify_access_token` does) so they are not double-wrapped. Never return `None` or a bare `dict` to signal failure, and never leak raw `httpx`/`authlib` errors from public methods.
- Route discovery and JWKS fetches through `fetch_oidc_metadata` / `fetch_jwks` so `custom_fetch` and caching apply. Token endpoint calls use `httpx.AsyncClient(timeout=httpx.Timeout(self.options.timeout))` and map `httpx.TimeoutException` to `ApiError` 504 and `httpx.HTTPError` to 502, as `get_access_token_for_connection` does.
- Export any new public symbol through `__init__.py` `__all__`.
- Update `README.md` and `EXAMPLES.md` (and `docs/*.md` when caching or MCD behaviour changes) in the same PR when changing the public API, `ApiClientOptions`, or supported integration patterns.
- When adding or bumping a runtime dependency in `pyproject.toml`, update `requirements.txt` to match. The SCA scan installs from it, not from Poetry.
- Keep code compatible with Python 3.9 (`target-version = "py39"`, CI matrix includes 3.9).

### Ask First

- Any breaking change. Never make one on your own initiative, stop and ask the maintainer before writing it. This includes a renamed or removed public method, a changed signature or default, a new required option, or a raised Python floor.
- Changing an existing error's `get_error_code()` string, `ApiError.code`, or `get_status_code()`. Integrators branch on these and they surface in `WWW-Authenticate`, so treat them as public API. Adding a new error code is not breaking.
- Adding or bumping dependencies (`pyproject.toml`, `poetry.lock`, `requirements.txt`).
- Modifying public API signatures or `ApiClientOptions` defaults (e.g. `dpop_enabled`, `dpop_required`, cache TTL/size, `timeout`).
- Changes to token, DPoP, issuer, or domain validation logic, the allowed algorithm lists, `RESERVED_PARAMS`, or `normalize_domain`.
- Changes to CI/CD configuration (`.github/workflows/`, `.github/actions/`), `.ruff.toml` rule selection, or `.snyk` suppressions.
- Changing the cache key format or what is stored in the cache (affects custom `CacheAdapter` implementations).

### Never Do

- Commit secrets, client secrets, real tokens, or private keys. Test fixtures use placeholder values (`cid`, `csecret`, `auth0.local`).
- Hand-edit `poetry.lock` or `CHANGELOG.md`, or edit `.version` / the `pyproject.toml` version (the release flow owns them via `.shiprc`).
- Remove or skip a failing test instead of fixing it, or weaken an assertion to make it pass.
- Fail open. A validation, resolver, discovery, JWKS, or token endpoint failure must raise a typed error, never fall through to a permissive default (no default domain, no "assume valid").
- Compare secrets or token-derived values with `==` in new code. Use `hmac.compare_digest`.
- Run `ruff format .` repo-wide. It is not a CI gate and the tree is not format-clean (see Common Pitfalls).
- Modify `.venv*/`, `dist/`, `__pycache__/`, `.coverage`, `coverage.xml`.
- Import `token_utils` from library code, or put a real key in it.
- Log, print, or include access tokens, DPoP proofs, client secrets, exchanged tokens, or full token endpoint response bodies in error messages. The SDK has no logger. Do not introduce one that emits these.
- Break backward compatibility without asking first and getting explicit approval.

---

## Security Considerations

- **Algorithm pinning:** access tokens verify with `RS256` only (`self._jwt = JsonWebToken(["RS256"])`), DPoP proofs with `ES256` only. Never add `none`, `HS*`, or derive the algorithm from the token header.
- **Never fetch from a token-derived host:** in MCD mode (`domains`), the unverified `iss` is normalized and must pass `_resolve_allowed_domains` before `_discover(issuer=...)` runs. In single-domain mode, discovery always targets the configured `domain`, and the token `iss` is matched against the discovery issuer afterwards. Never pass a token-derived issuer or URL to a fetch without the allowlist check. That turns token input into SSRF.
- **Domain normalization:** `normalize_domain` rejects `http://`, credentials, paths, queries, and fragments. Route every domain or issuer comparison through it.
- **MCD resolver input is untrusted:** `request_url`, `request_headers`, and `unverified_iss` in `DomainsResolverContext` are attacker-influenced. Resolver failures raise `DomainsResolverError`, never fall back to accepting the token (see `docs/MultipleCustomDomain.md` "Security Requirements").
- **Claims:** `iss`, `aud`, `exp`, `iat` are always validated. `required_claims` adds to them, never replaces them.
- **DPoP:** proofs must carry `iat`, `ath`, `htm`, `htu`, `jti`. `htu` is compared via `normalize_url_for_htu`, `ath` must match the access token hash, and `cnf.jkt` must match the proof key thumbprint. `dpop_required=True` rejects Bearer. `jti` is checked for presence and type only. There is no replay store, so replay is bounded only by the `dpop_iat_offset` / `dpop_iat_leeway` window.
- **Token exchange:** `RESERVED_PARAMS` blocks overriding OAuth parameters via `extra`, and `MAX_ARRAY_VALUES_PER_KEY` caps array values. Do not weaken either.
- **Errors:** `_prepare_error` builds `WWW-Authenticate` headers. Error messages reach HTTP responses, so keep them generic and free of token contents.
- **Anonymous callers:** tokens with `sub` starting `anon@` verify like any token. Authorization is the integrator's call, the SDK must not silently accept or reject them.
- **Dependency scanning:** Snyk (`sca_scan.yml`, from `requirements.txt`, on push to `main` only), CodeQL (`codeql.yml`), and ruff `S` (bandit) rules in CI.
- **Vulnerability reports:** go through Auth0's Responsible Disclosure Program (README "Vulnerability Reporting"), never a public issue or PR.

---

> The sections below are reference. Each keeps a short anchor inline and offloads detail to `references/`.

## Commands

`poetry install` to set up, `poetry run pytest` to test, `poetry run ruff check .` to lint. See [references/commands.md](references/commands.md) for the full CI-matching command list. Read it when you need to build, test, or lint.

## Testing

pytest + pytest-asyncio + pytest-httpx, in `tests/`. The default `poetry run pytest` suite needs no credentials (HTTP is mocked). See [references/testing.md](references/testing.md) for fixtures, async test patterns, and coverage. Read it when writing or running tests.

## Code Style

CI-enforced via `.ruff.toml`: rule sets `E, W, F, I, B, C4, UP, S`, isort import order, py39 target, `S101`/`S105`/`S106` allowed only under `tests/`. New non-secret string constants in `src/` use `# noqa: S105` with a reason (existing sites predate this and omit it). See [references/code-style.md](references/code-style.md) for naming, error patterns, and examples. Read it before adding a class, method, or error type.

## Git Workflow

Branches `feat/`, `fix/`, `docs/`, `chore/`, `release/<version>`. Commits use Conventional Commits prefixes. See [references/git-workflow.md](references/git-workflow.md) for PR template sections. Read it when committing or opening a PR.

## Common Pitfalls

The ones that bite most: the Python 3.9 floor (no `X | None`), `ruff format` is not a CI gate, a missing `@pytest.mark.asyncio`, and `custom_fetch` covering only discovery/JWKS. See [references/pitfalls.md](references/pitfalls.md). Read it when a command, test, or CI job behaves unexpectedly.

## Docs Update Rules

Public API, options, or integration pattern changes update `README.md`, `EXAMPLES.md`, and the matching `docs/` guide in the same PR. See [references/docs-update.md](references/docs-update.md) for the tracked-docs inventory and code-to-docs mapping. Read it before finishing any PR that touches `src/`.
