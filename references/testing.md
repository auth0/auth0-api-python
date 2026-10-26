# Testing

- **Framework:** pytest, with pytest-asyncio, pytest-httpx, pytest-mock, freezegun (versions in `pyproject.toml` dev group)
- **Location:** `tests/`, one `test_<module>.py` per source module
- **Coverage:** pytest-cov. `pyproject.toml` `addopts` always applies `--cov=src --cov-report=term-missing:skip-covered --cov-report=xml`. No minimum threshold is configured.

The default `poetry run pytest` suite needs no credentials. All Auth0 HTTP calls go through `httpx_mock` against `https://auth0.local`.

## Running tests

```bash
poetry run pytest                                   # all unit tests
poetry run pytest tests/test_cache.py               # one file
poetry run pytest tests/test_api_client.py -k dpop  # filter by name
```

## Conventions

- Module-level `test_<subject>_<condition>` functions (e.g. `test_verify_access_token_fail_no_iss`), often with a one-line docstring, grouped under `# ===== Section =====` comment banners. No test classes.
- Async tests are marked explicitly with `@pytest.mark.asyncio`. No `asyncio_mode` is configured, so an unmarked `async def test_...` will not run as intended.
- Assert error types with `pytest.raises(VerifyAccessTokenError)` and similar. Where both exist, assert on `get_error_code()` / `.code` and `get_status_code()` rather than message text. Codes are the contract, messages are not.
- Test placeholders stay obviously synthetic (`cid`, `csecret`, `auth0.local`). Never paste a real tenant value.
- Time-dependent tests use `@freeze_time(...)` from freezegun. Cache TTL tests in `test_cache.py` use short real sleeps.

## Mocking and test utilities

- `tests/conftest.py` provides:
  - `api_client_confidential`: an `ApiClient` with `domain="auth0.local"`, placeholder `client_id` / `client_secret`, and an `InMemoryTokenStore`, so OBO and Token Vault calls verify the token and cache
  - `api_client_confidential_no_store`: the same client without a `token_store`, for exchanges that must not verify or cache
  - `InMemoryTokenStore`, `InMemoryIndexedTokenStore`: test-only stores (never for production), the latter for `scope_matching="non_strict"`
  - `mock_discovery`: registers the discovery response
  - `mock_token_response(...)`, `token_success(...)`, `last_form(...)`, `last_auth_header(...)`: token endpoint mocking and request inspection
  - `assert_api_error(...)`, `assert_http_basic_auth(...)`, `assert_form_post(...)`, `assert_no_requests(...)`: shared assertions. Use `assert_api_error` rather than hand-rolling `.code` / status checks
- `src/auth0_api_python/token_utils.py` provides `generate_token`, `generate_dpop_proof`, `generate_token_with_cnf`, signed with a synthetic test key. Use these instead of hand-building JWTs.
- Use the constants `DISCOVERY_URL`, `JWKS_URL`, `TOKEN_ENDPOINT` from `conftest.py` rather than repeating URLs.
