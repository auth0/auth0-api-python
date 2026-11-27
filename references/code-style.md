# Code Style

## Naming

- `snake_case` functions, methods, and options. `PascalCase` classes. `UPPER_SNAKE` module constants (`RESERVED_PARAMS`, `TOKEN_EXCHANGE_GRANT_TYPE`).
- Private helpers carry a leading underscore (`_discover`, `_fetch_jwks`, `_prepare_error`) and sit together after the public methods of `ApiClient`. The one pre-existing exception is `_resolve_allowed_domains`, above `verify_request`. Leave it there.
- Error classes end in `Error` and live in `errors.py`.
- Type hints use builtin generics (`dict[str, Any]`, `list[str]`) and `X | None` unions. `Optional` remains only for the quoted forward references in `config.py`. ruff `UP` `target-version` is kept equal to the `pyproject.toml` Python floor.

## Errors

Every error subclasses `BaseAuthError`. A new error category defines its HTTP mapping. A specialization of an existing category (`MissingOrganizationError`, `OrganizationNotAllowedError` under `VerifyAccessTokenError`) inherits it:

```python
class DomainsResolverError(BaseAuthError):
    """Error raised when domains resolver function fails."""

    def get_status_code(self) -> int:
        return 500

    def get_error_code(self) -> str:
        return "domains_resolver_error"
```

Wrap third-party failures in a typed error and chain the cause:

```python
# Good (api_client.py, _resolve_allowed_domains)
try:
    result = self._allowed_domains(context)
    if asyncio.iscoroutine(result) or asyncio.isfuture(result):
        result = await result
except Exception as e:
    raise DomainsResolverError(
        f"Domains resolver function failed: {str(e)}"
    ) from e
```

Interpolating `str(e)` is acceptable here because the resolver is integrator code. Do not interpolate exception text that can carry token contents or a response body.

```python
# Bad
def get_token(self, options):
    client = httpx.Client()
    resp = client.post(url, data=options)
    if resp.status_code != 200:
        print(resp.text)
        return None
    return resp.json()
```

The snippet has six violations, in order. It is sync and untyped in an async SDK, the client has no `options.timeout`, the OAuth parameters are unfiltered (no `RESERVED_PARAMS` check), it prints a possibly token-bearing body, it returns a `None` a caller can mistake for success, and it lets an unvalidated response into the public API.

Public errors meant for integrators are exported from `__init__.py` (`ApiError`, `AuthServerUnavailableError`, `ConfigurationError`, `DomainsResolverError`, `GetAccessTokenForConnectionError`, `GetClientCredentialsTokenError`, `GetTokenByExchangeProfileError`, `MissingOrganizationError`, `OrganizationNotAllowedError`, `VerifyAccessTokenError`). Others are imported from `auth0_api_python.errors`.

## Patterns

- **Options object:** all configuration goes through `ApiClientOptions`. `ApiClient.__init__` raises `ConfigurationError` or `MissingRequiredArgumentError` at construction for `audience`, the `domain` / `domains` combination, `client_id` without `domain`, the cache settings, `organization_policy` / `organization_id`, `scope_matching`, and `client_info`. Not validated there: `timeout`, `dpop_iat_leeway`, `dpop_iat_offset`, and the format of a single `domain`. A bad entry in a `domains` list raises a plain `ValueError` from `normalize_domain`.
- **Async I/O:** network calls use `httpx.AsyncClient`, or the integrator's `custom_fetch` when provided. Public verification and token methods are `async def`.
- **Pluggable cache:** `CacheAdapter` ABC with `get` / `set` / `delete` / `clear`. `InMemoryCache` is the default. Entry TTL is `min(Cache-Control max-age, cache_ttl_seconds)` when the discovery/JWKS response sends `max-age`.
- **Token store:**
  - **Interfaces.** `AbstractTokenStore` ABC with `get` / `set` / `delete` plus `encrypt` / `decrypt`, separate from `CacheAdapter`. `IndexedTokenStore` adds `add_index_member` / `list_index_members` for `scope_matching="non_strict"`.
  - **Encryption helpers.** They are opt-in. The SDK never calls them, so a store encrypts in its own `get` / `set`.
  - **Internals.** Cache classes and key builders live in `_internal/` and are not public.
  - **Failures.** A store `get` failure is logged and treated as a miss. A `set` failure is logged and the fresh token is still returned. A malformed entry from a custom store can still raise, since `expires_at` reaches `is_fresh` outside the `try` in the client credentials and OBO paths, while the Token Vault cache checks its type first.
- **Docstrings:** Google style with `Args:` / `Returns:` / `Raises:` sections on public methods. `verify_dpop_proof` predates this convention and uses a numbered list instead.
- **Placement:** `api_client.py` has the banner `# ===== Private Methods =====`, and `_internal/obo_cache.py` has a lowercase `# ===== Private methods =====`. In `api_client.py`, new public methods go above the banner after the existing ones, and new helpers below it. In files without a banner, put new code next to related code or at the end, never at an arbitrary position.

## Comments and docstrings

Enforced on every change (code, tests, docs, commit messages):

1. **Comments earn their place.** Only a non-obvious why: a protocol citation (`# RFC 9449`), a security decision, an intentional omission. Never restate the line below. Default to one sharp line or none.
2. **Docstring format.** One-line description, then `Args`, then `Returns` / `Raises`. No design rationale. That belongs in the PR description.
3. **Plain hyphens only.** No em or en dashes in comments, docstrings, commit messages, or Markdown.
4. **No semicolon clause-splicing.** Split independent clauses into separate sentences.
5. **No internal references.** No ticket numbers, planning-doc paths, internal links, or references to other SDKs as a comparison or justification. PR bodies follow the PR template instead, whose References section is where tickets and links go.
6. **Helpers stay grouped.** Never interleave a private helper between public methods.
