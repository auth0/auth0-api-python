# Code Style

## Naming

- `snake_case` functions, methods, and options. `PascalCase` classes. `UPPER_SNAKE` module constants (`RESERVED_PARAMS`, `TOKEN_EXCHANGE_GRANT_TYPE`).
- Private helpers carry a leading underscore (`_discover`, `_fetch_jwks`, `_prepare_error`) and sit together after the public methods of `ApiClient`. The one pre-existing exception is `_resolve_allowed_domains`, above `verify_request`. Leave it there.
- Error classes end in `Error` and live in `errors.py`.
- Type hints use builtin generics (`dict[str, Any]`, `list[str]`) with `Optional` / `Union` from `typing`. ruff `UP` targets py39, so do not use `X | Y` syntax.

## Errors

Every error subclasses `BaseAuthError` and defines its HTTP mapping:

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
def get_token(self, options):                                   # sync, untyped
    client = httpx.Client()                                     # no options.timeout
    resp = client.post(url, data=options)                       # raw extras, no RESERVED_PARAMS check
    if resp.status_code != 200:
        print(resp.text)                                        # may print token material
        return None                                             # fails open, untyped
    return resp.json()                                          # unvalidated dict escapes
```

Each line is a separate violation: sync in an async SDK, no timeout, unfiltered OAuth parameters, a print of a possibly token-bearing body, a `None` a caller can mistake for success, and an unvalidated response in the public API.

Public errors meant for integrators are exported from `__init__.py` (`ApiError`, `ConfigurationError`, `DomainsResolverError`, `GetTokenByExchangeProfileError`). Others are imported from `auth0_api_python.errors`.

## Patterns

- **Options object:** all configuration goes through `ApiClientOptions` and is validated in `ApiClient.__init__`, raising `ConfigurationError` or `MissingRequiredArgumentError` at construction rather than at first use.
- **Async I/O:** network calls use `httpx.AsyncClient`, or the integrator's `custom_fetch` when provided. Public verification and token methods are `async def`.
- **Pluggable cache:** `CacheAdapter` ABC with `get` / `set` / `delete` / `clear`. `InMemoryCache` is the default. Entry TTL is `min(Cache-Control max-age, cache_ttl_seconds)` when the discovery/JWKS response sends `max-age`.
- **Docstrings:** Google style with `Args:` / `Returns:` / `Raises:` sections on public methods.
- **Placement:** `api_client.py` has one banner, `# ===== Private Methods =====`. New public methods go above it after the existing ones, new helpers below it. In files without banners, put new code next to related code or at the end, never at an arbitrary position.

## Comments and docstrings

Enforced on every change (code, tests, docs, commit messages):

1. **Comments earn their place.** Only a non-obvious why: a protocol citation (`# RFC 9449`), a security decision, an intentional omission. Never restate the line below. Default to one sharp line or none.
2. **Docstring format.** One-line description, then `Args`, then `Returns` / `Raises`. No design rationale, that belongs in the PR description.
3. **Plain hyphens only.** No em or en dashes in comments, docstrings, commit messages, or Markdown.
4. **No semicolon clause-splicing.** Split independent clauses into separate sentences.
5. **No internal references.** No ticket numbers, planning-doc paths, internal links, or cross-SDK comparisons ("same as the Node SDK").
6. **Helpers stay grouped.** Never interleave a private helper between public methods.
