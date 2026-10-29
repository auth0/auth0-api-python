# Flow Map

Before changing a flow, read its entry points and supporting helpers. Public methods are in `ApiClient` (`api_client.py`) above the `# ===== Private Methods =====` banner, and helpers are below it, except `_resolve_allowed_domains`, which sits above `verify_request`.

| Flow | Entry points | Also read | Docs |
|------|--------------|-----------|------|
| Request verification (Bearer + DPoP) | `verify_request` | `verify_access_token`, `verify_dpop_proof`, `_prepare_error`, `_build_www_authenticate`, `errors.py` | `README.md` sections 3 and 6, `EXAMPLES.md` "Bearer Authentication", "DPoP Authentication" |
| Access token verification | `verify_access_token` | `_resolve_allowed_domains`, `_discover`, `_fetch_jwks`, `_validate_claims_presence`, `utils.normalize_domain`, `utils.is_auth_server_outage`, `get_unverified_header` / `get_unverified_payload`, `AuthServerUnavailableError` | `README.md` section 3, `EXAMPLES.md` "Telling an Outage from an Invalid Token" |
| Organization policy | `verify_access_token`, options `organization_policy` / `organization_id` | `ApiClient.__init__` validation, `MissingOrganizationError`, `OrganizationNotAllowedError`. `get_token_on_behalf_of` / `get_access_token_for_connection` apply it only with a `token_store` and no `verified=` | `docs/OrganizationPolicy.md` (incl. "Token Exchange"), `README.md` section 9 |
| DPoP proof verification | `verify_dpop_proof` | `utils.normalize_url_for_htu`, `sha256_base64url`, `calculate_jwk_thumbprint`, options `dpop_enabled` / `dpop_required` / `dpop_iat_leeway` / `dpop_iat_offset` | `README.md` section 6, `EXAMPLES.md` "Direct DPoP Proof Verification" |
| Connection access token (Token Vault) | `get_access_token_for_connection` | `GetAccessTokenForConnectionError`, `ApiError`, `_discover` (token endpoint), `_internal/token_vault_cache.py`, `VerifiedToken` (`verified=`) | `README.md` section 4, `EXAMPLES.md` "Access Token for a Connection (Token Vault)", `docs/TokenStorage.md` |
| Custom token exchange | `get_token_by_exchange_profile` | `_apply_extra`, `RESERVED_PARAMS`, `MAX_ARRAY_VALUES_PER_KEY`, `GetTokenByExchangeProfileError` | `README.md` section 5 |
| On Behalf Of exchange | `get_token_on_behalf_of` | delegates to `get_token_by_exchange_profile`, returns `types.OnBehalfOfTokenResult`, `_internal/obo_cache.py`, `_internal/cache_keys.py`, `VerifiedToken` (`verified=`), option `scope_matching` | `README.md` "On Behalf Of Token Exchange", `EXAMPLES.md` "On Behalf Of Token Exchange", `docs/TokenStorage.md` |
| Client credentials (M2M) | `get_client_credentials_token` | `GetClientCredentialsTokenError`, `ApiError`, `_internal/cache_keys.m2m_cache_key`, `types.ClientCredentialsTokenResult` | `README.md` "Client Credentials for Server-to-Server Calls", `EXAMPLES.md` "Client Credentials for Server-to-Server Calls", `docs/TokenStorage.md` |
| Token store (minted-token caching) | option `token_store` (`AbstractTokenStore`, `IndexedTokenStore`) | `token_store.py`, `encryption.py`, `_internal/cache_expiry.py`, `TokenSet`, `VerifiedToken` | `docs/TokenStorage.md` |
| Delegation inspection | `get_current_actor`, `get_delegation_chain` (`act.py`) | `types.ActClaim` | `README.md` / `EXAMPLES.md` "Inspecting Delegation After Token Verification" |
| Multiple Custom Domains | `ApiClientOptions(domains=...)` | `_resolve_allowed_domains`, `utils.normalize_domain`, `types.DomainsResolverContext`, `DomainsResolverError` | `docs/MultipleCustomDomain.md`, `README.md` section 7 |
| Discovery / JWKS caching | `CacheAdapter`, `InMemoryCache` (`cache.py`) | `_discover`, `_fetch_jwks`, `utils.parse_cache_control_max_age` | `docs/Caching.md` |
| Anonymous callers | no dedicated code, verified like any token | `act.py` is unrelated, `sub` starts with `anon@` | `README.md` section 8, `EXAMPLES.md` "Anonymous Callers" |

Tests: `tests/test_api_client.py` covers every `ApiClient` flow, `tests/test_act.py` the delegation helpers, `tests/test_cache.py` the cache, `tests/test_utils.py` the utils, `tests/test_token_store.py` the token store, encryption, and cache keys.

With a `token_store`, `get_token_on_behalf_of` and `get_access_token_for_connection` call `verify_access_token` without `request_url` or `request_headers` when `verified=` is omitted, so a dynamic MCD resolver receives `None` for both. Pass `verified=` from a prior `verify_request` or `verify_access_token` call in that case.

Two rules cut across every flow: never fetch from a token-derived host unless it passed the allowlist (single-domain mode only fetches the configured `domain`), and fail closed with a typed error on every failure path.
