# Flow Map

Before changing a flow, read its entry points and supporting helpers. Public methods are in `ApiClient` (`api_client.py`) above the `# ===== Private Methods =====` banner, and helpers are below it, except `_resolve_allowed_domains`, which sits above `verify_request`.

| Flow | Entry points | Also read | Docs |
|------|--------------|-----------|------|
| Request verification (Bearer + DPoP) | `verify_request` | `verify_access_token`, `verify_dpop_proof`, `_prepare_error`, `_build_www_authenticate`, `errors.py` | `README.md` sections 3 and 6, `EXAMPLES.md` "Bearer Authentication", "DPoP Authentication" |
| Access token verification | `verify_access_token` | `_resolve_allowed_domains`, `_discover`, `_fetch_jwks`, `_validate_claims_presence`, `utils.normalize_domain`, `get_unverified_header` / `get_unverified_payload` | `README.md` section 3 |
| DPoP proof verification | `verify_dpop_proof` | `utils.normalize_url_for_htu`, `sha256_base64url`, `calculate_jwk_thumbprint`, options `dpop_enabled` / `dpop_required` / `dpop_iat_leeway` / `dpop_iat_offset` | `README.md` section 6, `EXAMPLES.md` "Direct DPoP Proof Verification" |
| Connection access token (Token Vault) | `get_access_token_for_connection` | `GetAccessTokenForConnectionError`, `ApiError`, `_discover` (token endpoint) | `README.md` section 4 |
| Custom token exchange | `get_token_by_exchange_profile` | `_apply_extra`, `RESERVED_PARAMS`, `MAX_ARRAY_VALUES_PER_KEY`, `GetTokenByExchangeProfileError` | `README.md` section 5 |
| On Behalf Of exchange | `get_token_on_behalf_of` | delegates to `get_token_by_exchange_profile`, returns `types.OnBehalfOfTokenResult` | `README.md` "On Behalf Of Token Exchange", `EXAMPLES.md` "On Behalf Of Token Exchange" |
| Delegation inspection | `get_current_actor`, `get_delegation_chain` (`act.py`) | `types.ActClaim` | `README.md` / `EXAMPLES.md` "Inspecting Delegation After Token Verification" |
| Multiple Custom Domains | `ApiClientOptions(domains=...)` | `_resolve_allowed_domains`, `utils.normalize_domain`, `types.DomainsResolverContext`, `DomainsResolverError` | `docs/MultipleCustomDomain.md`, `README.md` section 7 |
| Discovery / JWKS caching | `CacheAdapter`, `InMemoryCache` (`cache.py`) | `_discover`, `_fetch_jwks`, `utils.parse_cache_control_max_age` | `docs/Caching.md` |
| Anonymous callers | no dedicated code, verified like any token | `act.py` is unrelated, `sub` starts with `anon@` | `README.md` section 8, `EXAMPLES.md` "Anonymous Callers" |

Tests: `tests/test_api_client.py` covers every `ApiClient` flow, `tests/test_act.py` the delegation helpers, `tests/test_cache.py` the cache, `tests/test_utils.py` the utils.

Two rules cut across every flow: never fetch from a token-derived host unless it passed the allowlist (single-domain mode only fetches the configured `domain`), and fail closed with a typed error on every failure path.
