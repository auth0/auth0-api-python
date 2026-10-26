# Docs Update Rules

A PR that changes public API, configuration, or integration patterns is not complete until the matching docs are updated in the same PR.

## Tracked docs

| Doc | Covers | Exists |
|-----|--------|--------|
| `README.md` | Install, `ApiClient` setup, verification, connection tokens, custom token exchange, OBO, client credentials, DPoP modes and options, MCD summary, anonymous callers, organization policy | present |
| `EXAMPLES.md` | OBO exchange and caching, client credentials, Token Vault connection tokens, delegation inspection, Bearer and DPoP verification, auth server outage handling, DPoP modes, anonymous caller patterns | present |
| `docs/Caching.md` | Cache defaults, TTL/max entries, custom `CacheAdapter`, tuning | present |
| `docs/MultipleCustomDomain.md` | `domains` list and resolver modes, hybrid mode, resolver security requirements, MCD with DPoP, errors, migration | present |
| `docs/TokenStorage.md` | `token_store`, cache key shapes per flow, expiry buffer, implementing `AbstractTokenStore` and `IndexedTokenStore`, at-rest encryption, `scope_matching` | present |
| `docs/OrganizationPolicy.md` | `organization_policy` modes, `organization_id` allowlist, configuration and verification errors | present |

## When you change code, update these docs

| When this changes | Update |
|-------------------|--------|
| A public `ApiClient` method added, removed, renamed, or its arguments change | `README.md` (relevant numbered section), `EXAMPLES.md` (affected samples) |
| `ApiClientOptions` parameter added, removed, or default changed | `README.md` (setup and the DPoP "Configuration Options" example if DPoP-related), plus `docs/Caching.md` for `cache_*` or `docs/MultipleCustomDomain.md` for `domain` / `domains` |
| `CacheAdapter` interface or `InMemoryCache` behaviour | `docs/Caching.md` ("CacheAdapter API", "Default Behavior") |
| Domain resolver context, MCD validation, or resolver errors | `docs/MultipleCustomDomain.md`, `README.md` section 7 |
| Bearer/DPoP verification behaviour or error codes | `README.md` section 6, `EXAMPLES.md` (Bearer, DPoP sections) |
| Token exchange (connection, exchange profile, OBO, client credentials) behaviour or errors | `README.md` sections 4 and 5, `EXAMPLES.md` "On Behalf Of Token Exchange", "Client Credentials for Server-to-Server Calls", "Access Token for a Connection (Token Vault)" |
| `token_store`, `scope_matching`, the `AbstractTokenStore` / `IndexedTokenStore` interface, cache keys, or the expiry buffer | `docs/TokenStorage.md`, `README.md` sections 4 and 5, `EXAMPLES.md` caching samples |
| `organization_policy` / `organization_id` behaviour or their errors | `docs/OrganizationPolicy.md`, `README.md` section 9 |
| Discovery or JWKS outage handling (`AuthServerUnavailableError`) | `README.md` section 3, `docs/MultipleCustomDomain.md` "Issuer Rejection", `EXAMPLES.md` "Telling an Outage from an Invalid Token" |
| New exported symbol in `__init__.py` | `EXAMPLES.md` (add a usage sample) |
| Supported Python version or install method | `README.md` "Install the SDK" |
