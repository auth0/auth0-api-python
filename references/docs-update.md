# Docs Update Rules

A PR that changes public API, configuration, or integration patterns is not complete until the matching docs are updated in the same PR.

## Tracked docs

| Doc | Covers | Exists |
|-----|--------|--------|
| `README.md` | Install, `ApiClient` setup, verification, connection tokens, custom token exchange, OBO, DPoP modes and options, MCD summary, anonymous callers | present |
| `EXAMPLES.md` | OBO exchange, delegation inspection, Bearer and DPoP verification, DPoP modes, anonymous caller patterns | present |
| `docs/Caching.md` | Cache defaults, TTL/max entries, custom `CacheAdapter`, tuning | present |
| `docs/MultipleCustomDomain.md` | `domains` list and resolver modes, hybrid mode, resolver security requirements, MCD with DPoP, errors, migration | present |

## When you change code, update these docs

| When this changes | Update |
|-------------------|--------|
| A public `ApiClient` method added, removed, renamed, or its arguments change | `README.md` (relevant numbered section), `EXAMPLES.md` (affected samples) |
| `ApiClientOptions` parameter added, removed, or default changed | `README.md` (setup and the DPoP "Configuration Options" example if DPoP-related), plus `docs/Caching.md` for `cache_*` or `docs/MultipleCustomDomain.md` for `domain` / `domains` |
| `CacheAdapter` interface or `InMemoryCache` behaviour | `docs/Caching.md` ("CacheAdapter API", "Default Behavior") |
| Domain resolver context, MCD validation, or resolver errors | `docs/MultipleCustomDomain.md`, `README.md` section 7 |
| Bearer/DPoP verification behaviour or error codes | `README.md` section 6, `EXAMPLES.md` (Bearer, DPoP sections) |
| Token exchange (connection, exchange profile, OBO) behaviour or errors | `README.md` sections 4 and 5, `EXAMPLES.md` "On Behalf Of Token Exchange" |
| New exported symbol in `__init__.py` | `EXAMPLES.md` (add a usage sample) |
| Supported Python version or install method | `README.md` "Install the SDK" |
