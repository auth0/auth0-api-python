# Change Log

## [1.0.0b11](https://github.com/auth0/auth0-api-python/tree/1.0.0b11) (2026-11-11)
[Full Changelog](https://github.com/auth0/auth0-api-python/compare/1.0.0b10...1.0.0b11)

**⚠️ Breaking: Minimum supported Python version is now 3.10**
- Python 3.9 has reached end of life and is no longer supported. Upgrade to Python 3.10 or later, or stay on `1.0.0b10` if you are on Python 3.9. [\#159](https://github.com/auth0/auth0-api-python/pull/159) ([kishore7snehil](https://github.com/kishore7snehil))

**Added**
- feat: add organization policy enforcement [\#135](https://github.com/auth0/auth0-api-python/pull/135) ([kishore7snehil](https://github.com/kishore7snehil))
- feat: add server-side token storage with OBO caching [\#136](https://github.com/auth0/auth0-api-python/pull/136) ([kishore7snehil](https://github.com/kishore7snehil))
- feat: add client credentials token support for M2M [\#138](https://github.com/auth0/auth0-api-python/pull/138) ([kishore7snehil](https://github.com/kishore7snehil))
- feat: add caching for Token Vault connection token exchanges [\#139](https://github.com/auth0/auth0-api-python/pull/139) ([kishore7snehil](https://github.com/kishore7snehil))
- feat: add AuthServerUnavailableError for discovery and JWKS fetch failures [\#148](https://github.com/auth0/auth0-api-python/pull/148) ([kishore7snehil](https://github.com/kishore7snehil))
- feat: send Auth0-Client and User-Agent headers on requests to Auth0 [\#153](https://github.com/auth0/auth0-api-python/pull/153) ([kishore7snehil](https://github.com/kishore7snehil))

**Changed**
- docs: Added docs for anonymous sessions [\#122](https://github.com/auth0/auth0-api-python/pull/122) ([rmad17](https://github.com/rmad17))
- chore: migrate ruff config to [lint] and enforce top-level imports [\#140](https://github.com/auth0/auth0-api-python/pull/140) ([kishore7snehil](https://github.com/kishore7snehil))

**Fixed**
- fix: reject tokens that are not yet valid and avoid reusing near-expiry cached tokens [\#149](https://github.com/auth0/auth0-api-python/pull/149) ([kishore7snehil](https://github.com/kishore7snehil))
- fix: reject malformed token and DPoP proof input with SDK errors [\#151](https://github.com/auth0/auth0-api-python/pull/151) ([kishore7snehil](https://github.com/kishore7snehil))

## [1.0.0b10](https://github.com/auth0/auth0-api-python/tree/1.0.0b10) (2026-08-03)
[Full Changelog](https://github.com/auth0/auth0-api-python/compare/1.0.0b9...1.0.0b10)

**Deprecation**
- Support for Python 3.9.0 and 3.9.1 is dropped. 
- Support for Python 3.9 can be dropped in future releases. Please plan your upgrades accordingly.

**Changed**
- chore: Updated Dependencies [\#93](https://github.com/auth0/auth0-api-python/pull/93) ([rmad17](https://github.com/rmad17))
- chore: Documentation and dependency update [\#115](https://github.com/auth0/auth0-api-python/pull/115) ([rmad17](https://github.com/rmad17))

## [1.0.0b9](https://github.com/auth0/auth0-api-python/tree/1.0.0b9) (2026-04-30)
[Full Changelog](https://github.com/auth0/auth0-api-python/compare/1.0.0b8...1.0.0b9)

**Added**
- feat: add On Behalf Of Token Exchange support [\#88](https://github.com/auth0/auth0-api-python/pull/88) ([kishore7snehil](https://github.com/kishore7snehil))

## [1.0.0b8](https://github.com/auth0/auth0-api-python/tree/1.0.0b8) (2026-04-09)
[Full Changelog](https://github.com/auth0/auth0-api-python/compare/1.0.0b7...1.0.0b8)

**Added**
- feat: add Multiple Custom Domain Support [\#71](https://github.com/auth0/auth0-api-python/pull/71) ([kishore7snehil](https://github.com/kishore7snehil))

## [1.0.0b7](https://github.com/auth0/auth0-api-python/tree/1.0.0b7) (2026-04-02)
[Full Changelog](https://github.com/auth0/auth0-api-python/compare/1.0.0b6...1.0.0b7)

**Changed**
- chore: bump ada-url for Python 3.14, update deps, and fix CI [\#73](https://github.com/auth0/auth0-api-python/pull/73) ([kishore7snehil](https://github.com/kishore7snehil))

## [1.0.0b6](https://github.com/auth0/auth0-api-python/tree/1.0.0b6) (2025-10-29)
[Full Changelog](https://github.com/auth0/auth0-api-python/compare/1.0.0b5...1.0.0b6)

**Added**
- feat: Add Custom Token Exchange support (RFC 8693) [\#51](https://github.com/auth0/auth0-api-python/pull/51) ([btiernay](https://github.com/btiernay))

## [1.0.0b5](https://github.com/auth0/auth0-api-python/tree/1.0.0b5) (2025-09-11)
[Full Changelog](https://github.com/auth0/auth0-api-python/compare/1.0.0b4...1.0.0b5)

**Added**
- feat: Add token vault subject_token_type access_token to api sdk [\#28](https://github.com/auth0/auth0-api-python/pull/28) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [1.0.0b4](https://github.com/auth0/auth0-api-python/tree/1.0.0b4) (2025-08-28)
[Full Changelog](https://github.com/auth0/auth0-api-python/compare/1.0.0b3...1.0.0b4)

**Added**
- feat: add DPoP support [\#16](https://github.com/auth0/auth0-api-python/pull/16) ([kishore7snehil](https://github.com/kishore7snehil))
