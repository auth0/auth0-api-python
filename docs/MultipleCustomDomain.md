# Multi-Custom Domain (MCD)

Multi-Custom Domain support allows your API to accept tokens issued by multiple Auth0 domains. This is useful when:

- Your Auth0 tenant has multiple custom domains configured
- You're migrating from one domain to another and need to accept tokens from both during the transition
- Your API serves requests from clients using different Auth0 domains

## Configuration Modes

### Static Domain List

For APIs that accept tokens from a known set of domains:

```python
from auth0_api_python import ApiClient, ApiClientOptions

api_client = ApiClient(ApiClientOptions(
    domains=[
        "tenant.auth0.com",
        "auth.example.com",
        "auth.acme.org"
    ],
    audience="https://api.example.com"
))

# Tokens from any of the three domains are accepted
claims = await api_client.verify_access_token(access_token)
```

The SDK validates the token's issuer against the configured list before performing OIDC discovery. Each domain gets its own cached discovery metadata and JWKS.

### Dynamic Resolver

For APIs that need to determine allowed domains at runtime (e.g., based on the request):

```python
from auth0_api_python import ApiClient, ApiClientOptions, DomainsResolverContext

def resolve_domains(context: DomainsResolverContext) -> list[str]:
    # context contains:
    #   unverified_iss  - the token's issuer claim (before verification)
    #   request_url     - the URL the request was made to (if provided)
    #   request_headers - the request headers dict (if provided)
    return ["tenant.auth0.com", "auth.example.com"]

api_client = ApiClient(ApiClientOptions(
    domains=resolve_domains,
    audience="https://api.example.com"
))

claims = await api_client.verify_access_token(access_token)
```

The resolver is called on every token verification. It receives a `DomainsResolverContext` with the unverified issuer and (if available) the request URL and headers. It must return a non-empty list of allowed domain strings.

### Hybrid Mode (domain + domains)

For migration scenarios where you need `domain` for client-initiated flows (token exchange, connection tokens) and `domains` for token verification:

```python
api_client = ApiClient(ApiClientOptions(
    domain="tenant.auth0.com",         # Used for token exchange discovery
    domains=[                           # Used for token verification
        "tenant.auth0.com",
        "auth.newdomain.com"
    ],
    audience="https://api.example.com",
    client_id="<CLIENT_ID>",
    client_secret="<CLIENT_SECRET>"
))

# Token verification uses the domains list
claims = await api_client.verify_access_token(access_token)

# Token exchange uses the domain parameter for discovery
result = await api_client.get_token_by_exchange_profile(
    subject_token=access_token,
    subject_token_type="urn:example:subject-token"
)
```

---

## Resolver Patterns

### Host-Header Based

Route allowed domains based on the incoming request's host:

```python
def host_based_resolver(context: DomainsResolverContext) -> list[str]:
    host = (context.get("request_headers") or {}).get("host", "")

    domain_map = {
        "api.us.example.com": ["us-tenant.auth0.com", "auth.us.example.com"],
        "api.eu.example.com": ["eu-tenant.auth0.com", "auth.eu.example.com"],
    }
    return domain_map.get(host, ["default-tenant.auth0.com"])

api_client = ApiClient(ApiClientOptions(
    domains=host_based_resolver,
    audience="https://api.example.com"
))

# Pass request context through verify_request
claims = await api_client.verify_request(
    headers=request.headers,
    http_url=str(request.url)
)
```

> [!WARNING]
> If using `Host` or `X-Forwarded-Host` headers in your resolver, do not trust them without validation — these headers can be spoofed by clients. Always validate against a known allowlist of your API hostnames, or use server-determined values from your reverse proxy / API gateway that are not client-controllable.

### Tenant Lookup

Resolve domains from a database or configuration service:

```python
def tenant_resolver(context: DomainsResolverContext) -> list[str]:
    # Look up allowed domains from your tenant registry
    # The unverified_iss tells you which issuer the token claims to be from
    issuer = context["unverified_iss"]

    # Your lookup logic here (database, config file, etc.)
    allowed = get_domains_for_issuer(issuer)
    return allowed
```

> [!NOTE]
> The resolver can be synchronous or asynchronous. If your resolver is an `async def`, the SDK will automatically `await` the result.
>
> ```python
> async def async_resolver(context: DomainsResolverContext) -> list[str]:
>     domains = await fetch_domains_from_db(context["unverified_iss"])
>     return domains
> ```

---

## MCD with DPoP

MCD works with DPoP authentication. When using `verify_request()`, the SDK handles both MCD domain validation and DPoP proof verification:

```python
api_client = ApiClient(ApiClientOptions(
    domains=["tenant.auth0.com", "auth.example.com"],
    audience="https://api.example.com",
    dpop_required=True
))

claims = await api_client.verify_request(
    headers={
        "authorization": "DPoP eyJ0eXAiOiJKV1Q...",
        "dpop": "eyJ0eXAiOiJkcG9wK2p3dC..."
    },
    http_method="GET",
    http_url="https://api.example.com/resource"
)
```

The verification order is: extract issuer from token -> validate issuer against allowed domains -> perform OIDC discovery from the token's issuer -> verify token signature -> verify DPoP proof.

---

## Error Handling

### Configuration Errors

Raised at initialization when the SDK configuration is invalid:

```python
from auth0_api_python import ApiClient, ApiClientOptions, ConfigurationError

# Neither domain nor domains provided
try:
    api_client = ApiClient(ApiClientOptions(audience="https://api.example.com"))
except ConfigurationError as e:
    print(e)  # "Must provide either 'domain' or 'domains' parameter..."

# Empty domains list
try:
    api_client = ApiClient(ApiClientOptions(domains=[], audience="https://api.example.com"))
except ConfigurationError as e:
    print(e)  # "domains list cannot be empty"

# Invalid domains type
try:
    api_client = ApiClient(ApiClientOptions(domains="not-a-list", audience="https://api.example.com"))
except ConfigurationError as e:
    print(e)  # "domains must be either a list of domain strings or a callable..."
```

### Resolver Errors

Raised when the dynamic resolver function fails:

```python
from auth0_api_python import DomainsResolverError
from auth0_api_python.errors import VerifyAccessTokenError

# Resolver raises an exception
try:
    claims = await api_client.verify_access_token(token)
except DomainsResolverError as e:
    print(e)           # "Domains resolver function failed: <original error>"
    e.get_status_code() # 500
    e.get_error_code()  # "domains_resolver_error"

# Resolver returns invalid type or empty list
except DomainsResolverError as e:
    print(e)  # "Domains resolver must return a list" or "Domains resolver returned an empty list"
```

### Issuer Rejection

Raised when a token's issuer is not in the allowed domains:

```python
try:
    claims = await api_client.verify_access_token(token)
except VerifyAccessTokenError as e:
    print(e)           # "Token issuer is not in the list of allowed domains"
    e.get_status_code() # 401
    e.get_error_code()  # "invalid_token"
    e.get_headers()     # {"WWW-Authenticate": "Bearer error=\"invalid_token\", ..."}
```

---

## Migration Guide

### Single Domain to MCD

Migrate from a single Auth0 domain to multiple custom domains with zero downtime:

```python
# Phase 1: Start with single domain (current state)
client = ApiClient(ApiClientOptions(
    domain="tenant.auth0.com",
    audience="https://api.example.com"
))

# Phase 2: Add new domain alongside existing (during migration)
# Tokens from both domains are now accepted
client = ApiClient(ApiClientOptions(
    domain="tenant.auth0.com",
    domains=["tenant.auth0.com", "auth.newdomain.com"],
    audience="https://api.example.com"
))

# Phase 3: Full MCD with all domains (after migration)
client = ApiClient(ApiClientOptions(
    domain="tenant.auth0.com",
    domains=["tenant.auth0.com", "auth.newdomain.com", "auth.other.com"],
    audience="https://api.example.com"
))
```

### Rollback from MCD

To revert to single domain, remove the `domains` parameter:

```python
# Rollback: only the configured domain's tokens are accepted
client = ApiClient(ApiClientOptions(
    domain="tenant.auth0.com",
    audience="https://api.example.com"
))
```

---

## Configuration Reference

| Parameter | Type | Default | Description |
|---|---|---|---|
| `domain` | `str` | `None` | Single Auth0 domain. Used for client-initiated flows (token exchange, connection tokens) and single-domain verification. |
| `domains` | `list[str]` or `callable` | `None` | List of allowed domains or a resolver function. Used for token verification in MCD mode. |
| `cache_ttl_seconds` | `int` | `600` | Maximum TTL for cached discovery metadata and JWKS (seconds). The effective TTL is `min(server_max_age, cache_ttl_seconds)`. |
| `cache_max_entries` | `int` | `100` | Maximum entries per cache before LRU eviction. Each issuer uses one discovery entry and one JWKS entry. |
| `cache_adapter` | `CacheAdapter` | `None` | Custom cache backend. See [Caching Guide](Caching.md) for details. |

At least one of `domain` or `domains` must be provided. When both are provided, `domains` is used for token verification and `domain` is used for client-initiated flows.

### Domain Normalization

Domains are normalized automatically. All of these are equivalent:

- `"tenant.auth0.com"`
- `"TENANT.AUTH0.COM"`
- `"https://tenant.auth0.com"`
- `"https://tenant.auth0.com/"`
- `"  tenant.auth0.com  "`
