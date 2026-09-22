# Token Storage

The SDK can cache access tokens it mints on the caller's behalf. Currently this covers tokens
returned by `get_token_on_behalf_of()`. This is separate from the `CacheAdapter` described in the
[Caching Guide](Caching.md), which only caches OIDC discovery metadata and JWKS keys, never a live
bearer token.

## Default Behavior

Caching is disabled by default. Without a `token_store`, every call to `get_token_on_behalf_of()`
performs a fresh exchange and nothing is stored.

To enable caching, pass a `token_store` to `ApiClientOptions` and pass `principal` (from
`build_principal()`) to each `get_token_on_behalf_of()` call. Caching only activates when both are
present, so existing callers that omit `principal` or `token_store` see no behavior change.

## On Behalf Of Exchange with Caching

The following example verifies an incoming token, builds a principal, and exchanges for a
downstream token. The result is cached so a second call for the same caller, audience, org, and
scopes returns the cached token without hitting Auth0 again.

```python
import asyncio
import httpx

from auth0_api_python import ApiClient, ApiClientOptions, build_principal

async def exchange_on_behalf_of_cached(your_token_store):
    api_client = ApiClient(ApiClientOptions(
        domain="your-tenant.auth0.com",
        audience="https://mcp-server.example.com",
        client_id="<AUTH0_CLIENT_ID>",
        client_secret="<AUTH0_CLIENT_SECRET>",
        token_store=your_token_store,
    ))

    incoming_access_token = "incoming-auth0-access-token"

    claims = await api_client.verify_access_token(access_token=incoming_access_token)
    principal = build_principal(claims, access_token=incoming_access_token)

    result = await api_client.get_token_on_behalf_of(
        access_token=incoming_access_token,
        audience="https://calendar-api.example.com",
        scope="calendar:read calendar:write",
        principal=principal,
    )

    async with httpx.AsyncClient() as client:
        downstream_response = await client.get(
            "https://calendar-api.example.com/events",
            headers={"Authorization": f"Bearer {result['access_token']}"}
        )

    downstream_response.raise_for_status()
    return downstream_response.json()
```

The cached entry is scoped to the caller (`sub`), the target `audience`, the `org_id`, the
requested scopes, and the session the incoming token belongs to. Different callers or sessions
never share a cached token.

## Implementing a Token Store

To supply a store, subclass `AbstractTokenStore` and implement three async methods: `get`, `set`,
and `delete`. The base class requires a `secret` at construction and provides `encrypt` and
`decrypt` helpers that your methods can call to protect tokens at rest.

### Redis example

```python
import time
from typing import Optional

import redis.asyncio as redis

from auth0_api_python import AbstractTokenStore, TokenSet


class RedisTokenStore(AbstractTokenStore):
    def __init__(self, redis_client, *, secret: str):
        super().__init__(secret=secret)
        self.redis = redis_client

    async def get(self, key: str) -> Optional[TokenSet]:
        raw = await self.redis.get(key)
        if raw is None:
            return None
        return self.decrypt(key, raw)

    async def set(self, key: str, value: TokenSet) -> None:
        encrypted = self.encrypt(key, value)
        ttl = max(value["expires_at"] - int(time.time()), 0)
        await self.redis.set(key, encrypted, ex=ttl)

    async def delete(self, key: str) -> None:
        await self.redis.delete(key)


# Usage
redis_client = redis.Redis(host="localhost", port=6379, db=0)

api_client = ApiClient(ApiClientOptions(
    domain="your-tenant.auth0.com",
    audience="https://mcp-server.example.com",
    client_id="<AUTH0_CLIENT_ID>",
    client_secret="<AUTH0_CLIENT_SECRET>",
    token_store=RedisTokenStore(redis_client, secret="<YOUR_ENCRYPTION_SECRET>"),
))
```

### Encryption

`self.encrypt(key, value)` and `self.decrypt(key, data)` are provided by `AbstractTokenStore`.
They use HKDF-SHA256 to derive a per-entry encryption key from `secret` and the cache key, then
wrap the token in a JWE using `alg: dir` and `enc: A256CBC-HS512`. A fresh random `kid` is
generated on every write, so two encryptions of the same value produce different ciphertext.

`secret` must be kept outside your codebase, for example in an environment variable or a secrets
manager. Rotating it invalidates all existing cached entries, which is safe because the SDK falls
back to a fresh exchange on any cache miss or decryption failure.
