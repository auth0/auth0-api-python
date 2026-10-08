# Token Storage

The SDK can cache access tokens it mints on the caller's behalf. Currently this covers tokens
returned by `get_token_on_behalf_of()`. This is separate from the `CacheAdapter` described in the
[Caching Guide](Caching.md), which only caches OIDC discovery metadata and JWKS keys, never a live
bearer token.

## Default Behavior

Caching is disabled by default. Without a `token_store`, every call to `get_token_on_behalf_of()`
performs a fresh exchange and nothing is stored.

To enable caching, pass a `token_store` to `ApiClientOptions`. Once a store is configured, the SDK
automatically builds a cache key from the incoming token and no additional argument is needed per
call.

## On Behalf Of Exchange with Caching

The following example verifies an incoming token and exchanges for a downstream token. The result
is cached so a second call for the same caller, audience, org, and scopes returns the cached token
without hitting Auth0 again.

```python
import asyncio
import httpx

from auth0_api_python import ApiClient, ApiClientOptions

async def exchange_on_behalf_of_cached(your_token_store):
    api_client = ApiClient(ApiClientOptions(
        domain="your-tenant.auth0.com",
        audience="https://mcp-server.example.com",
        client_id="<AUTH0_CLIENT_ID>",
        client_secret="<AUTH0_CLIENT_SECRET>",
        token_store=your_token_store,
    ))

    incoming_access_token = "incoming-auth0-access-token"

    # With a store configured, the exchange verifies the incoming token itself, so there is
    # no need to call verify_access_token separately here.
    result = await api_client.get_token_on_behalf_of(
        access_token=incoming_access_token,
        audience="https://calendar-api.example.com",
        scope="calendar:read calendar:write",
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
scopes it was granted, and the session the incoming token belongs to. Different callers or
sessions never share a cached token.

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

## Matching cached tokens by scope

By default the SDK only reuses a cached token when a later call asks for exactly the same scopes.
This is the `strict` setting of `scope_matching` on `ApiClientOptions`, and it works with any
store that implements `get`, `set`, and `delete`.

Set `scope_matching="non_strict"` when a broader token should satisfy a narrower request. If an
earlier exchange was granted `calendar:read calendar:write` and a later call only needs
`calendar:read`, non_strict returns the cached token instead of exchanging again, because the
granted scopes already cover what was asked for.

To do that without one scope set evicting another, non_strict keeps every distinct token plus an
index of the scopes each one was granted, so any cached token whose scopes cover the request can
be reused. The index is maintained with an atomic add so that several server processes can write
to it at once without losing each other's entries. A plain `AbstractTokenStore` cannot offer that,
so non_strict requires a store that subclasses `IndexedTokenStore` and implements
`add_index_member` and `list_index_members`. Using non_strict with a plain store raises
`ConfigurationError` at construction.

### Redis IndexedTokenStore example

This extends the `RedisTokenStore` above and backs the index with a Redis hash, one field per
token. Adding a member is a single `HSET`, which is atomic per field and overwrites any member
stored under the same `token_key`.

```python
import json
import time

from auth0_api_python import IndexedTokenStore, TokenIndexMember


class RedisIndexedTokenStore(RedisTokenStore, IndexedTokenStore):
    async def add_index_member(self, index_key: str, member: TokenIndexMember) -> None:
        await self.redis.hset(index_key, member["token_key"], json.dumps(member))

    async def list_index_members(self, index_key: str) -> list[TokenIndexMember]:
        raw = await self.redis.hgetall(index_key)
        now = int(time.time())
        live: list[TokenIndexMember] = []
        expired_fields = []
        for field, value in raw.items():
            member = json.loads(value)
            if member["expires_at"] > now:
                live.append(member)
            else:
                expired_fields.append(field)
        # Drop expired fields so the hash does not grow without bound as tokens age out.
        if expired_fields:
            await self.redis.hdel(index_key, *expired_fields)
        return live


# Usage
api_client = ApiClient(ApiClientOptions(
    domain="your-tenant.auth0.com",
    audience="https://mcp-server.example.com",
    client_id="<AUTH0_CLIENT_ID>",
    client_secret="<AUTH0_CLIENT_SECRET>",
    token_store=RedisIndexedTokenStore(redis_client, secret="<YOUR_ENCRYPTION_SECRET>"),
    scope_matching="non_strict",
))
```

An index member holds a hashed `token_key`, the granted scopes, and an expiry, never a bearer
token, so it is not encrypted. The tokens themselves stay encrypted under their own keys as
described above.
