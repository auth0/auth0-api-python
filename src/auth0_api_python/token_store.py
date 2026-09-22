"""
Token storage for tokens the SDK itself mints (e.g. On Behalf Of exchanges),
distinct from CacheAdapter which only caches OIDC discovery metadata and JWKS.
"""

import hashlib
from abc import ABC, abstractmethod
from typing import Optional, TypedDict

from .encryption import decrypt, encrypt
from .utils import get_unverified_payload

_FIELD_SEPARATOR = "\x1f"


class TokenSet(TypedDict):
    """A minted access token and its absolute expiration, as stored by a TokenStore."""

    access_token: str
    expires_at: int


class AbstractTokenStore(ABC):
    """
    Base class for token stores that persist exchanged tokens outside process memory
    (e.g. Redis, Memcached, a database). Requires a secret at construction and provides
    encrypt/decrypt helpers so subclasses can protect tokens at rest without having to
    implement the encryption themselves.

    Example:
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
    """

    def __init__(self, *, secret: str) -> None:
        self._secret = secret

    @abstractmethod
    async def get(self, key: str) -> Optional[TokenSet]:
        """Return the stored token or None if absent."""
        ...

    @abstractmethod
    async def set(self, key: str, value: TokenSet) -> None:
        """Store a token under key."""
        ...

    @abstractmethod
    async def delete(self, key: str) -> None:
        """Delete a stored token by key."""
        ...

    def encrypt(self, key: str, value: TokenSet) -> str:
        """Encrypt a TokenSet to a JWE string, keyed to this specific cache entry."""
        return encrypt(dict(value), self._secret, key)

    def decrypt(self, key: str, data: str) -> TokenSet:
        """Decrypt a JWE string back to a TokenSet."""
        return decrypt(data, self._secret, key)


def _normalized_scopes(scope: Optional[str]) -> str:
    """Sort and dedupe scopes so equivalent scope strings produce the same cache key."""
    if not scope:
        return ""
    return " ".join(sorted(set(scope.split())))


def session_fingerprint(access_token: str) -> str:
    """
    Derive a session-scoped fingerprint for an access token, to keep concurrent
    sessions' cached tokens from colliding. Not a trust or authorization signal:
    the token is decoded without signature verification.
    """
    try:
        payload = get_unverified_payload(access_token)
    except ValueError:
        return hashlib.sha256(access_token.encode()).hexdigest()

    sid = payload.get("sid")
    if isinstance(sid, str) and sid:
        return sid

    jti = payload.get("jti")
    if isinstance(jti, str) and jti:
        return jti

    return hashlib.sha256(access_token.encode()).hexdigest()


def obo_cache_key(
    sub: str,
    audience: str,
    org_id: Optional[str],
    scopes: Optional[str],
    session_key: str,
) -> str:
    """Cache key for an On Behalf Of exchange, scoped to caller, audience, org, scopes, and session."""
    fields = _FIELD_SEPARATOR.join(
        ["obo", audience, org_id or "", _normalized_scopes(scopes), session_key]
    )
    return sub + ":" + hashlib.sha256(fields.encode()).hexdigest()


def m2m_cache_key(audience: str, scopes: Optional[str]) -> str:
    """Cache key for a client-credentials (M2M) exchange, scoped to audience and scopes."""
    fields = _FIELD_SEPARATOR.join(["m2m", audience, _normalized_scopes(scopes)])
    return hashlib.sha256(fields.encode()).hexdigest()


def token_vault_cache_key(sub: str, connection: str) -> str:
    """Cache key for a Token Vault exchange, scoped to caller and connection."""
    fields = _FIELD_SEPARATOR.join(["token_vault", sub, connection])
    return hashlib.sha256(fields.encode()).hexdigest()
