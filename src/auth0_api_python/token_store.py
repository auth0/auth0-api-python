"""
Token storage for tokens the SDK itself mints (e.g. On Behalf Of exchanges),
distinct from CacheAdapter which only caches OIDC discovery metadata and JWKS.
"""

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Optional, TypedDict

from .encryption import decrypt, encrypt


class _TokenSetRequired(TypedDict):
    access_token: str
    expires_at: int


class TokenSet(_TokenSetRequired, total=False):
    """A minted access token and its absolute expiration, as stored by a TokenStore."""

    granted_scopes: str


@dataclass(frozen=True)
class VerifiedToken:
    """An access token and the claims from verifying it.

    The claims must come from verify_access_token, since they are trusted to build the
    cache identity.
    """

    access_token: str
    claims: Mapping[str, Any]


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


class TokenIndexMember(TypedDict):
    """One cached token listed in an index, with the scopes it was granted and when it expires."""

    token_key: str
    granted_scopes: str
    expires_at: int


class IndexedTokenStore(AbstractTokenStore):
    """
    A token store that maintains a token index safely under concurrent writes and prunes it by expiry.

    Needed for any cache layout that keeps several tokens per principal and reuses one whose
    granted scopes cover a request. A plain AbstractTokenStore can only maintain such an index by
    reading it, adding to it, and writing it back, which loses a concurrent addition made in
    between. Implementations back the index with a structure that adds one member atomically and
    drops members once they expire, for example a Redis sorted set scored by each member's
    expiry. Adding a short-lived member must not shorten the whole index's lifetime.
    """

    @abstractmethod
    async def add_index_member(self, index_key: str, member: TokenIndexMember) -> None:
        """Atomically add member to the index, replacing any member with the same token_key."""
        ...

    @abstractmethod
    async def list_index_members(self, index_key: str) -> list[TokenIndexMember]:
        """Return the index members, possibly including expired ones, or [] if the index is absent."""
        ...
