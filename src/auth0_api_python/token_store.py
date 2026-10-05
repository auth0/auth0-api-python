"""Token storage for SDK-minted tokens (OBO, M2M, Token Vault), distinct from CacheAdapter."""

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
    """Access token with verified claims from verify_access_token, trusted to build the cache key."""

    access_token: str
    claims: Mapping[str, Any]


class AbstractTokenStore(ABC):
    """Base class for external token stores with built-in JWE encrypt and decrypt helpers."""

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
    """Token store variant that maintains a scope index with atomic member writes to avoid concurrent-add races."""

    @abstractmethod
    async def add_index_member(self, index_key: str, member: TokenIndexMember) -> None:
        """Atomically add member to the index, replacing any member with the same token_key."""
        ...

    @abstractmethod
    async def list_index_members(self, index_key: str) -> list[TokenIndexMember]:
        """Return the index members, possibly including expired ones, or [] if the index is absent."""
        ...
