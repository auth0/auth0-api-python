"""Caching for Token Vault (federated connection) exchanges: lookup and write."""

import logging
import time
from typing import Any, Optional

from ..token_store import AbstractTokenStore, TokenSet
from .cache_expiry import is_fresh
from .cache_keys import _normalized_scopes, token_vault_cache_key

logger = logging.getLogger(__name__)


class TokenVaultCache:
    """Caches Token Vault exchange results in a token store, keyed by caller and connection.

    ApiClient builds one TokenVaultCache when a token_store is configured and delegates
    every cache decision to it.
    """

    def __init__(self, token_store: AbstractTokenStore) -> None:
        self._store = token_store

    def cache_key(
        self, tenant: str, client_id: str, sub: Any, connection: str, login_hint: Optional[str] = None
    ) -> Optional[str]:
        """Return the cache key, or None when sub is not a usable string (cache skipped with a warning)."""
        if not isinstance(sub, str) or not sub:
            logger.warning("Access token has no usable sub claim, skipping Token Vault cache")
            return None
        return token_vault_cache_key(
            sub=sub, connection=connection, tenant=tenant, client_id=client_id, login_hint=login_hint
        )

    async def lookup(self, key: str) -> Optional[dict]:
        """Return a live cached token or None. Miss cases: absent, malformed, expired."""
        cached: Optional[TokenSet] = None
        try:
            cached = await self._store.get(key)
        except Exception as exc:
            logger.warning("Token store read failed, treating as cache miss: %s", exc)
            return None

        if cached is None:
            return None
        access_token = cached.get("access_token")
        expires_at = cached.get("expires_at")
        if not isinstance(access_token, str) or not access_token or not isinstance(expires_at, int):
            logger.warning("Token store returned a malformed entry, treating as cache miss")
            return None
        now = int(time.time())
        if not is_fresh(expires_at, now):
            return None

        return {
            "access_token": access_token,
            "expires_in": expires_at - now,
            "expires_at": expires_at,
            "scope": cached.get("granted_scopes") or "",
        }

    async def write(self, key: str, result: dict) -> None:
        """Store a freshly exchanged connection token. Failures are logged and swallowed."""
        entry: TokenSet = {
            "access_token": result["access_token"],
            "expires_at": result["expires_at"],
            "granted_scopes": _normalized_scopes(result.get("scope")),
        }
        try:
            await self._store.set(key, entry)
        except Exception as exc:
            logger.warning("Token store write failed, token still returned: %s", exc)
