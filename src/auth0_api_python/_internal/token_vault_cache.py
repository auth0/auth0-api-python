"""Caching for Token Vault (federated connection) exchanges: lookup and write."""

import logging
import time
from typing import Optional

from ..errors import TokenStoreError
from ..token_store import AbstractTokenStore, TokenSet
from .cache_keys import _normalized_scopes, token_vault_cache_key


class TokenVaultCache:
    """Caches Token Vault exchange results in a token store, keyed by caller and connection.

    ApiClient builds one TokenVaultCache when a token_store is configured and delegates
    every cache decision to it.
    """

    def __init__(self, token_store: AbstractTokenStore) -> None:
        self._store = token_store

    def cache_key(self, tenant: str, client_id: str, sub: Optional[str], connection: str) -> Optional[str]:
        """Return the cache key, or None when sub is absent (cache skipped with a warning)."""
        if not sub:
            logging.warning("Access token has no usable sub claim, skipping Token Vault cache")
            return None
        return token_vault_cache_key(sub=sub, connection=connection, tenant=tenant, client_id=client_id)

    async def lookup(self, key: str) -> Optional[dict]:
        """Return a live cached token or None. Miss cases: absent, malformed, expired."""
        cached: Optional[TokenSet] = None
        try:
            cached = await self._store.get(key)
        except Exception as exc:
            store_err = TokenStoreError("Token store read failed", cause=exc)
            logging.warning("Token store read failed, treating as cache miss: %s", store_err.cause)
            return None

        if cached is None:
            return None
        if "access_token" not in cached or "expires_at" not in cached:
            logging.warning("Token store returned a malformed entry, treating as cache miss")
            return None
        if cached["expires_at"] <= int(time.time()):
            return None

        result = {
            "access_token": cached["access_token"],
            "expires_in": cached["expires_at"] - int(time.time()),
            "expires_at": cached["expires_at"],
        }
        granted = cached.get("granted_scopes")
        if granted:
            result["scope"] = granted
        return result

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
            store_err = TokenStoreError("Token store write failed", cause=exc)
            logging.warning("Token store write failed, token still returned: %s", store_err.cause)
