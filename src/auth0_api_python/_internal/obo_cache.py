"""Caching for On Behalf Of exchanges: cache-key identity, lookup, and write."""

import logging
import time
from typing import NamedTuple, Optional, cast

from ..errors import TokenStoreError
from ..token_store import (
    AbstractTokenStore,
    IndexedTokenStore,
    TokenSet,
    VerifiedToken,
)
from ..types import OnBehalfOfTokenResult
from .cache_keys import (
    _normalized_scopes,
    index_cache_key,
    is_covered_by,
    obo_cache_key,
    session_fingerprint,
)


class _OboIdentity(NamedTuple):
    """The verified fields that identify one caller's OBO cache entries."""

    sub: str
    issuer: str
    incoming_client_id: str
    org_id: Optional[str]
    session_key: str


class OboCache:
    """Caches On Behalf Of exchange results in a token store, keyed by verified caller identity.

    scope_matching controls reuse. "strict" reuses a cached token only when its granted scopes
    equal the request. "non_strict" reuses any cached token whose granted scopes cover the
    request, which needs the per-caller index and so an IndexedTokenStore.
    """

    def __init__(
        self,
        token_store: AbstractTokenStore,
        *,
        exchange_tenant: str,
        exchange_client_id: str,
        scope_matching: str,
    ) -> None:
        self._store = token_store
        self._exchange_tenant = exchange_tenant
        self._exchange_client_id = exchange_client_id
        self._mode = scope_matching

    def identity(self, verified: VerifiedToken) -> Optional[_OboIdentity]:
        """Build the cache identity from verified claims, or None when they lack a usable subject."""
        claims = verified.claims
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            logging.warning("Verified token has no usable sub claim, skipping cache")
            return None
        issuer = claims.get("iss")
        if not isinstance(issuer, str) or not issuer:
            logging.warning("Verified token has no iss claim, skipping cache")
            return None
        org_id = claims.get("org_id") if isinstance(claims.get("org_id"), str) else None
        incoming = claims.get("azp") or claims.get("client_id")
        incoming_client_id = incoming if isinstance(incoming, str) else ""
        return _OboIdentity(
            sub=sub,
            issuer=issuer,
            incoming_client_id=incoming_client_id,
            org_id=org_id,
            session_key=session_fingerprint(verified.access_token),
        )

    async def lookup(
        self, identity: _OboIdentity, audience: str, scope: Optional[str]
    ) -> Optional[OnBehalfOfTokenResult]:
        """Return a reusable cached token for this request, or None on a miss."""
        if self._mode == "non_strict":
            return await self._index_lookup(identity, audience, scope)
        return await self._strict_lookup(identity, audience, scope)

    async def write(
        self,
        identity: _OboIdentity,
        audience: str,
        scope: Optional[str],
        obo_result: OnBehalfOfTokenResult,
    ) -> None:
        """Store a freshly exchanged token under its granted scopes."""
        # When Auth0 does not echo the granted scope, the requested scope is the best label available.
        granted = _normalized_scopes(obo_result["scope"] if "scope" in obo_result else scope)
        entry: TokenSet = {
            "access_token": obo_result["access_token"],
            "expires_at": obo_result["expires_at"],
            "granted_scopes": granted,
        }
        try:
            if self._mode == "non_strict":
                token_key = self._token_key(identity, audience, "index", granted)
                await self._store.set(token_key, entry)
                await cast(IndexedTokenStore, self._store).add_index_member(
                    self._index_key(identity, audience),
                    {"token_key": token_key, "granted_scopes": granted, "expires_at": obo_result["expires_at"]},
                )
            else:
                await self._store.set(self._token_key(identity, audience, "strict", granted), entry)
        except Exception as exc:
            store_err = TokenStoreError("Token store write failed", cause=exc)
            logging.warning("Token store write failed, token still returned: %s", store_err.cause)

    # ===== Private methods =====

    def _token_key(self, identity: _OboIdentity, audience: str, layout: str, scopes: Optional[str]) -> str:
        return obo_cache_key(
            layout=layout,
            sub=identity.sub,
            issuer=identity.issuer,
            incoming_client_id=identity.incoming_client_id,
            exchange_tenant=self._exchange_tenant,
            exchange_client_id=self._exchange_client_id,
            audience=audience,
            org_id=identity.org_id,
            scopes=scopes,
            session_key=identity.session_key,
        )

    def _index_key(self, identity: _OboIdentity, audience: str) -> str:
        return index_cache_key(
            sub=identity.sub,
            issuer=identity.issuer,
            incoming_client_id=identity.incoming_client_id,
            exchange_tenant=self._exchange_tenant,
            exchange_client_id=self._exchange_client_id,
            audience=audience,
            org_id=identity.org_id,
            session_key=identity.session_key,
        )

    async def _store_get(self, key: str) -> Optional[TokenSet]:
        try:
            return await self._store.get(key)
        except Exception as exc:
            store_err = TokenStoreError("Token store read failed", cause=exc)
            logging.warning("Token store read failed, treating as cache miss: %s", store_err.cause)
            return None

    @staticmethod
    def _well_formed_member(member: object) -> bool:
        """True when an index member has the fields the lookup reads, so a malformed one is a miss."""
        return (
            isinstance(member, dict)
            and isinstance(member.get("token_key"), str)
            and isinstance(member.get("granted_scopes"), str)
            and isinstance(member.get("expires_at"), int)
        )

    @staticmethod
    def _usable_entry(cached: Optional[TokenSet], now: int) -> bool:
        if cached is None:
            return False
        if "access_token" not in cached or "expires_at" not in cached:
            logging.warning("Token store returned a malformed entry, treating as cache miss")
            return False
        return cached["expires_at"] > now

    @staticmethod
    def _hit(cached: TokenSet) -> OnBehalfOfTokenResult:
        result: OnBehalfOfTokenResult = {
            "access_token": cached["access_token"],
            "expires_in": cached["expires_at"] - int(time.time()),
            "expires_at": cached["expires_at"],
        }
        granted = cached.get("granted_scopes")
        if granted:
            result["scope"] = granted
        return result

    async def _strict_lookup(
        self, identity: _OboIdentity, audience: str, scope: Optional[str]
    ) -> Optional[OnBehalfOfTokenResult]:
        cached = await self._store_get(self._token_key(identity, audience, "strict", scope))
        if not self._usable_entry(cached, int(time.time())):
            return None
        # Entries are stored under their granted-scope key, so confirm the grant matches exactly.
        if _normalized_scopes(cached.get("granted_scopes")) != _normalized_scopes(scope):
            return None
        return self._hit(cached)

    async def _index_lookup(
        self, identity: _OboIdentity, audience: str, scope: Optional[str]
    ) -> Optional[OnBehalfOfTokenResult]:
        # An unscoped request is covered by every cached token, so never reuse for one.
        if not scope:
            return None
        now = int(time.time())
        indexed = cast(IndexedTokenStore, self._store)
        try:
            members = await indexed.list_index_members(self._index_key(identity, audience))
        except Exception as exc:
            store_err = TokenStoreError("Token store read failed", cause=exc)
            logging.warning("Token store read failed, treating as cache miss: %s", store_err.cause)
            return None
        requested = set(_normalized_scopes(scope).split())
        candidates = [
            m for m in members
            if self._well_formed_member(m) and m["expires_at"] > now and is_covered_by(scope, m["granted_scopes"])
        ]
        # Prefer an exact grant, then the covering grant with the fewest extra scopes.
        candidates.sort(key=lambda m: len(set(_normalized_scopes(m["granted_scopes"]).split()) - requested))
        for member in candidates:
            cached = await self._store_get(member["token_key"])
            if not self._usable_entry(cached, now):
                continue
            # Trust the token value's own grant, not only the index label.
            if not is_covered_by(scope, cached.get("granted_scopes")):
                continue
            return self._hit(cached)
        return None
