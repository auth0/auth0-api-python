"""Cache-key builders and scope helpers for the tokens the SDK mints."""

import hashlib
from typing import Optional

from ..utils import get_unverified_payload

_FIELD_SEPARATOR = "\x1f"


def _normalized_scopes(scope: Optional[str]) -> str:
    """Sort and dedupe scopes so equivalent scope strings produce the same cache key."""
    if not scope:
        return ""
    return " ".join(sorted(set(scope.split())))


def is_covered_by(requested: Optional[str], granted: Optional[str]) -> bool:
    """True when the requested scopes are all covered by the granted scopes."""
    granted_set = set(_normalized_scopes(granted).split())
    requested_set = set(_normalized_scopes(requested).split())
    return requested_set.issubset(granted_set)


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


def _obo_identity_fields(
    namespace: str,
    *,
    issuer: str,
    incoming_client_id: str,
    exchange_tenant: str,
    exchange_client_id: str,
    audience: str,
    org_id: Optional[str],
    session_key: str,
) -> list[str]:
    """The fields every OBO cache key shares, namespaced by key kind.

    Folds in the verified issuer, the incoming token's client, the exchange tenant, and the
    exchange client so a token minted under one of them is never read back under another.
    """
    return [
        namespace,
        issuer,
        incoming_client_id,
        exchange_tenant,
        exchange_client_id,
        audience,
        org_id or "",
        session_key,
    ]


def obo_cache_key(
    *,
    layout: str,
    sub: str,
    issuer: str,
    incoming_client_id: str,
    exchange_tenant: str,
    exchange_client_id: str,
    audience: str,
    org_id: Optional[str],
    scopes: Optional[str],
    session_key: str,
) -> str:
    """Token cache key for an On Behalf Of exchange.

    layout is "strict" or "index" so the two scope-matching modes never read each other's tokens.
    The normalized scopes are folded in.
    """
    fields = _obo_identity_fields(
        "obo_token_" + layout,
        issuer=issuer,
        incoming_client_id=incoming_client_id,
        exchange_tenant=exchange_tenant,
        exchange_client_id=exchange_client_id,
        audience=audience,
        org_id=org_id,
        session_key=session_key,
    )
    fields.append(_normalized_scopes(scopes))
    return sub + ":" + hashlib.sha256(_FIELD_SEPARATOR.join(fields).encode()).hexdigest()


def index_cache_key(
    *,
    sub: str,
    issuer: str,
    incoming_client_id: str,
    exchange_tenant: str,
    exchange_client_id: str,
    audience: str,
    org_id: Optional[str],
    session_key: str,
) -> str:
    """Cache key for the OBO token index, scoped to caller, issuer, exchange, audience, org, and session.

    The "obo_index" namespace keeps it from colliding with either layout's token cache key.
    """
    fields = _obo_identity_fields(
        "obo_index",
        issuer=issuer,
        incoming_client_id=incoming_client_id,
        exchange_tenant=exchange_tenant,
        exchange_client_id=exchange_client_id,
        audience=audience,
        org_id=org_id,
        session_key=session_key,
    )
    return sub + ":" + hashlib.sha256(_FIELD_SEPARATOR.join(fields).encode()).hexdigest()


def m2m_cache_key(*, tenant: str, client_id: str, audience: str, scopes: Optional[str]) -> str:
    """Cache key for a client-credentials (M2M) exchange, scoped to tenant, client, audience, and scopes."""
    fields = _FIELD_SEPARATOR.join(
        ["m2m", tenant, client_id, audience, _normalized_scopes(scopes)]
    )
    return hashlib.sha256(fields.encode()).hexdigest()


def token_vault_cache_key(*, sub: str, connection: str, tenant: str, client_id: str) -> str:
    """Cache key for a Token Vault exchange, scoped to tenant, client, caller, and connection."""
    fields = _FIELD_SEPARATOR.join(["token_vault", tenant, client_id, sub, connection])
    return hashlib.sha256(fields.encode()).hexdigest()
