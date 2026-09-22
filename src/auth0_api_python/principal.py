"""
Verified caller identity, normalized from access token claims.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Optional

from .errors import VerifyAccessTokenError


@dataclass
class Principal:
    """
    Normalized caller identity built from a verified access token's claims.

    Attributes:
        sub: The subject claim identifying the caller.
        expires_at: Unix epoch seconds the token expires, from the "exp" claim.
        scopes: Parsed from the space-separated "scope" claim. Empty list if absent.
        permissions: From the "permissions" claim. None when the claim is absent from
            the token (RBAC not enabled on the API), a list (possibly empty) when present.
        client_id: From the "client_id" claim, falling back to "azp". None if neither is present.
        org_id: From the "org_id" claim. None when the token carries no Organization.
    """

    sub: str
    expires_at: int
    scopes: list[str]
    permissions: Optional[list[str]]
    client_id: Optional[str]
    org_id: Optional[str]


def build_principal(claims: Mapping[str, Any]) -> Principal:
    """
    Build a Principal from a verified access token's claims.

    Args:
        claims: The claims dict returned by ApiClient.verify_access_token. This must be
            the already-verified claims, never a raw token or unverified input.

    Returns:
        A Principal normalizing the claims tool code needs.

    Raises:
        VerifyAccessTokenError: If the claims are missing the required "sub" claim.
    """
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub.strip():
        raise VerifyAccessTokenError("Access token is missing the required 'sub' claim")

    scope = claims.get("scope") or ""
    scopes = scope.split() if isinstance(scope, str) else []

    permissions = claims.get("permissions")

    client_id = claims.get("client_id") or claims.get("azp")

    return Principal(
        sub=sub,
        expires_at=claims["exp"],
        scopes=scopes,
        permissions=permissions,
        client_id=client_id,
        org_id=claims.get("org_id"),
    )
