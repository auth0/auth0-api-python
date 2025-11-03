"""
Configuration classes and utilities for auth0-api-python.
"""

from typing import Callable, List, Optional


class ApiClientOptions:
    """
    Configuration for the ApiClient.

    Args:
        domain: The Auth0 domain, e.g., "my-tenant.us.auth0.com".
        audience: The expected 'aud' claim in the token.
        issuers: Static list of allowed issuer URLs (for multi-domain mode).
        issuer_resolver: Async function for dynamic issuer validation (for multi-tenant mode).
        issuer_cache_ttl: Cache TTL in seconds for issuer validation (default: 600 = 10 minutes).
        jwks_cache_ttl: Cache TTL in seconds for JWKS caching (default: 3600 = 1 hour).
        custom_fetch: Optional callable that can replace the default HTTP fetch logic.
        dpop_enabled: Whether DPoP is enabled (default: True for backward compatibility).
        dpop_required: Whether DPoP is required (default: False, allows both Bearer and DPoP).
        dpop_iat_leeway: Leeway in seconds for DPoP proof iat claim (default: 30).
        dpop_iat_offset: Maximum age in seconds for DPoP proof iat claim (default: 300).
        client_id: Optional required if you want to use get_access_token_for_connection.
        client_secret: Optional required if you want to use get_access_token_for_connection.
    """
    def __init__(
            self,
            domain: Optional[str] = None,
            audience: Optional[str] = None,
            issuers: Optional[List[str]] = None,
            issuer_resolver: Optional[Callable] = None,
            issuer_cache_ttl: int = 600,
            jwks_cache_ttl: int = 3600,
            custom_fetch: Optional[Callable[..., object]] = None,
            dpop_enabled: bool = True,
            dpop_required: bool = False,
            dpop_iat_leeway: int = 30,
            dpop_iat_offset: int = 300,
            client_id: Optional[str] = None,
            client_secret: Optional[str] = None,
    ):
        self.domain = domain
        self.audience = audience
        self.issuers = issuers
        self.issuer_resolver = issuer_resolver
        self.issuer_cache_ttl = issuer_cache_ttl
        self.jwks_cache_ttl = jwks_cache_ttl
        self.custom_fetch = custom_fetch
        self.dpop_enabled = dpop_enabled
        self.dpop_required = dpop_required
        self.dpop_iat_leeway = dpop_iat_leeway
        self.dpop_iat_offset = dpop_iat_offset
        self.client_id = client_id
        self.client_secret = client_secret
