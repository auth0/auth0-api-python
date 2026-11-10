"""
Configuration classes and utilities for auth0-api-python.
"""

from collections.abc import Callable
from typing import TYPE_CHECKING, Literal, Optional

if TYPE_CHECKING:
    from .cache import CacheAdapter
    from .token_store import AbstractTokenStore


class ApiClientOptions:
    """
    Configuration for the ApiClient.

    Args:
        domain: The Auth0 domain for single-domain mode and client flows,
                e.g., "my-tenant.us.auth0.com". Optional if domains is provided.
        domains: List of allowed domains or a resolver function for multi-domain mode.
                 Can be a static list of domain strings or a callable that returns
                 allowed domains dynamically. Optional if domain is provided.
        audience: The expected 'aud' claim in the token.
        custom_fetch: Optional callable that replaces the default HTTP fetch for discovery and JWKS requests. It is called with the URL only and receives no telemetry headers.
        cache_adapter: Custom cache implementation. If not provided, uses default InMemoryCache.
        token_store: Custom token storage for token caching. If not provided, caching is disabled and every exchange makes a fresh network call.
        cache_ttl_seconds: Time-to-live for cache entries in seconds (default: 600 = 10 minutes).
        cache_max_entries: Maximum number of cache entries before LRU eviction (default: 100).
        dpop_enabled: Whether DPoP is enabled (default: True for backward compatibility).
        dpop_required: Whether DPoP is required (default: False, allows both Bearer and DPoP).
        dpop_iat_leeway: Leeway in seconds for DPoP proof iat claim (default: 30).
        dpop_iat_offset: Maximum age in seconds for DPoP proof iat claim (default: 300).
        client_id: Required for get_access_token_for_connection, get_token_by_exchange_profile,
                   and get_token_on_behalf_of.
        client_secret: Required for get_access_token_for_connection, get_token_by_exchange_profile,
                       and get_token_on_behalf_of.
        timeout: HTTP timeout in seconds for token endpoint requests (default: 10.0).
        organization_policy: Whether the incoming token must carry an org_id claim.
                              "allow" (default) uses org_id when present but does not require it,
                              matching the pre-existing behavior of verify_access_token.
                              "required" rejects any token without an org_id claim.
        organization_id: Optional allowlist of org_id claim values (a non-empty string or a non-empty
                          list of non-empty strings). Only valid when organization_policy is
                          "required" - passing it with "allow" raises ConfigurationError at
                          construction time, as does an empty or non-string value.
        scope_matching: OBO cache scope-matching mode, applied only when token_store is set.
                        "strict" (default) reuses a cached token only on an exact granted-scope
                        match. "non_strict" reuses any cached token whose granted scopes cover
                        the request, and requires a token_store subclassing IndexedTokenStore
                        (raises ConfigurationError at construction without one).
        client_info: Name, version and optional env of a wrapper SDK built on this one, as a dict with non-empty string "name" and "version" keys and an optional "env" dict of string keys and values. Sent in the Auth0-Client header. An invalid value raises ConfigurationError at construction, and the "python" and "auth0-api-python" entries in env are set by this SDK.
    """
    def __init__(
            self,
            domain: str | None = None,
            audience: str = "",
            domains: list[str] | Callable[[dict], list[str]] | None = None,
            custom_fetch: Callable[..., object] | None = None,
            cache_adapter: Optional["CacheAdapter"] = None,
            token_store: Optional["AbstractTokenStore"] = None,
            cache_ttl_seconds: int = 600,
            cache_max_entries: int = 100,
            dpop_enabled: bool = True,
            dpop_required: bool = False,
            dpop_iat_leeway: int = 30,
            dpop_iat_offset: int = 300,
            client_id: str | None = None,
            client_secret: str | None = None,
            timeout: float = 10.0,
            organization_policy: Literal["required", "allow"] = "allow",
            organization_id: str | list[str] | None = None,
            scope_matching: str = "strict",
            client_info: dict | None = None,
    ):
        self.domain = domain
        self.domains = domains
        self.audience = audience
        self.custom_fetch = custom_fetch
        self.cache_adapter = cache_adapter
        self.token_store = token_store
        self.cache_ttl_seconds = cache_ttl_seconds
        self.cache_max_entries = cache_max_entries
        self.dpop_enabled = dpop_enabled
        self.dpop_required = dpop_required
        self.dpop_iat_leeway = dpop_iat_leeway
        self.dpop_iat_offset = dpop_iat_offset
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout
        self.organization_policy = organization_policy
        self.organization_id = organization_id
        self.scope_matching = scope_matching
        self.client_info = client_info
