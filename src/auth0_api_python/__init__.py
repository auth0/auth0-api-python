"""
auth0-api-python

A lightweight Python SDK for verifying Auth0-issued access tokens
in server-side APIs, using Authlib for OIDC discovery and JWKS fetching.
"""

from .act import get_current_actor, get_delegation_chain
from .api_client import ApiClient
from .api_registry import ApiRegistry, DownstreamApi
from .cache import CacheAdapter, InMemoryCache
from .config import ApiClientOptions
from .errors import (
    ApiError,
    ConfigurationError,
    DomainsResolverError,
    GetClientCredentialsTokenError,
    GetTokenByExchangeProfileError,
    TokenStoreError,
)
from .token_store import (
    AbstractTokenStore,
    TokenSet,
    m2m_cache_key,
    obo_cache_key,
    session_fingerprint,
)
from .types import (
    ClientCredentialsTokenResult,
    DomainsResolver,
    DomainsResolverContext,
    OnBehalfOfTokenResult,
)

__all__ = [
    "ApiClient",
    "ApiClientOptions",
    "ApiError",
    "ApiRegistry",
    "CacheAdapter",
    "ClientCredentialsTokenResult",
    "ConfigurationError",
    "DomainsResolver",
    "DomainsResolverContext",
    "DomainsResolverError",
    "DownstreamApi",
    "GetClientCredentialsTokenError",
    "GetTokenByExchangeProfileError",
    "TokenStoreError",
    "get_current_actor",
    "get_delegation_chain",
    "InMemoryCache",
    "AbstractTokenStore",
    "m2m_cache_key",
    "obo_cache_key",
    "session_fingerprint",
    "OnBehalfOfTokenResult",
    "TokenSet",
]
