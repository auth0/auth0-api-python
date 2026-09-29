"""
auth0-api-python

A lightweight Python SDK for verifying Auth0-issued access tokens
in server-side APIs, using Authlib for OIDC discovery and JWKS fetching.
"""

from .act import get_current_actor, get_delegation_chain
from .api_client import ApiClient
from .cache import CacheAdapter, InMemoryCache
from .config import ApiClientOptions
from .errors import (
    ApiError,
    ConfigurationError,
    DomainsResolverError,
    GetClientCredentialsTokenError,
    GetTokenByExchangeProfileError,
    MissingOrganizationError,
    OrganizationNotAllowedError,
    TokenStoreError,
)
from .token_store import (
    AbstractTokenStore,
    IndexedTokenStore,
    TokenIndexMember,
    TokenSet,
    VerifiedToken,
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
    "CacheAdapter",
    "ClientCredentialsTokenResult",
    "ConfigurationError",
    "DomainsResolver",
    "DomainsResolverContext",
    "DomainsResolverError",
    "GetClientCredentialsTokenError",
    "GetTokenByExchangeProfileError",
    "TokenStoreError",
    "get_current_actor",
    "get_delegation_chain",
    "InMemoryCache",
    "MissingOrganizationError",
    "AbstractTokenStore",
    "IndexedTokenStore",
    "TokenIndexMember",
    "VerifiedToken",
    "OnBehalfOfTokenResult",
    "OrganizationNotAllowedError",
    "TokenSet",
]
