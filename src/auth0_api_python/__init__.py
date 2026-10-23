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
    AuthServerUnavailableError,
    ConfigurationError,
    DomainsResolverError,
    GetAccessTokenForConnectionError,
    GetClientCredentialsTokenError,
    GetTokenByExchangeProfileError,
    MissingOrganizationError,
    OrganizationNotAllowedError,
    VerifyAccessTokenError,
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
    "AuthServerUnavailableError",
    "CacheAdapter",
    "ClientCredentialsTokenResult",
    "ConfigurationError",
    "DomainsResolver",
    "DomainsResolverContext",
    "DomainsResolverError",
    "GetAccessTokenForConnectionError",
    "GetClientCredentialsTokenError",
    "GetTokenByExchangeProfileError",
    "VerifyAccessTokenError",
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
