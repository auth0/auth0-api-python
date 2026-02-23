"""
Type definitions for auth0-api-python SDK
"""

from typing import Callable, Optional, TypedDict


class DomainsResolverContext(TypedDict, total=False):
    """
    Context passed to domains resolver functions.
    
    Attributes:
        request_url: The URL the API request was made to (optional)
        request_headers: Request headers dict (e.g., Host, X-Forwarded-Host) (optional)
        unverified_iss: The issuer claim from the unverified token (required)
    """
    request_url: Optional[str]
    request_headers: Optional[dict]
    unverified_iss: str  # This is required, others are optional


DomainsResolver = Callable[[DomainsResolverContext], list[str]]
"""
Type alias for domains resolver function.

A DomainsResolver is a function that receives a DomainsResolverContext and returns
a list of allowed domain strings.

Args:
    context (DomainsResolverContext): Dictionary containing:
        - 'request_url' (str | None): The URL the API request was made to
        - 'request_headers' (dict | None): Request headers (e.g., Host, X-Forwarded-Host)
        - 'unverified_iss' (str): The issuer claim from the unverified token

Returns:
    list[str]: List of allowed domain strings (e.g., ['tenant.auth0.com'])

Example:
    from auth0_api_python import DomainsResolverContext
    
    def my_resolver(context: DomainsResolverContext) -> list[str]:
        unverified_iss = context['unverified_iss']
        request_url = context.get('request_url')
        request_headers = context.get('request_headers')
        
        # Fetch allowed domains based on context
        return ['tenant1.auth0.com', 'tenant2.auth0.com']
"""
