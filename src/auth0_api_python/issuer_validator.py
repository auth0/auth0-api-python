"""
Issuer validation logic for Multi-Custom Domain (MCD) support.

This module provides three methods for validating JWT issuer claims:
1. Single issuer (backward compatible)
2. Static array of issuers
3. Dynamic issuer resolver function
"""

import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass
class IssuerValidationContext:
    """
    Context information passed to dynamic issuer validation functions.
    
    Attributes:
        token_issuer: The 'iss' claim from the JWT token
        request_domain: The domain the API request was made to
        request_headers: HTTP headers from the request
        request_url: Full URL of the request
    """
    token_issuer: str
    request_domain: Optional[str] = None
    request_headers: Optional[Dict[str, str]] = None
    request_url: Optional[str] = None


class ConfigurationError(Exception):
    """Raised when SDK configuration is invalid."""
    pass


class IssuerValidator:
    """
    Validates JWT issuer claims using one of three methods.
    
    The validator supports:
    - Single issuer mode (backward compatible)
    - Static array of issuers
    - Dynamic issuer resolver function
    
    Results are cached to minimize latency and reduce load on backend systems.
    """
    
    def __init__(
        self,
        domain: Optional[str] = None,
        issuers: Optional[List[str]] = None,
        issuer_resolver: Optional[Callable[[IssuerValidationContext], Any]] = None,
        cache_ttl: int = 3600
    ):
        """
        Initialize the issuer validator.
        
        Args:
            domain: Single domain for backward compatibility (e.g., "tenant.auth0.com")
            issuers: Static list of allowed issuer URLs
            issuer_resolver: Async function that validates issuers dynamically
            cache_ttl: Cache time-to-live in seconds (default: 3600 = 1 hour)
            
        Raises:
            ConfigurationError: If no method is provided or multiple methods are provided
        """
        # Validate that exactly one configuration method is provided
        config_count = sum([
            domain is not None,
            issuers is not None,
            issuer_resolver is not None
        ])
        
        if config_count == 0:
            raise ConfigurationError(
                "Must provide one issuer configuration method: domain, issuers, or issuer_resolver"
            )
        
        if config_count > 1:
            raise ConfigurationError(
                "Cannot provide multiple issuer configuration methods. "
                "Choose only one: domain, issuers, or issuer_resolver"
            )
        
        self.domain = domain
        self.issuers = issuers
        self.issuer_resolver = issuer_resolver
        self.cache_ttl = cache_ttl
        
        # Determine validation mode
        if domain is not None:
            self.mode = "single"
            # Normalize domain to full issuer URL
            self._single_issuer = self._normalize_issuer(domain)
        elif issuers is not None:
            self.mode = "static"
            # Normalize all issuers
            self._static_issuers = [self._normalize_issuer(iss) for iss in issuers]
        else:
            self.mode = "dynamic"
        
        # Cache: {issuer: (is_valid, jwks_url, timestamp)}
        self._cache: Dict[str, Tuple[bool, Optional[str], float]] = {}
    
    def _normalize_issuer(self, issuer: str) -> str:
        """
        Normalize an issuer to a full HTTPS URL.
        
        Args:
            issuer: Domain or full URL
            
        Returns:
            Normalized issuer URL (e.g., "https://tenant.auth0.com")
        """
        issuer = issuer.strip()
        
        # If it's just a domain, add https://
        if not issuer.startswith("http://") and not issuer.startswith("https://"):
            issuer = f"https://{issuer}"
        
        # Remove trailing slash
        issuer = issuer.rstrip("/")
        
        return issuer
    
    async def validate(self, context: IssuerValidationContext) -> Tuple[bool, Optional[str]]:
        """
        Validate an issuer with caching.
        
        Args:
            context: Validation context containing issuer and request information
            
        Returns:
            Tuple of (is_valid, jwks_url)
            - For single/static mode: jwks_url is None (use default path)
            - For dynamic resolver: jwks_url is returned by resolver or None if invalid
        """
        # Check cache first
        cached_result = self._get_from_cache(context.token_issuer)
        if cached_result is not None:
            return cached_result
        
        # Perform validation based on mode
        jwks_url = None
        
        if self.mode == "single":
            result = self._validate_single(context)
        elif self.mode == "static":
            result = self._validate_static(context)
        else:  # dynamic
            result, jwks_url = await self._validate_dynamic(context)
        
        # Cache the result
        self._add_to_cache(context.token_issuer, result, jwks_url)
        
        return (result, jwks_url)
    
    def _validate_single(self, context: IssuerValidationContext) -> bool:
        """Validate against single issuer (backward compatible mode)."""
        return context.token_issuer == self._single_issuer
    
    def _validate_static(self, context: IssuerValidationContext) -> bool:
        """Validate against static array of issuers."""
        return context.token_issuer in self._static_issuers
    
    async def _validate_dynamic(self, context: IssuerValidationContext) -> Tuple[bool, Optional[str]]:
        """
        Validate using dynamic resolver function.
        
        Returns:
            Tuple of (is_valid, jwks_url)
            - Resolver returns JWKS URL (string) if valid, None if invalid
        """
        try:
            result = self.issuer_resolver(context)
            
            # Handle both sync and async resolvers
            if hasattr(result, '__await__'):
                result = await result
            
            # Resolver returns JWKS URL (string) if valid, None if invalid
            if result is None:
                return (False, None)
            else:
                return (True, str(result))
        except Exception:
            # If resolver fails, reject the issuer
            return (False, None)
    
    def _get_from_cache(self, issuer: str) -> Optional[Tuple[bool, Optional[str]]]:
        """
        Get validation result from cache if not expired.
        
        Args:
            issuer: The issuer URL to look up
            
        Returns:
            Cached validation result (is_valid, jwks_url) or None if not cached or expired
        """
        if issuer not in self._cache:
            return None
        
        is_valid, jwks_url, timestamp = self._cache[issuer]
        
        # Check if cache entry has expired
        if time.time() - timestamp > self.cache_ttl:
            # Remove expired entry
            del self._cache[issuer]
            return None
        
        return (is_valid, jwks_url)
    
    def _add_to_cache(self, issuer: str, is_valid: bool, jwks_url: Optional[str] = None) -> None:
        """
        Add validation result to cache.
        
        Args:
            issuer: The issuer URL
            is_valid: Whether the issuer is valid
            jwks_url: The JWKS URL (for dynamic resolver mode)
        """
        self._cache[issuer] = (is_valid, jwks_url, time.time())
    
    def clear_cache(self) -> None:
        """Clear the validation cache. Useful for testing or forced refresh."""
        self._cache.clear()
