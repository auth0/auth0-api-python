"""
MCD Integration Test

Tests Multi-Custom Domain support with real Auth0 tokens.
This file demonstrates all three issuer validation methods.
"""

import asyncio
import httpx
from auth0_api_python.api_client import ApiClient
from auth0_api_python.config import ApiClientOptions
from auth0_api_python.issuer_validator import IssuerValidationContext


# ============================================================================
# CONFIGURATION
# ============================================================================

MODE = "dynamic"  # Options: "single", "static", "dynamic"

# Single domain mode
DOMAIN = "your-tenant.auth0.com"

# Static array mode
ISSUERS = [
    "https://your-tenant.us.auth0.com",
    "https://custom1.example.com",
    "https://custom2.example.com"
]

# Auth0 credentials
AUDIENCE = "https://api.example.com"
CLIENT_ID = "your_client_id"
CLIENT_SECRET = "your_client_secret"


# ============================================================================
# MAIN TEST FUNCTIONS
# ============================================================================

async def main():
    """Main test: Fetch and validate tokens from configured issuers"""
    print("=" * 70)
    print("Auth0 MCD Integration Test (SDK)")
    print("=" * 70)
    
    # Initialize API client based on mode
    print(f"\nMode: {MODE}")
    
    if MODE == "single":
        options = ApiClientOptions(domain=DOMAIN, audience=AUDIENCE)
        test_issuers = [f"https://{DOMAIN}"]
        print(f"Domain: {DOMAIN}")
    elif MODE == "static":
        options = ApiClientOptions(issuers=ISSUERS, audience=AUDIENCE)
        test_issuers = ISSUERS
        print(f"Issuers: {len(ISSUERS)}")
        for iss in ISSUERS:
            print(f"  - {iss}")
    elif MODE == "dynamic":
        options = ApiClientOptions(issuer_resolver=dynamic_resolver, audience=AUDIENCE)
        test_issuers = ISSUERS
        print(f"Resolver: {dynamic_resolver.__name__}")
    else:
        print(f"Invalid MODE: {MODE}")
        return
    
    client = ApiClient(options)
    print(f"Audience: {AUDIENCE}")
    
    # Fetch and validate tokens
    print("\n" + "=" * 70)
    print("Fetching and Validating Tokens")
    print("=" * 70)
    
    results = []
    for issuer in test_issuers:
        print(f"\n[{issuer}]")
        print("  Fetching token...")
        token = await fetch_token(issuer)
        
        if not token:
            print("  Status: FAILED (could not fetch token)")
            results.append(False)
            continue
        
        print("  Validating token...")
        result = await validate_token(client, token, issuer, MODE)
        results.append(result)
    
    # Summary
    print("\n" + "=" * 70)
    print("Summary")
    print("=" * 70)
    
    passed = sum(results)
    total = len(results)
    print(f"\nResults: {passed}/{total} tokens validated successfully")
    
    for i, (issuer, result) in enumerate(zip(test_issuers, results), 1):
        status = "PASS" if result else "FAIL"
        print(f"  {i}. [{status}] {issuer}")
    
    if passed == total:
        print("\nAll tokens validated successfully!")
    else:
        print(f"\n{total - passed} token(s) failed validation")


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

async def dynamic_resolver(context: IssuerValidationContext):
    """
    Dynamic issuer resolver with request context access.
    Returns JWKS URL if issuer is valid, None if invalid.
    """
    is_valid_domain = (context.token_issuer.endswith(".auth0.com") or 
                       context.token_issuer.endswith(".acmetest.org"))
    
    # Demonstrate request context access
    if context.request_domain:
        print(f"    [Resolver] Request domain: {context.request_domain}")
    if context.request_headers:
        print(f"    [Resolver] Request headers available: {len(context.request_headers)} headers")
    
    # Return JWKS URL if valid, None if invalid
    if is_valid_domain:
        return f"{context.token_issuer}/.well-known/jwks.json"
    else:
        return None


async def fetch_token(issuer: str) -> str:
    """Fetch access token from issuer"""
    token_url = f"{issuer}/oauth/token"
    
    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "audience": AUDIENCE,
        "grant_type": "client_credentials"
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, json=payload, timeout=10.0)
            response.raise_for_status()
            data = response.json()
            return data.get("access_token")
    except Exception as e:
        print(f"  Error fetching token: {e}")
        return None


async def validate_token(client: ApiClient, token: str, issuer: str, mode: str):
    """Validate a token and display results"""
    if not token:
        print(f"  Status: SKIPPED (no token)")
        return False
    
    try:
        # Pass request context to dynamic resolver
        request_context = None
        if mode == "dynamic":
            # Simulate request context (in real app, this comes from HTTP request)
            request_context = {
                "domain": "api.example.com",
                "headers": {
                    "user-agent": "MCD-SDK-Test/1.0",
                    "x-forwarded-for": "192.168.1.1"
                },
                "url": f"https://api.example.com/protected"
            }
        
        claims = await client.verify_access_token(
            access_token=token,
            request_context=request_context
        )
        print(f"  Status: VALID")
        print(f"  Issuer: {claims.get('iss')}")
        print(f"  Subject: {claims.get('sub')}")
        print(f"  Expires: {claims.get('exp')}")
        return True
    except Exception as e:
        print(f"  Status: INVALID")
        print(f"  Error: {type(e).__name__}: {e}")
        return False


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    asyncio.run(main())
