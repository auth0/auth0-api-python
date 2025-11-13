# AGENTS.MD - AI Integration Guide for auth0-api-python SDK

> **Purpose**: This guide helps AI coding assistants understand how to integrate the `auth0-api-python` SDK into customer applications. When a customer says "add Auth0 authentication to my API" or "protect my endpoints with DPoP", the AI should be able to implement complete, production-ready solutions.

---

## 1. SDK Overview

### Installation

Customers must install the SDK before using it:

```bash
pip install auth0-api-python
```

**Alternative methods:**
```bash
# Using Poetry
poetry add auth0-api-python

# Using requirements.txt
pip install -r requirements.txt
```

See [README.md](README.md) for detailed installation instructions and version requirements (Python 3.9+).

### What This SDK Does

The `auth0-api-python` is a **server-side Python SDK** that helps customers secure their APIs with Auth0-issued access tokens. It provides:

- **JWT Access Token Verification** (RS256 signature validation)
- **DPoP (Demonstrating Proof-of-Possession)** authentication support
- **OIDC Discovery** and JWKS fetching
- **Token Exchange** capabilities (RFC 8693)
- **Unified Request Verification** that auto-detects Bearer vs DPoP schemes

### Key Characteristics

- **Async-first**: All I/O operations use `async/await` with `httpx`
- **Framework-agnostic**: Works with FastAPI, Django, Flask, or any Python web framework
- **Production-ready**: Comprehensive error handling with proper HTTP status codes
- **Standards-compliant**: Implements RFC 7519 (JWT), RFC 9449 (DPoP), RFC 8693 (Token Exchange)

### Typical Customer Use Cases

1. **FastAPI API** - Protect REST API endpoints with Bearer or DPoP tokens
2. **Flask API** - Add Auth0 authentication to existing Flask routes
3. **Django API** - Integrate Auth0 token validation in Django views
4. **Microservices** - Service-to-service authentication with token exchange
5. **Multi-tenant Apps** - Handle different Auth0 tenants dynamically
6. **WebSocket APIs** - Authenticate WebSocket connections
7. **Background Jobs** - Validate tokens in async workers

---

## 2. Quick Start for AI Agents

### Typical Customer Workflow

When a customer says "add Auth0 authentication to my API", follow this pattern:

1. **Understand Their Setup**
   - Framework: FastAPI? Flask? Django?
   - Auth scheme: Bearer only? DPoP? Both?
   - Protection scope: All routes? Specific routes? Public + protected?

2. **Locate Their Code**
   - Find where they define routes/endpoints
   - Find their app initialization file
   - Check for existing auth middleware or dependencies

3. **Implement SDK Integration**
   - Ensure SDK is installed (`pip install auth0-api-python`)
   - Add SDK setup in their app initialization
   - Create auth verification function/dependency
   - Add auth to their routes
   - Implement error handling

4. **Add Tests**
   - Test protected endpoints require auth
   - Test valid tokens work
   - Test invalid tokens fail appropriately

5. **Update Their Documentation**
   - Document how to call protected endpoints
   - Show token requirements
   - Provide example requests

### Example: Customer says "Add Auth0 to my FastAPI API"

**AI Agent Actions**:

```python
# STEP 1: Add SDK setup in their app.py or config.py
from auth0_api_python import ApiClient, ApiClientOptions

# Initialize SDK client (reuse across requests)
api_client = ApiClient(ApiClientOptions(
    domain="customer-tenant.auth0.com",  # From their Auth0 dashboard
    audience="https://their-api.example.com",  # Their API identifier
    dpop_enabled=True,  # Enable DPoP support
    dpop_required=False  # Allow both Bearer and DPoP
))

# STEP 2: Create authentication dependency in auth.py
from fastapi import Depends, HTTPException, Request
from auth0_api_python.errors import VerifyAccessTokenError, BaseAuthError

async def verify_auth0_token(request: Request) -> dict:
    """
    FastAPI dependency that verifies Auth0 tokens.
    Returns verified token claims if valid, raises HTTPException if not.
    """
    try:
        # Verify the request (auto-detects Bearer or DPoP)
        claims = await api_client.verify_request(
            headers=dict(request.headers),
            http_method=request.method,
            http_url=str(request.url)
        )
        return claims
    except BaseAuthError as e:
        raise HTTPException(
            status_code=e.get_status_code(),
            headers=e.get_headers(),
            detail=str(e)
        )

# STEP 3: Protect their routes
from fastapi import APIRouter

router = APIRouter()

@router.get("/api/users")
async def get_users(claims: dict = Depends(verify_auth0_token)):
    """Protected endpoint - requires valid Auth0 token"""
    user_id = claims["sub"]  # Get user ID from verified token
    # Their business logic here
    return {"users": [...], "requesting_user": user_id}

# Public endpoint (no auth dependency)
@router.get("/health")
async def health_check():
    return {"status": "healthy"}

# STEP 4: Add tests in test_api.py
import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_protected_endpoint_requires_auth(client: AsyncClient):
    """Test that protected endpoints reject requests without tokens"""
    response = await client.get("/api/users")
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers

@pytest.mark.asyncio
async def test_protected_endpoint_with_valid_token(client: AsyncClient, valid_token):
    """Test that protected endpoints accept valid tokens"""
    response = await client.get(
        "/api/users",
        headers={"Authorization": f"Bearer {valid_token}"}
    )
    assert response.status_code == 200
    assert "users" in response.json()
```

---

## 3. Framework Integration Patterns

### 3.1 FastAPI Integration

#### Pattern A: Dependency Injection (Recommended)

**Best for**: Protecting specific endpoints, flexibility per-route

```python
# auth.py - Create reusable auth dependency
from fastapi import Depends, HTTPException, Request
from auth0_api_python import ApiClient, ApiClientOptions
from auth0_api_python.errors import BaseAuthError

api_client = ApiClient(ApiClientOptions(
    domain="your-tenant.auth0.com",
    audience="https://api.example.com"
))

async def require_auth(request: Request) -> dict:
    """Dependency that requires valid Auth0 token"""
    try:
        claims = await api_client.verify_request(
            headers=dict(request.headers),
            http_method=request.method,
            http_url=str(request.url)
        )
        return claims
    except BaseAuthError as e:
        raise HTTPException(
            status_code=e.get_status_code(),
            headers=e.get_headers(),
            detail=str(e)
        )

# routes.py - Use in routes
from fastapi import APIRouter, Depends

router = APIRouter()

@router.get("/public/status")
async def public_endpoint():
    """No auth required"""
    return {"status": "ok"}

@router.get("/api/protected")
async def protected_endpoint(claims: dict = Depends(require_auth)):
    """Requires valid Auth0 token"""
    return {"message": "Success", "user": claims["sub"]}

@router.get("/api/admin")
async def admin_endpoint(claims: dict = Depends(require_auth)):
    """Check for admin role after auth"""
    if "admin" not in claims.get("scope", ""):
        raise HTTPException(403, "Admin access required")
    return {"message": "Admin access granted"}
```

#### Pattern B: Middleware (All Routes Protected)

**Best for**: Protecting all routes by default, with explicit exclusions

```python
# middleware.py
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from auth0_api_python import ApiClient, ApiClientOptions
from auth0_api_python.errors import BaseAuthError

api_client = ApiClient(ApiClientOptions(
    domain="your-tenant.auth0.com",
    audience="https://api.example.com"
))

# Public routes that don't require auth
PUBLIC_PATHS = {"/health", "/docs", "/openapi.json", "/"}

class Auth0Middleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # Skip auth for public paths
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)
        
        try:
            # Verify auth for all other routes
            claims = await api_client.verify_request(
                headers=dict(request.headers),
                http_method=request.method,
                http_url=str(request.url)
            )
            # Attach claims to request state for route handlers
            request.state.user_claims = claims
            return await call_next(request)
        
        except BaseAuthError as e:
            return JSONResponse(
                status_code=e.get_status_code(),
                headers=e.get_headers(),
                content={"error": str(e)}
            )

# app.py
from fastapi import FastAPI, Request

app = FastAPI()
app.add_middleware(Auth0Middleware)

@app.get("/api/users")
async def get_users(request: Request):
    """Automatically protected by middleware"""
    claims = request.state.user_claims
    return {"users": [...], "user": claims["sub"]}
```

### 3.2 Flask Integration

```python
# auth.py
from functools import wraps
from flask import request, jsonify
from auth0_api_python import ApiClient, ApiClientOptions
from auth0_api_python.errors import BaseAuthError
import asyncio

api_client = ApiClient(ApiClientOptions(
    domain="your-tenant.auth0.com",
    audience="https://api.example.com"
))

def require_auth(f):
    """Decorator to protect Flask routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # Run async verification in sync context
            claims = asyncio.run(api_client.verify_request(
                headers=dict(request.headers),
                http_method=request.method,
                http_url=request.url
            ))
            # Pass claims to route handler
            return f(claims=claims, *args, **kwargs)
        except BaseAuthError as e:
            return jsonify({"error": str(e)}), e.get_status_code(), e.get_headers()
    return decorated_function

# routes.py
from flask import Flask, jsonify
from auth import require_auth

app = Flask(__name__)

@app.route("/api/users")
@require_auth
def get_users(claims):
    """Protected endpoint"""
    return jsonify({"users": [...], "user": claims["sub"]})

@app.route("/health")
def health():
    """Public endpoint"""
    return jsonify({"status": "ok"})
```

### 3.3 Django Integration

```python
# auth/middleware.py
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from auth0_api_python import ApiClient, ApiClientOptions
from auth0_api_python.errors import BaseAuthError
import asyncio

api_client = ApiClient(ApiClientOptions(
    domain="your-tenant.auth0.com",
    audience="https://api.example.com"
))

PUBLIC_URLS = ['/health/', '/admin/']

class Auth0Middleware(MiddlewareMixin):
    def process_request(self, request):
        # Skip auth for public URLs
        if any(request.path.startswith(url) for url in PUBLIC_URLS):
            return None
        
        try:
            # Verify token
            claims = asyncio.run(api_client.verify_request(
                headers=dict(request.headers),
                http_method=request.method,
                http_url=request.build_absolute_uri()
            ))
            # Attach claims to request
            request.user_claims = claims
            return None
        except BaseAuthError as e:
            return JsonResponse(
                {"error": str(e)},
                status=e.get_status_code(),
                headers=e.get_headers()
            )

# settings.py
MIDDLEWARE = [
    # ... other middleware
    'auth.middleware.Auth0Middleware',
]

# views.py
from django.http import JsonResponse

def get_users(request):
    """Protected view - middleware handles auth"""
    claims = request.user_claims
    return JsonResponse({"users": [...], "user": claims["sub"]})
```

### 3.4 Frontend Integration Guidelines (For AI Agents)

#### CRITICAL: This SDK is Backend-Only

The `auth0-api-python` SDK:
- ✅ **Verifies tokens** sent by frontend/clients
- ✅ **Protects backend API** endpoints
- ❌ **Does NOT help frontend obtain tokens** (use Auth0 frontend SDKs)
- ❌ **Does NOT handle user login UI** (use Auth0 Universal Login or frontend SDK)

#### Complete Authentication Flow

```
┌─────────────────┐     1. Login / Get Token      ┌──────────────┐
│   Frontend      │─────────────────────────────▶ │   Auth0      │
│ (React/Vue/     │◀─────────────────────────────│   Tenant     │
│  Mobile/etc)    │     2. Return access_token    └──────────────┘
└─────────────────┘
         │
         │ 3. API Request
         │    Authorization: Bearer <token>
         │
         ▼
┌─────────────────┐     4. Verify Token           ┌──────────────┐
│  Customer's     │─────────────────────────────▶ │ This SDK     │
│  Backend API    │◀─────────────────────────────│ auth0-api-   │
│ (FastAPI/Flask) │     5. Return claims          │ python       │
└─────────────────┘                               └──────────────┘
         │
         │ 6. Return API data
         ▼
┌─────────────────┐
│   Frontend      │
└─────────────────┘
```

#### AI Agent Workflow for Frontend Integration

When customer asks about frontend integration:

**1. Identify Their Stack**
   - Frontend: React? Vue? Angular? Next.js? Mobile (iOS/Android)? Vanilla JS?
   - Backend: Already covered (FastAPI/Flask/Django in sections 3.1-3.3)

**2. Direct to Appropriate Auth0 Frontend SDK**

AI should recommend:
```
Frontend Stack          Auth0 SDK to Use
─────────────────       ──────────────────────────
React                   npm install @auth0/auth0-react
Vue                     npm install @auth0/auth0-vue
Angular                 npm install @auth0/auth0-angular
Next.js                 npm install @auth0/nextjs-auth0
Vanilla JS/SPA          npm install @auth0/auth0-spa-js
iOS (Swift)             Auth0.swift
Android (Kotlin/Java)   Auth0.Android
React Native            react-native-auth0
Flutter                 auth0_flutter
```

**3. Key Configuration Principle: Audience MUST Match**

```
Frontend Config                 Backend Config (this SDK)
┌─────────────────────┐        ┌──────────────────────────┐
│ audience: "api.com" │   ═══▶ │ audience: "api.com"      │  ✅ MUST MATCH
└─────────────────────┘        └──────────────────────────┘

If different → Customer gets "audience mismatch" error!
```

**4. Frontend Responsibilities (Generic Pattern)**

AI should explain the frontend must:

```javascript
// 1. Configure Auth0 SDK (adapt syntax to their framework)
{
  domain: "customer-tenant.auth0.com",
  clientId: "frontend-client-id",
  audience: "https://api.example.com"  // SAME as backend!
}

// 2. Get access token (method varies by SDK)
const token = await getAccessToken(); // or getAccessTokenSilently()

// 3. Send token to backend API
fetch('https://api.example.com/api/users', {
  headers: {
    'Authorization': `Bearer ${token}`  // This reaches backend
  }
})
```

**5. Backend Responsibilities (Already Covered)**

Backend uses patterns from sections 3.1-3.3:
- Configure `ApiClient` with same audience
- Use `verify_request()` to validate incoming tokens
- Return 401 with WWW-Authenticate on failures

#### CORS Configuration (When Frontend ≠ Backend Origin)

If customer's frontend runs on different origin than backend (e.g., `localhost:3000` → `localhost:8000`):

**AI must add CORS middleware. Adapt pattern to their framework:**

```python
# FastAPI Pattern:
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",          # React dev server
        "https://app.example.com"         # Production frontend
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "DPoP"],  # Include DPoP if used
)

# Flask: Install flask-cors, then:
from flask_cors import CORS
CORS(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:3000", "https://app.example.com"],
        "allow_headers": ["Authorization", "Content-Type", "DPoP"]
    }
})

# Django: Install django-cors-headers, add to MIDDLEWARE, then:
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "https://app.example.com",
]
CORS_ALLOW_HEADERS = ['authorization', 'content-type', 'dpop']
```

#### DPoP with Frontend Applications

If customer asks about DPoP:

**Prerequisites Check:**
1. Not all Auth0 frontend SDKs support DPoP yet
2. AI should check Auth0 docs for customer's specific frontend SDK

**If supported:**

Frontend must:
- Generate DPoP proof for each request
- Send two headers: `Authorization: DPoP <token>` and `DPoP: <proof>`

Backend (this SDK):
- Configure with `dpop_enabled=True` (see Section 4.3)
- Use `verify_request()` - automatically handles DPoP

#### Common Frontend Integration Patterns

**Single Page Apps (SPA):**
- User logs in via Auth0 Universal Login
- SPA stores tokens (memory recommended, not localStorage)
- SPA sends token with each API request
- Backend uses this SDK to verify

**Mobile Apps:**
- User logs in via Auth0 native SDK
- App stores tokens securely (Keychain/Keystore)
- App sends token in Authorization header
- Backend uses this SDK to verify

**Server-Side Rendered (SSR):**
- Consider if Bearer tokens are the right approach
- Might use session cookies instead
- If using tokens, similar pattern to SPA

**Microservices / Service-to-Service:**
- See Section 5.9 for service authentication patterns
- Use machine-to-machine (M2M) credentials

#### Example AI Response Template

When customer says: "I have [Frontend] and [Backend], add Auth0"

**AI should respond:**

```
I'll help you add Auth0 authentication. This requires setup in both places:

1. Frontend ([Their Stack]) - Obtain tokens:
   - Install: [recommend Auth0 SDK for their stack]
   - Configure with your Auth0 domain, client ID, and audience
   - Use SDK method to get access token
   - Send token in Authorization header when calling your API

2. Backend ([Their Stack]) - Verify tokens:
   [Use patterns from Section 3.1/3.2/3.3 based on their framework]
   - Configure ApiClient with SAME audience as frontend
   - Protect routes with token verification
   - Handle auth errors properly

3. CORS (if needed):
   [Add CORS middleware if frontend/backend on different origins]

CRITICAL: The audience in frontend config MUST match backend config.

[Then provide specific code for their exact setup]
```

#### What AI Should NOT Do

❌ Don't suggest frontend use this Python SDK (backend-only!)  
❌ Don't forget CORS configuration (very common issue)  
❌ Don't hardcode tokens in frontend code  
❌ Don't assume audience mismatch is a backend-only issue  
❌ Don't recommend DPoP without checking frontend SDK support  

#### Troubleshooting Frontend Integration

**"audience mismatch" error:**
- Check frontend Auth0 config - does `audience` match backend?
- Common issue: frontend missing audience parameter

**CORS errors:**
- Backend must allow frontend origin
- Backend must allow Authorization header
- See CORS patterns above

**"No Authorization header" error:**
- Frontend not sending token
- Check frontend SDK token retrieval
- Verify token is included in fetch/axios request

**401 but token seems valid:**
- Check if backend can reach Auth0 (network/firewall)
- Verify backend domain configuration matches token issuer
- Check token hasn't expired

---

## 4. Authentication Scheme Configuration

### 4.1 Bearer Token Only (Traditional OAuth 2.0)

**Use case**: Standard OAuth 2.0 APIs, existing implementations

```python
from auth0_api_python import ApiClient, ApiClientOptions

api_client = ApiClient(ApiClientOptions(
    domain="your-tenant.auth0.com",
    audience="https://api.example.com",
    dpop_enabled=False  # Disable DPoP, Bearer only
))

# Client sends: Authorization: Bearer eyJ...
claims = await api_client.verify_request(headers={"authorization": "Bearer eyJ..."})
```

### 4.2 DPoP Allowed (Default - Mixed Mode)

**Use case**: Gradual migration to DPoP, support both schemes

```python
api_client = ApiClient(ApiClientOptions(
    domain="your-tenant.auth0.com",
    audience="https://api.example.com",
    dpop_enabled=True,  # Enable DPoP support (default)
    dpop_required=False  # Allow both Bearer and DPoP (default)
))

# Client can send Bearer:
# Authorization: Bearer eyJ...

# OR Client can send DPoP:
# Authorization: DPoP eyJ...
# DPoP: eyJ0eXAiOiJkcG9w...

claims = await api_client.verify_request(
    headers=headers,
    http_method="GET",
    http_url="https://api.example.com/resource"
)
```

### 4.3 DPoP Required (Enhanced Security)

**Use case**: Maximum security, reject Bearer tokens

```python
api_client = ApiClient(ApiClientOptions(
    domain="your-tenant.auth0.com",
    audience="https://api.example.com",
    dpop_required=True  # Reject Bearer tokens, require DPoP
))

# Bearer tokens will be rejected with 400 Bad Request
# Only DPoP tokens accepted:
# Authorization: DPoP eyJ...
# DPoP: eyJ0eXAiOiJkcG9w...

claims = await api_client.verify_request(
    headers=headers,
    http_method="GET",
    http_url="https://api.example.com/resource"
)
```

### 4.4 DPoP Configuration Options

```python
api_client = ApiClient(ApiClientOptions(
    domain="your-tenant.auth0.com",
    audience="https://api.example.com",
    dpop_enabled=True,
    dpop_required=False,
    dpop_iat_leeway=30,      # Clock skew tolerance (seconds)
    dpop_iat_offset=300,     # Maximum proof age (seconds)
))
```

**Configuration Guidelines**:
- `dpop_iat_leeway`: Use 30-60 seconds for clock skew (network + server time differences)
- `dpop_iat_offset`: Use 60-300 seconds for proof freshness (balance security vs usability)

---

## 5. Common Integration Scenarios

### 5.1 Scenario: "Protect Specific Routes Only"

**Customer Request**: "Add Auth0 to /api/* routes but keep /health and /docs public"

**Solution (FastAPI)**:

```python
# auth.py
from fastapi import Depends, HTTPException, Request
from auth0_api_python import ApiClient, ApiClientOptions
from auth0_api_python.errors import BaseAuthError

api_client = ApiClient(ApiClientOptions(
    domain="customer-tenant.auth0.com",
    audience="https://customer-api.com"
))

async def require_auth(request: Request) -> dict:
    try:
        return await api_client.verify_request(
            headers=dict(request.headers),
            http_method=request.method,
            http_url=str(request.url)
        )
    except BaseAuthError as e:
        raise HTTPException(
            status_code=e.get_status_code(),
            headers=e.get_headers(),
            detail=str(e)
        )

# app.py
from fastapi import FastAPI, Depends
from auth import require_auth

app = FastAPI()

# Public endpoints - NO auth dependency
@app.get("/health")
async def health():
    return {"status": "ok"}

@app.get("/docs")
async def docs():
    return {"docs": "..."}

# Protected endpoints - WITH auth dependency
@app.get("/api/users")
async def get_users(claims: dict = Depends(require_auth)):
    return {"users": [...], "user": claims["sub"]}

@app.get("/api/orders")
async def get_orders(claims: dict = Depends(require_auth)):
    return {"orders": [...], "user": claims["sub"]}
```

### 5.2 Scenario: "Check for Specific Scopes"

**Customer Request**: "Only allow users with 'read:users' scope to access /api/users"

**Solution**:

```python
# auth.py
from fastapi import Depends, HTTPException, Request

async def require_auth(request: Request) -> dict:
    # ... (same as above)
    pass

def require_scope(required_scope: str):
    """Create a dependency that requires a specific scope"""
    async def scope_checker(claims: dict = Depends(require_auth)) -> dict:
        scope_string = claims.get("scope", "")
        scopes = scope_string.split()
        
        if required_scope not in scopes:
            raise HTTPException(
                status_code=403,
                detail=f"Missing required scope: {required_scope}"
            )
        return claims
    return scope_checker

# routes.py
@app.get("/api/users")
async def get_users(claims: dict = Depends(require_scope("read:users"))):
    """Requires 'read:users' scope"""
    return {"users": [...]}

@app.post("/api/users")
async def create_user(claims: dict = Depends(require_scope("write:users"))):
    """Requires 'write:users' scope"""
    return {"created": True}

@app.delete("/api/users/{user_id}")
async def delete_user(
    user_id: str,
    claims: dict = Depends(require_scope("delete:users"))
):
    """Requires 'delete:users' scope"""
    return {"deleted": user_id}
```

### 5.3 Scenario: "Cache Token Validation"

**Customer Request**: "Reduce latency by caching valid tokens for 5 minutes"

**Solution**:

```python
# cache.py
import aiocache
from auth0_api_python import ApiClient, ApiClientOptions
from auth0_api_python.errors import BaseAuthError

api_client = ApiClient(ApiClientOptions(
    domain="customer-tenant.auth0.com",
    audience="https://customer-api.com"
))

cache = aiocache.Cache(aiocache.Cache.MEMORY)

async def verify_token_cached(token: str) -> dict:
    """
    Verify token with 5-minute caching.
    Cache key is the token itself (already a hash-like string).
    """
    # Check cache first
    cached_claims = await cache.get(token)
    if cached_claims:
        return cached_claims
    
    # Not in cache - verify with Auth0
    claims = await api_client.verify_access_token(token)
    
    # Cache the verified claims (5 minutes)
    await cache.set(token, claims, ttl=300)
    
    return claims

# auth.py
from fastapi import Depends, HTTPException, Request
from cache import verify_token_cached

async def require_auth_cached(request: Request) -> dict:
    """Auth dependency with caching"""
    auth_header = request.headers.get("authorization", "")
    
    if not auth_header.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid Authorization header")
    
    token = auth_header.split(" ", 1)[1]
    
    try:
        claims = await verify_token_cached(token)
        return claims
    except BaseAuthError as e:
        raise HTTPException(
            status_code=e.get_status_code(),
            headers=e.get_headers(),
            detail=str(e)
        )

# routes.py
@app.get("/api/users")
async def get_users(claims: dict = Depends(require_auth_cached)):
    """Uses cached token validation"""
    return {"users": [...]}
```

### 5.4 Scenario: "Multi-Tenant Application"

**Customer Request**: "Support multiple Auth0 tenants based on subdomain"

**Solution**:

```python
# tenants.py
from auth0_api_python import ApiClient, ApiClientOptions

# Define tenant configurations
TENANT_CONFIGS = {
    "acme": ApiClientOptions(
        domain="acme.us.auth0.com",
        audience="https://api.acme.com"
    ),
    "widget": ApiClientOptions(
        domain="widget.eu.auth0.com",
        audience="https://api.widget.com"
    ),
}

# Create ApiClient instances for each tenant
tenant_clients = {
    tenant_id: ApiClient(config)
    for tenant_id, config in TENANT_CONFIGS.items()
}

def get_tenant_from_request(request) -> str:
    """Extract tenant ID from subdomain or header"""
    # Option 1: From subdomain (acme.api.example.com)
    host = request.headers.get("host", "")
    subdomain = host.split(".")[0]
    if subdomain in tenant_clients:
        return subdomain
    
    # Option 2: From custom header
    tenant = request.headers.get("x-tenant-id", "")
    if tenant in tenant_clients:
        return tenant
    
    raise ValueError("Unknown tenant")

# auth.py
from fastapi import Depends, HTTPException, Request
from tenants import tenant_clients, get_tenant_from_request
from auth0_api_python.errors import BaseAuthError

async def require_auth_multi_tenant(request: Request) -> dict:
    """Multi-tenant auth dependency"""
    try:
        # Get the tenant ID
        tenant_id = get_tenant_from_request(request)
        
        # Get the appropriate API client for this tenant
        api_client = tenant_clients[tenant_id]
        
        # Verify the token with tenant-specific configuration
        claims = await api_client.verify_request(
            headers=dict(request.headers),
            http_method=request.method,
            http_url=str(request.url)
        )
        
        # Attach tenant ID to claims for use in route
        claims["tenant_id"] = tenant_id
        return claims
        
    except ValueError as e:
        raise HTTPException(400, f"Invalid tenant: {e}")
    except BaseAuthError as e:
        raise HTTPException(
            status_code=e.get_status_code(),
            headers=e.get_headers(),
            detail=str(e)
        )

# routes.py
@app.get("/api/data")
async def get_data(claims: dict = Depends(require_auth_multi_tenant)):
    """Returns tenant-specific data"""
    tenant_id = claims["tenant_id"]
    user_id = claims["sub"]
    return {"tenant": tenant_id, "user": user_id, "data": [...]}
```

### 5.5 Scenario: "WebSocket Authentication"

**Customer Request**: "Authenticate WebSocket connections with Auth0 tokens"

**Solution (FastAPI WebSockets)**:

```python
# auth.py
from fastapi import WebSocket, WebSocketDisconnect
from auth0_api_python import ApiClient, ApiClientOptions
from auth0_api_python.errors import BaseAuthError

api_client = ApiClient(ApiClientOptions(
    domain="customer-tenant.auth0.com",
    audience="https://customer-api.com"
))

async def verify_websocket_token(websocket: WebSocket) -> dict:
    """
    Verify token for WebSocket connection.
    Token can be sent via:
    1. Query parameter: ws://api.example.com/ws?token=eyJ...
    2. Sec-WebSocket-Protocol header
    """
    # Try query parameter first
    token = websocket.query_params.get("token")
    
    if not token:
        # Try Sec-WebSocket-Protocol header
        # Client sends: Sec-WebSocket-Protocol: auth0-token, <token>
        protocols = websocket.headers.get("sec-websocket-protocol", "")
        if protocols.startswith("auth0-token, "):
            token = protocols.replace("auth0-token, ", "")
    
    if not token:
        await websocket.close(code=1008, reason="Missing auth token")
        raise WebSocketDisconnect(1008, "Missing auth token")
    
    try:
        claims = await api_client.verify_access_token(token)
        return claims
    except BaseAuthError as e:
        await websocket.close(code=1008, reason=str(e))
        raise WebSocketDisconnect(1008, str(e))

# websocket_routes.py
from fastapi import WebSocket, WebSocketDisconnect
from auth import verify_websocket_token

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    
    try:
        # Verify token on connection
        claims = await verify_websocket_token(websocket)
        user_id = claims["sub"]
        
        # Send welcome message
        await websocket.send_json({
            "type": "connected",
            "user": user_id
        })
        
        # Handle messages
        while True:
            data = await websocket.receive_text()
            # Process authenticated websocket messages
            await websocket.send_text(f"Echo: {data}")
            
    except WebSocketDisconnect:
        pass  # Client disconnected
```

### 5.6 Scenario: "Rate Limiting Per User"

**Customer Request**: "Implement rate limiting based on user ID from token"

**Solution**:

```python
# rate_limit.py
from collections import defaultdict
from time import time
from fastapi import HTTPException

class UserRateLimiter:
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)  # user_id -> [timestamps]
    
    def check_rate_limit(self, user_id: str):
        """Check if user has exceeded rate limit"""
        now = time()
        window_start = now - self.window_seconds
        
        # Clean old requests
        self.requests[user_id] = [
            ts for ts in self.requests[user_id]
            if ts > window_start
        ]
        
        # Check limit
        if len(self.requests[user_id]) >= self.max_requests:
            retry_after = int(self.requests[user_id][0] - window_start) + 1
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded",
                headers={"Retry-After": str(retry_after)}
            )
        
        # Record this request
        self.requests[user_id].append(now)

# Create rate limiter instance
rate_limiter = UserRateLimiter(max_requests=100, window_seconds=60)

# auth.py
from fastapi import Depends, Request
from rate_limit import rate_limiter

async def require_auth_with_rate_limit(request: Request) -> dict:
    """Auth dependency with per-user rate limiting"""
    # First verify the token
    claims = await require_auth(request)  # Your existing auth function
    
    # Then check rate limit for this user
    user_id = claims["sub"]
    rate_limiter.check_rate_limit(user_id)
    
    return claims

# routes.py
@app.get("/api/data")
async def get_data(claims: dict = Depends(require_auth_with_rate_limit)):
    """Rate-limited endpoint (100 requests/minute per user)"""
    return {"data": [...], "user": claims["sub"]}
```

### 5.7 Scenario: "Custom Error Responses"

**Customer Request**: "Return custom error format matching our API standard"

**Solution**:

```python
# errors.py
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from auth0_api_python.errors import BaseAuthError

class CustomErrorResponse:
    """Custom error format for the customer's API"""
    
    @staticmethod
    def format_error(error_code: str, message: str, details: dict = None):
        return {
            "error": {
                "code": error_code,
                "message": message,
                "details": details or {},
                "timestamp": int(time.time())
            }
        }

# Exception handler for auth errors
from fastapi import FastAPI

app = FastAPI()

@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    """Convert HTTPException to custom format"""
    error_response = CustomErrorResponse.format_error(
        error_code=f"HTTP_{exc.status_code}",
        message=exc.detail,
        details={"path": request.url.path}
    )
    return JSONResponse(
        status_code=exc.status_code,
        content=error_response,
        headers=getattr(exc, 'headers', {})
    )

# auth.py - Updated to use custom error format
from errors import CustomErrorResponse

async def require_auth(request: Request) -> dict:
    try:
        claims = await api_client.verify_request(
            headers=dict(request.headers),
            http_method=request.method,
            http_url=str(request.url)
        )
        return claims
    except BaseAuthError as e:
        # Transform to custom error format
        error_data = CustomErrorResponse.format_error(
            error_code=e.get_error_code(),
            message=str(e),
            details={"auth_scheme": "Bearer or DPoP required"}
        )
        raise HTTPException(
            status_code=e.get_status_code(),
            headers=e.get_headers(),
            detail=error_data
        )
```

### 5.8 Scenario: "Background Job Authentication"

**Customer Request**: "Authenticate background workers that process jobs from queue"

**Solution**:

```python
# worker.py
import asyncio
from auth0_api_python import ApiClient, ApiClientOptions
from auth0_api_python.errors import BaseAuthError

api_client = ApiClient(ApiClientOptions(
    domain="customer-tenant.auth0.com",
    audience="https://customer-api.com"
))

async def process_job(job_data: dict):
    """Process a background job with auth verification"""
    
    # Job contains user's access token
    user_token = job_data.get("access_token")
    
    if not user_token:
        print("Error: Job missing access token")
        return
    
    try:
        # Verify the user's token is still valid
        claims = await api_client.verify_access_token(user_token)
        user_id = claims["sub"]
        
        print(f"Processing job for user {user_id}")
        
        # Do the background work
        # ... process data, call APIs, etc.
        
        print(f"Job completed for user {user_id}")
        
    except BaseAuthError as e:
        print(f"Auth error processing job: {e}")
        # Handle expired/invalid token (notify user, retry, etc.)

# Queue worker
from celery import Celery

celery_app = Celery('worker', broker='redis://localhost:6379/0')

@celery_app.task
def background_task(job_data):
    """Celery task that verifies auth before processing"""
    asyncio.run(process_job(job_data))

# Enqueue job (from API endpoint)
@app.post("/api/jobs")
async def create_job(request_data: dict, claims: dict = Depends(require_auth)):
    """Create a background job with user's token"""
    job_data = {
        "user_id": claims["sub"],
        "access_token": request_data["access_token"],  # Client sends their token
        "payload": request_data["payload"]
    }
    background_task.delay(job_data)
    return {"job_id": "...", "status": "queued"}
```

### 5.9 Scenario: "Service-to-Service Authentication"

**Customer Request**: "Authenticate requests between microservices using client credentials"

**Solution**:

```python
# service_auth.py
from auth0_api_python import ApiClient, ApiClientOptions

# Service-to-service API client
service_api_client = ApiClient(ApiClientOptions(
    domain="customer-tenant.auth0.com",
    audience="https://internal-service.com",  # Internal service audience
    client_id="service-client-id",  # Machine-to-machine client
    client_secret="service-client-secret"
))

# In receiving service (validates incoming service tokens)
async def verify_service_token(request: Request) -> dict:
    """Verify tokens from other services"""
    try:
        claims = await service_api_client.verify_request(
            headers=dict(request.headers),
            http_method=request.method,
            http_url=str(request.url)
        )
        
        # Verify it's a service token (not a user token)
        # Service tokens have gty=client-credentials
        grant_type = claims.get("gty")
        if grant_type != "client-credentials":
            raise HTTPException(403, "User tokens not allowed for service endpoints")
        
        return claims
    except BaseAuthError as e:
        raise HTTPException(
            status_code=e.get_status_code(),
            headers=e.get_headers(),
            detail=str(e)
        )

# Internal service endpoint
@app.post("/internal/process")
async def process_internal(
    data: dict,
    claims: dict = Depends(verify_service_token)
):
    """Internal endpoint - only accepts service tokens"""
    service_client_id = claims["azp"]  # Authorized party (client ID)
    return {"processed": True, "by_service": service_client_id}
```

---

## 6. Error Handling in Customer Applications

### 6.1 Understanding Auth Errors

All auth errors from the SDK inherit from `BaseAuthError` and provide:

```python
from auth0_api_python.errors import BaseAuthError

try:
    claims = await api_client.verify_access_token(token)
except BaseAuthError as e:
    status_code = e.get_status_code()        # HTTP status code (401, 400, etc.)
    error_code = e.get_error_code()          # OAuth error code ("invalid_token", etc.)
    error_message = str(e)                   # Human-readable message
    headers = e.get_headers()                # WWW-Authenticate headers
```

### 6.2 Common Error Scenarios

| Error | Status | When It Happens | Customer Action |
|-------|--------|-----------------|-----------------|
| `VerifyAccessTokenError` | 401 | Token expired, invalid signature, wrong audience | Client needs to get new token |
| `InvalidDpopProofError` | 400 | DPoP proof invalid or expired | Client needs to generate new proof |
| `InvalidAuthSchemeError` | 400 | Wrong auth scheme (Bearer vs DPoP) | Check API requirements |
| `MissingAuthorizationError` | 400 | No Authorization header | Client must include Authorization header |
| `ApiError` | varies | Network error, Auth0 unreachable | Retry or check Auth0 status |

### 6.3 Error Handling Pattern for FastAPI

```python
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from auth0_api_python.errors import (
    BaseAuthError,
    VerifyAccessTokenError,
    InvalidDpopProofError,
    InvalidAuthSchemeError,
    ApiError
)

app = FastAPI()

@app.exception_handler(VerifyAccessTokenError)
async def handle_token_error(request: Request, exc: VerifyAccessTokenError):
    """Handle invalid/expired tokens"""
    return JSONResponse(
        status_code=exc.get_status_code(),
        headers=exc.get_headers(),
        content={
            "error": "invalid_token",
            "message": "Your token is invalid or expired. Please obtain a new token.",
            "details": str(exc)
        }
    )

@app.exception_handler(InvalidDpopProofError)
async def handle_dpop_error(request: Request, exc: InvalidDpopProofError):
    """Handle DPoP proof errors"""
    return JSONResponse(
        status_code=exc.get_status_code(),
        headers=exc.get_headers(),
        content={
            "error": "invalid_dpop_proof",
            "message": "Your DPoP proof is invalid. Generate a new proof.",
            "details": str(exc)
        }
    )

@app.exception_handler(ApiError)
async def handle_api_error(request: Request, exc: ApiError):
    """Handle SDK API errors (network issues, etc.)"""
    return JSONResponse(
        status_code=exc.status_code or 502,
        content={
            "error": "auth_service_error",
            "message": "Unable to verify authentication. Please try again.",
            "details": str(exc)
        }
    )

# Generic handler for all auth errors
@app.exception_handler(BaseAuthError)
async def handle_auth_error(request: Request, exc: BaseAuthError):
    """Catch-all for auth errors"""
    return JSONResponse(
        status_code=exc.get_status_code(),
        headers=exc.get_headers(),
        content={
            "error": exc.get_error_code(),
            "message": str(exc)
        }
    )
```

### 6.4 Logging Auth Failures

```python
import logging
from auth0_api_python.errors import BaseAuthError

logger = logging.getLogger(__name__)

async def require_auth_with_logging(request: Request) -> dict:
    """Auth dependency with security event logging"""
    try:
        claims = await api_client.verify_request(
            headers=dict(request.headers),
            http_method=request.method,
            http_url=str(request.url)
        )
        
        # Log successful auth
        logger.info(
            "Auth success",
            extra={
                "user_id": claims["sub"],
                "path": request.url.path,
                "ip": request.client.host
            }
        )
        return claims
        
    except BaseAuthError as e:
        # Log auth failure for security monitoring
        logger.warning(
            f"Auth failure: {e.get_error_code()}",
            extra={
                "error": str(e),
                "path": request.url.path,
                "ip": request.client.host,
                "headers": dict(request.headers)
            }
        )
        raise HTTPException(
            status_code=e.get_status_code(),
            headers=e.get_headers(),
            detail=str(e)
        )
```

---

## 7. Testing Customer Integrations

### 7.1 Testing Protected Endpoints

```python
# test_api.py
import pytest
from httpx import AsyncClient
from fastapi.testclient import TestClient

@pytest.mark.asyncio
async def test_protected_endpoint_requires_auth():
    """Test that protected endpoints reject unauthenticated requests"""
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get("/api/users")
        
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers

@pytest.mark.asyncio
async def test_protected_endpoint_with_invalid_token():
    """Test that invalid tokens are rejected"""
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get(
            "/api/users",
            headers={"Authorization": "Bearer invalid_token"}
        )
    
    assert response.status_code == 401
    assert "invalid_token" in response.json()["error"]

@pytest.mark.asyncio
async def test_protected_endpoint_with_valid_token(valid_auth0_token):
    """Test that valid tokens grant access"""
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get(
            "/api/users",
            headers={"Authorization": f"Bearer {valid_auth0_token}"}
        )
    
    assert response.status_code == 200
    assert "users" in response.json()
```

### 7.2 Test Fixtures for Auth0 Tokens

```python
# conftest.py
import pytest
from jose import jwt
from datetime import datetime, timedelta

@pytest.fixture
def valid_auth0_token():
    """Generate a valid Auth0 token for testing"""
    # In real tests, you'd generate this from your test Auth0 tenant
    # or use a mock that matches Auth0's structure
    payload = {
        "iss": "https://your-tenant.auth0.com/",
        "sub": "auth0|test-user-123",
        "aud": "https://api.example.com",
        "iat": int(datetime.utcnow().timestamp()),
        "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
        "azp": "test-client-id",
        "scope": "read:users write:users"
    }
    
    # Sign with your test private key (matching your test Auth0 tenant)
    token = jwt.encode(payload, TEST_PRIVATE_KEY, algorithm="RS256")
    return token

@pytest.fixture
def expired_auth0_token():
    """Generate an expired token for testing"""
    payload = {
        "iss": "https://your-tenant.auth0.com/",
        "sub": "auth0|test-user-123",
        "aud": "https://api.example.com",
        "iat": int((datetime.utcnow() - timedelta(hours=2)).timestamp()),
        "exp": int((datetime.utcnow() - timedelta(hours=1)).timestamp()),  # Expired
    }
    token = jwt.encode(payload, TEST_PRIVATE_KEY, algorithm="RS256")
    return token
```

### 7.3 Mocking the SDK for Tests

```python
# conftest.py
import pytest
from unittest.mock import AsyncMock, patch

@pytest.fixture
def mock_auth0_verify():
    """Mock the SDK verification for unit tests"""
    with patch('auth0_api_python.ApiClient.verify_request') as mock:
        # Configure mock to return valid claims
        mock.return_value = {
            "sub": "auth0|test-user-123",
            "aud": "https://api.example.com",
            "scope": "read:users write:users"
        }
        yield mock

# Use in tests
@pytest.mark.asyncio
async def test_endpoint_logic_only(mock_auth0_verify):
    """Test endpoint logic without actually calling Auth0"""
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get(
            "/api/users",
            headers={"Authorization": "Bearer fake_token"}
        )
    
    # Verify mock was called
    assert mock_auth0_verify.called
    
    # Test the business logic
    assert response.status_code == 200
    assert "users" in response.json()
```

## 8. Troubleshooting Guide for Customers

### 8.1 Common Issues and Solutions

#### Issue: "Audience mismatch" Error

**Error Message**: `Token audience 'https://wrong-api.com' doesn't match configured audience 'https://api.example.com'`

**Cause**: The token's `aud` claim doesn't match the `audience` configured in `ApiClientOptions`.

**Solutions**:
1. Check Auth0 Dashboard → APIs → Your API → "Identifier" (this is your audience)
2. Ensure your token request uses the same audience
3. Update `ApiClientOptions` to use the correct audience

```python
# Check token audience (decode without verification)
import jwt
payload = jwt.decode(token, options={"verify_signature": False})
print(f"Token audience: {payload['aud']}")

# Fix: Use correct audience in SDK configuration
api_client = ApiClient(ApiClientOptions(
    domain="your-tenant.auth0.com",
    audience="https://api.example.com",  # Must match token's aud claim
))
```

---

#### Issue: "Issuer mismatch" Error

**Cause**: Token's `iss` claim doesn't match your Auth0 tenant.

**Solutions**:
1. Verify domain is correct (NO protocol: ✅ `tenant.auth0.com` ❌ `https://tenant.auth0.com`)
2. If using custom domain, use it consistently everywhere
3. Check OIDC discovery: `curl https://your-tenant.auth0.com/.well-known/openid-configuration`

```python
# ❌ WRONG - includes protocol
api_client = ApiClient(ApiClientOptions(
    domain="https://tenant.auth0.com",  # WRONG!
    audience="https://api.example.com"
))

# ✅ CORRECT - domain only
api_client = ApiClient(ApiClientOptions(
    domain="tenant.auth0.com",  # Correct
    audience="https://api.example.com"
))
```

---

#### Issue: "No matching key found for kid: xyz"

**Cause**: The token's `kid` (key ID) doesn't exist in the JWKS.

**Solutions**:
1. Token might be from wrong Auth0 tenant
2. Key rotation just occurred (wait a few minutes)
3. Verify JWKS: `curl https://your-tenant.auth0.com/.well-known/jwks.json`

```python
# Debug: Check which kid is in the token
from auth0_api_python.utils import get_unverified_header

header = get_unverified_header(token)
print(f"Token kid: {header['kid']}")

# Verify it exists in JWKS
import httpx
async with httpx.AsyncClient() as client:
    resp = await client.get("https://your-tenant.auth0.com/.well-known/jwks.json")
    jwks = resp.json()
    kids = [key["kid"] for key in jwks["keys"]]
    print(f"Available kids: {kids}")
```

---

#### Issue: Token expired

**Error Message**: `Token has expired`

**Cause**: Token's `exp` (expiration) claim is in the past.

**Solutions**:
1. Client needs to request a new token from Auth0
2. Check token lifetime in Auth0 Dashboard → APIs → Token Settings
3. Implement token refresh logic in your client app

```python
# Debug: Check when token expires
import jwt
from datetime import datetime

payload = jwt.decode(token, options={"verify_signature": False})
exp_timestamp = payload['exp']
exp_datetime = datetime.fromtimestamp(exp_timestamp)
now = datetime.utcnow()

print(f"Token expired at: {exp_datetime}")
print(f"Current time: {now}")
print(f"Expired: {now > exp_datetime}")
```

---

#### Issue: "DPoP Proof htu mismatch"

**Error Message**: `DPoP proof htu 'https://api.example.com/resource?page=1' doesn't match request URL 'https://api.example.com/resource'`

**Cause**: The `htu` claim in DPoP proof includes query parameters or doesn't match the request URL.

**Solutions**:
1. URLs are normalized (no query params, no fragments)
2. Client must generate proof with normalized URL
3. Scheme, host, port must match exactly

```python
# ❌ WRONG - DPoP proof includes query params
# Client generates proof with: https://api.example.com/resource?page=1
# But request URL normalizes to: https://api.example.com/resource

# ✅ CORRECT - Client should normalize URL before generating proof
from auth0_api_python.utils import normalize_url_for_htu

full_url = "https://api.example.com/resource?page=1&filter=active#section"
normalized_url = normalize_url_for_htu(full_url)
print(normalized_url)  # https://api.example.com/resource

# Client generates proof with normalized URL
```

---

#### Issue: "Missing DPoP header"

**Cause**: Client sent `Authorization: DPoP ...` but forgot the `DPoP:` header with the proof.

**Solution**: Client must send BOTH headers for DPoP:

```python
# ❌ WRONG - missing DPoP header
headers = {
    "Authorization": "DPoP eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."
}

# ✅ CORRECT - includes both headers
headers = {
    "Authorization": "DPoP eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",  # Access token
    "DPoP": "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2In0..."  # DPoP proof
}
```

---

#### Issue: 401 error but WWW-Authenticate header missing

**Cause**: Error wasn't prepared with `_prepare_error()` before raising.

**Solution**: Always let the SDK handle errors - don't catch and re-raise without headers:

```python
# ❌ WRONG - loses WWW-Authenticate headers
try:
    claims = await api_client.verify_request(headers)
except BaseAuthError:
    raise HTTPException(401, "Unauthorized")  # Missing headers!

# ✅ CORRECT - preserve error metadata
try:
    claims = await api_client.verify_request(headers)
except BaseAuthError as e:
    raise HTTPException(
        status_code=e.get_status_code(),
        headers=e.get_headers(),  # Includes WWW-Authenticate
        detail=str(e)
    )
```

---

### 8.2 Debugging Techniques

#### Enable Verbose Logging

```python
import logging

# Enable httpx debug logging to see SDK HTTP requests
logging.basicConfig(level=logging.DEBUG)
httpx_logger = logging.getLogger("httpx")
httpx_logger.setLevel(logging.DEBUG)

# Now you'll see:
# - OIDC discovery requests
# - JWKS fetching
# - HTTP status codes
# - Response bodies
```

#### Inspect Token Without Verification

```python
import jwt

# Decode token to see claims (DON'T use for production auth!)
payload = jwt.decode(access_token, options={"verify_signature": False})

print("Token claims:")
print(f"  Issuer: {payload.get('iss')}")
print(f"  Subject: {payload.get('sub')}")
print(f"  Audience: {payload.get('aud')}")
print(f"  Expiration: {payload.get('exp')}")
print(f"  Scope: {payload.get('scope')}")
print(f"  DPoP bound: {'cnf' in payload}")
```

#### Test Auth0 Configuration

```python
import httpx

async def test_auth0_config(domain: str):
    """Verify Auth0 tenant configuration"""
    
    # Test OIDC discovery
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"https://{domain}/.well-known/openid-configuration")
            resp.raise_for_status()
            metadata = resp.json()
            print(f"✅ OIDC discovery works")
            print(f"   Issuer: {metadata['issuer']}")
            print(f"   JWKS URI: {metadata['jwks_uri']}")
            
            # Test JWKS
            jwks_resp = await client.get(metadata["jwks_uri"])
            jwks_resp.raise_for_status()
            jwks = jwks_resp.json()
            print(f"✅ JWKS accessible")
            print(f"   Keys available: {len(jwks['keys'])}")
            
        except Exception as e:
            print(f"❌ Configuration error: {e}")

# Run test
import asyncio
asyncio.run(test_auth0_config("your-tenant.auth0.com"))
```

---

## 9. Configuration Reference

### 9.1 ApiClientOptions - Complete Reference

```python
from auth0_api_python import ApiClient, ApiClientOptions

api_client = ApiClient(ApiClientOptions(
    # ============ REQUIRED ============
    domain="your-tenant.auth0.com",        # Auth0 tenant domain (NO protocol)
    audience="https://api.example.com",    # API identifier from Auth0 dashboard
    
    # ============ OPTIONAL ============
    
    # DPoP Configuration
    dpop_enabled=True,                     # Enable DPoP support (default: True)
    dpop_required=False,                   # Require DPoP, reject Bearer (default: False)
    dpop_iat_leeway=30,                    # Clock skew tolerance in seconds (default: 30)
    dpop_iat_offset=300,                   # Max DPoP proof age in seconds (default: 300)
    
    # Token Exchange (requires Early Access)
    client_id="your-client-id",            # For token exchange methods
    client_secret="your-client-secret",    # For token exchange methods
    
    # HTTP Configuration
    timeout=10.0,                          # HTTP timeout for Auth0 API calls (default: 10.0)
    custom_fetch=None,                     # Custom HTTP client function (advanced)
))
```

### 9.2 Configuration Recommendations by Use Case

#### Standard OAuth 2.0 API (Bearer only)
```python
ApiClientOptions(
    domain="tenant.auth0.com",
    audience="https://api.example.com",
    dpop_enabled=False  # Disable DPoP
)
```

#### Modern API (DPoP recommended, Bearer allowed)
```python
ApiClientOptions(
    domain="tenant.auth0.com",
    audience="https://api.example.com",
    dpop_enabled=True,   # Enable DPoP (default)
    dpop_required=False  # Allow both (default)
)
```

#### High-security API (DPoP only)
```python
ApiClientOptions(
    domain="tenant.auth0.com",
    audience="https://api.example.com",
    dpop_required=True  # Reject Bearer tokens
)
```

#### Multi-tenant SaaS
```python
# Create separate instances per tenant
tenants = {
    "acme": ApiClient(ApiClientOptions(
        domain="acme.auth0.com",
        audience="https://api.acme.com"
    )),
    "widget": ApiClient(ApiClientOptions(
        domain="widget.auth0.com",
        audience="https://api.widget.com"
    ))
}
```

#### Microservices with Token Exchange
```python
ApiClientOptions(
    domain="tenant.auth0.com",
    audience="https://internal-service.com",
    client_id="service-m2m-client",
    client_secret="secret",
    timeout=5.0  # Shorter timeout for internal calls
)
```

---

## 10. Best Practices for Customer Integration

### 10.1 Security Best Practices

#### ✅ Always Use HTTPS in Production
```python
# ❌ WRONG - HTTP is insecure
http_url = "http://api.example.com/resource"

# ✅ CORRECT - Always HTTPS
http_url = "https://api.example.com/resource"
```

#### ✅ Don't Log Tokens
```python
# ❌ WRONG - logs sensitive token
logger.info(f"Received token: {access_token}")

# ✅ CORRECT - log token metadata only
logger.info(f"Received token for user: {claims['sub']}")
```

#### ✅ Validate Token on Every Request
```python
# ❌ WRONG - caching tokens without expiration check
cached_claims = cache.get(token)
if cached_claims:
    return cached_claims  # Might be expired!

# ✅ CORRECT - verify expiration even when cached
cached_claims = cache.get(token)
if cached_claims and cached_claims['exp'] > time.time():
    return cached_claims
```

#### ✅ Use Least-Privilege Scopes
```python
# ✅ Check for specific scopes, not broad permissions
def require_scope(required_scope: str):
    async def checker(claims: dict = Depends(require_auth)):
        if required_scope not in claims.get("scope", "").split():
            raise HTTPException(403, f"Missing scope: {required_scope}")
        return claims
    return checker

# Use specific scopes
@app.get("/api/users")
async def get_users(claims: dict = Depends(require_scope("read:users"))):
    pass

@app.post("/api/users")
async def create_user(claims: dict = Depends(require_scope("write:users"))):
    pass
```

### 10.2 Performance Best Practices

#### ✅ Reuse ApiClient Instance
```python
# ❌ WRONG - creates new client on every request
async def verify_token(request: Request):
    api_client = ApiClient(ApiClientOptions(...))  # DON'T DO THIS
    return await api_client.verify_request(...)

# ✅ CORRECT - create once, reuse
api_client = ApiClient(ApiClientOptions(...))  # Module level

async def verify_token(request: Request):
    return await api_client.verify_request(...)
```

#### ✅ Cache OIDC Metadata (SDK does this automatically)
```python
# SDK automatically caches OIDC metadata and JWKS
# First request fetches metadata
claims1 = await api_client.verify_access_token(token1)

# Subsequent requests use cached metadata
claims2 = await api_client.verify_access_token(token2)  # No fetch!
```

#### ✅ Consider Token Caching for High-Traffic APIs
```python
# For very high-traffic APIs, cache verified tokens
import aiocache

cache = aiocache.Cache()

async def verify_with_cache(token: str):
    # Check cache first
    claims = await cache.get(f"token:{token}")
    if claims:
        return claims
    
    # Not cached - verify
    claims = await api_client.verify_access_token(token)
    
    # Cache for 5 minutes (or token exp - now, whichever is shorter)
    ttl = min(300, claims['exp'] - int(time.time()))
    await cache.set(f"token:{token}", claims, ttl=ttl)
    
    return claims
```

### 10.3 Error Handling Best Practices

#### ✅ Return Proper HTTP Status Codes
```python
from auth0_api_python.errors import BaseAuthError

try:
    claims = await api_client.verify_request(headers)
except BaseAuthError as e:
    # Use the error's status code, don't hardcode 401
    raise HTTPException(
        status_code=e.get_status_code(),  # Could be 400, 401, etc.
        headers=e.get_headers(),
        detail=str(e)
    )
```

#### ✅ Include WWW-Authenticate Headers
```python
# ❌ WRONG - missing WWW-Authenticate
raise HTTPException(401, "Unauthorized")

# ✅ CORRECT - includes proper headers
try:
    claims = await api_client.verify_request(headers)
except BaseAuthError as e:
    raise HTTPException(
        status_code=e.get_status_code(),
        headers=e.get_headers(),  # Includes WWW-Authenticate
        detail=str(e)
    )
```

#### ✅ Log Auth Failures for Security Monitoring
```python
import logging

logger = logging.getLogger(__name__)

try:
    claims = await api_client.verify_request(headers)
except BaseAuthError as e:
    # Log for security monitoring
    logger.warning(
        "Authentication failed",
        extra={
            "error_code": e.get_error_code(),
            "error": str(e),
            "ip": request.client.host,
            "path": request.url.path
        }
    )
    raise HTTPException(...)
```

### 10.4 Testing Best Practices

#### ✅ Test All Auth Scenarios
```python
# Test matrix
scenarios = [
    ("no_token", None, 401),
    ("invalid_token", "invalid", 401),
    ("expired_token", expired_token, 401),
    ("wrong_audience", wrong_aud_token, 401),
    ("valid_token", valid_token, 200),
]

@pytest.mark.parametrize("name,token,expected_status", scenarios)
async def test_auth_scenarios(name, token, expected_status):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    response = await client.get("/api/users", headers=headers)
    assert response.status_code == expected_status
```

#### ✅ Use Test Auth0 Tenant
```python
# ✅ Separate test tenant for integration tests
TEST_AUTH0_DOMAIN = "test-tenant.auth0.com"
PROD_AUTH0_DOMAIN = "prod-tenant.auth0.com"

# In tests
api_client = ApiClient(ApiClientOptions(
    domain=TEST_AUTH0_DOMAIN,  # Use test tenant
    audience="https://test-api.example.com"
))
```

#### ✅ Mock SDK for Unit Tests
```python
from unittest.mock import patch, AsyncMock

@patch('auth0_api_python.ApiClient.verify_request')
async def test_business_logic_only(mock_verify):
    """Test business logic without calling Auth0"""
    mock_verify.return_value = {"sub": "user123", "scope": "read:users"}
    
    # Test your business logic
    response = await client.get("/api/users", headers={"Authorization": "Bearer fake"})
    assert response.status_code == 200
```

---

## 11. Quick Reference

### 11.1 SDK Methods for Customers

| Method | Purpose | When to Use |
|--------|---------|-------------|
| `verify_request()` | Verify any request (auto-detects Bearer/DPoP) | **Recommended** - Use for all protected endpoints |
| `verify_access_token()` | Verify Bearer token only | When you only handle Bearer, or parsing headers yourself |
| `verify_dpop_proof()` | Verify DPoP proof separately | Advanced use cases, custom flows |
| `get_access_token_for_connection()` | Exchange for upstream IdP token | Token vault, getting user's Google/Facebook token |
| `get_token_by_exchange_profile()` | Custom token exchange (RFC 8693) | Migrating users, external IdP integration |

### 11.2 Error Classes Customers Will Encounter

| Error | Status | Meaning | Customer Action |
|-------|--------|---------|-----------------|
| `VerifyAccessTokenError` | 401 | Invalid/expired token | Get new token from Auth0 |
| `InvalidDpopProofError` | 400 | Invalid DPoP proof | Generate new proof |
| `InvalidAuthSchemeError` | 400 | Wrong scheme used | Check API requirements (Bearer vs DPoP) |
| `MissingAuthorizationError` | 400 | No Authorization header | Include Authorization header |
| `ApiError` | varies | Network/Auth0 error | Retry, check Auth0 status |

### 11.3 Common Token Claims

| Claim | Type | Description | Customer Usage |
|-------|------|-------------|----------------|
| `sub` | string | User ID | Identify the user making the request |
| `aud` | string/array | Audience | Must match your API identifier |
| `iss` | string | Issuer | Must be your Auth0 tenant |
| `exp` | number | Expiration | Unix timestamp when token expires |
| `iat` | number | Issued at | Unix timestamp when token was issued |
| `scope` | string | Scopes | Space-separated permissions (e.g., "read:users write:users") |
| `azp` | string | Authorized party | Client ID that requested the token |

---

## 12. AI Agent Checklist for Customer Integrations

When helping a customer integrate this SDK, verify:

### ✅ Configuration Checklist
- [ ] Correct Auth0 domain (no protocol prefix)
- [ ] Correct audience (API identifier from Auth0 Dashboard)
- [ ] DPoP configuration matches API requirements
- [ ] Client credentials configured if using token exchange

### ✅ Code Integration Checklist
- [ ] SDK client instance created once (module level)
- [ ] Auth verification added to protected routes
- [ ] Error handling includes status codes AND headers
- [ ] Public endpoints don't have auth checks
- [ ] Scope validation implemented where needed

### ✅ Testing Checklist
- [ ] Test: Endpoint rejects requests without tokens
- [ ] Test: Endpoint rejects invalid tokens
- [ ] Test: Endpoint accepts valid tokens
- [ ] Test: Scope checks work correctly
- [ ] Test: Error responses include proper headers

### ✅ Security Checklist
- [ ] HTTPS used in production
- [ ] Tokens not logged
- [ ] WWW-Authenticate headers included in auth errors
- [ ] Least-privilege scopes used
- [ ] Auth failures logged for security monitoring

### ✅ Documentation Checklist
- [ ] Document how to obtain tokens
- [ ] Document required scopes for each endpoint
- [ ] Provide example requests with curl/Postman
- [ ] Document error responses

---

## 13. Client-Side DPoP Proof Generation (CRITICAL - MISSING FROM EARLIER SECTIONS)

### 13.1 Overview: What's Missing From This Guide

**IMPORTANT**: The previous sections explained how to **verify** DPoP proofs on the backend using `auth0-api-python`, but they did NOT explain how clients **create/generate** DPoP proofs. This is a **prerequisite** for end-to-end DPoP implementation.

This section fills that gap.

### 13.2 DPoP Proof Requirements (RFC 9449)

A DPoP proof is a JWT that the client must create for each API request. It proves the client possesses a private key.

**DPoP Proof Structure:**

```json
{
  "typ": "dpop+jwt",     // REQUIRED: Must be "dpop+jwt"
  "alg": "ES256",        // REQUIRED: Signing algorithm (ES256, RS256, etc.)
  "jwk": {               // REQUIRED: Public key in JWK format
    "kty": "EC",
    "crv": "P-256",
    "x": "...",
    "y": "..."
  }
}
.
{
  "jti": "unique-id",              // REQUIRED: Unique identifier for this proof
  "htm": "GET",                    // REQUIRED: HTTP method (GET, POST, etc.)
  "htu": "https://api.example.com/resource",  // REQUIRED: Target URL (no query params, no fragment)
  "iat": 1234567890,               // REQUIRED: Unix timestamp when proof was created
  "ath": "hash-of-token"           // OPTIONAL: Hash of access token (for token binding)
}
```

**Key Points:**
- Each request needs a **new DPoP proof** with unique `jti` and fresh `iat`
- The `htu` must match the request URL (normalized: no query params, no fragment)
- The `htm` must match the HTTP method
- The proof is signed with a **private key**, and the **public key** is included in the `jwk` header
- The same key pair can be reused across requests

### 13.3 Client-Side Implementation (JavaScript/TypeScript)

#### Option A: Using Web Crypto API (Modern Browsers)

**Best for:** React, Vue, Angular, vanilla JS web apps

```typescript
// dpop-utils.ts - DPoP proof generation utility for browsers

/**
 * Generate or retrieve a persistent DPoP key pair
 * Store in sessionStorage for the session duration
 */
async function getDpopKeyPair(): Promise<CryptoKeyPair> {
  // Check if we have a stored key
  const storedPrivateKey = sessionStorage.getItem('dpop_private_key');
  const storedPublicKey = sessionStorage.getItem('dpop_public_key');
  
  if (storedPrivateKey && storedPublicKey) {
    // Import stored keys
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      JSON.parse(storedPrivateKey),
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign']
    );
    
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      JSON.parse(storedPublicKey),
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      []
    );
    
    return { privateKey, publicKey };
  }
  
  // Generate new key pair
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256', // Use P-256 curve for ES256
    },
    true, // extractable
    ['sign', 'verify']
  );
  
  // Export and store keys
  const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  
  sessionStorage.setItem('dpop_private_key', JSON.stringify(privateJwk));
  sessionStorage.setItem('dpop_public_key', JSON.stringify(publicJwk));
  
  return keyPair;
}

/**
 * Generate a unique JTI (JWT ID) for the DPoP proof
 */
function generateJti(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Base64URL encode (without padding)
 */
function base64UrlEncode(data: ArrayBuffer | string): string {
  const base64 = typeof data === 'string' 
    ? btoa(data)
    : btoa(String.fromCharCode(...new Uint8Array(data)));
  
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Normalize URL for htu claim (remove query params and fragment)
 */
function normalizeUrlForHtu(url: string): string {
  const urlObj = new URL(url);
  return `${urlObj.protocol}//${urlObj.host}${urlObj.pathname}`;
}

/**
 * Create a DPoP proof JWT
 * 
 * @param httpMethod - HTTP method (GET, POST, etc.)
 * @param httpUrl - Full URL of the request
 * @param accessToken - Optional access token to bind the proof to
 * @returns DPoP proof JWT string
 */
export async function createDpopProof(
  httpMethod: string,
  httpUrl: string,
  accessToken?: string
): Promise<string> {
  const keyPair = await getDpopKeyPair();
  
  // Export public key as JWK for the header
  const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  
  // Remove private key material from JWK
  const { d, ...publicJwkWithoutPrivate } = publicJwk as any;
  
  // Create JWT header
  const header = {
    typ: 'dpop+jwt',
    alg: 'ES256',
    jwk: publicJwkWithoutPrivate
  };
  
  // Create JWT payload
  const payload: any = {
    jti: generateJti(),
    htm: httpMethod.toUpperCase(),
    htu: normalizeUrlForHtu(httpUrl),
    iat: Math.floor(Date.now() / 1000)
  };
  
  // Optional: Add token hash for token binding
  if (accessToken) {
    const encoder = new TextEncoder();
    const tokenData = encoder.encode(accessToken);
    const hashBuffer = await crypto.subtle.digest('SHA-256', tokenData);
    payload.ath = base64UrlEncode(hashBuffer);
  }
  
  // Encode header and payload
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  
  // Create signature
  const dataToSign = `${encodedHeader}.${encodedPayload}`;
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(dataToSign);
  
  const signatureBuffer = await crypto.subtle.sign(
    {
      name: 'ECDSA',
      hash: { name: 'SHA-256' }
    },
    keyPair.privateKey,
    dataBuffer
  );
  
  const encodedSignature = base64UrlEncode(signatureBuffer);
  
  // Return complete JWT
  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
}

/**
 * Make a DPoP-protected API request
 * 
 * @param url - API endpoint URL
 * @param options - Fetch options
 * @param accessToken - Auth0 access token
 * @returns Fetch response
 */
export async function fetchWithDpop(
  url: string,
  options: RequestInit,
  accessToken: string
): Promise<Response> {
  const method = options.method || 'GET';
  
  // Generate DPoP proof
  const dpopProof = await createDpopProof(method, url, accessToken);
  
  // Make request with both headers
  return fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      'Authorization': `DPoP ${accessToken}`,  // Note: DPoP scheme, not Bearer
      'DPoP': dpopProof                         // DPoP proof header
    }
  });
}
```

#### Usage in React App:

```typescript
// App.tsx
import { useAuth0 } from '@auth0/auth0-react';
import { fetchWithDpop } from './dpop-utils';

function App() {
  const { getAccessTokenSilently } = useAuth0();
  
  const callProtectedAPI = async () => {
    try {
      // Get access token from Auth0
      const token = await getAccessTokenSilently();
      
      // Make DPoP-protected request
      const response = await fetchWithDpop(
        'https://api.example.com/api/users',
        { method: 'GET' },
        token
      );
      
      if (!response.ok) {
        throw new Error(`API Error: ${response.status}`);
      }
      
      const data = await response.json();
      console.log('API response:', data);
      
    } catch (err) {
      console.error('API call failed:', err);
    }
  };
  
  return (
    <button onClick={callProtectedAPI}>
      Call DPoP-Protected API
    </button>
  );
}
```

### 13.4 Client-Side Implementation (Node.js/Backend)

**Best for:** Node.js services calling downstream APIs with DPoP

```typescript
// dpop-utils-node.ts - DPoP for Node.js using jose library

import * as jose from 'jose';
import crypto from 'crypto';

let dpopKeyPair: { privateKey: jose.KeyLike; publicKey: jose.KeyLike } | null = null;

/**
 * Get or generate DPoP key pair for Node.js
 */
async function getDpopKeyPair() {
  if (dpopKeyPair) {
    return dpopKeyPair;
  }
  
  // Generate ES256 key pair
  const { publicKey, privateKey } = await jose.generateKeyPair('ES256');
  dpopKeyPair = { publicKey, privateKey };
  
  return dpopKeyPair;
}

/**
 * Create DPoP proof using jose library
 */
export async function createDpopProof(
  httpMethod: string,
  httpUrl: string,
  accessToken?: string
): Promise<string> {
  const { privateKey, publicKey } = await getDpopKeyPair();
  
  // Export public key as JWK
  const publicJwk = await jose.exportJWK(publicKey);
  
  // Normalize URL
  const urlObj = new URL(httpUrl);
  const htu = `${urlObj.protocol}//${urlObj.host}${urlObj.pathname}`;
  
  // Create payload
  const payload: any = {
    jti: crypto.randomBytes(16).toString('hex'),
    htm: httpMethod.toUpperCase(),
    htu,
    iat: Math.floor(Date.now() / 1000)
  };
  
  // Add token hash if provided
  if (accessToken) {
    const hash = crypto.createHash('sha256').update(accessToken).digest();
    payload.ath = jose.base64url.encode(hash);
  }
  
  // Create and sign JWT
  const dpopProof = await new jose.SignJWT(payload)
    .setProtectedHeader({
      typ: 'dpop+jwt',
      alg: 'ES256',
      jwk: publicJwk
    })
    .sign(privateKey);
  
  return dpopProof;
}

/**
 * Make DPoP-protected request with axios or fetch
 */
export async function fetchWithDpop(
  url: string,
  method: string,
  accessToken: string,
  body?: any
): Promise<any> {
  const dpopProof = await createDpopProof(method, url, accessToken);
  
  const response = await fetch(url, {
    method,
    headers: {
      'Authorization': `DPoP ${accessToken}`,
      'DPoP': dpopProof,
      'Content-Type': 'application/json'
    },
    body: body ? JSON.stringify(body) : undefined
  });
  
  return response.json();
}
```

**Installation for Node.js:**
```bash
npm install jose
```

### 13.5 Common Client-Side DPoP Issues

#### Issue: "DPoP proof expired"
**Cause**: The `iat` claim is too old  
**Solution**: Generate a new proof for each request (don't reuse proofs)

```typescript
// ❌ WRONG - Reusing proof across requests
const proof = await createDpopProof('GET', url, token);
await fetch(url1, { headers: { 'DPoP': proof } });  // OK
await fetch(url2, { headers: { 'DPoP': proof } });  // WRONG - stale iat

// ✅ CORRECT - Generate new proof per request
const proof1 = await createDpopProof('GET', url1, token);
await fetch(url1, { headers: { 'DPoP': proof1 } });

const proof2 = await createDpopProof('GET', url2, token);
await fetch(url2, { headers: { 'DPoP': proof2 } });
```

#### Issue: "DPoP proof htu doesn't match request URL"
**Cause**: Query parameters or fragments in `htu` claim  
**Solution**: Normalize the URL (remove query params and fragments)

```typescript
// ❌ WRONG - Including query params in htu
createDpopProof('GET', 'https://api.example.com/users?page=1', token);

// ✅ CORRECT - Normalized URL for htu
const fullUrl = 'https://api.example.com/users?page=1';
const normalizedUrl = normalizeUrlForHtu(fullUrl);  // https://api.example.com/users
createDpopProof('GET', normalizedUrl, token);

// But still send the request to the full URL
fetch('https://api.example.com/users?page=1', { ... });
```

#### Issue: "Invalid DPoP proof signature"
**Cause**: Using wrong key, wrong algorithm, or corrupted key  
**Solution**: Ensure ES256 algorithm and valid key pair

```typescript
// ✅ Verify your key generation
const keyPair = await crypto.subtle.generateKey(
  {
    name: 'ECDSA',
    namedCurve: 'P-256'  // Must be P-256 for ES256
  },
  true,
  ['sign', 'verify']
);
```

#### Issue: "Missing Authorization header with DPoP scheme"
**Cause**: Using Bearer scheme instead of DPoP  
**Solution**: Use `Authorization: DPoP <token>`, not `Bearer`

```typescript
// ❌ WRONG - Bearer scheme with DPoP proof
headers: {
  'Authorization': `Bearer ${token}`,  // Should be DPoP!
  'DPoP': dpopProof
}

// ✅ CORRECT - DPoP scheme
headers: {
  'Authorization': `DPoP ${token}`,   // DPoP scheme
  'DPoP': dpopProof
}
```

### 13.6 DPoP Key Management Best Practices

#### For Web Apps (Browser)
```typescript
// ✅ Store key in sessionStorage (cleared when browser closes)
sessionStorage.setItem('dpop_private_key', JSON.stringify(privateJwk));

// ❌ Don't use localStorage (persists across sessions, security risk)
localStorage.setItem('dpop_private_key', ...);  // DON'T DO THIS
```

#### For Mobile Apps
```typescript
// ✅ Use secure storage
// iOS: Keychain
// Android: KeyStore
// React Native: react-native-keychain

// ❌ Don't store in AsyncStorage (not encrypted)
```

#### For Node.js Services
```typescript
// ✅ Keep key in memory (regenerate on restart)
let dpopKeyPair: CryptoKeyPair | null = null;

// ✅ Or store encrypted in database/secrets manager for persistence
// ❌ Don't hardcode keys in source code
```

### 13.7 Complete End-to-End DPoP Flow

```typescript
// 1. User logs in via Auth0 (gets access token)
const token = await getAccessTokenSilently();

// 2. Client generates DPoP key pair (once per session)
const keyPair = await getDpopKeyPair();

// 3. For each API request, client creates DPoP proof
const dpopProof = await createDpopProof('GET', apiUrl, token);

// 4. Client sends request with two headers
const response = await fetch(apiUrl, {
  headers: {
    'Authorization': `DPoP ${token}`,      // Access token with DPoP scheme
    'DPoP': dpopProof                      // Fresh DPoP proof
  }
});

// 5. Backend verifies both token and proof
// (handled by auth0-api-python SDK automatically)
claims = await api_client.verify_request(
  headers=dict(request.headers),
  http_method=request.method,
  http_url=str(request.url)
);

// 6. Backend returns data if both are valid
return {"data": "...", "user": claims["sub"]};
```

### 13.8 AI Agent Implementation Checklist for DPoP

When implementing DPoP for a customer:

#### ✅ Backend Checklist
- [ ] Enable DPoP in ApiClient: `dpop_enabled=True`
- [ ] Decide if DPoP is required or optional: `dpop_required=True/False`
- [ ] Use `verify_request()` (auto-detects Bearer vs DPoP)
- [ ] Include DPoP header in CORS: `allow_headers=["Authorization", "DPoP"]`

#### ✅ Frontend Checklist  
- [ ] Create DPoP key pair (once per session)
- [ ] Store key securely (sessionStorage for web, Keychain for mobile)
- [ ] Generate fresh DPoP proof for each request
- [ ] Use `Authorization: DPoP <token>` (not Bearer)
- [ ] Include both `Authorization` and `DPoP` headers
- [ ] Normalize URLs for `htu` claim (no query params)
- [ ] Match `htm` claim to HTTP method

#### ✅ Testing Checklist
- [ ] Test Bearer tokens still work (if dpop_required=False)
- [ ] Test DPoP tokens work
- [ ] Test DPoP proof with wrong URL fails
- [ ] Test DPoP proof with wrong method fails
- [ ] Test expired DPoP proof fails
- [ ] Test reused DPoP proof fails (if iat too old)

---

## 14. Resources for Customers

- **Auth0 Documentation**: https://auth0.com/docs
- **SDK GitHub**: https://github.com/auth0/auth0-api-python
- **RFC 7519 (JWT)**: https://datatracker.ietf.org/doc/html/rfc7519
- **RFC 9449 (DPoP)**: https://datatracker.ietf.org/doc/html/rfc9449
- **RFC 8693 (Token Exchange)**: https://datatracker.ietf.org/doc/html/rfc8693
- **FastAPI Security**: https://fastapi.tiangolo.com/tutorial/security/
- **Testing with pytest**: https://docs.pytest.org/

---

**END OF FILE**
