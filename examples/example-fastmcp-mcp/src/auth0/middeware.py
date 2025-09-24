import logging
import os
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

from auth0_api_python import ApiClient, ApiClientOptions
from auth0_api_python.errors import VerifyAccessTokenError

logger = logging.getLogger(__name__)

class Auth0Middleware(BaseHTTPMiddleware):
    """
    Middleware that requires a valid Bearer token in the Authorization header.
    This will validate the token using Auth0 SDK Client and add the auth info to request.scope["auth"].
    """

    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.client = ApiClient(ApiClientOptions(
            domain=os.getenv("AUTH0_DOMAIN", "your-tenant.auth0.com"),
            audience=os.getenv("AUTH0_AUDIENCE", "https://api.example.com")
        ))

    async def dispatch(self, request: Request, call_next):
        # Extract Authorization header
        auth_header = request.headers.get("authorization")
        if not auth_header:
            return self._return_auth_error_response(status_code=401, error="Authentication required", description="Missing Authorization header")
        if not auth_header.lower().startswith("bearer "):
            return self._return_auth_error_response(
                status_code=401,
                error="Authentication required",
                description="Invalid Authorization header format"
            )

        # Extract and verify token
        token = auth_header[7:] # Remove "Bearer " prefix
        try:
            decoded_and_verified_token = await self.client.verify_access_token(
                token,
                required_claims=["sub"]
            )

            # Check for client_id or azp
            clientId = decoded_and_verified_token.get('client_id') or decoded_and_verified_token.get('azp')
            if not clientId:
                raise VerifyAccessTokenError("Token is missing 'client_id' or 'azp' claim")

            # Set up authentication context
            auth_data = {
                "token": token,
                "client_id": clientId,
                "scopes": decoded_and_verified_token.get("scope", "").split() 
                         if decoded_and_verified_token.get("scope") else []
            }

            if decoded_and_verified_token.get('exp'):
                auth_data["expiresAt"] = decoded_and_verified_token.get('exp')

            extra = {"sub": decoded_and_verified_token.get('sub'), "client_id": clientId}

            for field in ['azp', 'name', 'email']:
                if decoded_and_verified_token.get(field):
                    extra[field] = decoded_and_verified_token.get(field)

            auth_data["extra"] = extra
            request.scope["auth"] = auth_data

            return await call_next(request)
        except VerifyAccessTokenError as e:
            logger.error(f"Token verification failed: {str(e)}")
            return self._return_auth_error_response(
                status_code=401,
                error="Authentication failed",
                description="Invalid token"
            )
        except Exception as e:
            logger.error(f"Unexpected error in middleware: {str(e)}")
            return self._return_auth_error_response(
                status_code=500,
                error="Internal Server Error",
                description="Internal Server Error"
            )

    def _return_auth_error_response(self, status_code: int, error: str, description: str) -> JSONResponse:
        www_auth_parts = [f'error="{error}"', f'error_description="{description}"', f'resource_metadata="{os.getenv("MCP_SERVER_URL")}"']
        www_authenticate = f"Bearer {', '.join(www_auth_parts)}"

        return JSONResponse(
            status_code=status_code,
            content={"error": error, "error_description": description},
            headers={"WWW-Authenticate": www_authenticate}
        )