import logging

from auth0_api_python import ApiClient, ApiClientOptions
from auth0_api_python.errors import VerifyAccessTokenError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.types import ASGIApp

from .errors import AuthenticationRequired, MalformedAuthorizationRequest

logger = logging.getLogger(__name__)

class Auth0Middleware(BaseHTTPMiddleware):
    """
    Middleware that requires a valid Bearer token in the Authorization header.
    Validates the token using Auth0 SDK Client and stores auth info in request.state.auth.
    """

    def __init__(self, app: ASGIApp, domain: str, audience: str):
        super().__init__(app)
        if not domain or not audience:
            raise RuntimeError("domain and audience must be provided")
        self.client = ApiClient(ApiClientOptions(
            domain=domain,
            audience=audience
        ))

    async def dispatch(self, request: Request, call_next):
        # Extract Authorization header
        auth_header = request.headers.get("authorization")
        if not auth_header:
            raise AuthenticationRequired("Missing Authorization header")
        if not auth_header.lower().startswith("bearer "):
            raise MalformedAuthorizationRequest("Invalid Authorization header format")

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
            request.state.auth = auth_data

            return await call_next(request)
        except VerifyAccessTokenError as e:
            logger.error(f"Token verification failed: {str(e)}")
            raise AuthenticationRequired("Invalid token")
        except Exception as e:
            logger.error(f"Unexpected error in middleware: {str(e)}")
            # Re-raise unexpected errors to be handled by generic exception handler
            raise
