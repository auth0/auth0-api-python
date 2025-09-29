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
            raise MalformedAuthorizationRequest("Missing Authorization header")
        if not auth_header.lower().startswith("bearer "):
            raise MalformedAuthorizationRequest("Invalid Authorization header format")

        # Extract and verify token
        token = auth_header[7:].strip() # Remove "Bearer " prefix
        try:
            decoded_and_verified_token = await self.client.verify_access_token(
                token,
                required_claims=["sub"]
            )

            # Check for client_id or azp
            client_id = decoded_and_verified_token.get('client_id') or decoded_and_verified_token.get('azp')
            if not client_id:
                raise VerifyAccessTokenError("Token is missing 'client_id' or 'azp' claim")

            # Set up authentication context
            auth_data = {
                "client_id": client_id,
                "scopes": decoded_and_verified_token.get("scope", "").split()
                         if decoded_and_verified_token.get("scope") else []
            }

            if decoded_and_verified_token.get('exp'):
                auth_data["expires_at"] = decoded_and_verified_token.get('exp')

            extra = {"sub": decoded_and_verified_token.get('sub'), "client_id": client_id}

            for field in ['azp', 'name', 'email']:
                if decoded_and_verified_token.get(field):
                    extra[field] = decoded_and_verified_token.get(field)

            auth_data["extra"] = extra
            request.state.auth = auth_data

            return await call_next(request)
        except VerifyAccessTokenError:
            logger.info("Token verification failed")
            raise AuthenticationRequired("Invalid token")
        except Exception:
            logger.exception("Unexpected error in middleware")
            raise
