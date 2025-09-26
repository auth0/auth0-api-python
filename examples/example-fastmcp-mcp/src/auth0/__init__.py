"""
Auth0 integration for MCP server.

This module provides Auth0 authentication and authorization for MCP servers,
including token verification, middleware, and scoped tool decorators.
"""

from mcp.server.auth.routes import create_protected_resource_routes
from starlette.middleware import Middleware
from starlette.routing import Route, Router

from .middleware import Auth0Middleware


class Auth0Mcp:
    def __init__(self, name: str, audience: str, domain: str):
        self.name = name
        self.audience = audience
        self.domain = domain
        if not self.audience or not self.domain:
            raise RuntimeError("audience and domain must be provided")

    def auth_metadata_router(self) -> Router:
        """
        Returns a router that serves the OAuth Protected Resource Metadata
        at the standard endpoint: /.well-known/oauth-protected-resource
        """
        routes: list[Route] = create_protected_resource_routes(
            resource_url=self.audience,
            authorization_servers=[f"https://{self.domain}"],
            scopes_supported=[
                "openid",
                "profile",
                "email",
            ],
            resource_name=self.name,
        )

        return Router(routes=routes)

    def auth_middleware(self) -> list[Middleware]:
        return [Middleware(Auth0Middleware, domain=self.domain, audience=self.audience)]
