"""
Auth0 integration for MCP server.

This module provides Auth0 authentication and authorization for MCP servers,
including token verification, middleware, and scoped tool decorators.
"""

import os
from typing import List
from pydantic import AnyHttpUrl
from dotenv import load_dotenv
from mcp.server.auth.routes import create_protected_resource_routes
from starlette.routing import Router, Route
from starlette.middleware import Middleware
from .middeware import Auth0Middleware

# Load environment variables
load_dotenv()

class Auth0Mcp:
    def __init__(self, name: str):
        self.name = name
        self.audience = os.getenv("AUTH0_AUDIENCE", "https://api.example.com")
        self.domain = os.getenv("AUTH0_DOMAIN", "your-tenant.auth0.com")

    def auth_metadata_router(self) -> Router:
        """
        Returns a router that serves the OAuth Protected Resource Metadata
        at the standard endpoint: /.well-known/oauth-protected-resource
        """
        routes: List[Route] = []

        routes = create_protected_resource_routes(
            resource_url=AnyHttpUrl(self.audience),
            authorization_servers=[AnyHttpUrl(f"https://{self.domain}")],
            scopes_supported=[
                "openid",
                "profile",
                "email",
            ],
            resource_name=self.name,
        )

        return Router(routes=routes)
    
    def auth_middleware(self) -> list[Middleware]:
        middleware: list[Middleware] = []

        middleware.append(
            Middleware(
                Auth0Middleware
            )
        )

        return middleware