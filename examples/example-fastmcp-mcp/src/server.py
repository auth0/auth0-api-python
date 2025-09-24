import os
import logging
import contextlib
from collections.abc import AsyncIterator

from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.middleware.cors import CORSMiddleware

from .auth0 import Auth0Mcp
from .mcp import mcp

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

auth0_mcp = Auth0Mcp(name="Example FastMCP Server")

@contextlib.asynccontextmanager
async def lifespan(app: Starlette) -> AsyncIterator[None]:
    async with contextlib.AsyncExitStack() as stack:
        await stack.enter_async_context(mcp.session_manager.run())

        # Import tools here to ensure tools are loaded after mcp is initialized
        from . import tools
        yield

starlette_app = Starlette(
    debug=True,
    routes=[
        # Add discovery metadata route
        *auth0_mcp.auth_metadata_router().routes,

        # Main MCP app route with authentication middleware
        Mount(
            "/",
            app=mcp.streamable_http_app(),
            middleware=auth0_mcp.auth_middleware()
        ),
    ],
    lifespan=lifespan,
)

# Wrap ASGI application with CORS middleware to expose Mcp-Session-Id header
# for browser-based clients (ensures 500 errors get proper CORS headers)
app = CORSMiddleware(
    starlette_app,
    allow_origins=["*"], # Adjust as needed for production
    allow_methods=["GET", "POST", "DELETE"], # MCP streamable HTTP methods
    expose_headers=["Mcp-Session-Id"],
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, port=int(os.getenv("PORT", "3001")))
