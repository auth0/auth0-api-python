import contextlib
import logging
import os
from collections.abc import AsyncIterator

from dotenv import load_dotenv
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.routing import Mount

from .auth0 import Auth0Mcp
from .tools import register_tools

load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

auth0_mcp = Auth0Mcp(
    name="Example FastMCP Server",
    audience=os.getenv("AUTH0_AUDIENCE"),
    domain=os.getenv("AUTH0_DOMAIN")
)
register_tools(auth0_mcp)

@contextlib.asynccontextmanager
async def lifespan(app: Starlette) -> AsyncIterator[None]:
    async with contextlib.AsyncExitStack() as stack:
        await stack.enter_async_context(auth0_mcp.mcp.session_manager.run())
        yield

starlette_app = Starlette(
    debug=os.getenv("DEBUG", "true").lower() == "true",
    routes=[
        # Add discovery metadata route
        *auth0_mcp.auth_metadata_router().routes,

        # Main MCP app route with authentication middleware
        Mount(
            "/",
            app=auth0_mcp.mcp.streamable_http_app(),
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
