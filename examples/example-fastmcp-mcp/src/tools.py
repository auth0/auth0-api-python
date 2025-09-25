from json import dumps as jsonDumps

from mcp.server.fastmcp import Context

from .auth0.tools import create_scoped_tool_decorator, get_auth_info
from .mcp import mcp

# Create a scoped_tool decorator bound to the mcp instance
scoped_tool = create_scoped_tool_decorator(mcp)

# Tool without required scopes
@mcp.tool()
def echo(text: str) -> str:
    """Echoes the input text"""
    return text

# A MCP tool with required scopes
@scoped_tool(
    required_scopes=["tool:greet"],
    name="greet",
    title="Greet Tool",
    description="Greets a user",
    annotations={"readOnlyHint": True}
)
def greet(name: str, ctx: Context) -> str:
    if not name or name.strip() == "":
        name = "world"
    request = ctx.request_context.request
    auth_info = get_auth_info(request)
    user_id = auth_info.get("extra", {}).get("sub")
    return f"Hello, {name}! You are authenticated as {user_id}"

# A MCP tool with required scopes
@scoped_tool(
    required_scopes=["tool:whoami"],
    name="whoami",
    title="Who Am I Tool",
    description="Returns information about the authenticated user",
    annotations={"readOnlyHint": True}
)
def whoami(ctx: Context) -> str:
    request = ctx.request_context.request
    auth_info = get_auth_info(request)

    response_data = {
        "user": auth_info.get("extra", {}),
        "scopes": auth_info.get("scopes", []),
    }
    return jsonDumps(response_data, indent=2)
