"""
FastMCP server instance for Auth0 protected MCP server.
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    name="Auth0 Protected MCP Server",
    stateless_http=True,
)
