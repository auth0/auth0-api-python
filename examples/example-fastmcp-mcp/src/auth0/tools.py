"""
Scope-based auth decorators for MCP tools.

Provides a decorator with Auth0 scope checking for MCP tools.
"""
import asyncio
from functools import wraps
from typing import Callable

from mcp.server.fastmcp import Context


def create_scoped_tool_decorator(mcp_server):
    """Factory function to create a scoped_tool decorator bound to a MCP server instance."""

    def scoped_tool(
        required_scopes: list[str],
        **tool_kwargs
    ):
        """
        Decorator that combines FastMCP tool registration with Auth0 scope checking.

        Args:
            required_scopes: List of scopes required to use this tool
            **tool_kwargs: Additional parameters passed to @mcp.tool()

        Example:
            @scoped_tool(required_scopes=["read:data", "write:data"])
            def sensitive_tool(data: str, ctx: Context) -> str:
                return f"Processing: {data}"
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            async def scope_checked_wrapper(*args, **kwargs):
                # Find the Context parameter in kwargs
                ctx = None
                for value in kwargs.values():
                    if isinstance(value, Context):
                        ctx = value
                        break

                if not ctx:
                    raise Exception(f"Tool '{func.__name__}' requires a Context parameter for scope checking")

                # Get auth info and check scopes
                try:
                    request = ctx.request_context.request
                    auth_info = get_auth_info(request)

                    if not auth_info or auth_info == {}:
                        raise Exception("Authentication required to use this tool")

                    user_scopes = auth_info.get("scopes", [])
                    client_id = auth_info.get("client_id", "unknown")

                    # Check if user has all required scopes
                    missing_scopes = [scope for scope in required_scopes if scope not in user_scopes]
                    if missing_scopes:
                        await ctx.error(f"Access denied: missing required scopes {missing_scopes}")
                        raise Exception(
                            f"Missing required scopes for tool '{func.__name__}': {missing_scopes}."
                        )

                    # Log successful scope check
                    await ctx.info(f"Tool '{func.__name__}' authorized for client '{client_id}' with scopes: {user_scopes}")

                except Exception as e:
                    # Log other unexpected errors and wrap them
                    await ctx.error(f"Authorization check failed for tool '{func.__name__}': {str(e)}")
                    raise Exception(f"Authorization check failed: {str(e)}")

                # Call the original function
                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)

            # Register the wrapped function as an MCP tool
            mcp_server.add_tool(
                scope_checked_wrapper,
                **tool_kwargs
            )
            return scope_checked_wrapper

        return decorator

    return scoped_tool


def get_auth_info(request) -> dict:
    """Get authentication info from request."""
    return request.scope.get("auth", {})
