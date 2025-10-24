"""MCP OAuth Server - Minimal OAuth provider for MCP servers.

This library provides a simple way to add OAuth authentication to MCP servers.

Example:
    >>> from mcp_base import create_oauth_server
    >>>
    >>> def check_user(username: str, password: str) -> int | None:
    >>>     # Return the user id if the user is valid, otherwise return None
    >>>     return 1
    >>>
    >>> mcp = create_oauth_server("my-app", check_user)
    >>>
    >>> @mcp.tool()
    >>> def my_tool(arg: str) -> str:
    >>>     return f"Result: {arg}"
    >>>
    >>> mcp.run()
"""

__version__ = "0.1.0"

from mcp_base.config import ServerConfig
from mcp_base.database import Database
from mcp_base.factory import CompleteUserChecker, LoginHandler, create_oauth_server
from mcp_base.oauth_provider import PasswordOAuthProvider

__all__ = [
    "create_oauth_server",
    "ServerConfig",
    "PasswordOAuthProvider",
    "Database",
    "CompleteUserChecker",
    "LoginHandler",
]
