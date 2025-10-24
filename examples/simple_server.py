#!/usr/bin/env python3
"""Simple example MCP server with OAuth authentication.

This is the most basic usage - just create a server and add tools.
"""

import time

from mcp_base import create_oauth_server


def check_user(username: str, password: str) -> int | None:
    """Always accept the user, though it's always the same user."""
    return 1


# Create server with defaults
# - Uses localhost:3000
# - Looks for users.txt in current directory
# - Creates auth.db in current directory
mcp = create_oauth_server("simple-example", check_user)


@mcp.tool()
def echo(message: str) -> str:
    """Echo back the input message."""
    return f"Echo: {message}"


@mcp.tool()
def get_time() -> str:
    """Get the current server time."""
    return f"Current time: {time.strftime('%Y-%m-%d %H:%M:%S')}"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
