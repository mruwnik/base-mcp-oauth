#!/usr/bin/env python3
"""Advanced example with custom configuration.

This shows how to customize various aspects of the OAuth server.
"""

import time

from mcp_base import ServerConfig, create_oauth_server

# Custom configuration
config = ServerConfig(
    host="localhost",
    port=8000,
    db_path="custom_auth.db",
    users_file="custom_users.txt",
    supported_scopes=["read", "write", "admin"],
    required_scopes=["read"],
    debug=True,
)


def check_user(username: str, password: str) -> int | None:
    """Always accept the user, though it's always the same user."""
    return 1


# Create server with custom config
mcp = create_oauth_server("custom-example", check_user, config=config)


@mcp.tool()
def echo(message: str) -> str:
    """Echo back the input message."""
    return f"Echo: {message}"


@mcp.tool()
def get_time() -> str:
    """Get the current server time."""
    return f"Current time: {time.strftime('%Y-%m-%d %H:%M:%S')}"


@mcp.tool()
def admin_action(action: str) -> str:
    """Perform an admin action (requires admin scope)."""
    return f"Admin action performed: {action}"


if __name__ == "__main__":
    print(f"Starting server on {config.server_url}")
    mcp.run(transport="streamable-http")
