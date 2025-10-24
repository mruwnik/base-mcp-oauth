"""Example MCP server with OAuth authentication over HTTP."""

import asyncio
import logging
import time

from mcp_base import Database
from mcp_base.factory import create_oauth_server

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Background task for cleanup
async def periodic_cleanup(db: Database):
    """Periodically clean up expired tokens."""
    while True:
        await asyncio.sleep(3600)  # Run every hour
        try:
            db.cleanup_expired()
            logger.info("Cleaned up expired tokens")
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")


def check_user(username: str, password: str) -> int | None:
    """Check if the user is valid."""
    with open("users.txt") as f:
        for i, line in enumerate(f.readlines()):
            if line.strip() == f"{username}:{password}":
                return i + 1
    return None


def main():
    """Run the MCP server over HTTP."""
    server = create_oauth_server("mcp-server", check_user)

    # Define example tools
    @server.tool()
    def echo(message: str) -> str:
        """Echo back the input message."""
        return f"Echo: {message}"

    @server.tool()
    def get_time() -> str:
        """Get the current server time."""
        return f"Current time: {time.strftime('%Y-%m-%d %H:%M:%S')}"

    # Run the HTTP server
    server.run(transport="streamable-http")


if __name__ == "__main__":
    main()
