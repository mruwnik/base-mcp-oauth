"""Example MCP server with OAuth authentication over HTTP."""

import asyncio
import logging
import time
from typing import cast

from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp import FastMCP
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse

from mcp_base import settings
from mcp_base.oauth_provider import SUPPORTED_SCOPES, MinimalOAuthProvider

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize OAuth provider
oauth_provider = MinimalOAuthProvider()

# Configure auth settings
auth_settings = AuthSettings(
    issuer_url=cast(AnyHttpUrl, settings.SERVER_URL),
    resource_server_url=cast(AnyHttpUrl, settings.SERVER_URL),
    client_registration_options=ClientRegistrationOptions(
        enabled=True,
        valid_scopes=SUPPORTED_SCOPES,
        default_scopes=["read"],
    ),
    required_scopes=["read"],
)

# Create FastMCP server with HTTP transport
mcp = FastMCP(
    "example-oauth-server",
    auth_server_provider=oauth_provider,
    auth=auth_settings,
    host=settings.HOST,
    port=settings.PORT,
    debug=True,
)


# Define example tools
@mcp.tool()
def echo(message: str) -> str:
    """Echo back the input message."""
    return f"Echo: {message}"


@mcp.tool()
def get_time() -> str:
    """Get the current server time."""
    return f"Current time: {time.strftime('%Y-%m-%d %H:%M:%S')}"


# Root endpoint helper
@mcp.custom_route("/", methods=["GET", "POST"])
async def root_handler(request: Request):
    """Root endpoint - redirect to MCP endpoint."""
    from starlette.responses import JSONResponse

    return JSONResponse(
        {
            "message": "MCP Server",
            "mcp_endpoint": f"{settings.SERVER_URL}/mcp",
            "oauth_metadata": f"{settings.SERVER_URL}/.well-known/oauth-authorization-server",
        }
    )


# Protected Resource Metadata endpoint
# @mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
# async def oauth_protected_resource(request: Request):
#     """OAuth 2.0 Protected Resource Metadata."""
#     metadata = oauth_provider.get_protected_resource_metadata()
#     return JSONResponse(metadata)


# OAuth login routes
@mcp.custom_route("/oauth/login", methods=["GET"])
async def login_page(request: Request):
    """Display the login page."""
    params = dict(request.query_params)
    state = params.get("state", "")

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login</title>
        <style>
            body {{ font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }}
            input {{ width: 100%; padding: 8px; margin: 5px 0; box-sizing: border-box; }}
            button {{ width: 100%; padding: 10px; background: #007bff; color: white; border: none; cursor: pointer; }}
            button:hover {{ background: #0056b3; }}
        </style>
    </head>
    <body>
        <h1>Login</h1>
        <form method="post" action="/oauth/login">
            <input type="hidden" name="state" value="{state}">
            <div>
                <label>Username:</label>
                <input type="text" name="username" required autofocus>
            </div>
            <div>
                <label>Password:</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@mcp.custom_route("/oauth/login", methods=["POST"])
async def handle_login(request: Request):
    """Handle login form submission."""
    form = await request.form()
    state = form.get("state")
    username = form.get("username")
    password = form.get("password")

    try:
        redirect_url = oauth_provider.complete_authorization_sync(
            str(state), str(username), str(password)
        )
        return RedirectResponse(url=redirect_url, status_code=302)
    except ValueError as e:
        logger.error(f"Login failed: {e}")
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login Failed</title>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }}
                .error {{ color: red; padding: 10px; background: #ffeeee; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <h1>Login Failed</h1>
            <div class="error">{str(e)}</div>
            <p><a href="/oauth/login?state={state}">Try again</a></p>
        </body>
        </html>
        """
        return HTMLResponse(content=html_content, status_code=401)


# Background task for cleanup
async def periodic_cleanup():
    """Periodically clean up expired tokens."""
    while True:
        await asyncio.sleep(3600)  # Run every hour
        try:
            oauth_provider.cleanup_expired()
            logger.info("Cleaned up expired tokens")
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")


def main():
    """Run the MCP server over HTTP."""
    # Start cleanup task in background
    import threading

    def cleanup_loop():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(periodic_cleanup())

    cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
    cleanup_thread.start()

    # Run the HTTP server
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
