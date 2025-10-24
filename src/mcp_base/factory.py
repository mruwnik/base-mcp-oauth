"""Factory for creating MCP OAuth servers."""

import logging
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Any, cast

from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp import FastMCP
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse

from mcp_base.config import ServerConfig
from mcp_base.oauth_provider import PasswordOAuthProvider, UserChecker

logger = logging.getLogger(__name__)


CompleteUserChecker = Callable[[str, str, str], str]
LoginHandler = Callable[
    [
        Request,
        CompleteUserChecker,
    ],
    Coroutine[Any, Any, HTMLResponse | RedirectResponse],
]


def make_login_handler(name: str, template: str | None = None) -> LoginHandler:
    if not template:
        template_dir = Path(__file__).parent / "templates"
        template = (template_dir / "login.html").read_text()

    async def login_handler(request: Request, complete_user_checker: CompleteUserChecker):
        """Display the login page."""
        username = ""
        error_message = ""

        if request.method == "GET":
            params = dict(request.query_params)
            state = params.get("state", "")
        elif request.method == "POST":
            form = await request.form()
            state = form.get("state", "")
            username = form.get("username", "")
            password = form.get("password", "")
            try:
                redirect_url = complete_user_checker(str(state), str(username), str(password))
                return RedirectResponse(url=redirect_url, status_code=302)
            except ValueError as e:
                error_message = f'<div class="error">{str(e)}</div>'
        else:
            return HTMLResponse(content="", status_code=405)

        to_replace = {
            "app_name": name,
            "state": state,
            "error_message": error_message,
            "username": username,
        }
        html_content = template
        for key, value in to_replace.items():
            html_content = html_content.replace(f"{{{key}}}", str(value))
        return HTMLResponse(content=html_content)

    return login_handler


def create_oauth_server(
    name: str,
    user_checker: UserChecker,
    config: ServerConfig | None = None,
    oauth_provider: PasswordOAuthProvider | None = None,
    login_handler: LoginHandler | None = None,
    login_template: str | None = None,
) -> FastMCP:
    """Create an MCP server with OAuth authentication.

    Args:
        name: Name of the MCP server
        config: Server configuration (uses defaults if not provided)
        oauth_provider: Custom OAuth provider (creates default if not provided)
        login_handler: Custom login handler (creates default if not provided)
        login_template: Custom login template (uses default if not provided)

    Returns:
        Configured FastMCP instance

    Example:
        >>> mcp = create_oauth_server("my-app")
        >>> @mcp.tool()
        >>> def my_tool(arg: str) -> str:
        >>>     return f"Result: {arg}"
        >>> mcp.run()
    """
    # Use defaults if not provided
    config = config or ServerConfig()
    oauth_provider = oauth_provider or PasswordOAuthProvider(
        db_path=config.db_path,
        user_checker=user_checker,
    )

    # Configure auth settings
    auth_settings = AuthSettings(
        issuer_url=cast(AnyHttpUrl, config.server_url),
        resource_server_url=cast(AnyHttpUrl, config.server_url),
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=config.supported_scopes,
            default_scopes=config.default_scopes,
        ),
        required_scopes=config.required_scopes,
    )

    # Create FastMCP server with HTTP transport
    mcp = FastMCP(
        name,
        auth_server_provider=oauth_provider,
        auth=auth_settings,
        host=config.host,
        port=config.port,
        debug=True,
    )

    login_handler = login_handler or make_login_handler(name, login_template)

    @mcp.custom_route("/oauth/login", methods=["GET", "POST"])
    async def login_page(request: Request):
        return await login_handler(request, oauth_provider.complete_authorization_sync)

    return mcp
