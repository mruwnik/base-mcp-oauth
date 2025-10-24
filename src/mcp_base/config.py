"""Configuration for MCP OAuth servers."""

from dataclasses import dataclass, field


@dataclass
class ServerConfig:
    """Configuration for MCP OAuth server.

    Args:
        use_ssl: Use SSL (default: False)
        host: Server host (default: localhost)
        port: Server port (default: 3000)
        db_path: Path to SQLite database (default: auth.db)
        users_file: Path to users file (default: users.txt)
        supported_scopes: List of OAuth scopes (default: ["read", "write", "user"])
        access_token_lifetime: Access token lifetime in seconds (default: 30 days)
        refresh_token_lifetime: Refresh token lifetime in seconds (default: 30 days)
        default_scopes: Default scopes for access (default: ["read"])
        required_scopes: Required scopes for access (default: ["read"])
        debug: Enable debug mode (default: False)
    """

    use_ssl: bool = False
    host: str = "localhost"
    port: int = 3000
    db_path: str = "auth.db"
    users_file: str = "users.txt"
    supported_scopes: list[str] = field(default_factory=lambda: ["read", "write", "user"])
    access_token_lifetime: int = 30 * 24 * 60 * 60  # 30 days
    refresh_token_lifetime: int = 30 * 24 * 60 * 60  # 30 days
    debug: bool = False

    default_scopes: list[str] = field(default_factory=lambda: ["read"])
    required_scopes: list[str] = field(default_factory=lambda: ["read"])

    @property
    def server_url(self) -> str:
        """Get the full server URL."""
        return f"{'https' if self.use_ssl else 'http'}://{self.host}:{self.port}"
