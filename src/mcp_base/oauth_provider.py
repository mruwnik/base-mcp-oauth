"""Minimal OAuth provider implementation for MCP servers."""

import secrets
import time
from collections.abc import Callable

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from mcp_base.database import Database

# Configuration
ACCESS_TOKEN_LIFETIME = 30 * 24 * 60 * 60  # 30 days
REFRESH_TOKEN_LIFETIME = 30 * 24 * 60 * 60  # 30 days
AUTHORIZATION_CODE_LIFETIME = 10 * 60  # 10 minutes
SUPPORTED_SCOPES = ["read", "write", "user"]


UserChecker = Callable[[str, str], int | None]


class PasswordOAuthProvider(OAuthAuthorizationServerProvider):
    """Minimal OAuth provider using SQLite for state management."""

    def __init__(self, user_checker: UserChecker, db_path: str = "auth.db"):
        self.db = Database(db_path)
        self.user_checker = user_checker

    def _generate_token(self) -> str:
        """Generate a secure random token."""
        return secrets.token_urlsafe(32)

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Get OAuth client information."""
        client = self.db.get_client(client_id)
        if not client:
            return None

        return OAuthClientInformationFull(
            client_id=client["client_id"],
            client_secret=client.get("client_secret"),
            client_name=client.get("client_name"),
            redirect_uris=[uri for uri in client["redirect_uris"]],
            grant_types=client["grant_types"],
            response_types=client["response_types"],
            scope=client.get("scope"),
        )

    async def register_client(self, client_info: OAuthClientInformationFull):
        """Register a new OAuth client."""
        self.db.create_client(
            client_id=client_info.client_id,
            client_secret=client_info.client_secret or "",
            client_name=client_info.client_name or "",
            redirect_uris=[str(uri) for uri in client_info.redirect_uris],
            grant_types=client_info.grant_types or [],
            response_types=client_info.response_types or [],
            scope=client_info.scope or "",
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        """Load and validate an access token."""
        session = self.db.get_session(token)
        if not session:
            return None

        flow = (
            self.db.get_oauth_flow(session["oauth_state_id"])
            if session.get("oauth_state_id")
            else None
        )

        return AccessToken(
            token=token,
            client_id=flow["client_id"] if flow else "unknown",
            scopes=session["scopes"].split(),
            expires_at=session["expires_at"],
        )

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """Start OAuth authorization flow."""
        # Validate scopes
        requested_scopes = set(params.scopes or SUPPORTED_SCOPES)
        if not requested_scopes.issubset(SUPPORTED_SCOPES):
            raise ValueError(f"Invalid scopes. Supported: {SUPPORTED_SCOPES}")

        state = params.state or secrets.token_urlsafe(16)

        # Store flow state
        expires_at = int(time.time()) + AUTHORIZATION_CODE_LIFETIME
        self.db.create_oauth_flow(
            state=state,
            client_id=client.client_id,
            redirect_uri=str(params.redirect_uri),
            scopes=" ".join(requested_scopes),
            code_challenge=params.code_challenge,
            expires_at=expires_at,
        )

        # Return URL for user to complete login
        return f"/oauth/login?state={state}"

    def complete_authorization_sync(self, state: str, username: str, password: str) -> str:
        """Complete authorization after user authentication. Returns redirect URL."""
        # Get OAuth flow
        flow = self.db.get_oauth_flow(state)
        if not flow:
            raise ValueError("Invalid or expired state")

        if flow["expires_at"] < int(time.time()):
            raise ValueError("Authorization request expired")

        # Authenticate user - returns user_id or None
        user_id = self.user_checker(username, password)
        if user_id is None:
            raise ValueError("Invalid credentials")

        # Generate authorization code
        code = self._generate_token()
        self.db.update_oauth_flow(state, code, user_id)

        return f"{flow['redirect_uri']}?code={code}&state={state}"

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        """Load an authorization code."""
        flow = self.db.get_oauth_flow_by_code(authorization_code)
        if not flow:
            return None

        if flow["expires_at"] < int(time.time()):
            return None

        return AuthorizationCode(
            code=authorization_code,
            client_id=flow["client_id"],
            redirect_uri=flow["redirect_uri"],
            scopes=flow["scopes"].split(),
            code_challenge=flow.get("code_challenge") or "",
            expires_at=flow.get("expires_at") or int(time.time()) + AUTHORIZATION_CODE_LIFETIME,
            redirect_uri_provided_explicitly=True,
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        """Exchange authorization code for tokens."""
        # Get OAuth flow by code
        flow = self.db.get_oauth_flow_by_code(authorization_code.code)
        if not flow:
            raise ValueError("Invalid authorization code")

        if flow["expires_at"] < int(time.time()):
            raise ValueError("Authorization code expired")

        if flow["client_id"] != client.client_id:
            raise ValueError("Client ID mismatch")

        # Generate tokens
        access_token = self._generate_token()
        refresh_token = self._generate_token()

        access_expires = int(time.time()) + ACCESS_TOKEN_LIFETIME
        refresh_expires = int(time.time()) + REFRESH_TOKEN_LIFETIME

        # Store tokens with state reference
        self.db.create_session(
            token=access_token,
            user_id=flow["user_id"],
            client_id=client.client_id,
            scopes=flow["scopes"],
            expires_at=access_expires,
            oauth_state_id=flow["state"],
        )

        self.db.create_refresh_token(
            token=refresh_token,
            user_id=flow["user_id"],
            client_id=client.client_id,
            scopes=flow["scopes"],
            expires_at=refresh_expires,
        )

        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_LIFETIME,
            refresh_token=refresh_token,
            scope=flow["scopes"],
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        """Load and validate a refresh token."""
        db_token = self.db.get_refresh_token(refresh_token)
        if not db_token:
            return None

        if db_token["client_id"] != client.client_id:
            return None

        return RefreshToken(
            token=refresh_token,
            client_id=db_token["client_id"],
            scopes=db_token["scopes"].split(),
            expires_at=db_token["expires_at"],
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """Exchange refresh token for new access token."""
        db_token = self.db.get_refresh_token(refresh_token.token)
        if not db_token:
            raise ValueError("Invalid or expired refresh token")

        # Generate new access token
        access_token = self._generate_token()
        access_expires = int(time.time()) + ACCESS_TOKEN_LIFETIME

        self.db.create_session(
            token=access_token,
            user_id=db_token["user_id"],
            client_id=client.client_id,
            scopes=" ".join(scopes),
            expires_at=access_expires,
        )

        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_LIFETIME,
            scope=" ".join(scopes),
        )

    async def revoke_token(self, token: str, token_type_hint: str | None = None):
        """Revoke a token."""
        if token_type_hint == "refresh_token" or not token_type_hint:
            self.db.revoke_refresh_token(token)
