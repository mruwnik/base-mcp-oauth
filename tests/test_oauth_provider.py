"""Tests for OAuth provider."""

import time
from pathlib import Path

import bcrypt
import pytest

from mcp_base.oauth_provider import PasswordOAuthProvider


@pytest.fixture
def users_file(tmp_path: Path) -> Path:
    """Create a test users file with bcrypt hashed passwords."""
    users_file = tmp_path / "users.txt"

    # Create test user with known password
    password_hash = bcrypt.hashpw(b"testpass123", bcrypt.gensalt()).decode()
    users_file.write_text(f"testuser:{password_hash}")

    return users_file


@pytest.fixture
def user_checker(users_file: Path):
    """Create a user checker function for testing."""
    password_hash = bcrypt.hashpw(b"testpass123", bcrypt.gensalt()).decode()

    def checker(username: str, password: str) -> int | None:
        if username == "testuser" and bcrypt.checkpw(password.encode(), password_hash.encode()):
            return 1
        return None

    return checker


@pytest.fixture
def provider(tmp_path: Path, user_checker) -> PasswordOAuthProvider:
    """Create a test OAuth provider."""
    db_path = tmp_path / "test_auth.db"
    return PasswordOAuthProvider(user_checker, str(db_path))


def test_generate_token(provider: PasswordOAuthProvider):
    """Test token generation."""
    token1 = provider._generate_token()
    token2 = provider._generate_token()

    assert token1 != token2
    assert len(token1) > 20
    assert len(token2) > 20


@pytest.mark.asyncio
async def test_register_and_get_client(provider: PasswordOAuthProvider):
    """Test client registration and retrieval."""
    from mcp.shared.auth import OAuthClientInformationFull
    from pydantic import AnyHttpUrl

    client_info = OAuthClientInformationFull(
        client_id="test_client",
        client_secret="test_secret",
        client_name="Test Client",
        redirect_uris=[AnyHttpUrl("http://localhost/callback")],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope="read write",
    )

    await provider.register_client(client_info)

    retrieved = await provider.get_client("test_client")
    assert retrieved is not None
    assert retrieved.client_id == "test_client"
    assert retrieved.client_secret == "test_secret"
    assert retrieved.client_name == "Test Client"
    assert str(retrieved.redirect_uris[0]) == "http://localhost/callback"


@pytest.mark.asyncio
async def test_get_nonexistent_client(provider: PasswordOAuthProvider):
    """Test getting a client that doesn't exist."""
    client = await provider.get_client("nonexistent")
    assert client is None


@pytest.mark.asyncio
async def test_authorize_creates_flow(provider: PasswordOAuthProvider):
    """Test that authorize creates an OAuth flow."""
    from mcp.server.auth.provider import AuthorizationParams
    from mcp.shared.auth import OAuthClientInformationFull
    from pydantic import AnyHttpUrl

    client = OAuthClientInformationFull(
        client_id="test_client",
        redirect_uris=[AnyHttpUrl("http://localhost/callback")],
        grant_types=["authorization_code"],
        response_types=["code"],
    )

    params = AuthorizationParams(
        redirect_uri=AnyHttpUrl("http://localhost/callback"),
        redirect_uri_provided_explicitly=True,
        state="test_state",
        scopes=["read"],
        code_challenge="test_challenge",
    )

    auth_url = await provider.authorize(client, params)

    assert "/login?state=test_state" in auth_url
    flow = provider.db.get_oauth_flow("test_state")
    assert flow is not None
    assert flow["client_id"] == "test_client"


@pytest.mark.asyncio
async def test_authorize_invalid_scope(provider: PasswordOAuthProvider):
    """Test that invalid scopes are rejected."""
    from mcp.server.auth.provider import AuthorizationParams
    from mcp.shared.auth import OAuthClientInformationFull
    from pydantic import AnyHttpUrl

    client = OAuthClientInformationFull(
        client_id="test_client",
        redirect_uris=[AnyHttpUrl("http://localhost/callback")],
        grant_types=["authorization_code"],
        response_types=["code"],
    )

    params = AuthorizationParams(
        redirect_uri=AnyHttpUrl("http://localhost/callback"),
        redirect_uri_provided_explicitly=True,
        state="test_state",
        scopes=["invalid_scope"],
        code_challenge="test_challenge",
    )

    with pytest.raises(ValueError, match="Invalid scopes"):
        await provider.authorize(client, params)


def test_complete_authorization_success(provider: PasswordOAuthProvider):
    """Test successful authorization completion."""
    from pydantic import AnyHttpUrl

    # Start authorization
    provider.db.create_oauth_flow(
        state="test_state",
        client_id="test_client",
        redirect_uri="http://localhost/callback",
        scopes="read",
        code_challenge=None,
        expires_at=int(time.time()) + 600,
    )

    # Complete with valid credentials
    redirect_url = provider.complete_authorization_sync(
        state="test_state",
        username="testuser",
        password="testpass123",
    )

    assert "code=" in redirect_url
    assert "state=test_state" in redirect_url


def test_complete_authorization_invalid_state(provider: PasswordOAuthProvider):
    """Test authorization fails with invalid state."""
    with pytest.raises(ValueError, match="Invalid or expired state"):
        provider.complete_authorization_sync(
            state="invalid_state",
            username="testuser",
            password="testpass123",
        )


def test_complete_authorization_expired_state(provider: PasswordOAuthProvider):
    """Test authorization fails with expired state."""
    # Create expired flow
    provider.db.create_oauth_flow(
        state="test_state",
        client_id="test_client",
        redirect_uri="http://localhost/callback",
        scopes="read",
        code_challenge=None,
        expires_at=int(time.time()) - 600,  # Expired
    )

    with pytest.raises(ValueError, match="Authorization request expired"):
        provider.complete_authorization_sync(
            state="test_state",
            username="testuser",
            password="testpass123",
        )


def test_complete_authorization_invalid_credentials(provider: PasswordOAuthProvider):
    """Test authorization fails with invalid credentials."""
    provider.db.create_oauth_flow(
        state="test_state",
        client_id="test_client",
        redirect_uri="http://localhost/callback",
        scopes="read",
        code_challenge=None,
        expires_at=int(time.time()) + 600,
    )

    with pytest.raises(ValueError, match="Invalid credentials"):
        provider.complete_authorization_sync(
            state="test_state",
            username="testuser",
            password="wrongpassword",
        )


@pytest.mark.asyncio
async def test_load_authorization_code(provider: PasswordOAuthProvider):
    """Test loading an authorization code."""
    from mcp.shared.auth import OAuthClientInformationFull
    from pydantic import AnyHttpUrl

    client = OAuthClientInformationFull(
        client_id="test_client",
        redirect_uris=[AnyHttpUrl("http://localhost/callback")],
        grant_types=["authorization_code"],
        response_types=["code"],
    )

    # Create flow with code
    provider.db.create_oauth_flow(
        state="test_state",
        client_id="test_client",
        redirect_uri="http://localhost/callback",
        scopes="read write",
        code_challenge="challenge",
        expires_at=int(time.time()) + 600,
    )
    provider.db.update_oauth_flow("test_state", "auth_code_123", 1)

    auth_code = await provider.load_authorization_code(client, "auth_code_123")
    assert auth_code is not None
    assert auth_code.code == "auth_code_123"
    assert auth_code.client_id == "test_client"
    assert "read" in auth_code.scopes
    assert "write" in auth_code.scopes


@pytest.mark.asyncio
async def test_load_expired_authorization_code(provider: PasswordOAuthProvider):
    """Test loading an expired authorization code."""
    from mcp.shared.auth import OAuthClientInformationFull
    from pydantic import AnyHttpUrl

    client = OAuthClientInformationFull(
        client_id="test_client",
        redirect_uris=[AnyHttpUrl("http://localhost/callback")],
        grant_types=["authorization_code"],
        response_types=["code"],
    )

    # Create expired flow
    provider.db.create_oauth_flow(
        state="test_state",
        client_id="test_client",
        redirect_uri="http://localhost/callback",
        scopes="read",
        code_challenge=None,
        expires_at=int(time.time()) - 600,  # Expired
    )
    provider.db.update_oauth_flow("test_state", "expired_code", 1)

    auth_code = await provider.load_authorization_code(client, "expired_code")
    assert auth_code is None


@pytest.mark.asyncio
async def test_exchange_authorization_code(provider: PasswordOAuthProvider):
    """Test exchanging authorization code for tokens."""
    from mcp.server.auth.provider import AuthorizationCode
    from mcp.shared.auth import OAuthClientInformationFull
    from pydantic import AnyHttpUrl

    client = OAuthClientInformationFull(
        client_id="test_client",
        redirect_uris=[AnyHttpUrl("http://localhost/callback")],
        grant_types=["authorization_code"],
        response_types=["code"],
    )

    # Create complete flow
    provider.db.create_oauth_flow(
        state="test_state",
        client_id="test_client",
        redirect_uri="http://localhost/callback",
        scopes="read write",
        code_challenge=None,
        expires_at=int(time.time()) + 600,
    )
    provider.db.update_oauth_flow("test_state", "auth_code_123", 1)

    auth_code = AuthorizationCode(
        code="auth_code_123",
        client_id="test_client",
        redirect_uri="http://localhost/callback",
        scopes=["read", "write"],
        code_challenge="",
        expires_at=int(time.time()) + 600,
        redirect_uri_provided_explicitly=True,
    )

    tokens = await provider.exchange_authorization_code(client, auth_code)

    assert tokens.access_token is not None
    assert tokens.refresh_token is not None
    assert tokens.token_type == "Bearer"
    assert tokens.scope == "read write"


@pytest.mark.asyncio
async def test_exchange_invalid_authorization_code(provider: PasswordOAuthProvider):
    """Test exchanging invalid authorization code."""
    from mcp.server.auth.provider import AuthorizationCode
    from mcp.shared.auth import OAuthClientInformationFull
    from pydantic import AnyHttpUrl

    client = OAuthClientInformationFull(
        client_id="test_client",
        redirect_uris=[AnyHttpUrl("http://localhost/callback")],
        grant_types=["authorization_code"],
        response_types=["code"],
    )

    auth_code = AuthorizationCode(
        code="invalid_code",
        client_id="test_client",
        redirect_uri="http://localhost/callback",
        scopes=["read"],
        code_challenge="",
        expires_at=int(time.time()) + 600,
        redirect_uri_provided_explicitly=True,
    )

    with pytest.raises(ValueError, match="Invalid authorization code"):
        await provider.exchange_authorization_code(client, auth_code)


@pytest.mark.asyncio
async def test_exchange_expired_authorization_code(provider: PasswordOAuthProvider):
    """Test exchanging expired authorization code."""
    from mcp.server.auth.provider import AuthorizationCode
    from mcp.shared.auth import OAuthClientInformationFull
    from pydantic import AnyHttpUrl

    client = OAuthClientInformationFull(
        client_id="test_client",
        redirect_uris=[AnyHttpUrl("http://localhost/callback")],
        grant_types=["authorization_code"],
        response_types=["code"],
    )

    # Create expired flow
    provider.db.create_oauth_flow(
        state="test_state",
        client_id="test_client",
        redirect_uri="http://localhost/callback",
        scopes="read",
        code_challenge=None,
        expires_at=int(time.time()) - 600,
    )
    provider.db.update_oauth_flow("test_state", "expired_code", 1)

    auth_code = AuthorizationCode(
        code="expired_code",
        client_id="test_client",
        redirect_uri="http://localhost/callback",
        scopes=["read"],
        code_challenge="",
        expires_at=int(time.time()) - 600,
        redirect_uri_provided_explicitly=True,
    )

    with pytest.raises(ValueError, match="Authorization code expired"):
        await provider.exchange_authorization_code(client, auth_code)


@pytest.mark.asyncio
async def test_load_access_token(provider: PasswordOAuthProvider):
    """Test loading a valid access token."""
    # Create a session directly
    expires_at = int(time.time()) + 600
    provider.db.create_oauth_flow(
        state="test_state",
        client_id="test_client",
        redirect_uri="http://localhost/callback",
        scopes="read",
        code_challenge=None,
        expires_at=expires_at,
    )
    provider.db.create_session(
        token="test_token",
        user_id=1,
        client_id="test_client",
        scopes="read",
        expires_at=expires_at,
        oauth_state_id="test_state",
    )

    access_token = await provider.load_access_token("test_token")
    assert access_token is not None
    assert access_token.token == "test_token"
    assert "read" in access_token.scopes


@pytest.mark.asyncio
async def test_load_expired_access_token(provider: PasswordOAuthProvider):
    """Test that expired tokens are not loaded."""
    expires_at = int(time.time()) - 600  # Expired
    provider.db.create_session(
        token="expired_token",
        user_id=1,
        client_id="test_client",
        scopes="read",
        expires_at=expires_at,
    )

    access_token = await provider.load_access_token("expired_token")
    assert access_token is None


@pytest.mark.asyncio
async def test_load_refresh_token(provider: PasswordOAuthProvider):
    """Test loading a refresh token."""
    from mcp.shared.auth import OAuthClientInformationFull
    from pydantic import AnyHttpUrl

    client = OAuthClientInformationFull(
        client_id="test_client",
        redirect_uris=[AnyHttpUrl("http://localhost/callback")],
        grant_types=["refresh_token"],
        response_types=["code"],
    )

    # Create refresh token directly
    expires_at = int(time.time()) + 600
    provider.db.create_refresh_token(
        token="refresh_token_123",
        user_id=1,
        client_id="test_client",
        scopes="read write",
        expires_at=expires_at,
    )

    refresh_token = await provider.load_refresh_token(client, "refresh_token_123")
    assert refresh_token is not None
    assert refresh_token.token == "refresh_token_123"
    assert refresh_token.client_id == "test_client"
    assert "read" in refresh_token.scopes


@pytest.mark.asyncio
async def test_exchange_refresh_token(provider: PasswordOAuthProvider):
    """Test refreshing an access token."""
    from mcp.server.auth.provider import RefreshToken
    from mcp.shared.auth import OAuthClientInformationFull
    from pydantic import AnyHttpUrl

    client = OAuthClientInformationFull(
        client_id="test_client",
        redirect_uris=[AnyHttpUrl("http://localhost/callback")],
        grant_types=["refresh_token"],
        response_types=["code"],
    )

    # Create refresh token
    expires_at = int(time.time()) + 600
    provider.db.create_refresh_token(
        token="refresh_token_123",
        user_id=1,
        client_id="test_client",
        scopes="read write",
        expires_at=expires_at,
    )

    refresh_token = RefreshToken(
        token="refresh_token_123",
        client_id="test_client",
        scopes=["read", "write"],
        expires_at=expires_at,
    )

    new_tokens = await provider.exchange_refresh_token(
        client,
        refresh_token,
        ["read", "write"],
    )

    assert new_tokens.access_token is not None
    assert new_tokens.token_type == "Bearer"
    assert new_tokens.scope == "read write"


@pytest.mark.asyncio
async def test_revoke_token(provider: PasswordOAuthProvider):
    """Test revoking a refresh token."""
    expires_at = int(time.time()) + 600
    provider.db.create_refresh_token(
        token="refresh_token_123",
        user_id=1,
        client_id="test_client",
        scopes="read",
        expires_at=expires_at,
    )

    await provider.revoke_token("refresh_token_123", token_type_hint="refresh_token")

    token = provider.db.get_refresh_token("refresh_token_123")
    assert token is None


def test_cleanup_expired(provider: PasswordOAuthProvider):
    """Test cleanup of expired tokens."""
    now = int(time.time())
    future = now + 600
    past = now - 600

    # Create expired and valid tokens
    provider.db.create_session(
        token="expired_session",
        user_id=1,
        client_id="test_client",
        scopes="read",
        expires_at=past,
    )

    provider.db.create_session(
        token="valid_session",
        user_id=1,
        client_id="test_client",
        scopes="read",
        expires_at=future,
    )

    # Run cleanup
    provider.db.cleanup_expired()

    # Verify expired is gone, valid remains
    with provider.db._connection() as conn:
        expired_count = conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE token = ?", ("expired_session",)
        ).fetchone()[0]
        assert expired_count == 0

        valid_count = conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE token = ?", ("valid_session",)
        ).fetchone()[0]
        assert valid_count == 1
