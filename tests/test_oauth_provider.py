"""Tests for OAuth provider."""

import time
from pathlib import Path

import bcrypt
import pytest

from src.oauth_provider import MinimalOAuthProvider


@pytest.fixture
def users_file(tmp_path: Path) -> Path:
    """Create a test users file with bcrypt hashed passwords."""
    users_file = tmp_path / "users.txt"

    # Create test user with known password
    password_hash = bcrypt.hashpw(b"testpass123", bcrypt.gensalt()).decode()
    users_file.write_text(f"testuser:{password_hash}")

    return users_file


@pytest.fixture
def provider(tmp_path: Path, users_file: Path) -> MinimalOAuthProvider:
    """Create a test OAuth provider."""
    db_path = tmp_path / "test_auth.db"
    return MinimalOAuthProvider(str(db_path), str(users_file))


@pytest.mark.asyncio
async def test_authorize_creates_flow(provider: MinimalOAuthProvider):
    """Test that authorize creates an OAuth flow."""
    auth_url = await provider.authorize(
        client_id="test_client",
        redirect_uri="http://localhost/callback",
        scope="read write",
        state="test_state",
    )

    assert "/login?state=test_state" in auth_url
    flow = provider.db.get_oauth_flow("test_state")
    assert flow is not None
    assert flow["client_id"] == "test_client"


@pytest.mark.asyncio
async def test_authorize_invalid_scope(provider: MinimalOAuthProvider):
    """Test that invalid scopes are rejected."""
    with pytest.raises(ValueError, match="Invalid scopes"):
        await provider.authorize(
            client_id="test_client",
            redirect_uri="http://localhost/callback",
            scope="invalid_scope",
            state="test_state",
        )


@pytest.mark.asyncio
async def test_complete_authorization_success(provider: MinimalOAuthProvider):
    """Test successful authorization completion."""
    # Start authorization
    await provider.authorize(
        client_id="test_client",
        redirect_uri="http://localhost/callback",
        scope="read",
        state="test_state",
    )

    # Complete with valid credentials
    auth_code = await provider.complete_authorization(
        state="test_state",
        username="testuser",
        password="testpass123",
    )

    assert auth_code.code is not None
    assert auth_code.state == "test_state"


@pytest.mark.asyncio
async def test_complete_authorization_invalid_credentials(provider: MinimalOAuthProvider):
    """Test authorization fails with invalid credentials."""
    await provider.authorize(
        client_id="test_client",
        redirect_uri="http://localhost/callback",
        scope="read",
        state="test_state",
    )

    with pytest.raises(ValueError, match="Invalid credentials"):
        await provider.complete_authorization(
            state="test_state",
            username="testuser",
            password="wrongpassword",
        )


@pytest.mark.asyncio
async def test_exchange_authorization_code(provider: MinimalOAuthProvider):
    """Test exchanging authorization code for tokens."""
    # Complete full flow
    await provider.authorize(
        client_id="test_client",
        redirect_uri="http://localhost/callback",
        scope="read write",
        state="test_state",
    )

    auth_code = await provider.complete_authorization(
        state="test_state",
        username="testuser",
        password="testpass123",
    )

    tokens = await provider.exchange_authorization_code(
        client_id="test_client",
        code=auth_code.code,
        redirect_uri="http://localhost/callback",
    )

    assert "access_token" in tokens
    assert "refresh_token" in tokens
    assert tokens["token_type"] == "Bearer"
    assert tokens["scope"] == "read write"


@pytest.mark.asyncio
async def test_load_access_token(provider: MinimalOAuthProvider):
    """Test loading a valid access token."""
    # Create a session directly
    expires_at = int(time.time()) + 600
    provider.db.create_session(
        token="test_token",
        user_id=1,
        client_id="test_client",
        scopes="read",
        expires_at=expires_at,
    )

    access_token = await provider.load_access_token("test_token")
    assert access_token is not None
    assert access_token.token == "test_token"
    assert access_token.scope == "read"


@pytest.mark.asyncio
async def test_load_expired_access_token(provider: MinimalOAuthProvider):
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
async def test_refresh_access_token(provider: MinimalOAuthProvider):
    """Test refreshing an access token."""
    # Create refresh token directly
    expires_at = int(time.time()) + 600
    provider.db.create_refresh_token(
        token="refresh_token_123",
        user_id=1,
        client_id="test_client",
        scopes="read write",
        expires_at=expires_at,
    )

    new_tokens = await provider.refresh_access_token(
        client_id="test_client",
        refresh_token_str="refresh_token_123",
    )

    assert "access_token" in new_tokens
    assert new_tokens["token_type"] == "Bearer"
    assert new_tokens["scope"] == "read write"


@pytest.mark.asyncio
async def test_revoke_token(provider: MinimalOAuthProvider):
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
