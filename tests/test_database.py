"""Tests for database module."""

import time
from pathlib import Path

import pytest

from mcp_base.database import Database


@pytest.fixture
def db(tmp_path: Path) -> Database:
    """Create a test database in a temporary directory."""
    db_path = tmp_path / "test.db"
    return Database(str(db_path))


def test_database_initialization(db: Database):
    """Test database initializes with correct schema."""
    with db._connection() as conn:
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = [row[0] for row in tables]

        assert "users" in table_names
        assert "clients" in table_names
        assert "oauth_flows" in table_names
        assert "sessions" in table_names
        assert "refresh_tokens" in table_names


def test_create_and_get_client(db: Database):
    """Test creating and retrieving OAuth clients."""
    db.create_client(
        client_id="test_client",
        client_secret="test_secret",
        client_name="Test Client",
        redirect_uris=["http://localhost/callback", "http://example.com/cb"],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope="read write",
    )

    client = db.get_client("test_client")
    assert client is not None
    assert client["client_id"] == "test_client"
    assert client["client_secret"] == "test_secret"
    assert client["client_name"] == "Test Client"
    assert client["redirect_uris"] == ["http://localhost/callback", "http://example.com/cb"]
    assert client["grant_types"] == ["authorization_code", "refresh_token"]
    assert client["response_types"] == ["code"]
    assert client["scope"] == "read write"


def test_get_nonexistent_client(db: Database):
    """Test getting a client that doesn't exist."""
    client = db.get_client("nonexistent")
    assert client is None


def test_oauth_flow_lifecycle(db: Database):
    """Test creating and retrieving OAuth flows."""
    expires_at = int(time.time()) + 600

    db.create_oauth_flow(
        state="test_state",
        client_id="test_client",
        redirect_uri="http://localhost/callback",
        scopes="read write",
        code_challenge="challenge123",
        expires_at=expires_at,
    )

    flow = db.get_oauth_flow("test_state")
    assert flow is not None
    assert flow["state"] == "test_state"
    assert flow["client_id"] == "test_client"
    assert flow["redirect_uri"] == "http://localhost/callback"
    assert flow["scopes"] == "read write"
    assert flow["code_challenge"] == "challenge123"
    assert flow["expires_at"] == expires_at
    assert flow["code"] is None
    assert flow["user_id"] is None


def test_update_oauth_flow(db: Database):
    """Test updating OAuth flow with authorization code."""
    expires_at = int(time.time()) + 600

    db.create_oauth_flow(
        state="test_state",
        client_id="test_client",
        redirect_uri="http://localhost/callback",
        scopes="read",
        code_challenge=None,
        expires_at=expires_at,
    )

    db.update_oauth_flow("test_state", "auth_code_123", 1)

    flow = db.get_oauth_flow("test_state")
    assert flow["code"] == "auth_code_123"
    assert flow["user_id"] == 1


def test_get_oauth_flow_by_code(db: Database):
    """Test retrieving OAuth flow by authorization code."""
    expires_at = int(time.time()) + 600

    db.create_oauth_flow(
        state="test_state",
        client_id="test_client",
        redirect_uri="http://localhost/callback",
        scopes="read",
        code_challenge=None,
        expires_at=expires_at,
    )

    db.update_oauth_flow("test_state", "auth_code_123", 1)

    flow = db.get_oauth_flow_by_code("auth_code_123")
    assert flow is not None
    assert flow["state"] == "test_state"
    assert flow["code"] == "auth_code_123"
    assert flow["user_id"] == 1


def test_get_nonexistent_oauth_flow(db: Database):
    """Test getting OAuth flow that doesn't exist."""
    flow = db.get_oauth_flow("nonexistent")
    assert flow is None


def test_session_lifecycle(db: Database):
    """Test creating and retrieving sessions."""
    expires_at = int(time.time()) + 600

    db.create_session(
        token="access_token_123",
        user_id=1,
        client_id="test_client",
        scopes="read write",
        expires_at=expires_at,
        oauth_state_id="test_state",
    )

    session = db.get_session("access_token_123")
    assert session is not None
    assert session["token"] == "access_token_123"
    assert session["user_id"] == 1
    assert session["client_id"] == "test_client"
    assert session["scopes"] == "read write"
    assert session["expires_at"] == expires_at


def test_expired_session_not_returned(db: Database):
    """Test that expired sessions are not returned."""
    expires_at = int(time.time()) - 600  # Expired 10 minutes ago

    db.create_session(
        token="expired_token",
        user_id=1,
        client_id="test_client",
        scopes="read",
        expires_at=expires_at,
    )

    session = db.get_session("expired_token")
    assert session is None


def test_get_nonexistent_session(db: Database):
    """Test getting a session that doesn't exist."""
    session = db.get_session("nonexistent")
    assert session is None


def test_refresh_token_lifecycle(db: Database):
    """Test creating and retrieving refresh tokens."""
    expires_at = int(time.time()) + 600

    db.create_refresh_token(
        token="refresh_token_123",
        user_id=1,
        client_id="test_client",
        scopes="read write",
        expires_at=expires_at,
    )

    token = db.get_refresh_token("refresh_token_123")
    assert token is not None
    assert token["token"] == "refresh_token_123"
    assert token["user_id"] == 1
    assert token["client_id"] == "test_client"
    assert token["scopes"] == "read write"
    assert token["expires_at"] == expires_at
    assert token["revoked"] == 0


def test_expired_refresh_token_not_returned(db: Database):
    """Test that expired refresh tokens are not returned."""
    expires_at = int(time.time()) - 600  # Expired

    db.create_refresh_token(
        token="expired_token",
        user_id=1,
        client_id="test_client",
        scopes="read",
        expires_at=expires_at,
    )

    token = db.get_refresh_token("expired_token")
    assert token is None


def test_revoke_refresh_token(db: Database):
    """Test revoking a refresh token."""
    expires_at = int(time.time()) + 600

    db.create_refresh_token(
        token="refresh_token_123",
        user_id=1,
        client_id="test_client",
        scopes="read",
        expires_at=expires_at,
    )

    # Token should be retrievable initially
    token = db.get_refresh_token("refresh_token_123")
    assert token is not None

    # Revoke it
    db.revoke_refresh_token("refresh_token_123")

    # Should no longer be retrievable
    token = db.get_refresh_token("refresh_token_123")
    assert token is None


def test_revoke_nonexistent_token(db: Database):
    """Test revoking a token that doesn't exist."""
    db.revoke_refresh_token("nonexistent")
    # Should not raise an error


def test_get_nonexistent_refresh_token(db: Database):
    """Test getting a refresh token that doesn't exist."""
    token = db.get_refresh_token("nonexistent")
    assert token is None


def test_cleanup_expired(db: Database):
    """Test cleanup of expired entries."""
    now = int(time.time())
    future = now + 600
    past = now - 600

    # Create expired session
    db.create_session(
        token="expired_session",
        user_id=1,
        client_id="test_client",
        scopes="read",
        expires_at=past,
    )

    # Create valid session
    db.create_session(
        token="valid_session",
        user_id=1,
        client_id="test_client",
        scopes="read",
        expires_at=future,
    )

    # Create expired OAuth flow
    db.create_oauth_flow(
        state="expired_state",
        client_id="test_client",
        redirect_uri="http://localhost/callback",
        scopes="read",
        code_challenge=None,
        expires_at=past,
    )

    # Create valid OAuth flow
    db.create_oauth_flow(
        state="valid_state",
        client_id="test_client",
        redirect_uri="http://localhost/callback",
        scopes="read",
        code_challenge=None,
        expires_at=future,
    )

    # Create expired and revoked refresh token
    db.create_refresh_token(
        token="expired_revoked_token",
        user_id=1,
        client_id="test_client",
        scopes="read",
        expires_at=past,
    )
    db.revoke_refresh_token("expired_revoked_token")

    # Create valid refresh token
    db.create_refresh_token(
        token="valid_refresh",
        user_id=1,
        client_id="test_client",
        scopes="read",
        expires_at=future,
    )

    # Run cleanup
    db.cleanup_expired()

    # Verify expired entries are gone
    with db._connection() as conn:
        expired_session = conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE token = ?", ("expired_session",)
        ).fetchone()[0]
        assert expired_session == 0

        valid_session = conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE token = ?", ("valid_session",)
        ).fetchone()[0]
        assert valid_session == 1

        expired_flow = conn.execute(
            "SELECT COUNT(*) FROM oauth_flows WHERE state = ?", ("expired_state",)
        ).fetchone()[0]
        assert expired_flow == 0

        valid_flow = conn.execute(
            "SELECT COUNT(*) FROM oauth_flows WHERE state = ?", ("valid_state",)
        ).fetchone()[0]
        assert valid_flow == 1

        expired_refresh = conn.execute(
            "SELECT COUNT(*) FROM refresh_tokens WHERE token = ?", ("expired_revoked_token",)
        ).fetchone()[0]
        assert expired_refresh == 0

        valid_refresh = conn.execute(
            "SELECT COUNT(*) FROM refresh_tokens WHERE token = ?", ("valid_refresh",)
        ).fetchone()[0]
        assert valid_refresh == 1


def test_database_file_created(tmp_path: Path):
    """Test that database file is created on initialization."""
    db_path = tmp_path / "new_db.db"
    assert not db_path.exists()

    Database(str(db_path))

    assert db_path.exists()
