"""Tests for database module."""

import time
from pathlib import Path

import pytest

from src.database import Database


@pytest.fixture
def db(tmp_path: Path) -> Database:
    """Create a test database."""
    db_path = tmp_path / "test.db"
    return Database(str(db_path))


@pytest.fixture
def users_file(tmp_path: Path) -> Path:
    """Create a test users file."""
    users_path = tmp_path / "users.txt"
    users_path.write_text("alice:$2b$12$test_hash\nbob:$2b$12$another_hash")
    return users_path


def test_database_initialization(db: Database):
    """Test database initializes with correct schema."""
    with db._connection() as conn:
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = [row[0] for row in tables]
        assert "users" in table_names
        assert "oauth_flows" in table_names
        assert "sessions" in table_names
        assert "refresh_tokens" in table_names


def test_load_users_from_file(db: Database, users_file: Path):
    """Test loading users from file."""
    db.load_users_from_file(str(users_file))
    alice = db.get_user("alice")
    assert alice is not None
    assert alice["username"] == "alice"
    assert alice["password_hash"] == "$2b$12$test_hash"


def test_get_nonexistent_user(db: Database):
    """Test getting a user that doesn't exist."""
    user = db.get_user("nonexistent")
    assert user is None


def test_oauth_flow_lifecycle(db: Database):
    """Test creating and retrieving OAuth flows."""
    expires_at = int(time.time()) + 600
    db.create_oauth_flow(
        state="test_state",
        client_id="test_client",
        redirect_uri="http://localhost/callback",
        scopes="read write",
        code_challenge="challenge",
        expires_at=expires_at,
    )

    flow = db.get_oauth_flow("test_state")
    assert flow is not None
    assert flow["client_id"] == "test_client"
    assert flow["scopes"] == "read write"


def test_update_oauth_flow(db: Database):
    """Test updating OAuth flow with code."""
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
    assert flow["user_id"] == 1


def test_session_lifecycle(db: Database):
    """Test creating and retrieving sessions."""
    expires_at = int(time.time()) + 600
    db.create_session(
        token="access_token_123",
        user_id=1,
        client_id="test_client",
        scopes="read write",
        expires_at=expires_at,
    )

    session = db.get_session("access_token_123")
    assert session is not None
    assert session["user_id"] == 1
    assert session["scopes"] == "read write"


def test_expired_session_not_returned(db: Database):
    """Test that expired sessions are not returned."""
    expires_at = int(time.time()) - 600  # Expired
    db.create_session(
        token="expired_token",
        user_id=1,
        client_id="test_client",
        scopes="read",
        expires_at=expires_at,
    )

    session = db.get_session("expired_token")
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
    assert token["user_id"] == 1


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

    db.revoke_refresh_token("refresh_token_123")
    token = db.get_refresh_token("refresh_token_123")
    assert token is None


def test_cleanup_expired(db: Database):
    """Test cleanup of expired entries."""
    now = int(time.time())

    # Create expired session
    db.create_session(
        token="expired_session",
        user_id=1,
        client_id="test_client",
        scopes="read",
        expires_at=now - 600,
    )

    # Create expired OAuth flow
    db.create_oauth_flow(
        state="expired_state",
        client_id="test_client",
        redirect_uri="http://localhost/callback",
        scopes="read",
        code_challenge=None,
        expires_at=now - 600,
    )

    db.cleanup_expired()

    # Verify they're gone
    with db._connection() as conn:
        session_count = conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE token = ?", ("expired_session",)
        ).fetchone()[0]
        flow_count = conn.execute(
            "SELECT COUNT(*) FROM oauth_flows WHERE state = ?", ("expired_state",)
        ).fetchone()[0]

        assert session_count == 0
        assert flow_count == 0
