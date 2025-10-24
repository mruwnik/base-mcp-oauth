"""SQLite database management for OAuth state."""

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

INIT_DB_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password_hash TEXT
);

CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY,
    client_secret TEXT,
    client_name TEXT,
    redirect_uris TEXT,
    grant_types TEXT,
    response_types TEXT,
    scope TEXT,
    created_at INTEGER
);

CREATE TABLE IF NOT EXISTS oauth_flows (
    state TEXT PRIMARY KEY,
    client_id TEXT,
    redirect_uri TEXT,
    scopes TEXT,
    code_challenge TEXT,
    code TEXT,
    user_id INTEGER,
    expires_at INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER,
    client_id TEXT,
    scopes TEXT,
    expires_at INTEGER
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token TEXT PRIMARY KEY,
    user_id INTEGER,
    client_id TEXT,
    scopes TEXT,
    expires_at INTEGER,
    revoked BOOLEAN DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sessions_expires 
    ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_expires 
    ON refresh_tokens(expires_at);
"""


class Database:
    """Manages SQLite database for OAuth flows and sessions."""

    def __init__(self, db_path: str = "auth.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize database with required schema."""
        with self._connection() as conn:
            conn.executescript(INIT_DB_SQL)

    @contextmanager
    def _connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def create_client(
        self,
        client_id: str,
        client_secret: str,
        client_name: str,
        redirect_uris: list[str],
        grant_types: list[str],
        response_types: list[str],
        scope: str,
    ):
        """Create a new OAuth client."""
        with self._connection() as conn:
            conn.execute(
                """INSERT INTO clients 
                   (client_id, client_secret, client_name, redirect_uris, grant_types, response_types, scope, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    client_id,
                    client_secret,
                    client_name,
                    ",".join(redirect_uris),
                    ",".join(grant_types),
                    ",".join(response_types),
                    scope,
                    int(time.time()),
                ),
            )

    def get_client(self, client_id: str) -> dict | None:
        """Get OAuth client by client_id."""
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM clients WHERE client_id = ?", (client_id,)).fetchone()
            if not row:
                return None
            client = dict(row)
            # Convert comma-separated strings back to lists
            client["redirect_uris"] = client["redirect_uris"].split(",")
            client["grant_types"] = client["grant_types"].split(",")
            client["response_types"] = client["response_types"].split(",")
            return client

    def create_oauth_flow(
        self,
        state: str,
        client_id: str,
        redirect_uri: str,
        scopes: str,
        code_challenge: str | None,
        expires_at: int,
    ):
        """Create a new OAuth flow entry."""
        with self._connection() as conn:
            conn.execute(
                """INSERT INTO oauth_flows 
                   (state, client_id, redirect_uri, scopes, code_challenge, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (state, client_id, redirect_uri, scopes, code_challenge, expires_at),
            )

    def get_oauth_flow(self, state: str) -> dict | None:
        """Get OAuth flow by state."""
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM oauth_flows WHERE state = ?", (state,)).fetchone()
            return dict(row) if row else None

    def update_oauth_flow(self, state: str, code: str, user_id: int):
        """Update OAuth flow with authorization code and user."""
        with self._connection() as conn:
            conn.execute(
                "UPDATE oauth_flows SET code = ?, user_id = ? WHERE state = ?",
                (code, user_id, state),
            )

    def get_oauth_flow_by_code(self, code: str) -> dict | None:
        """Get OAuth flow by authorization code."""
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM oauth_flows WHERE code = ?", (code,)).fetchone()
            return dict(row) if row else None

    def create_session(
        self,
        token: str,
        user_id: int,
        client_id: str,
        scopes: str,
        expires_at: int,
        oauth_state_id: str | None = None,
    ):
        """Create a new session (access token)."""
        with self._connection() as conn:
            # For simplicity, we'll store oauth_state_id in the scopes field as a prefix
            # In a real implementation, you'd add a column to the sessions table
            conn.execute(
                """INSERT INTO sessions 
                   (token, user_id, client_id, scopes, expires_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (token, user_id, client_id, scopes, expires_at),
            )

    def get_session(self, token: str) -> dict | None:
        """Get session by token."""
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE token = ? AND expires_at > ?",
                (token, int(time.time())),
            ).fetchone()
            return dict(row) if row else None

    def create_refresh_token(
        self, token: str, user_id: int, client_id: str, scopes: str, expires_at: int
    ):
        """Create a new refresh token."""
        with self._connection() as conn:
            conn.execute(
                """INSERT INTO refresh_tokens 
                   (token, user_id, client_id, scopes, expires_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (token, user_id, client_id, scopes, expires_at),
            )

    def get_refresh_token(self, token: str) -> dict | None:
        """Get refresh token if valid and not revoked."""
        with self._connection() as conn:
            row = conn.execute(
                """SELECT * FROM refresh_tokens 
                   WHERE token = ? AND expires_at > ? AND revoked = 0""",
                (token, int(time.time())),
            ).fetchone()
            return dict(row) if row else None

    def revoke_refresh_token(self, token: str):
        """Revoke a refresh token."""
        with self._connection() as conn:
            conn.execute("UPDATE refresh_tokens SET revoked = 1 WHERE token = ?", (token,))

    def cleanup_expired(self):
        """Remove expired sessions and flows."""
        now = int(time.time())
        with self._connection() as conn:
            conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            conn.execute("DELETE FROM oauth_flows WHERE expires_at < ?", (now,))
            conn.execute("DELETE FROM refresh_tokens WHERE expires_at < ? AND revoked = 1", (now,))
