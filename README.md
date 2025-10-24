# MCP OAuth Server

Portable OAuth implementation for MCP servers that handles auth/discovery, allowing developers to implement tools without worrying about auth infrastructure.

## Features

- SQLite-based session management
- Bcrypt password hashing
- OAuth 2.0 authorization code flow with PKCE
- Refresh token support
- Simple file-based user management

## Quick Start

1. Install dependencies:

Using uv (recommended):

```bash
uv pip install -e .
```

Or using pip:

```bash
pip install -r requirements.txt
```

2. Create a user account:

Create `users.txt` in the repo root:

```bash
echo "alice:$(python3 -c 'import bcrypt; print(bcrypt.hashpw(b"password123", bcrypt.gensalt()).decode())')" > users.txt
```

3. Run the server:

```bash
python3 -m src.server
```

The server will auto-create `auth.db` on first run.

4. Test with the example client:

```bash
python3 examples/client_example.py
```

## Configuration with MCP Clients

To use with Claude Desktop or other MCP clients, add to your configuration file:

```json
{
  "mcpServers": {
    "example-oauth-server": {
      "command": "python3",
      "args": ["-m", "src.server"],
      "cwd": "/absolute/path/to/mcp-base",
      "env": {}
    }
  }
}
```

See `examples/claude_desktop_config.json` for a full example.

## Architecture

### Storage

- `auth.db` - SQLite database (auto-created)
- `users.txt` - username:password_hash pairs

### Database Schema

- `users` - user credentials
- `oauth_flows` - authorization flow state
- `sessions` - access tokens
- `refresh_tokens` - refresh tokens

### Configuration

Default token lifetimes (configurable in code):

- Access tokens: 30 days
- Refresh tokens: 30 days

## Extending the Server

To add your own tools, edit `src/server.py`:

```python
@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="your_tool",
            description="Description of your tool",
            inputSchema={
                "type": "object",
                "properties": {
                    "param": {"type": "string"}
                }
            }
        )
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "your_tool":
        # Your tool implementation
        return [TextContent(type="text", text="Result")]
```

## Development

Run tests:

```bash
pytest
```

Lint:

```bash
ruff check src tests
```

Format:

```bash
ruff format src tests
```
