# MCP OAuth Server

A Python library that adds OAuth 2.0 authentication to MCP servers with minimal setup.

## Installation

```bash
pip install -e .
# or
uv pip install -e .
```

## Quick Start

### 1. Decide how you want to store users

e.g. make a `users.txt` file like:

```
alice:cows
bob:dogs
```

### 2. Create your MCP server

```python
from mcp_base import create_oauth_server


def check_user(username: str, password: str) -> int:
  with open("users.txt") as f:
    for i, line in enumerate(f.readlines()):
      if line == f"{username}:{password}":
        return i

# Create server with defaults
mcp = create_oauth_server("my-app", check_user)

# Add your tools
@mcp.tool()
def echo(message: str) -> str:
    """Echo back the input message."""
    return f"Echo: {message}"

# Run the server
if __name__ == "__main__":
    mcp.run(transport="streamable-http")
```

### 3. Run it

```bash
python your_server.py
```

That's it! Your MCP server now has OAuth authentication running on `http://localhost:3000`.

## User config

OAuth requires a bunch of complicated flows, but often you just want a user + password. This
is what this library is for. You come up with your desired way of checking users, and provide
a function that returns the id of a valid user, and None if the user and password combination is
incorrect. The library takes care of the rest for you.

## Login screen

The OAuth flow requires you to verify that a user going through the flow is a valid user.
A default HTML login page is provided by default that requests a username and password.
If you want to customize this, you can either provide your own HTML that is to be used, via
the `login_template` parameter, or provide a custom handler that will take care of incoming requests.

### Login templates

A login template is a chunk of HTML. This will be displayed to the user for them to provide credentials.
The default handler expects a form with a `state` value for OAuth stuff, and a `username` and `password`
with the user credentials. The following macros will be replaced in the HTML (by using a very simple
string replace, so make sure to use these exact strings):

* `{state}` - the OAuth state, as provided in the GET URL or POST form data
* `{username}` - you can use this to keep the username if an invalid password was provided
* `{app_name}` - the name of your app, as provided to `create_oauth_server`
* `{error_message}` - any exception that happened during validation

### Custom login handler

The OAuth flow requires `/oauth/login` to be called via a GET request, and for a subsequent redirect
to an appropriate endpoint for the flow to continue. The first part is hard coded, while the redirect
is provided by any client when they initialise the flow. That being said, you can control how this happens.

To use your own handler, provide a function with the following signature to the `login_handler` of the
`create_oauth_server` call:

```python
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse

async def login_handler(request: Request, complete_user_checker: Callable[[str, str, str], str]) -> HTMLResponse | RedirectResponse:
  (...)
```

`request` is the Starlette request. `complete_user_checker` is a function that receives the OAuth
state, usernam and password, and returns a redirect url if correct, or raises a ValueError if anything
is incorrect.

Basically, you extract the state from the request (`request.query_params.get("state")`), extract the
username and password however you want, then do a:

```python
try:
  redirect_url = complete_user_checker(state, username, password)
  return RedirectResponse(url=redirect_url, status_code=302)
except ValueError as e:
  # handle the error
```

## Custom Configuration

```python
from mcp_base import create_oauth_server, ServerConfig

config = ServerConfig(
    host="localhost",
    port=8000,
    db_path="my_auth.db",
    supported_scopes=["read", "write", "admin"],
    required_scopes=["read"],
    debug=True,
)

mcp = create_oauth_server("my-app", config=config)
```

## Examples

See the [examples/](examples/) directory for complete examples:

* `simple_server.py` - Basic usage
* `custom_server.py` - Custom configuration  
* `file_credentials_server.py` - users are defined in `users.txt`

# Deployment

If you want to run behind an Nginx proxy, then the following should do the trick:

```
server {
    server_name <your domain>;

    # Basic security headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Rate limiting (optional)
    # limit_req zone=api burst=20 nodelay;

    # Handle MCP endpoint redirect internally

    # Proxy everything to your memory app
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

Where `<your domain>` should be changed to whatever your actual domain is, and `http://localhost:3000` to
whereever you're running your MCP server.

# Testing

It's non trivial to test MCP stuff manually, so you probably want something like the
[MCP inspector](https://github.com/modelcontextprotocol/inspector) before you actually
try using a model with things.
