# Python Flask Example

This example demonstrates how to integrate Andy Auth with a Python Flask application using OAuth 2.0 with PKCE.

## Prerequisites

- Python 3.10+
- Andy Auth server running (default: https://localhost:7088)

## Setup

1. Create a virtual environment:

```bash
cd examples/python-flask
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Register your client in Andy Auth or use Dynamic Client Registration

4. Set environment variables (optional):

```bash
export ANDY_AUTH_SERVER=https://localhost:7088
export CLIENT_ID=my-python-app
export REDIRECT_URI=http://localhost:5000/callback
export SECRET_KEY=your-secret-key
```

## Running

```bash
python app.py
```

The application will start at http://localhost:5000

## Features Demonstrated

- OAuth 2.0 Authorization Code flow with PKCE
- OpenID Connect discovery
- Token exchange and storage
- User info retrieval
- Token refresh
- Session management

## Files

| File | Description |
|------|-------------|
| `andy_auth_client.py` | Reusable OAuth client with PKCE support |
| `app.py` | Flask application with OAuth routes |
| `requirements.txt` | Python dependencies |

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `/` | Home page with login status |
| `/login` | Initiates OAuth login |
| `/callback` | OAuth callback handler |
| `/logout` | Clears session and logs out |
| `/profile` | Returns user info as JSON |
| `/tokens` | Shows current token info |
| `/refresh` | Refreshes the access token |

## Documentation

See the full tutorial at: `/docs/tutorials/python.html`
