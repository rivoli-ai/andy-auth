# JavaScript / Express Example

This example demonstrates how to integrate Andy Auth with a Node.js Express application using OAuth 2.0 with PKCE.

## Prerequisites

- Node.js 18+
- Andy Auth server running (default: https://localhost:7088)

## Setup

1. Install dependencies:

```bash
cd examples/javascript-express
npm install
```

2. Register your client in Andy Auth or use Dynamic Client Registration

3. Set environment variables (optional):

```bash
export ANDY_AUTH_SERVER=https://localhost:7088
export CLIENT_ID=my-js-app
export CLIENT_SECRET=
export REDIRECT_URI=http://localhost:3000/callback
export SESSION_SECRET=your-secret-key
```

## Running

```bash
npm start
# or for development with auto-reload:
npm run dev
```

The application will start at http://localhost:3000

## Features Demonstrated

- OAuth 2.0 Authorization Code flow with PKCE
- OpenID Connect discovery
- Token exchange using native fetch API
- Session management with express-session
- User info retrieval

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `/` | Home page with login status |
| `/login` | Initiates OAuth login |
| `/callback` | OAuth callback handler |
| `/logout` | Clears session and logs out |
| `/profile` | Returns user info as JSON |
| `/tokens` | Shows current token info |

## Documentation

See the full tutorial at: `/docs/tutorials/javascript.html`
