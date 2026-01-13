# Rust OAuth Example

This example demonstrates how to integrate Andy Auth with a Rust application using the `oauth2` crate and the Axum web framework.

## Prerequisites

- Rust 1.70+
- Andy Auth server running (default: https://localhost:7088)

## Setup

1. Register your client in Andy Auth or use Dynamic Client Registration

2. Set environment variables (optional):

```bash
export ANDY_AUTH_SERVER=https://localhost:7088
export CLIENT_ID=my-rust-app
export CLIENT_SECRET=your-client-secret
export REDIRECT_URL=http://localhost:3000/callback
```

## Running

```bash
cd examples/rust-oauth
cargo run
```

The application will start at http://localhost:3000

## Features Demonstrated

- OAuth 2.0 Authorization Code Flow
- PKCE (Proof Key for Code Exchange)
- Session management with tower-sessions
- UserInfo endpoint access
- Axum web framework integration

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `/` | Home page with login status |
| `/login` | Initiates OAuth login with PKCE |
| `/callback` | OAuth callback handler |
| `/logout` | Logs out the user |
| `/profile` | Returns user claims as JSON |
| `/tokens` | Returns current token info |

## Documentation

See the full tutorial at: `/docs/tutorials/rust.html`
