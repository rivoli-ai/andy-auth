# Go OAuth Example

This example demonstrates how to integrate Andy Auth with a Go application using the standard `oauth2` package and `gorilla/sessions` for session management.

## Prerequisites

- Go 1.21+
- Andy Auth server running (default: https://localhost:7088)

## Setup

1. Register your client in Andy Auth or use Dynamic Client Registration

2. Set environment variables (optional):

```bash
export ANDY_AUTH_SERVER=https://localhost:7088
export CLIENT_ID=my-go-app
export CLIENT_SECRET=your-client-secret
export REDIRECT_URL=http://localhost:8080/callback
export SESSION_KEY=change-this-in-production
```

## Running

```bash
cd examples/go-oauth
go mod download
go run main.go
```

The application will start at http://localhost:8080

## Features Demonstrated

- OAuth 2.0 Authorization Code Flow
- PKCE (Proof Key for Code Exchange)
- Session management with secure cookies
- UserInfo endpoint access
- Token management

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

See the full tutorial at: `/docs/tutorials/go.html`
