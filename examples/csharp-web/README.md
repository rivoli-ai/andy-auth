# C# / .NET Web Application Example

This example demonstrates how to integrate Andy Auth with a .NET 8 web application using OpenID Connect.

## Prerequisites

- .NET 8 SDK
- Andy Auth server running (default: https://localhost:7088)

## Setup

1. Register your client in Andy Auth or use Dynamic Client Registration
2. Update `appsettings.json` with your client credentials:

```json
{
  "AndyAuth": {
    "Authority": "https://localhost:7088",
    "ClientId": "my-csharp-app",
    "ClientSecret": "your-client-secret"
  }
}
```

## Running

```bash
cd examples/csharp-web
dotnet run
```

The application will start at https://localhost:5001

## Features Demonstrated

- OpenID Connect authentication with PKCE
- Cookie-based session management
- Login and logout flows
- Accessing user claims
- Retrieving access/ID/refresh tokens

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `/` | Home page with login status |
| `/Account/login` | Initiates OAuth login |
| `/Account/logout` | Logs out the user |
| `/Account/profile` | Returns user claims as JSON |
| `/Account/tokens` | Returns current tokens |
| `/Home/Secure` | Protected page requiring authentication |

## Documentation

See the full tutorial at: `/docs/tutorials/csharp.html`
