# Andy Auth Server

Self-hosted OAuth 2.0 / OpenID Connect server built with ASP.NET Core and OpenIddict.

## Features

- **OAuth 2.0 & OpenID Connect** - Standards-compliant authentication server
- **Multiple Grant Types** - Authorization Code, Client Credentials, Refresh Tokens
- **PKCE Support** - Secure authentication for public clients
- **MCP Compatible** - Full Model Context Protocol OAuth 2.1 support for AI assistants
- **Dynamic Client Registration** - RFC 7591/7592 compliant DCR
- **User Management** - Complete admin UI for managing users and OAuth clients
- **Audit Logging** - Track all authentication and authorization events
- **Security Hardened** - Rate limiting, account lockout, security headers

## Quick Start

### Prerequisites

- .NET 8.0 SDK
- Docker Desktop (for PostgreSQL)
- IDE (VS Code, Visual Studio, or Rider)

### Local Development

```bash
# 1. Start PostgreSQL
docker-compose up -d

# 2. Run the server
cd src/Andy.Auth.Server
dotnet run
```

Server runs at: **https://localhost:7088**

**Test credentials:**
- Email: `test@andy.local`
- Password: `Test123!`

See [docs/LOCAL-SETUP.md](./docs/LOCAL-SETUP.md) for detailed setup instructions.

## Andy.Auth Client Library

In addition to the OAuth server, this repository includes **Andy.Auth**, a NuGet library for easy integration with ASP.NET Core APIs.

**Installation:**
```bash
dotnet add package Andy.Auth
```

**Usage:**
```csharp
// Add to Program.cs
builder.Services.AddAndyAuth(builder.Configuration);
```

See [docs/LIBRARY.md](./docs/LIBRARY.md) for complete documentation.

## What's Included

### OAuth/OIDC Server
- Authorization endpoint (`/connect/authorize`)
- Token endpoint (`/connect/token`)
- Introspection endpoint (`/connect/introspect`)
- Revocation endpoint (`/connect/revoke`)
- Dynamic Client Registration (`/connect/register`)
- OpenID Discovery (`/.well-known/openid-configuration`)
- JWKS endpoint (`/.well-known/jwks`)

### Admin Dashboard
- **Users**: View, suspend, expire, soft delete users
- **OAuth Clients**: Manage registered applications
- **Tokens**: View and revoke active tokens
- **Audit Logs**: Track all authentication events

Access at: **/Admin**

### Seeded OAuth Clients

| Client | Type | Use Case |
|--------|------|----------|
| `lexipro-api` | Confidential | Server-to-server communication |
| `wagram-web` | Public SPA | Angular/React web applications |
| `claude-desktop` | Public | Claude Desktop MCP integration |
| `chatgpt` | Public | ChatGPT MCP integration |
| `cline` | Public | Cline VS Code extension |
| `roo` | Public | Roo VS Code extension |
| `continue-dev` | Public | Continue.dev extension |

## Security Features

- Rate limiting on all auth endpoints
- Account lockout (30 min after 5 failed attempts)
- Password requirements (8+ chars, uppercase, lowercase, digit)
- Security headers (CSP, X-Frame-Options, HSTS)
- CSRF protection on all forms
- SQL injection protection (EF Core)
- XSS protection (Razor auto-encoding)
- HTTPS enforcement in production

See [docs/SECURITY.md](./docs/SECURITY.md) for complete security documentation.

## Technology Stack

- **Framework**: ASP.NET Core 8.0
- **Authentication**: ASP.NET Core Identity
- **OAuth/OIDC**: OpenIddict 5.x
- **Database**: PostgreSQL 16
- **ORM**: Entity Framework Core
- **UI**: Razor Views with custom CSS

## Deployment

### Railway

Deploy to Railway:

1. Push to GitHub
2. Connect Railway project
3. Configure environment variables
4. Deploy

See [docs/DEPLOYMENT.md](./docs/DEPLOYMENT.md) for complete deployment guide.

### Docker

```bash
docker build -t andy-auth .
docker run -p 8080:8080 andy-auth
```

## Documentation

| Document | Description |
|----------|-------------|
| [LOCAL-SETUP.md](./docs/LOCAL-SETUP.md) | Development setup guide |
| [ARCHITECTURE.md](./docs/ARCHITECTURE.md) | System architecture |
| [SECURITY.md](./docs/SECURITY.md) | Security features |
| [ADMIN.md](./docs/ADMIN.md) | Admin UI documentation |
| [DEPLOYMENT.md](./docs/DEPLOYMENT.md) | Production deployment |
| [TESTING.md](./docs/TESTING.md) | Testing guide |
| [LIBRARY.md](./docs/LIBRARY.md) | Client library documentation |
| [ASSISTANT-INTEGRATION.md](./docs/ASSISTANT-INTEGRATION.md) | AI assistant setup |

## Testing

Run all tests:
```bash
# .NET unit tests
dotnet test

# Python OAuth tests (against UAT)
cd tests/oauth-python
ANDY_AUTH_TEST_PASSWORD="Test123!" python3 run_all_tests.py --env uat
```

**Current Status:**
- .NET unit tests: 54/54 passed (100%)
- Python OAuth tests: 42/42 passed (100%)

See [docs/TESTING.md](./docs/TESTING.md) for testing guide.

## Contributing

This is a private repository for Rivoli AI. Contributions are welcome from team members.

## License

Apache 2.0

---

**Status:** Production (UAT deployed)
**Version:** 1.0.0
**Last Updated:** 2025-12-16
