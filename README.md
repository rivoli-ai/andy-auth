# Andy Auth Server

Self-hosted OAuth 2.0 / OpenID Connect server built with ASP.NET Core and OpenIddict.

> **ALPHA RELEASE WARNING**
>
> This software is in ALPHA stage. **NO GUARANTEES** are made about its functionality, stability, or safety.
>
> **CRITICAL WARNINGS:**
> - This tool performs **DESTRUCTIVE OPERATIONS** on files and directories
> - Permission management is **NOT FULLY TESTED** and may have security vulnerabilities
> - **DO NOT USE** in production environments
> - **DO NOT USE** on systems with critical or irreplaceable data
> - **DO NOT USE** on systems without complete, verified backups
> - The authors assume **NO RESPONSIBILITY** for data loss, system damage, or security breaches
>
> **USE AT YOUR OWN RISK**

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

Server runs at: **https://localhost:5001**

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
- End-session / RP-initiated logout (`/connect/logout`)
- Device authorization (`/connect/device`, `/connect/verify`)
- OpenID Discovery (`/.well-known/openid-configuration`)
- JWKS endpoint (`/.well-known/jwks`)
- Protected resource metadata (`/.well-known/oauth-protected-resource`)

### Admin Dashboard
- **Users**: View, suspend, expire, soft delete users
- **OAuth Clients**: Manage registered applications
- **Tokens**: View and revoke active tokens
- **Audit Logs**: Track all authentication events

Access at: **/Admin**

### Seeded OAuth Clients

| Client | Type | Use Case |
|--------|------|----------|
| `andy-docs-api` | Confidential | Server-to-server communication |
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
- Security headers (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HSTS). CSP ships **disabled** by default — enable with `SecurityHeaders:EnableCsp` (tracked in [#128](https://github.com/rivoli-ai/andy-auth/issues/128))
- CSRF protection on OAuth client, DCR and user-creation forms. Several destructive admin POSTs are still unprotected (tracked in [#51](https://github.com/rivoli-ai/andy-auth/issues/51))
- SQL injection protection (EF Core)
- XSS protection (Razor auto-encoding)
- HTTPS enforcement in production

See [docs/SECURITY.md](./docs/SECURITY.md) for complete security documentation.

## Technology Stack

- **Framework**: ASP.NET Core 8.0
- **Authentication**: ASP.NET Core Identity
- **OAuth/OIDC**: OpenIddict 7.x
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

The Dockerfile trusts corporate root CAs from `certs/`, supplied as a named
build context. Without it the build fails at the `COPY --from=certs` step:

```bash
docker build --build-context certs=./certs -t andy-auth .
docker run -p 8080:8080 andy-auth
```

`docker compose build` passes the context automatically (see
`additional_contexts` in `docker-compose.yml`).

## Examples

Working example applications for integrating with Andy Auth:

| Example | Language/Framework | Description |
|---------|-------------------|-------------|
| [csharp-web](./examples/csharp-web/) | C# / ASP.NET Core | .NET 8 with OpenID Connect |
| [python-flask](./examples/python-flask/) | Python / Flask | OAuth 2.0 + PKCE |
| [javascript-express](./examples/javascript-express/) | JavaScript / Express | OAuth 2.0 + PKCE |
| [typescript-express](./examples/typescript-express/) | TypeScript / Express | Type-safe OAuth 2.0 |
| [java-spring](./examples/java-spring/) | Java / Spring Boot | Spring Security OAuth |
| [go-oauth](./examples/go-oauth/) | Go | Standard library + oauth2 |
| [rust-oauth](./examples/rust-oauth/) | Rust / Axum | Axum + oauth2 crate |

Run all examples tests:
```bash
./examples/test-examples.sh
```

## Documentation

**Interactive docs:** Run the server and visit **/docs/** for full documentation with tutorials.

| Document | Description |
|----------|-------------|
| [LOCAL-SETUP.md](./docs/LOCAL-SETUP.md) | Development setup guide |
| [ARCHITECTURE.md](./docs/ARCHITECTURE.md) | System architecture |
| [SECURITY.md](./docs/SECURITY.md) | Security features |
| [ADMIN.md](./docs/ADMIN.md) | Admin UI documentation |
| [DEPLOYMENT.md](./docs/DEPLOYMENT.md) | Production deployment |
| [testing.md](./docs/testing.md) | Testing guide |
| [LIBRARY.md](./docs/LIBRARY.md) | Client library documentation |
| [ASSISTANT-INTEGRATION.md](./docs/ASSISTANT-INTEGRATION.md) | AI assistant setup |

## Testing

Run all tests:
```bash
# Integration tests need the dev PostgreSQL from docker-compose
docker-compose up -d postgres

# .NET unit tests
dotnet test

# Python OAuth tests (against UAT)
cd tests/oauth-python
ANDY_AUTH_TEST_PASSWORD="Test123!" python3 run_all_tests.py --env uat
```

**Current Status:** See [docs/testing.md](./docs/testing.md) for the latest test counts and pass rates.

See [docs/testing.md](./docs/testing.md) for testing guide.

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, and pull requests.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

Apache 2.0

---

**Status:** Alpha (UAT deployed for testing)
**Version:** 0.1.0-alpha
**Last Updated:** 2026-01-13
