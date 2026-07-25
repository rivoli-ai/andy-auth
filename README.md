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
| `andy-docs-web` | Public SPA | Angular/React web applications (renamed from `wagram-web` per andy-auth#25) |
| `claude-desktop` | Public | Claude Desktop MCP integration |
| `chatgpt` | Public | ChatGPT MCP integration |
| `cline` | Public | Cline VS Code extension |
| `roo` | Public | Roo VS Code extension |
| `continue-dev` | Public | Continue.dev extension |

## Security Features

- Rate limiting on all auth endpoints (keyed on the trusted, proxy-normalized client IP — not a spoofable header)
- Account lockout (30 min after 5 failed attempts)
- Password requirements (8+ chars, uppercase, lowercase, digit)
- Security headers including a nonce-based Content-Security-Policy (enabled by default in Production/UAT), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HSTS
- Forwarded headers honored only from configured trusted proxies (per-mode `ForwardedHeaders` config)
- CSRF protection on all forms, enforced at controller scope on the admin surface
- SQL injection protection (EF Core)
- XSS protection (Razor auto-encoding)
- HTTPS enforcement in production
- Liveness (`/health`) and readiness (`/ready`) probes; readiness gates traffic on successful migration + seeding

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

```bash
docker build --build-context certs=./certs -t andy-auth .
docker run -p 8080:8080 andy-auth
```

`certs` is a named build context the Dockerfile expects; `docker compose build`
supplies it automatically (see `additional_contexts` in `docker-compose.yml`).

The image runs as a **non-root** user (`app`, uid 1654) and contains no build
tooling. Two paths are writable by that user: `/data/keys` for the persisted
OpenIddict signing keypair, and `/https` for the development certificate used
by the compose stack.

Corporate TLS interception is opt-in rather than the default — the image used
to ship with NuGet signature verification and certificate revocation checking
disabled outright:

```bash
docker build --build-context certs=./certs \
  --build-arg TRUST_CORPORATE_CA=true \
  --build-arg NUGET_CERT_REVOCATION_MODE=offline \
  -t andy-auth .
```

Base images are pinned to explicit patch tags (`DOTNET_SDK_TAG`,
`DOTNET_RUNTIME_TAG`) so a rebuild is reproducible and a bump is a reviewable
commit.

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
