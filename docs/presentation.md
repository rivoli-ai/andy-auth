---
marp: true
theme: default
paginate: true
size: 16:9
header: 'Andy Auth — End-to-End Walkthrough'
footer: 'Rivoli AI · andy-auth'
style: |
  section { font-size: 24px; }
  section h1 { color: #1f4e79; }
  section h2 { color: #2e75b6; border-bottom: 2px solid #2e75b6; padding-bottom: 4px; }
  code { background: #f4f4f4; padding: 2px 4px; border-radius: 3px; }
  pre { font-size: 18px; }
  table { font-size: 20px; }
---

<!-- _class: lead -->
<!-- _paginate: false -->

# Andy Auth
## End-to-End System Walkthrough

The self-hosted OAuth 2.0 / OpenID Connect identity provider at the center of the Andy ecosystem.

*Designed for engineers who have never seen this service before.*

---

## What is Andy Auth?

A **self-hosted OAuth 2.0 + OIDC server** built on OpenIddict. It authenticates users, issues JWTs, and is the single identity provider for every other Andy service.

- User login + 2FA (TOTP)
- OAuth2 + OIDC (authorization code + PKCE, client credentials, refresh)
- Dynamic Client Registration (RFC 7591)
- MCP client registration for Claude Desktop / ChatGPT / Cursor
- Admin UI for users, clients, tokens, audit logs
- A NuGet client library (`Andy.Auth`) for downstream services

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Runtime | .NET 8.0 |
| OAuth server | **OpenIddict 7.2** |
| Identity | ASP.NET Core Identity (PBKDF2, 100k iterations, lockout) |
| UI | Razor Pages / MVC Views |
| Database | PostgreSQL 16 (default) / SQLite (embedded) |
| ORM | Entity Framework Core 8 |
| Rate limiting | AspNetCoreRateLimit |
| MCP | ModelContextProtocol 0.2.0-preview |
| Testing | xUnit + Playwright E2E + Python OAuth suite |

---

## Solution Layout

```
andy-auth/
├── src/
│   ├── Andy.Auth.Server/          ← OAuth/OIDC server (web)
│   └── Andy.Auth/                 ← NuGet client library
├── tests/
│   ├── Andy.Auth.Server.Tests/    ← unit (54 tests)
│   ├── Andy.Auth.Tests/           ← client lib tests
│   └── Andy.Auth.E2E.Tests/       ← Playwright
├── examples/csharp-web/           ← reference integration
└── oauth-python/                  ← 42-test external suite
```

6 `.csproj` in total. The client library is the integration contract.

---

## Identity Model

**`ApplicationUser`** (`Data/ApplicationUser.cs`) extends `IdentityUser`:

- `Email` (unique), `FullName`, `ProfilePictureUrl`
- `IsActive`, `IsSuspended`, `SuspensionReason`
- `IsDeleted` (soft), `IsSystemUser`, `MustChangePassword`
- `CreatedAt`, `LastLoginAt`, `ExpiresAt`

**Roles** (seeded): `Admin`, `User`.

**Standard OIDC claims**: `openid`, `profile`, `email`, `roles`, `offline_access`.

**Custom resource scopes**: `urn:andy-docs-api`, `urn:andy-issues-api`, `urn:andy-agents-api`, `urn:andy-code-index-api`, `urn:andy-containers-api`, `urn:andy-narration-api`, `urn:andy-subscription-api`, `urn:andy-tasks-api`, `andy-rbac`.

---

## Supported OAuth 2.0 / OIDC Flows

**Supported** (`Program.cs:156–158`):

- Authorization Code (web apps)
- **Authorization Code + PKCE** (SPAs, CLIs, AI clients)
- Client Credentials (server-to-server)
- Refresh Token (with rotation)

**Intentionally unsupported**: Implicit, Resource Owner Password.

---

## Registered OAuth Clients

| Client | Type | Purpose |
|--------|------|---------|
| `andy-docs-api` | Confidential | S2S for MCP backend |
| `wagram-web` | Public SPA | Angular/React web app |
| `claude-desktop` | Public | Claude Desktop MCP |
| `chatgpt` | Public | ChatGPT MCP |
| `cline`, `roo`, `continue-dev` | Public | VS Code extensions |

Seeded in `DbSeeder.cs:198+`. MCP clients use specific redirect URIs like `https://claude.ai/api/mcp/auth_callback`.

**Dev test user**: `test@andy.local` / `Test123!`.

---

## OAuth / OIDC Endpoints

Configured in `Program.cs:139–142`:

- `GET/POST /connect/authorize` — authorization (PKCE)
- `POST /connect/token` — token exchange
- `POST /connect/introspect` — token state check
- `POST /connect/revoke` — revoke refresh token
- `GET /.well-known/openid-configuration` — discovery
- `GET /.well-known/jwks` — public signing keys

**Dynamic Client Registration** (RFC 7591):

- `POST /connect/register` — register new client
- `GET / POST / DELETE /connect/register/{client_id}` — manage

---

## Custom Controllers

| Controller | Surface |
|------------|---------|
| `AccountController` | `/Account/Login`, `/Register`, `/Logout`, `/ChangePassword` |
| `AuthorizationController` | `/connect/authorize` — redirects to login if needed |
| `ConsentController` | `/Consent` — scope consent UI |
| `TwoFactorController` | TOTP setup, recovery codes, 2FA login |
| `SessionController` | session listing & revocation |
| `DynamicClientRegistrationController` | RFC 7591 endpoints |
| `AdminController` | `/Admin/Users`, `/Clients`, `/Tokens`, `/AuditLogs` |
| `McpUsersController` | MCP-specific identity operations |

---

## The Login UI (Razor Pages)

- `/Account/Login` — email + password (rate-limited 10/min)
- `/Account/Register` — 3 per hour
- `/Consent/Index` — friendly scope descriptions
- `/TwoFactor/EnableAuthenticator` — QR for TOTP
- `/TwoFactor/ShowRecoveryCodes`
- `/Admin/Users | Clients | Tokens | AuditLogs`
- `/Home/Index`, `/Home/Error`

Minimal vanilla JS; custom CSS — no frontend framework.

---

## Token Format

**Access Token** — RS256-signed JWT (not encrypted):

```json
{
  "sub": "<user-id>",
  "aud": "urn:andy-docs-api",
  "scope": "openid profile email offline_access urn:andy-docs-api",
  "iss": "https://auth.rivoli.ai",
  "exp": 1234567890,
  "email": "user@example.com",
  "name": "…"
}
```

**ID Token** — encrypted + signed (OIDC).
**Refresh Token** — reference token stored in DB → revocable via `/connect/revoke`.

Lifetimes: access **1 hour**, refresh **14 days** (rotated).

---

## Signing Keys

**Dev / Staging / UAT** — ephemeral RSA keys generated on startup (see `Program.cs:160–190`).

**Production** — requires explicit key configuration (key vault or `OpenIddict:UseEphemeralKeys`).

JWKS endpoint returns only public keys. Reference refresh tokens (`options.UseReferenceRefreshTokens()`) let ops revoke individual sessions.

---

## How Other Services Consume Tokens

Ship a downstream service via the **`Andy.Auth` NuGet package**:

```csharp
// Program.cs
builder.Services.AddAndyAuth(builder.Configuration);
```

`appsettings.json`:

```json
{
  "AndyAuth": {
    "Provider": "AndyAuth",
    "Authority": "https://auth.rivoli.ai",
    "Audience": "urn:andy-docs-api"
  }
}
```

Then `[Authorize]` on controllers. Middleware fetches JWKS, validates RS256, checks `aud`/`iss`/`exp`.

---

## Security Layers

- **PKCE** — prevents auth code interception
- **State param** — CSRF protection on `/authorize` round-trip
- **Rate limits** — Login 10/min, Register 3/h, `/token` 30/min, DCR 20/h
- **Account lockout** — 5 failed logins → 30 min lockout
- **Reference refresh tokens** — revocable without rotating signing keys
- **Audit log** — admin actions recorded (`/Admin/AuditLogs`)
- **2FA** — TOTP with recovery codes
- HTTPS enforced in production (`Program.cs:308`)

---

## Data Flow — Auth Code + PKCE Login (1/2)

1. **SPA** generates `code_verifier` + `code_challenge = Base64URL(SHA256(verifier))`
2. **SPA** → `GET /connect/authorize?client_id=wagram-web&response_type=code&code_challenge=…&code_challenge_method=S256&scope=openid profile email offline_access urn:andy-docs-api`
3. **AuthorizationController**: not authenticated → `Challenge()` → redirect to `/Account/Login`
4. **User** submits email+password → cookie set → back to `/connect/authorize`
5. **Consent screen** (first time) — user clicks **Allow**
6. **Server** mints authorization `code` (~10 min TTL, stores `code_challenge`)
7. **Redirect** → `https://wagram.ai/callback?code=…&state=…`

---

## Data Flow — Auth Code + PKCE Login (2/2)

8. **SPA** → `POST /connect/token`
   `grant_type=authorization_code&code=…&code_verifier=…`
9. **Token endpoint**:
   - Verify `code` exists + not expired
   - Verify `SHA256(code_verifier) == stored code_challenge`
   - Verify `redirect_uri` matches
10. Issue **access_token** (JWT, 1h), **id_token**, **refresh_token** (reference, 14d)
11. **SPA** → `Authorization: Bearer <jwt>` on every `/api` call
12. **Downstream service** validates via JWKS + `aud` + `iss` + `exp`
13. Access expires → **refresh** via `grant_type=refresh_token` → new access + rotated refresh

---

## MCP Integration

AI clients (Claude Desktop, ChatGPT, Cursor) hit OAuth endpoints using the same PKCE flow with callback URLs like:

- `https://claude.ai/api/mcp/auth_callback`
- `https://chat.openai.com/api/mcp/auth_callback`

MCP endpoint at `POST /mcp` (`Program.cs:366–368`) requires OAuth; tools provided by `AuthMcpTools` expose group management to agents.

**RFC 7591 DCR** lets new MCP clients self-register without admin intervention (optional approval workflow).

---

## Configuration & Ports

| Port | Purpose |
|------|---------|
| 5001 | OAuth server HTTPS (dev) |
| 5002 | OAuth server HTTP (dev) |
| 5435 | PostgreSQL (docker-compose) |

Key settings:

- `ConnectionStrings.DefaultConnection`
- `Database.Provider` — `PostgreSql` / `Sqlite`
- `CorsOrigins.AllowedOrigins`
- `DynamicClientRegistration.{Enabled, RequireInitialAccessToken, RequireAdminApproval}`
- `IpRateLimiting.*`
- `OpenIddict.UseEphemeralKeys` — `true` in cloud

---

## Docker

Multi-stage Dockerfile:

1. `dotnet/sdk:8.0` — build + publish
2. `dotnet/aspnet:8.0` — runtime, non-root, self-signed dev cert auto-generated, corporate CAs installable via mount

`docker-compose.yml`:

- `postgres:16-alpine` with healthcheck
- `adminer` for DB inspection
- Auth server on `5001:5001` (HTTPS) / `5002:5000` (HTTP)

Railway production deployment supported via `PORT` env var.

---

## Testing

- **`Andy.Auth.Server.Tests`** — 54 xUnit tests (100% passing)
- **`Andy.Auth.Tests`** — client library (JWT validation, multi-provider)
- **`Andy.Auth.E2E.Tests`** — Playwright: LoginLogout, AdminDashboard, SessionManagement, PasswordChange, DateFormatting
- **`oauth-python/`** — 42 external OAuth2/OIDC conformance tests (run against UAT)

Covers: OAuth flows, 2FA, account lockout, consent, admin ops, session tracking.

---

<!-- _class: lead -->

# Where to start reading

1. `src/Andy.Auth.Server/Program.cs` — endpoint configuration (lines 139–227)
2. `src/Andy.Auth.Server/Data/DbSeeder.cs` — clients, scopes, roles
3. `src/Andy.Auth.Server/Controllers/AuthorizationController.cs` — the PKCE flow
4. `src/Andy.Auth.Server/Controllers/DynamicClientRegistrationController.cs` — RFC 7591
5. `src/Andy.Auth/` — the NuGet client library
6. `docs/ARCHITECTURE.md`, `docs/LIBRARY.md`

Discovery: `GET /.well-known/openid-configuration`.
