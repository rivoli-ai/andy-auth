# Architecture

Andy Auth Server architecture and design decisions.

## System Overview

```
┌──────────────────────────────────────────────────────────────┐
│                    Andy Auth Server                           │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐    ┌─────────────────┐   ┌─────────────┐  │
│  │   Web UI     │    │  OAuth/OIDC     │   │   Admin     │  │
│  │  (MVC Razor) │    │   Endpoints     │   │     UI      │  │
│  │              │    │  (OpenIddict)   │   │             │  │
│  │ - Login      │    │                 │   │ - Users     │  │
│  │ - Register   │    │ - /authorize    │   │ - Clients   │  │
│  │ - Profile    │    │ - /token        │   │ - Logs      │  │
│  └──────────────┘    │ - /introspect   │   │             │  │
│                      │ - /revoke       │   └─────────────┘  │
│                      └─────────────────┘                     │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │           ASP.NET Core Identity + OpenIddict          │   │
│  │                                                        │   │
│  │  - User Management                                     │   │
│  │  - Password Hashing (PBKDF2)                          │   │
│  │  - Account Lockout                                    │   │
│  │  - OAuth Client Management                            │   │
│  │  - Token Generation/Validation                        │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │        Entity Framework Core + PostgreSQL             │   │
│  │                                                        │   │
│  │  - AspNetUsers              - OpenIddictApplications  │   │
│  │  - AspNetRoles              - OpenIddictAuthorizations│   │
│  │  - AspNetUserClaims         - OpenIddictTokens        │   │
│  │  - AuditLogs                - OpenIddictScopes        │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

## Technology Stack

### Backend
- **Framework**: ASP.NET Core 8.0
- **Authentication**: ASP.NET Core Identity
- **OAuth/OIDC**: OpenIddict 5.x
- **ORM**: Entity Framework Core 8.0
- **Database**: PostgreSQL 16
- **UI**: Razor Views (MVC)

### Security
- **Rate Limiting**: AspNetCoreRateLimit
- **Password Hashing**: PBKDF2 (via Identity)
- **Token Signing**: RSA/HMAC (ephemeral in dev, certificates in prod)
- **HTTPS**: Required in production

### Frontend
- **CSS**: Custom CSS with modern design system
- **Icons**: SVG icons
- **JavaScript**: Vanilla JS (minimal, progressively enhanced)

## Data Model

### User Management

```
ApplicationUser (extends IdentityUser)
├── Id: string (GUID)
├── Email: string (unique)
├── FullName: string?
├── LastLoginAt: DateTime?
├── IsActive: bool
├── IsSuspended: bool
├── SuspendedAt: DateTime?
├── SuspendedBy: string?
├── SuspensionReason: string?
├── ExpiresAt: DateTime?
├── IsDeleted: bool (soft delete)
├── DeletedAt: DateTime?
└── DeletedBy: string?
```

### OAuth Clients

```
OpenIddictApplication
├── Id: string
├── ClientId: string (unique)
├── ClientSecret: string? (hashed)
├── DisplayName: string
├── Type: string (confidential/public)
├── Permissions: JSON array
│   ├── Endpoints (authorize, token, etc.)
│   ├── Grant types (code, refresh, etc.)
│   └── Scopes (openid, profile, etc.)
└── RedirectUris: JSON array
```

### Tokens

```
OpenIddictToken
├── Id: string
├── ApplicationId: string (FK)
├── AuthorizationId: string? (FK)
├── Subject: string (User ID)
├── Type: string (access_token, refresh_token)
├── Payload: string? (JWT)
├── ReferenceId: string? (for reference tokens)
├── Status: string (valid, revoked)
├── CreationDate: DateTime
├── ExpirationDate: DateTime?
└── RedemptionDate: DateTime?
```

### Audit Logs

```
AuditLog
├── Id: long
├── Timestamp: DateTime
├── UserId: string?
├── UserEmail: string?
├── Action: string
├── Entity: string
├── EntityId: string?
├── IpAddress: string?
├── UserAgent: string?
├── Changes: string? (JSON)
└── Result: string (Success/Failure)
```

## OAuth 2.0 Flows

### 1. Authorization Code Flow (Web Apps)

```
┌─────────┐                                  ┌──────────────┐
│ Browser │                                  │  Andy Auth   │
└────┬────┘                                  └──────┬───────┘
     │                                              │
     │  1. GET /authorize?client_id=...&redirect_uri=...&response_type=code&code_challenge=...
     ├─────────────────────────────────────────────>│
     │                                              │
     │  2. Show login page                          │
     │<─────────────────────────────────────────────┤
     │                                              │
     │  3. POST /Account/Login (credentials)        │
     ├─────────────────────────────────────────────>│
     │                                              │
     │  4. Redirect with code                       │
     │<─────────────────────────────────────────────┤
     │  Location: redirect_uri?code=ABC123          │
     │                                              │
     │  5. POST /token (code + code_verifier)       │
     ├─────────────────────────────────────────────>│
     │                                              │
     │  6. Return tokens                            │
     │<─────────────────────────────────────────────┤
     │  { access_token, refresh_token, id_token }   │
     │                                              │
```

### 2. Client Credentials Flow (Server-to-Server)

```
┌─────────────┐                          ┌──────────────┐
│   Client    │                          │  Andy Auth   │
│   Server    │                          └──────┬───────┘
└──────┬──────┘                                  │
       │                                         │
       │  POST /token                            │
       │  grant_type=client_credentials          │
       │  client_id=xxx&client_secret=yyy        │
       ├────────────────────────────────────────>│
       │                                         │
       │  { access_token }                       │
       │<────────────────────────────────────────┤
       │                                         │
```

### 3. Refresh Token Flow

```
┌─────────┐                                  ┌──────────────┐
│ Client  │                                  │  Andy Auth   │
└────┬────┘                                  └──────┬───────┘
     │                                              │
     │  POST /token                                 │
     │  grant_type=refresh_token                    │
     │  refresh_token=xyz                           │
     ├─────────────────────────────────────────────>│
     │                                              │
     │  { access_token, refresh_token }             │
     │<─────────────────────────────────────────────┤
     │                                              │
```

## Security Architecture

### Defense in Depth

```
Layer 1: Network
  - HTTPS only (TLS 1.2+)
  - HSTS enabled
  - Security headers (CSP, X-Frame-Options, etc.)

Layer 2: Rate Limiting
  - Login: 5 attempts/minute
  - Register: 3 attempts/hour
  - Token: 10 requests/minute
  - Global: 60 requests/minute

Layer 3: Authentication
  - Password hashing (PBKDF2, 100k iterations)
  - Account lockout (30 min after 5 failures)
  - Secure password requirements

Layer 4: Authorization
  - OAuth 2.0 scopes
  - Role-based access control
  - Resource-based authorization

Layer 5: Token Security
  - JWT signature validation
  - Token expiration
  - Refresh token rotation
  - Token revocation support

Layer 6: Application
  - CSRF protection (anti-forgery tokens)
  - XSS protection (auto-encoding)
  - SQL injection protection (parameterized queries)
  - Input validation
```

### Threat Model

**Protected Against:**
- ✅ Brute force attacks (rate limiting + account lockout)
- ✅ SQL injection (EF Core parameterized queries)
- ✅ XSS (Razor auto-encoding)
- ✅ CSRF (anti-forgery tokens)
- ✅ Token theft (HTTPS, secure cookies, short expiration)
- ✅ Replay attacks (nonce, timestamp validation)
- ✅ Clickjacking (X-Frame-Options: DENY)

**Future Enhancements:**
- ⏳ DDoS protection (Cloudflare/WAF)
- ⏳ Account takeover (2FA, anomaly detection)
- ⏳ Session hijacking (device fingerprinting)
- ⏳ Credential stuffing (breach password detection)

## Deployment Architecture

### Development

```
┌─────────────────────────────────────┐
│  localhost                           │
├─────────────────────────────────────┤
│  Andy.Auth.Server                    │
│  https://localhost:7088              │
│  ├─ Ephemeral signing keys           │
│  └─ Local PostgreSQL                 │
│     (docker-compose)                 │
└─────────────────────────────────────┘
```

### Production (Railway)

```
┌────────────────────────────────────────────────┐
│  Railway: auth.rivoli.ai                        │
├────────────────────────────────────────────────┤
│  ┌──────────────┐      ┌──────────────────┐   │
│  │  Andy.Auth   │─────>│  PostgreSQL      │   │
│  │  Server      │      │  (Railway)       │   │
│  │  (Container) │      │  - Automatic     │   │
│  │              │      │    backups       │   │
│  │  - Proper    │      │  - Connection    │   │
│  │    certs     │      │    pooling       │   │
│  │  - Env vars  │      └──────────────────┘   │
│  └──────────────┘                              │
│                                                 │
│  Environment Variables:                         │
│  - ConnectionStrings__DefaultConnection         │
│  - OpenIddict__Server__EncryptionKey           │
│  - OpenIddict__Server__SigningKey              │
│  - ASPNETCORE_ENVIRONMENT=Production           │
└────────────────────────────────────────────────┘
```

## Request Pipeline

### Middleware Order

```csharp
1. app.UseDeveloperExceptionPage() / UseExceptionHandler()
2. app.UseHsts()
3. app.UseHttpsRedirection()
4. app.UseStaticFiles()
5. app.UseSecurityHeaders()        // Custom middleware
6. app.UseIpRateLimiting()         // Rate limiting
7. app.UseRouting()
8. app.UseAuthentication()         // Identity + OpenIddict
9. app.UseAuthorization()
10. app.MapControllers()
```

### Request Flow

```
HTTP Request
  │
  ├─> Security Headers Added
  │
  ├─> Rate Limit Check
  │     │
  │     ├─> Allowed: Continue
  │     └─> Blocked: 429 Too Many Requests
  │
  ├─> Route Matching
  │
  ├─> Authentication
  │     │
  │     ├─> Cookie Auth (web UI)
  │     └─> Bearer Token (API/OAuth)
  │
  ├─> Authorization
  │     │
  │     ├─> [Authorize]: Check if authenticated
  │     ├─> [Authorize(Roles="...")]: Check role
  │     └─> Policy-based: Check custom policy
  │
  ├─> Controller Action
  │
  └─> Response
        │
        ├─> View (Razor)
        └─> JSON (API)
```

## Design Patterns

### 1. Repository Pattern
- `ApplicationDbContext` encapsulates data access
- Migrations handle schema changes
- DbSeeder for initial data

### 2. MVC Pattern
- Controllers handle HTTP requests
- Models represent data
- Views render UI (Razor)

### 3. Dependency Injection
- Services registered in Program.cs
- Scoped lifetime for DbContext
- Singleton for rate limiting

### 4. Options Pattern
- Configuration bound to typed classes
- Validated on startup
- Easy to test

## Performance Considerations

### Database
- **Connection Pooling**: Enabled by default (EF Core)
- **Indexes**: On foreign keys, email, client ID
- **Query Optimization**: Eager loading for related entities

### Caching
- **Rate Limiting**: In-memory cache
- **Static Assets**: Browser caching with CDN-ready headers
- **Future**: Redis for distributed caching

### Scalability
- **Stateless Design**: Can run multiple instances
- **Horizontal Scaling**: Load balancer + multiple containers
- **Database**: PostgreSQL can handle 10k+ active users

## Monitoring & Observability

### Logging
- **Serilog** (future): Structured logging
- **Log Levels**: Information, Warning, Error
- **Audit Logs**: All auth events logged to database

### Metrics
- **Health Checks**: `/health` endpoint
- **OpenTelemetry** (future): Distributed tracing
- **Application Insights** (future): Performance monitoring

### Alerts
- **Railway**: Built-in monitoring
- **Custom**: Failed login attempts, suspicious activity

## Extension Points

### Custom Authentication Providers
- Implement external IdP integration (Google, GitHub)
- SAML support for enterprise SSO
- Passkeys/WebAuthn

### Custom Claims
- Add application-specific claims to tokens
- Transform claims from external providers
- Enrich user profile

### Custom Scopes
- Define application-specific OAuth scopes
- Implement custom authorization policies
- Fine-grained permissions

## References

- [ASP.NET Core Identity](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity)
- [OpenIddict Documentation](https://documentation.openiddict.com/)
- [OAuth 2.0 RFC](https://datatracker.ietf.org/doc/html/rfc6749)
- [OpenID Connect Spec](https://openid.net/specs/openid-connect-core-1_0.html)
- [PKCE RFC](https://datatracker.ietf.org/doc/html/rfc7636)

---

**Last Updated:** 2025-11-16
