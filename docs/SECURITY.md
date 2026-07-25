# Security Documentation

This document outlines the security measures implemented in Andy Auth Server.

## Overview

Andy Auth Server implements multiple layers of security to protect against common web vulnerabilities and attacks. This document details the security features, configurations, and best practices implemented.

## Security Features

### 1. Rate Limiting

**Implementation**: AspNetCoreRateLimit (v5.0.0)

**Configuration**: `appsettings.json`

Rate limits are enforced on critical endpoints to prevent brute force attacks and API abuse:

- **Login endpoint**: 5 attempts per minute per IP
- **Registration endpoint**: 3 attempts per hour per IP
- **Token endpoint**: 10 requests per minute per IP
- **Authorization endpoint**: 10 requests per minute per IP
- **Global limit**: 60 requests per minute per IP

When rate limits are exceeded, the server returns HTTP 429 (Too Many Requests).

**Trusted client IP (issue #125)**: The rate-limit identity is the *normalized*
client IP from `HttpContext.Connection.RemoteIpAddress` (resolved by
`UseForwardedHeaders` from the trusted-proxy set — see "Forwarded Headers &
Trusted Proxies" below), **not** a caller-supplied header. `IpRateLimiting:RealIpHeader`
is intentionally empty; a raw header such as `X-Real-IP` is never used as the
identity, so a client cannot rotate a header to evade login/token limits.

**Code Location**: `Program.cs` (rate-limit service registration), `Program.cs`
(`app.UseIpRateLimiting()`), `appsettings.json` (`IpRateLimiting`).

### 2. Account Lockout

**Implementation**: ASP.NET Core Identity

**Configuration**: `Program.cs:36-39`

- **Max failed attempts**: 5
- **Lockout duration**: 30 minutes
- **Applies to**: All users (including new users)

This prevents brute force attacks on user accounts by temporarily locking accounts after multiple failed login attempts.

### 3. Security Headers

**Implementation**: Custom middleware

**Code Location**: `Program.cs:127-137`

The following security headers are automatically added to all responses:

- **X-Frame-Options: DENY**
  - Prevents clickjacking attacks by disabling iframe embedding

- **X-Content-Type-Options: nosniff**
  - Prevents MIME-sniffing attacks

- **X-XSS-Protection: 1; mode=block**
  - Enables browser XSS protection

- **Referrer-Policy: no-referrer**
  - Prevents leaking sensitive information in referrer headers

- **Content-Security-Policy** (issue #128)
  - **Enabled by default in Production and UAT** (`SecurityHeaders:EnableCsp=true`
    in `appsettings.Production.json` / `appsettings.UAT.json`); off by default in
    Development so local iteration isn't blocked. Toggle per-deployment via the
    same key.
  - Nonce-based, not `'unsafe-inline'`: a fresh per-request nonce is emitted in
    the header and stamped onto every inline `<script>`/`<style>` element by
    `NonceTagHelper` (registered in `Views/_ViewImports.cshtml`). Injected
    script/style *elements* without the nonce are blocked.
  - Directives: `default-src 'self'`; `base-uri 'self'`; `object-src 'none'`;
    `frame-ancestors 'none'`; `form-action 'self'`; `img-src 'self' data:`;
    `font-src 'self'`; `style-src 'self' 'nonce-<per-request>'`;
    `script-src 'self' 'nonce-<per-request>'`.
  - Inline event handlers (`onclick=...`) and `style="..."` attributes remain
    permitted via `script-src-attr 'unsafe-inline'` / `style-src-attr
    'unsafe-inline'`; the document-level directives above stay restrictive. All
    login / consent / device-verification / MFA / admin flows work under this
    policy.

### 4. HTTPS Enforcement

**Implementation**: ASP.NET Core HTTPS Redirection + HSTS

**Code Location**: `Program.cs:114,124`

- All HTTP requests are automatically redirected to HTTPS
- HSTS (HTTP Strict Transport Security) is enabled in production
  - Forces browsers to only communicate over HTTPS
  - Prevents protocol downgrade attacks

### 4a. Forwarded Headers & Trusted Proxies (issue #125)

**Implementation**: ASP.NET Core `UseForwardedHeaders`, configured per deployment
mode via the `ForwardedHeaders` config section.

The server runs behind a reverse proxy (Railway's HTTPS edge in Production/UAT,
Conductor's unified proxy in Embedded, a local proxy in Development/Docker), so
it honours `X-Forwarded-For` / `X-Forwarded-Proto` to recover the real client IP
and scheme. Honouring those headers from an **untrusted** peer would let a caller
spoof its IP (evading rate limits, poisoning audit/session records) or scheme, so
the trusted-proxy set is configurable:

| Key | Meaning |
| --- | --- |
| `ForwardedHeaders:TrustAllProxies` | `true` → accept forwarded headers from any immediate peer (empty known-proxy set). Only for local modes behind a trusted local proxy. |
| `ForwardedHeaders:KnownNetworks` | CIDR list of trusted proxy networks. |
| `ForwardedHeaders:KnownProxies` | Individual trusted proxy IPs. |
| `ForwardedHeaders:ForwardLimit` | Max proxy hops to unwind (default 1). |

- **Local modes** (Development/Docker/Embedded) inherit `TrustAllProxies=true`
  from base `appsettings.json` — unchanged behaviour behind the local proxy.
- **Production/UAT** set `TrustAllProxies=false` plus an explicit `KnownNetworks`
  list (the private ranges the Railway edge connects from). When no trusted
  proxy/network is configured and `TrustAllProxies=false`, the middleware keeps
  ASP.NET Core's loopback-only default rather than trusting everything.

**Edge contract**: In Production/UAT the app is reachable **only** through the
platform edge (Railway), which **overwrites** any inbound `X-Forwarded-*` before
proxying and connects to the container over the private network in
`KnownNetworks`. An external client therefore cannot forge these headers. If the
platform's proxy range differs, override `ForwardedHeaders__KnownNetworks__*` (or
set `ForwardedHeaders__TrustAllProxies=true`) via environment variables.

**Diagnostics**: an opt-in anonymous endpoint `/internal/client-info`
(`Diagnostics:EnableClientInfoEndpoint=true`, off by default) echoes the resolved
client IP + scheme so operators can verify the proxy contract in staging.

### 5. CSRF (Cross-Site Request Forgery) Protection

**Implementation**: ASP.NET Core Anti-Forgery Tokens

**Code Location**:
- Form helpers: `Views/Account/Login.cshtml:11`, `Views/Account/Register.cshtml:11`
- Validation: `Controllers/AccountController.cs:34,103,148` ([ValidateAntiForgeryToken])

All POST forms automatically include anti-forgery tokens via the `<form>` tag helper. The tokens are validated on the server-side using the [ValidateAntiForgeryToken] attribute.

### 6. SQL Injection Protection

**Implementation**: Entity Framework Core

**Code Location**: All database operations use EF Core

Entity Framework Core uses parameterized queries for all database operations, which prevents SQL injection attacks. User input is never directly concatenated into SQL statements.

**Example**: `Controllers/AccountController.cs`, `Data/DbSeeder.cs`

### 7. XSS (Cross-Site Scripting) Protection

**Implementation**: Razor Views Auto-Encoding

**Code Location**: All `.cshtml` files

Razor views automatically HTML-encode all output by default. This prevents XSS attacks by ensuring user-supplied data cannot be interpreted as HTML or JavaScript.

To explicitly render raw HTML, developers must use `@Html.Raw()`, which is intentionally avoided in this codebase.

### 8. Password Requirements

**Implementation**: ASP.NET Core Identity

**Code Location**: `Program.cs:28-34`

- Minimum length: 8 characters
- Requires: Digit, uppercase letter, lowercase letter
- Does not require: Special characters (for better usability)

Passwords are automatically hashed using PBKDF2 with a random salt before storage.

### 9. Authentication & Authorization

**Implementation**: OpenIddict + ASP.NET Core Identity

**Features**:
- OAuth 2.0 Authorization Code Flow with PKCE
- Refresh token rotation
- Client credentials flow
- Token introspection and revocation
- Secure token storage and validation

**Code Location**: `Program.cs:41-102`

### 9a. Consent Integrity (server-side consent state)

**Implementation**: `Services/ConsentGrantService.cs`, `Data/ConsentGrant.cs`,
`Controllers/ConsentController.cs`, `Controllers/AuthorizationController.cs`

For clients configured with **explicit** (interactive) consent, the
authorization endpoint must never treat the consent decision as something the
client can assert. The authorization request is fully client-controlled, so any
value carried in it — a query parameter, a form field — is attacker-controllable.

**Invariant**: The authorization endpoint issues an authorization code for an
explicit-consent client only when it can find, validate, and consume a
**server-side consent grant** that the consent UI created for *this* approval.
The code (and the resulting tokens) carry **only the scopes the user actually
approved** — never the raw requested scope set.

A `ConsentGrant` record binds an approval to:

- the **authenticated user** (`sub`),
- the **client id**,
- the **redirect URI**,
- the **exact set of requested scopes** the user was shown,
- the **approved scope subset** (what actually gets issued), and
- a **short expiry** (5 minutes — long enough to survive the redirect back from
  the consent screen, no longer).

Only an unguessable, cryptographically-random grant id (`consent_id`) travels
back through the browser. The authorization endpoint looks the grant up by that
id and enforces every binding above before issuing anything. A grant is
**single-use**: it is marked consumed the moment it is honoured.

This closes the previous vulnerability (issue #124) where the endpoint trusted a
client-supplied `consent_granted=true` query marker as proof of consent and then
issued every requested scope. That marker has been removed entirely.

**Protections and their negative-path tests**
(`Services/ConsentGrantServiceTests.cs`, `ConsentControllerTests.cs`):

- **Forgery** — a fabricated/absent `consent_id` matches no server-side grant, so
  consent cannot be self-asserted by the client.
- **Replay** — a consumed grant is rejected on any subsequent use. Consumption
  is **atomic**: the grant is claimed with a conditional
  `UPDATE ... SET ConsumedAt = now WHERE ConsumedAt IS NULL`, so even two
  requests replaying the same `consent_id` concurrently result in exactly one
  success (covered by a concurrency test firing N simultaneous consumes).
- **Expiry** — a grant past its short TTL is rejected.
- **Tampering** — a request whose user, client, redirect URI, or requested-scope
  set differs from the recorded grant is rejected and re-prompts for consent
  (this defeats post-consent scope escalation via the redirect).
- **Partial consent** — when the user approves a subset, only that subset is
  recorded and issued; the de-selected scopes never reach a token.
- **Non-remembered consent** — a "don't remember" decision creates no durable
  record; only the short-lived grant authorizes that single request.

> **Housekeeping (follow-up, not security-critical):** consumed/expired grants
> are inert but are not yet pruned by any background job, so the `ConsentGrants`
> table grows over time. The `(ExpiresAt, ConsumedAt)` index is in place so a
> future scheduled reaper can delete `ConsumedAt IS NOT NULL OR ExpiresAt < now`
> cheaply.
### 9a. External Login & Account Linking

**Implementation**: `Controllers/AccountController.cs` (`ExternalLoginCallback`, `LinkExternalLogin`), `Configuration/ExternalLoginOptions.cs`

**Invariant**: An external (federated) identity is **NEVER** auto-linked to an
existing local account solely because the provider asserts a matching email.
Sign-in and account-linking are separate operations with separate proof
requirements. Closes andy-auth#119.

The `ExternalLoginCallback` has exactly three outcomes:

1. **The external login is already linked** to a local account — sign the user
   in via `SignInManager.ExternalLoginSignInAsync`. This does **not** silently
   bypass a locally configured second factor: `bypassTwoFactor` is driven by
   `ExternalLogin:BypassLocalTwoFactor` (default `false`), so a user with local
   2FA is redirected through the normal 2FA challenge. Set the flag to `true`
   only when the upstream provider's MFA is trusted to satisfy the local
   second-factor requirement.
2. **No local account has this email** — a new account is auto-provisioned and
   bound to the external identity. This requires a verified email and an allowed
   tenant/issuer (see below). This is provisioning, not linking to a pre-existing
   account.
3. **An existing local account shares the email but the login is not linked** —
   the identity is **not** auto-linked. If (and only if) the request carries an
   authenticated local session for that **same** user, the user is routed to an
   explicit link-confirmation flow (`LinkExternalLogin`) that requires
   **reauthentication with the local password** (the ownership challenge) before
   the provider is attached. Otherwise the request is rejected with a clear
   message and no link is created.

**Explicit trust requirements** (`ExternalLoginOptions`, config section
`ExternalLogin`):

- `RequireVerifiedEmail` (default `true`) — the provider must assert
  `email_verified`/`verified_email` = `true` before an account is provisioned or
  linked. Providers that do not emit the claim must be configured to map it, or
  an operator must explicitly opt out.
- `AllowedTenantIds` — when non-empty, the principal's `tid` claim must be in the
  allow-list.
- `AllowedIssuers` — when non-empty, the principal's `iss` claim must be in the
  allow-list.

**User-state enforcement**: disabled (`IsActive == false`), suspended
(`IsSuspended`), deleted (`DeletedAt`), and expired (`ExpiresAt`) users cannot be
signed in or linked via the external flow. These checks are applied explicitly
because ASP.NET Identity's sign-in path does not know about these custom
`ApplicationUser` fields.

**Audit events** distinguish each step: `UserLoginExternal` (external sign-in),
`UserLoginExternalRejected` (blocked linked-account sign-in), `ExternalLinkRequested`
(authenticated user began linking), `ExternalLinkSucceeded` (link confirmed after
reauthentication), and `ExternalLinkRejected` (link refused — no session, unverified
email, disallowed tenant/issuer, failed reauthentication, or email mismatch).

### 10. Database Security

**Implementation**: PostgreSQL + Entity Framework Core

**Measures**:
- Parameterized queries (prevents SQL injection)
- Password hashing (PBKDF2)
- Secure connection strings (should use environment variables in production)
- Database migrations for schema versioning

### 11. Audit Logging

**Implementation**: Custom audit log system

**Code Location**: `Data/AuditLog.cs`, `Controllers/AdminController.cs:56-65`

All authentication and authorization events are logged, including:
- Login attempts (successful and failed)
- User registrations
- Account suspensions/deletions
- OAuth token grants
- Administrative actions

### 14. Startup Health & Readiness (issue #130)

**Implementation**: ASP.NET Core HealthChecks + an init-status singleton set by
the startup migration/seed step.

Two distinct probes:

- **`/health`** — anonymous, dependency-free **liveness**. Answers 200 as long as
  the process is up; never touches the DB, OpenIddict, or the session store.
- **`/ready`** — anonymous **readiness**. Returns 200 only once startup migration
  **and** required seeding both completed; otherwise 503. It reflects
  DB/schema/required-seed state via the `StartupReadinessState` singleton.

If migration or a required seed step fails (DB unavailable, migration error,
missing production admin/client secrets), the process stays up, logs the error,
and `/ready` reports 503 with the reason — so the orchestrator withholds traffic
and retries/redeploys while liveness stays green. Set
`Startup:FailFastOnInitError=true` to instead crash the process on init failure.
Migration (EF tracks applied migrations; SQLite `EnsureCreated` is a no-op when
the schema exists) and seeding (delete-then-create for clients/scopes,
`FindByEmail` guards for users) are idempotent, so a partial init is safe to
re-run on the next start.

**Traffic admission**: `railway.json` sets `healthcheckPath=/ready` so Railway
withholds traffic from a new deployment until it is ready. Container orchestrators
should likewise probe `/ready` for readiness and `/health` for liveness. (The
`docker-compose.yml` server image — `mcr.microsoft.com/dotnet/aspnet:8.0` — has no
`curl`/`wget`, so no compose `HEALTHCHECK` is wired; probe `/ready` from the
orchestrator instead.)

## Security Best Practices

### Development

1. **Never commit secrets**: Use environment variables or Azure Key Vault for production
2. **Ephemeral keys**: Development uses ephemeral encryption/signing keys (see `Program.cs:66-70`)
3. **Local database**: PostgreSQL running locally with default credentials (postgres/postgres)

### Production

1. **Use proper certificates**: Replace ephemeral keys with real certificates (see `Program.cs:72-77`)
2. **Secure connection strings**: Use environment variables or managed identities
3. **Enable HTTPS**: Configure proper SSL/TLS certificates
4. **Monitor audit logs**: Set up alerting for suspicious activities
5. **Regular updates**: Keep all NuGet packages up to date
6. **Backup database**: Implement automated database backups
7. **Rate limit tuning**: Adjust rate limits based on actual usage patterns
8. **Trusted proxies**: Confirm `ForwardedHeaders:KnownNetworks` matches the
   platform edge's proxy range, and that the edge strips/overwrites inbound
   `X-Forwarded-*` (see "Forwarded Headers & Trusted Proxies")
9. **CSP**: Keep `SecurityHeaders:EnableCsp=true` (default); only disable to
   debug a browser-specific issue
10. **Readiness gating**: Point the platform health check at `/ready` (Railway is
    pre-wired) so traffic is withheld until migration + seeding succeed

## Vulnerability Reporting

If you discover a security vulnerability, please email security@rivoli.ai. Do not create public GitHub issues for security vulnerabilities.

## Security Checklist

Before deploying to production, verify:

- [ ] HTTPS is properly configured with valid certificates
- [ ] Database connection string uses environment variables
- [ ] OpenIddict signing and encryption certificates are properly configured
- [ ] Rate limits are appropriate for your use case
- [ ] Audit logging is enabled and monitored
- [ ] Database backups are configured
- [ ] Security headers are verified using tools like securityheaders.com
- [ ] Application is behind a reverse proxy (nginx, Caddy, etc.)
- [ ] PostgreSQL is not exposed to the public internet
- [ ] Admin accounts use strong passwords and 2FA (TOTP, via `TwoFactorController`)

## Security Testing

### Automated Testing

Currently, automated security testing is tracked in Issue #1. The test suite should include:
- Authentication flow tests
- Authorization tests
- Rate limiting tests
- CSRF protection tests

### Manual Testing

Before UAT deployment:
1. Test rate limiting on all endpoints
2. Verify account lockout after failed attempts
3. Test CSRF protection by attempting cross-origin form submissions
4. Verify security headers using browser dev tools
5. Test XSS protection by attempting to inject scripts
6. Verify HTTPS redirects work correctly

### Security Scanning

Consider using:
- OWASP ZAP for vulnerability scanning
- Dependabot for dependency vulnerability alerts
- SonarQube for code quality and security analysis

## Updates

- 2025-11-16: Initial security hardening (Issue #4)
  - Added rate limiting
  - Increased account lockout to 30 minutes
  - Added security headers
  - Documented all security measures

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [ASP.NET Core Security](https://docs.microsoft.com/en-us/aspnet/core/security/)
- [OpenIddict Documentation](https://documentation.openiddict.com/)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
