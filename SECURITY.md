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

**Code Location**: `Program.cs:12-17` (service registration), `Program.cs:140` (middleware)

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

- **Content-Security-Policy**
  - `default-src 'self'`: Only load resources from same origin
  - `script-src 'self'`: Only execute scripts from same origin
  - `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com`: Styles from same origin and Google Fonts
  - `font-src 'self' https://fonts.gstatic.com`: Fonts from same origin and Google Fonts

### 4. HTTPS Enforcement

**Implementation**: ASP.NET Core HTTPS Redirection + HSTS

**Code Location**: `Program.cs:114,124`

- All HTTP requests are automatically redirected to HTTPS
- HSTS (HTTP Strict Transport Security) is enabled in production
  - Forces browsers to only communicate over HTTPS
  - Prevents protocol downgrade attacks

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
- [ ] Admin accounts use strong passwords and 2FA (when implemented)

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
