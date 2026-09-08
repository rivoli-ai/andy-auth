# Deployment Guide

Production deployment guide for Andy Auth Server.

## Overview

Andy Auth Server is deployed to **Railway** with PostgreSQL database.

**Environments:**
- **UAT**: auth-uat.rivoli.ai (Issue #3)
- **Production**: auth.rivoli.ai (Issue #8)

## Prerequisites

- GitHub repository: `rivoli-ai/andy-auth`
- Railway account with project created
- PostgreSQL database (Railway provides)
- Domain DNS access (Cloudflare)

## Railway Deployment

### 1. Create Railway Project

1. Go to https://railway.app
2. Create new project
3. Add PostgreSQL database
4. Add service from GitHub → `rivoli-ai/andy-auth`

### 2. Configure Build

Railway uses **Nixpacks** to detect and build .NET applications automatically.

**nixpacks.toml** (in repo root):
```toml
[phases.setup]
nixPkgs = ["dotnet-sdk_10"]

[phases.build]
cmds = ["dotnet publish src/Andy.Auth.Server/Andy.Auth.Server.csproj -c Release -o out"]

[phases.start]
cmd = "dotnet out/Andy.Auth.Server.dll"
```

**railway.json** (optional, for advanced config):
```json
{
  "$schema": "https://railway.app/railway.schema.json",
  "build": {
    "builder": "NIXPACKS",
    "buildCommand": "dotnet publish src/Andy.Auth.Server/Andy.Auth.Server.csproj -c Release -o out"
  },
  "deploy": {
    "startCommand": "dotnet out/Andy.Auth.Server.dll",
    "restartPolicyType": "ON_FAILURE",
    "restartPolicyMaxRetries": 10
  }
}
```

### 3. Environment Variables

Configure in Railway dashboard → Variables:

**Required:**
```bash
# Database (Railway sets this automatically)
DATABASE_URL=postgresql://user:pass@host:port/db

# Connection string (format Railway's DATABASE_URL)
ConnectionStrings__DefaultConnection=${{Postgres.DATABASE_URL}}

# ASP.NET Core
ASPNETCORE_ENVIRONMENT=Production
ASPNETCORE_URLS=http://0.0.0.0:${{PORT}}

# Issuer — must match the public URL clients reach this server on
OpenIddict__Issuer=https://auth.example.com/

# Configure protected certificate bundles and shared Data Protection; see below.
```

> Production requires [protected certificates and a shared encrypted Data Protection ring](operations/key-rotation.md). Provision these before deployment; legacy PEM paths and ephemeral overrides are rejected.

**Optional:**
```bash
# Logging
Logging__LogLevel__Default=Information
Logging__LogLevel__Microsoft.AspNetCore=Warning

# Rate Limiting (defaults in appsettings.json)
IpRateLimiting__EnableEndpointRateLimiting=true
```

### 4. Custom Domain

In Railway → Settings → Domains:

1. Add custom domain: `auth-uat.rivoli.ai` (UAT) or `auth.rivoli.ai` (Production)
2. Copy CNAME target from Railway
3. Update DNS records in Cloudflare:

**Cloudflare DNS:**
```
Type: CNAME
Name: auth-uat (or auth)
Target: <railway-generated-url>
Proxy: On (orange cloud)
```

### 5. Deploy

Railway deploys automatically on git push to main branch.

**Manual deploy:**
1. Railway Dashboard → Deployments
2. Click "Deploy" → select commit/branch

**Monitor deployment:**
- Watch build logs in Railway
- Check for errors
- Verify health check passes

## Database Migration

Migrations run automatically on application startup (Program.cs:136).

**Manual migration (if needed):**
```bash
# SSH into Railway container (not available in Hobby plan)
railway run dotnet ef database update

# Or deploy with migrations in startup
# (already configured in Program.cs)
```

## Health Checks

**Endpoints:**
- `https://auth.rivoli.ai/.well-known/openid-configuration` - OpenID Discovery
- `https://auth.rivoli.ai/Account/Login` - Login page
- `https://auth.rivoli.ai/Admin` - Admin dashboard

**Test OAuth flow:**
```bash
curl -I https://auth.rivoli.ai/.well-known/openid-configuration
# Should return: 200 OK
```

## Security Configuration

### Production Certificates

In production, Andy Auth uses proper signing/encryption keys from environment variables.

**Generate secure keys:**
```bash
# Encryption key
openssl rand -base64 32

# Signing key
openssl rand -base64 32
```

**Store in Railway environment variables** - never commit to git!

### HTTPS

Railway provides automatic HTTPS with Let's Encrypt certificates.

**Verify:**
- `RequireHttpsMetadata: true` in production (Program.cs)
- All redirect URIs use HTTPS
- HSTS enabled (Program.cs:114)

### Security Headers

All security headers are configured (Program.cs:127-137):
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- X-XSS-Protection: 1; mode=block
- Referrer-Policy: no-referrer
- Content-Security-Policy

### Rate Limiting

Configured in appsettings.json:
- Login: 5/minute
- Register: 3/hour
- Token: 10/minute
- Global: 60/minute

## Monitoring

### Railway Dashboard

- CPU usage
- Memory usage
- Request count
- Error rate
- Deployment status

### Application Logs

View in Railway → Logs tab:
```bash
# Or via CLI
railway logs --service andy-auth
```

### Audit Logs

View in Admin UI:
- Navigate to `/Admin/AuditLogs`
- Filter by date, action, user
- Monitor suspicious activity

## Client Configuration

After deployment, update OAuth clients to use production URLs.

### Andy Docs API (Railway)

**Environment Variables:**
```bash
AndyAuth__Authority=https://auth.rivoli.ai
AndyAuth__Audience=andy-docs-api
AndyAuth__RequireHttpsMetadata=true
```

### Andy Docs SPA (Vercel)

> Historically referred to as the "Wagram frontend"; the `andy-docs-web` client
> still keeps `docs.wagram.ai` / `docs.uat.wagram.ai` in its redirect-URI
> allow-list (see `DbSeeder.cs`) until the public domain migration lands.

**Environment Variables:**
```bash
VITE_AUTH_URL=https://auth.rivoli.ai
VITE_API_URL=https://andy-docs-api.rivoli.ai
```

**Update auth config:**
```typescript
export const environment = {
  authUrl: 'https://auth.rivoli.ai',
  clientId: 'andy-docs-web',
  redirectUri: 'https://docs.wagram.ai/auth/callback'
};
```

### Claude Desktop MCP

Claude Desktop should autodiscover OAuth settings via:
```
https://andy-docs-api.rivoli.ai/.well-known/oauth-protected-resource
```

## Troubleshooting

### Deployment Fails

**Check:**
- Build logs in Railway
- .NET SDK version (8.0)
- Project file path is correct
- All dependencies are restored

**Common issues:**
- Missing DATABASE_URL → Add PostgreSQL service
- Build command incorrect → Check nixpacks.toml
- Port binding error → Use `${{PORT}}` not hardcoded port

### Database Connection Error

**Check:**
- DATABASE_URL is set
- ConnectionStrings__DefaultConnection format is correct
- PostgreSQL service is running
- Database migrations completed

**Fix:**
```bash
# Verify connection string format
postgresql://user:pass@host:port/dbname

# Check Railway PostgreSQL service status
```

### OAuth Errors

**"Invalid redirect_uri":**
- Update OAuth client redirect URIs in database
- Ensure URLs match exactly (including https://)
- Check for trailing slashes

**"Invalid issuer":**
- Verify `Authority` URL matches deployed server
- Check HTTPS is enforced
- Confirm OpenID Discovery is accessible

**"Token validation failed":**
- Verify signing keys match between environments
- Check clock sync
- Validate audience claim

### Rate Limiting Issues

If legitimate users are being rate-limited:

1. Review rate limiting config in appsettings.json
2. Adjust limits based on actual usage
3. Consider implementing user-based rate limiting
4. Check for bot traffic in audit logs

## Rollback

If deployment fails:

1. Railway Dashboard → Deployments
2. Find previous working deployment
3. Click "Redeploy"

Or revert git commit and push:
```bash
git revert HEAD
git push origin main
```

## Backup & Recovery

### Database Backups

Railway PostgreSQL includes automatic backups:
- Daily backups retained for 7 days
- Point-in-time recovery available

**Manual backup:**
```bash
# Export database
railway run pg_dump > backup.sql

# Restore
railway run psql < backup.sql
```

### Configuration Backup

Export environment variables regularly:
```bash
railway variables --json > env-backup.json
```

## Cost Estimate

**Railway (Hobby Plan):**
- Web service: $5/month
- PostgreSQL: $5/month
- Total: ~$10/month

**Railway (Pro Plan - Production):**
- Web service: $20/month
- PostgreSQL: $10/month
- Total: ~$30/month

**Additional costs:**
- Domain: Free (using existing)
- SSL: Free (Let's Encrypt via Railway)
- Monitoring: Included in Railway

## Deployment Checklist

### Pre-Deployment
- [ ] All tests passing (77/81 minimum)
- [ ] Security hardening complete (Issue #4)
- [ ] Documentation up to date
- [ ] Environment variables prepared
- [ ] Signing keys generated

### Deployment
- [ ] Railway project created
- [ ] PostgreSQL added
- [ ] GitHub repository connected
- [ ] Environment variables configured
- [ ] Custom domain configured
- [ ] DNS records updated

### Post-Deployment
- [ ] Health checks passing
- [ ] OpenID Discovery accessible
- [ ] Test user can login
- [ ] OAuth flow works end-to-end
- [ ] Audit logs working
- [ ] Rate limiting active
- [ ] Security headers present

### Client Integration
- [ ] Andy Docs API updated
- [ ] Andy Docs SPA (`andy-docs-web`) updated
- [ ] Claude Desktop tested
- [ ] All OAuth clients working

## Next Steps

After successful deployment:

1. **UAT Testing** (Issue #7)
   - Test with Claude Desktop
   - Test with Cline
   - Test with ChatGPT/Roo
   - Verify no authorization loops

2. **Production Deployment** (Issue #8)
   - Same process as UAT
   - Use auth.rivoli.ai domain
   - Update all clients to production URLs
   - Monitor closely for first 24 hours

3. **Post-Production**
   - Implement monitoring alerts
   - Set up log aggregation
   - Configure automated backups
   - Plan for scale (if needed)

## References

- [Railway Docs](https://docs.railway.app/)
- [Nixpacks .NET](https://nixpacks.com/docs/providers/dotnet)
- [ASP.NET Core Deployment](https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/)
- [OpenIddict Deployment](https://documentation.openiddict.com/)

---

**Last Updated:** 2025-11-16
**Current Environment:** Local Development
**Next Deployment:** UAT (Issue #3)


## Ingress trust and readiness admission

UAT and Production trust only loopback by default. Configure
`ForwardedHeaders__KnownProxies__0` (an individual IP) or
`ForwardedHeaders__KnownNetworks__0` (the dedicated ingress CIDR) using the actual
peers assigned to the deployment. Do not substitute all RFC1918, CGNAT or IPv6
private address space. `TrustAllProxies=true` is rejected outside local/embedded
modes, and malformed entries fail startup instead of silently emptying the trust
list. `ForwardLimit` must match the intended positive proxy-hop count.

Before routing traffic, verify that the ingress overwrites inbound
`X-Forwarded-For`/`X-Forwarded-Proto`, that a non-ingress private peer cannot
change the application's observed IP/scheme, and that direct container access
is blocked. The repository cannot establish those platform properties; record
the deployed checks on issue #174.

Route only to instances whose `/ready` returns 200. `/health` is liveness only.
The application also rejects non-probe requests with non-cacheable 503 responses
when migration or required seeding has failed, even if an edge misroutes traffic.
This startup gate does not replace continuous platform readiness checks or
shared rate-limit enforcement.

### Shared rate-limit counters

UAT and Production require `RateLimiting__RedisConnectionString` and refuse startup without it. Supply the same Redis endpoint/database to every replica through the deployment secret store; use TLS, authentication and a dedicated non-evicting database. Redis increments and expiry are atomic across replicas, and outages reject requests with 503 rather than reverting to local allowances. All replicas must use the same rate-limit rules. Redis data loss or eviction can reset allowances, so operate it with persistence and `noeviction`; monitor outages and capacity.

`RateLimiting__RequireDistributed=false` is only for isolated single-process fixtures or local deployments. A real multi-replica deployment must retain the hardened default. Configured IP policies remain local immutable configuration; counters use Redis. The real regression test runs in CI against Redis and can be run locally with `ANDY_TEST_REDIS=localhost:16379 dotnet test tests/Andy.Auth.Server.Tests --filter FullyQualifiedName~DistributedRateLimitingTests`.

Before increasing replicas, alternate requests at the login/token limit across two instances and verify one shared allowance; disconnect Redis and verify 503 without any fallback. These checks supplement the ingress and readiness acceptance above.

### Privileged browser access

UAT, Staging and Production require an authenticator step-up for both interactive admin controllers. An ordinary Admin-role login first routes to `/AdminAccess`; authenticator enrollment remains available under `/TwoFactor`. Password accounts must provide both their current password and an authenticator code. External-only accounts must have signed in within 15 minutes and provide a local authenticator code. Failed proof attempts use Identity lockout.

Admin proof expires after 15 minutes without sliding renewal. Its Secure/HttpOnly/SameSite=Strict cookie is bound to the current user, server-side session id, and security stamp, and the filter rechecks Admin membership and MFA enrollment. Logout/new sessions, password/security-stamp changes, removal of Admin, or disabling MFA invalidate access. Every admin mutation retains CSRF validation. Local/embedded development can opt in with `AdminAccess__EnforceInLocal=true`; hardened environments cannot disable the requirement through this local setting. Bearer-authorized service APIs retain their separate authorization contract.
