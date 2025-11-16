# Andy Auth Deployment Guide

Complete guide for deploying Andy Auth Server and integrating with your applications.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    PRODUCTION/UAT                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Railway: auth.rivoli.ai (Andy.Auth.Server)                 │
│    ├─ OpenIddict OAuth/OIDC server                          │
│    ├─ PostgreSQL database                                   │
│    └─ Issues JWT tokens                                     │
│                          ↓                                   │
│  Railway: lexipro-api.rivoli.ai (Lexipro.Api)              │
│    ├─ Uses Andy.Auth NuGet package                          │
│    ├─ Validates tokens from Andy.Auth.Server                │
│    └─ MCP server endpoints                                  │
│                          ↓                                   │
│  Vercel: wagram.ai (Angular Frontend)                       │
│    └─ Redirects to auth.rivoli.ai for login                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Phase 1: Local Development Setup

### Step 1: Complete Andy.Auth.Server Implementation

The server structure exists but needs OpenIddict implementation.

**Option A: Use OpenIddict Templates (Fastest)**

```bash
cd /Users/samibengrine/Devel/rivoli-ai/andy-auth

# Install OpenIddict templates
dotnet new install OpenIddict.Templates

# Generate server files into a temp directory
mkdir temp-openiddict
cd temp-openiddict
dotnet new openiddict-server -n TempServer --framework net8.0

# Copy relevant files to Andy.Auth.Server
# - Controllers/
# - Data/
# - Models/
# - Views/
# - appsettings.json structure

cd ..
rm -rf temp-openiddict
```

**Option B: Manual Implementation (More Control)**

I can implement this for you - it involves:
- Database context with OpenIddict entities
- Authorization controller
- Token endpoint
- User management
- Login/consent UI

### Step 2: Local Database Setup

**Using SQLite (Development):**

```bash
cd src/Andy.Auth.Server

# Add SQLite package
dotnet add package Microsoft.EntityFrameworkCore.Sqlite

# Update appsettings.Development.json
```

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Data Source=andy-auth.db"
  },
  "OpenIddict": {
    "Server": {
      "EncryptionKey": "YOUR-DEV-ENCRYPTION-KEY-32-CHARS",
      "SigningKey": "YOUR-DEV-SIGNING-KEY-32-CHARS"
    }
  }
}
```

**Using PostgreSQL (Matches Production):**

```bash
# Install PostgreSQL locally
brew install postgresql  # macOS
# or use Docker
docker run --name andy-auth-postgres -e POSTGRES_PASSWORD=devpass -p 5432:5432 -d postgres

# Add PostgreSQL package
dotnet add package Npgsql.EntityFrameworkCore.PostgreSQL

# Connection string
"DefaultConnection": "Host=localhost;Database=andy_auth_dev;Username=postgres;Password=devpass"
```

### Step 3: Run Andy.Auth.Server Locally

```bash
cd src/Andy.Auth.Server

# Run migrations
dotnet ef database update

# Run server (will be at https://localhost:7156 by default)
dotnet run

# Server endpoints will be available:
# - https://localhost:7156/.well-known/openid-configuration
# - https://localhost:7156/connect/authorize
# - https://localhost:7156/connect/token
# - https://localhost:7156/connect/register
```

### Step 4: Update Lexipro.Api to Use Andy.Auth

**Install Andy.Auth Package:**

```bash
cd /Users/samibengrine/Devel/rivoli-ai/lexipro/src/Lexipro.Api

# For local testing, reference the local project
dotnet add reference /Users/samibengrine/Devel/rivoli-ai/andy-auth/src/Andy.Auth/Andy.Auth.csproj

# Or use the published NuGet package (once published)
dotnet add package Andy.Auth --version 1.0.0-beta
```

**Update Lexipro.Api/appsettings.Development.json:**

```json
{
  "AndyAuth": {
    "Provider": "AndyAuth",
    "Authority": "https://localhost:7156",
    "Audience": "lexipro-api",
    "RequireHttpsMetadata": false
  },
  "Mcp": {
    "ServerUrl": "https://localhost:7001",
    "McpPath": "/mcp"
  }
}
```

**Update Lexipro.Api/Program.cs:**

```csharp
using Andy.Auth.Extensions;

// REMOVE these sections:
// - All JWT Bearer configuration
// - Clerk authentication setup
// - ClerkOAuthTokenHandler registration
// - Policy scheme configuration

// REPLACE with:
builder.Services.AddAndyAuth(builder.Configuration);

// Keep MCP configuration as is:
builder.Services
    .AddMcpServer()
    .WithHttpTransport()
    .WithToolsFromAssembly()
    // ... rest of MCP config

// Update MCP metadata to point to Andy Auth:
.AddMcp(options =>
{
    var serverUrl = builder.Configuration["Mcp:ServerUrl"] ?? "https://localhost:7001";
    options.ResourceMetadata = new()
    {
        Resource = new Uri($"{serverUrl}/mcp"),
        AuthorizationServers = { new Uri("https://localhost:7156") }, // Andy.Auth.Server
        ScopesSupported = ["openid", "profile", "email"]
    };
});
```

**Remove these files from Lexipro.Api:**
- `Authentication/ClerkOAuthTokenHandler.cs`
- `Controllers/DynamicClientRegistrationController.cs`

**Keep CurrentUserService.cs or replace with Andy.Auth's version.**

### Step 5: Test Locally

**Terminal 1 - Run Andy.Auth.Server:**
```bash
cd /Users/samibengrine/Devel/rivoli-ai/andy-auth/src/Andy.Auth.Server
dotnet run
```

**Terminal 2 - Run Lexipro.Api:**
```bash
cd /Users/samibengrine/Devel/rivoli-ai/lexipro/src/Lexipro.Api
dotnet run
```

**Terminal 3 - Run Angular Frontend:**
```bash
cd /Users/samibengrine/Devel/rivoli-ai/lexipro/client
npm start
```

**Test Authentication:**
1. Navigate to http://localhost:4200
2. Click login → redirects to https://localhost:7156/login
3. Enter credentials
4. Redirects back with access token
5. Frontend calls Lexipro.Api with token
6. API validates token with Andy.Auth.Server

---

## Phase 2: Railway Deployment

### Step 1: Create Railway Project for Andy.Auth.Server

**Railway Setup:**

1. Go to https://railway.app
2. Create new project: "andy-auth-uat"
3. Add PostgreSQL database
4. Add service from GitHub: `rivoli-ai/andy-auth`

**railway.json** (create in andy-auth repo root):

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

**nixpacks.toml** (for Railway .NET deployment):

```toml
[phases.setup]
nixPkgs = ["dotnet-sdk_8"]

[phases.build]
cmds = ["dotnet publish src/Andy.Auth.Server/Andy.Auth.Server.csproj -c Release -o out"]

[phases.start]
cmd = "dotnet out/Andy.Auth.Server.dll"
```

### Step 2: Configure Environment Variables in Railway

**For Andy.Auth.Server:**

```bash
# Database (automatically set by Railway PostgreSQL)
DATABASE_URL=postgres://user:pass@host:5432/dbname

# Connection string (formatted from DATABASE_URL)
ConnectionStrings__DefaultConnection=${{Postgres.DATABASE_URL}}

# Server URLs
ASPNETCORE_URLS=http://0.0.0.0:${{PORT}}
Mcp__ServerUrl=https://auth-uat.rivoli.ai

# Security keys (generate with: openssl rand -base64 32)
OpenIddict__Server__EncryptionKey=<your-encryption-key>
OpenIddict__Server__SigningKey=<your-signing-key>

# Environment
ASPNETCORE_ENVIRONMENT=UAT
```

### Step 3: Set Up Custom Domain

In Railway:
1. Go to Settings → Domains
2. Add custom domain: `auth-uat.rivoli.ai`
3. Update DNS:
   ```
   Type: CNAME
   Name: auth-uat
   Value: <railway-generated-url>
   ```

### Step 4: Deploy Lexipro.Api to Railway

**Update Lexipro.Api Environment Variables:**

```bash
# Andy Auth configuration
AndyAuth__Provider=AndyAuth
AndyAuth__Authority=https://auth-uat.rivoli.ai
AndyAuth__Audience=lexipro-api
AndyAuth__RequireHttpsMetadata=true

# MCP configuration
Mcp__ServerUrl=https://lexipro-api-uat.rivoli.ai
Mcp__McpPath=/mcp

# Keep existing Lexipro variables
# (Database, ElevenLabs, MinIO, etc.)
```

### Step 5: Update Angular Frontend (Vercel)

**Update environment files:**

**`client/src/environments/environment.uat.ts`:**
```typescript
export const environment = {
  production: false,
  apiUrl: 'https://lexipro-api-uat.rivoli.ai',
  authUrl: 'https://auth-uat.rivoli.ai',
  clientId: 'lexipro-web',
  redirectUri: 'https://wagram-uat.vercel.app/callback'
};
```

**Update Vercel environment variables:**
```bash
VITE_AUTH_URL=https://auth-uat.rivoli.ai
VITE_API_URL=https://lexipro-api-uat.rivoli.ai
```

---

## Phase 3: Production Deployment

### Production Environment Variables

**Andy.Auth.Server (Railway):**
```bash
ConnectionStrings__DefaultConnection=${{Postgres.DATABASE_URL}}
ASPNETCORE_URLS=http://0.0.0.0:${{PORT}}
ASPNETCORE_ENVIRONMENT=Production
Mcp__ServerUrl=https://auth.rivoli.ai
OpenIddict__Server__EncryptionKey=<prod-encryption-key>
OpenIddict__Server__SigningKey=<prod-signing-key>
```

**Lexipro.Api (Railway):**
```bash
AndyAuth__Provider=AndyAuth
AndyAuth__Authority=https://auth.rivoli.ai
AndyAuth__Audience=lexipro-api
AndyAuth__RequireHttpsMetadata=true
Mcp__ServerUrl=https://lexipro-api.rivoli.ai
```

**Frontend (Vercel):**
```bash
VITE_AUTH_URL=https://auth.rivoli.ai
VITE_API_URL=https://lexipro-api.rivoli.ai
```

---

## Deployment Checklist

### UAT Deployment
- [ ] Deploy Andy.Auth.Server to Railway (auth-uat.rivoli.ai)
- [ ] Run database migrations
- [ ] Publish Andy.Auth NuGet package (v1.0.0-beta)
- [ ] Update Lexipro.Api to use Andy.Auth
- [ ] Deploy Lexipro.Api to Railway (lexipro-api-uat.rivoli.ai)
- [ ] Update Angular frontend environment variables
- [ ] Deploy frontend to Vercel (wagram-uat.vercel.app)
- [ ] Test login flow end-to-end
- [ ] Test MCP authentication (Claude Desktop)
- [ ] Verify token validation

### Production Deployment
- [ ] Publish Andy.Auth v1.0.0 (stable)
- [ ] Deploy Andy.Auth.Server to Railway (auth.rivoli.ai)
- [ ] Run production migrations
- [ ] Update Lexipro.Api production config
- [ ] Deploy Lexipro.Api to Railway
- [ ] Deploy frontend to Vercel (wagram.ai)
- [ ] Update DNS records
- [ ] Monitor logs and performance
- [ ] Set up alerting

---

## Monitoring & Troubleshooting

### Health Checks

**Andy.Auth.Server:**
```bash
curl https://auth-uat.rivoli.ai/.well-known/openid-configuration
curl https://auth-uat.rivoli.ai/health
```

**Lexipro.Api:**
```bash
curl https://lexipro-api-uat.rivoli.ai/health
curl https://lexipro-api-uat.rivoli.ai/.well-known/oauth-protected-resource
```

### Common Issues

**"Invalid issuer" errors:**
- Check `AndyAuth__Authority` matches Andy.Auth.Server URL
- Verify SSL certificate is valid
- Check `RequireHttpsMetadata` setting

**"Token validation failed":**
- Verify signing keys match between environments
- Check clock sync between servers
- Validate audience claim

**"Redirect URI mismatch":**
- Check registered redirect URIs in database
- Verify client configuration
- Check URL encoding

### Logs

**Railway logs:**
```bash
# View logs in Railway dashboard
# Or use Railway CLI
railway logs --service andy-auth-server
railway logs --service lexipro-api
```

**Application Insights (optional):**
Add to Andy.Auth.Server and Lexipro.Api for advanced monitoring.

---

## Security Considerations

### Keys and Secrets

**Generate secure keys:**
```bash
# Encryption key (32 bytes)
openssl rand -base64 32

# Signing key (32 bytes)
openssl rand -base64 32
```

**Store in Railway environment variables** - never commit to git!

### HTTPS/TLS

- Railway provides automatic HTTPS
- Ensure `RequireHttpsMetadata: true` in production
- Use HTTPS for all redirect URIs

### Rate Limiting

Add to Andy.Auth.Server:
```csharp
builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter("auth", opt =>
    {
        opt.Window = TimeSpan.FromMinutes(1);
        opt.PermitLimit = 10;
    });
});
```

---

## Migration Strategy

### From Clerk to Andy.Auth

**Phase 1: Side-by-side (Keep Clerk working)**
1. Deploy Andy.Auth.Server
2. Update Lexipro.Api to use Andy.Auth library
3. Configure `Provider: "Clerk"` initially
4. Test everything works

**Phase 2: Switch providers**
1. Change config to `Provider: "AndyAuth"`
2. Update frontend to use auth.rivoli.ai
3. Test authentication flow
4. Monitor for issues

**Phase 3: Remove Clerk**
1. Export users from Clerk (if needed)
2. Import to Andy.Auth.Server
3. Remove Clerk configuration
4. Cancel Clerk subscription

---

## Cost Estimate

**UAT Environment:**
- Railway Andy.Auth.Server: $5/month (Hobby plan)
- Railway PostgreSQL: $5/month
- Lexipro.Api: Already running
- Vercel: Free (current plan)
- **Total: ~$10/month**

**Production:**
- Railway Andy.Auth.Server: $20/month (Pro)
- Railway PostgreSQL: $10/month
- Higher traffic costs
- **Total: ~$30-50/month**

**Savings:**
- Clerk: $25-100+/month (depending on MAU)
- **ROI: Positive after 1-2 months**

---

## Next Steps

1. **I can implement Andy.Auth.Server with OpenIddict** - takes ~1-2 hours
2. **Test locally** with all three services running
3. **Deploy to Railway UAT** for testing
4. **Migrate Lexipro.Api** to use Andy.Auth
5. **Production deployment** after UAT validation

Would you like me to:
1. Implement the Andy.Auth.Server with OpenIddict now?
2. Create the Railway configuration files?
3. Update Lexipro.Api to use Andy.Auth?
4. All of the above?
