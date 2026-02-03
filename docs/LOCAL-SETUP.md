# Andy Auth - Local Setup Guide

## Prerequisites

- .NET 8.0 SDK
- Docker Desktop (for PostgreSQL)
- IDE (Visual Studio, VS Code, or Rider)

## Quick Start

### 1. Start PostgreSQL

```bash
docker-compose up -d
```

This starts:
- PostgreSQL on port 5432
- Adminer (database UI) on http://localhost:8080

### 2. Run Andy.Auth.Server

```bash
cd src/Andy.Auth.Server
dotnet run
```

The server will:
- Run migrations automatically
- Seed OAuth clients (andy-docs-api, wagram-web, claude-desktop)
- Create test user: `test@andy.local` / `Test123!`
- Start on https://localhost:5001

### 3. Test Authentication

**Visit the server:**
```
https://localhost:5001
```

**Login with test user:**
- Email: `test@andy.local`
- Password: `Test123!`

**Test OAuth endpoints:**
```bash
# Get OpenID configuration
curl https://localhost:5001/.well-known/openid-configuration

# Authorization endpoint
https://localhost:5001/connect/authorize?client_id=andy-docs-api&redirect_uri=https://localhost:7001/callback&response_type=code&scope=openid%20profile%20email
```

## Configuration

### Database Connection

Edit `src/Andy.Auth.Server/appsettings.Development.json`:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Host=localhost;Database=andy_auth_dev;Username=postgres;Password=postgres"
  }
}
```

### OAuth Clients

Clients are automatically seeded on startup. Edit `src/Andy.Auth.Server/Data/DbSeeder.cs` to modify:
- `andy-docs-api` - Confidential client for Andy Docs API
- `wagram-web` - Public client for Angular frontend
- `claude-desktop` - Public client for Claude Desktop MCP

### Security Keys

For development, keys are in `appsettings.Development.json`:
```json
{
  "OpenIddict": {
    "Server": {
      "EncryptionKey": "DEV-ENCRYPTION-KEY-32-CHARS!!",
      "SigningKey": "DEV-SIGNING-KEY-32-CHARS-HERE!"
    }
  }
}
```

**For production:** Generate secure keys:
```bash
openssl rand -base64 32
```

## Database Management

### View Database

Access Adminer at http://localhost:8080:
- System: PostgreSQL
- Server: postgres
- Username: postgres
- Password: postgres
- Database: andy_auth_dev

### Run Migrations

```bash
cd src/Andy.Auth.Server

# Create new migration
dotnet ef migrations add MigrationName

# Apply migrations
dotnet ef database update

# Remove last migration
dotnet ef migrations remove
```

### Reset Database

```bash
cd src/Andy.Auth.Server

# Drop and recreate
dotnet ef database drop -f
dotnet ef database update
```

## Testing with Andy Docs.Api

### 1. Update Andy Docs.Api Configuration

Edit `Andy Docs.Api/appsettings.Development.json`:

```json
{
  "AndyAuth": {
    "Provider": "AndyAuth",
    "Authority": "https://localhost:5001",
    "Audience": "andy-docs-api",
    "RequireHttpsMetadata": false
  }
}
```

### 2. Run Both Services

**Terminal 1 - Andy.Auth.Server:**
```bash
cd andy-auth/src/Andy.Auth.Server
dotnet run
```

**Terminal 2 - Andy Docs.Api:**
```bash
cd andy-docs/src/Andy Docs.Api
dotnet run
```

**Terminal 3 - Angular Frontend:**
```bash
cd andy-docs/client
npm start
```

### 3. Test Authentication Flow

1. Navigate to http://localhost:4200
2. Click login → redirects to Andy Auth (https://localhost:5001)
3. Login with test@andy.local / Test123!
4. Redirected back to app with access token
5. Frontend calls Andy Docs.Api with token
6. API validates token with Andy.Auth.Server

## Troubleshooting

### Port Already in Use

```bash
# Find process using port 5001
lsof -i :5001

# Kill process
kill -9 <PID>
```

### Database Connection Failed

```bash
# Check PostgreSQL is running
docker ps

# Restart PostgreSQL
docker-compose down
docker-compose up -d

# Check logs
docker logs andy-auth-postgres
```

### SSL Certificate Issues

```bash
# Trust development certificate
dotnet dev-certs https --trust

# Clean and regenerate
dotnet dev-certs https --clean
dotnet dev-certs https --trust
```

### Migration Errors

```bash
# Reset migrations
rm -rf src/Andy.Auth.Server/Migrations
dotnet ef migrations add InitialCreate
dotnet ef database update
```

## Development Workflow

### 1. Make Code Changes

Edit files in `src/Andy.Auth.Server/`

### 2. Hot Reload

The server supports hot reload:
```bash
dotnet watch run
```

### 3. Test Changes

```bash
# Run tests
dotnet test

# Check code coverage
dotnet test /p:CollectCoverage=true /p:CoverageReportsDirectory=coverage
```

### 4. Commit Changes

```bash
git add .
git commit -m "Description of changes"
git push origin develop
```

## Environment Variables

Create `.env` file (not committed):

```bash
ConnectionStrings__DefaultConnection=Host=localhost;Database=andy_auth_dev;Username=postgres;Password=postgres
OpenIddict__Server__EncryptionKey=your-32-char-encryption-key
OpenIddict__Server__SigningKey=your-32-char-signing-key
ASPNETCORE_ENVIRONMENT=Development
```

Load with:
```bash
export $(cat .env | xargs)
dotnet run
```

## Next Steps

- [ ] Test OAuth flow with Andy Docs.Api
- [ ] Add users via registration form
- [ ] Test with Claude Desktop MCP
- [ ] Test with ChatGPT/Roo
- [ ] Deploy to Railway UAT
- [ ] Update Wagram frontend to use Andy Auth

## Resources

- [OpenIddict Documentation](https://documentation.openiddict.com/)
- [ASP.NET Core Identity](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity)
- [OAuth 2.0 Spec](https://oauth.net/2/)
- [OpenID Connect Spec](https://openid.net/connect/)
