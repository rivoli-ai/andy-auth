# Andy Auth

Multi-provider authentication library for ASP.NET Core supporting:
- Andy Auth (self-hosted OpenIddict server)
- Microsoft Azure Active Directory
- Clerk
- Custom OpenID Connect providers

## Features

- 🎯 **Provider Abstraction** - Easily switch between authentication providers
- 🔐 **Standards-Based** - OAuth 2.0, OpenID Connect, PKCE support
- 🚀 **Easy Integration** - One line to add authentication to your API
- 📦 **NuGet Package** - Distributed via GitHub Packages
- 🧪 **Tested** - Comprehensive test coverage

## Quick Start

### Installation

```bash
dotnet add package Andy.Auth
```

### Configuration (appsettings.json)

#### Option 1: Andy Auth (Self-Hosted)
```json
{
  "AndyAuth": {
    "Provider": "AndyAuth",
    "Authority": "https://auth.rivoli.ai",
    "Audience": "your-api-id"
  }
}
```

#### Option 2: Azure AD
```json
{
  "AndyAuth": {
    "Provider": "AzureAD",
    "AzureAd": {
      "TenantId": "your-tenant-id",
      "ClientId": "your-client-id"
    }
  }
}
```

#### Option 3: Clerk
```json
{
  "AndyAuth": {
    "Provider": "Clerk",
    "Clerk": {
      "Domain": "your-app.clerk.accounts.dev"
    }
  }
}
```

### Usage (Program.cs)

```csharp
using Andy.Auth.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add Andy Auth
builder.Services.AddAndyAuth(builder.Configuration);

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// Your protected endpoints
app.MapGet("/api/protected", () => "Hello!")
    .RequireAuthorization();

app.Run();
```

### Accessing Current User

```csharp
using Andy.Auth.Services;

public class MyService
{
    private readonly ICurrentUserService _currentUser;

    public MyService(ICurrentUserService currentUser)
    {
        _currentUser = currentUser;
    }

    public async Task DoSomething()
    {
        var userId = await _currentUser.GetUserIdAsync();
        var claims = await _currentUser.GetUserClaimsAsync();

        // Use user information
    }
}
```

## Andy Auth Server

This repository also includes **Andy.Auth.Server** - a complete self-hosted OAuth/OIDC server built with OpenIddict.

### Local Development

```bash
# Start PostgreSQL
docker-compose up -d

# Run the server
cd src/Andy.Auth.Server
dotnet run
```

Server runs at: https://localhost:5001

**Test credentials:**
- Email: `test@andy.local`
- Password: `Test123!`

See [LOCAL-SETUP.md](./LOCAL-SETUP.md) for detailed instructions.

### Deployment

Deploy to Railway with the included configuration:
- `railway.json` - Railway deployment config
- `nixpacks.toml` - Nixpacks build configuration

See [docs/DEPLOYMENT.md](./docs/DEPLOYMENT.md) for production deployment guide.

## Documentation

- [LOCAL-SETUP.md](./LOCAL-SETUP.md) - Local development setup
- [docs/DEPLOYMENT.md](./docs/DEPLOYMENT.md) - Production deployment guide
- [docs/PASSKEYS.md](./docs/PASSKEYS.md) - WebAuthn/FIDO2 passkey support
- [docs/testing.md](./docs/testing.md) - Testing guide
- [PROJECT-SUMMARY.md](./PROJECT-SUMMARY.md) - Complete project overview

## License

Apache 2.0

## Contributing

This is a private repository for Rivoli AI. Contributions are welcome from team members.
