# Andy Docs Integration Example

This example demonstrates migrating Andy Docs API from manual JWT Bearer configuration to the **Andy.Auth** library.

## Overview

**Before:** ~50 lines of manual JWT configuration
**After:** 3 lines with Andy.Auth library
**Savings:** 95% less code, type-safe configuration, multi-provider support

## Migration Steps

### Step 1: Install Andy.Auth Library

Add the NuGet package to your Andy Docs API project:

```bash
cd andy-docs/src/Andy.Docs.Api
dotnet add package Andy.Auth
```

### Step 2: Update appsettings.json

**Before** (Manual configuration scattered across Program.cs):
```csharp
// Authority, Audience, and validation parameters hardcoded in code
```

**After** (Centralized configuration):

`appsettings.json`:
```json
{
  "AndyAuth": {
    "Provider": "AndyAuth",
    "Authority": "https://localhost:7088",
    "Audience": "andy-docs-api",
    "RequireHttpsMetadata": false
  }
}
```

`appsettings.Production.json`:
```json
{
  "AndyAuth": {
    "Authority": "https://auth.rivoli.ai",
    "RequireHttpsMetadata": true
  }
}
```

### Step 3: Update Program.cs

**Before:**

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Manual JWT Bearer configuration
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = "https://localhost:7088";
        options.Audience = "andy-docs-api";
        options.RequireHttpsMetadata = false;

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "https://localhost:7088",
            ValidateAudience = true,
            ValidAudience = "andy-docs-api",
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ClockSkew = TimeSpan.FromMinutes(5),
            NameClaimType = ClaimTypes.NameIdentifier,
            RoleClaimType = ClaimTypes.Role
        };

        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILogger<Program>>();
                logger.LogError(context.Exception, "Authentication failed");
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILogger<Program>>();
                logger.LogInformation("Token validated for user: {User}",
                    context.Principal?.Identity?.Name);
                return Task.CompletedTask;
            }
        };
    });

// Custom service to access user claims
builder.Services.AddScoped<IUserContext, UserContext>();
builder.Services.AddHttpContextAccessor();

// ... rest of configuration
```

**After:**

```csharp
using Andy.Auth.Extensions;

var builder = WebApplication.CreateBuilder(args);

// One-line authentication setup
builder.Services.AddAndyAuth(builder.Configuration);

// ... rest of configuration
```

### Step 4: Update UserContext Service

**Before** (Custom implementation):

`Services/IUserContext.cs`:
```csharp
public interface IUserContext
{
    string? GetUserId();
    string? GetUserEmail();
    bool IsAuthenticated();
}
```

`Services/UserContext.cs`:
```csharp
using System.Security.Claims;

public class UserContext : IUserContext
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public UserContext(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public string? GetUserId()
    {
        var principal = _httpContextAccessor.HttpContext?.User;
        return principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? principal?.FindFirst("sub")?.Value;
    }

    public string? GetUserEmail()
    {
        var principal = _httpContextAccessor.HttpContext?.User;
        return principal?.FindFirst(ClaimTypes.Email)?.Value
            ?? principal?.FindFirst("email")?.Value;
    }

    public bool IsAuthenticated()
    {
        return _httpContextAccessor.HttpContext?.User?.Identity?.IsAuthenticated ?? false;
    }
}
```

**After** (Use ICurrentUserService):

Remove custom `IUserContext` and `UserContext` classes. Use built-in `ICurrentUserService`:

```csharp
using Andy.Auth.Services;

public class BookService
{
    private readonly ICurrentUserService _currentUser;

    public BookService(ICurrentUserService currentUser)
    {
        _currentUser = currentUser;
    }

    public async Task<List<Book>> GetUserBooks()
    {
        var userId = await _currentUser.GetUserIdAsync();
        // Fetch books for user
    }
}
```

### Step 5: Update Controllers

**Before:**

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class BooksController : ControllerBase
{
    private readonly IUserContext _userContext;
    private readonly IBookRepository _books;

    public BooksController(IUserContext userContext, IBookRepository books)
    {
        _userContext = userContext;
        _books = books;
    }

    [HttpGet]
    public async Task<IActionResult> GetBooks()
    {
        var userId = _userContext.GetUserId();
        if (userId == null)
            return Unauthorized();

        var books = await _books.GetByUserIdAsync(userId);
        return Ok(books);
    }

    [HttpGet("profile")]
    public IActionResult GetProfile()
    {
        var userId = _userContext.GetUserId();
        var email = _userContext.GetUserEmail();

        return Ok(new { UserId = userId, Email = email });
    }
}
```

**After:**

```csharp
using Andy.Auth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class BooksController : ControllerBase
{
    private readonly ICurrentUserService _currentUser;
    private readonly IBookRepository _books;

    public BooksController(ICurrentUserService currentUser, IBookRepository books)
    {
        _currentUser = currentUser;
        _books = books;
    }

    [HttpGet]
    public async Task<IActionResult> GetBooks()
    {
        var userId = await _currentUser.GetUserIdAsync();
        var books = await _books.GetByUserIdAsync(userId);
        return Ok(books);
    }

    [HttpGet("profile")]
    public async Task<IActionResult> GetProfile()
    {
        var claims = await _currentUser.GetUserClaimsAsync();

        return Ok(new
        {
            UserId = claims.UserId,
            Email = claims.Email,
            Name = claims.Name
        });
    }
}
```

## Complete Program.cs Comparison

### Before (Manual Configuration)

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Andy.Docs.Api.Data;
using Andy.Docs.Api.Services;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Database
builder.Services.AddDbContext<AndyDocsDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// Authentication - Manual JWT Bearer Setup
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        var authority = builder.Configuration["Auth:Authority"];
        var audience = builder.Configuration["Auth:Audience"];

        options.Authority = authority;
        options.Audience = audience;
        options.RequireHttpsMetadata = builder.Environment.IsProduction();

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = authority,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ClockSkew = TimeSpan.FromMinutes(5),
            NameClaimType = ClaimTypes.NameIdentifier,
            RoleClaimType = ClaimTypes.Role
        };

        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILogger<Program>>();
                logger.LogError(context.Exception, "Authentication failed");
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILogger<Program>>();
                var userId = context.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                logger.LogInformation("Token validated for user: {UserId}", userId);
                return Task.CompletedTask;
            },
            OnChallenge = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILogger<Program>>();
                logger.LogWarning("Authentication challenge: {Error}", context.Error);
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();

// Custom user context service
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<IUserContext, UserContext>();

// Application services
builder.Services.AddScoped<IBookService, BookService>();

// Controllers
builder.Services.AddControllers();

// Swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
```

**Total Lines:** ~110 lines

### After (Andy.Auth Library)

```csharp
using Andy.Auth.Extensions;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using Andy.Docs.Api.Data;
using Andy.Docs.Api.Services;

var builder = WebApplication.CreateBuilder(args);

// Database
builder.Services.AddDbContext<AndyDocsDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// Authentication - Andy.Auth Library (one line!)
builder.Services.AddAndyAuth(builder.Configuration);

builder.Services.AddAuthorization();

// Application services
builder.Services.AddScoped<IBookService, BookService>();

// Controllers
builder.Services.AddControllers();

// Swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
```

**Total Lines:** ~55 lines (50% reduction!)

## Configuration Files

### appsettings.json

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Host=localhost;Database=andy_docs;Username=postgres;Password=postgres"
  },
  "AndyAuth": {
    "Provider": "AndyAuth",
    "Authority": "https://localhost:7088",
    "Audience": "andy-docs-api",
    "RequireHttpsMetadata": false
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  }
}
```

### appsettings.Production.json

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "${DATABASE_URL}"
  },
  "AndyAuth": {
    "Authority": "https://auth.rivoli.ai",
    "RequireHttpsMetadata": true
  }
}
```

## Testing the Integration

### 1. Start Andy.Auth.Server

```bash
cd ../andy-auth/src/Andy.Auth.Server
dotnet run
# Server runs at https://localhost:7088
```

### 2. Start Andy Docs API

```bash
cd andy-docs/src/Andy.Docs.Api
dotnet run
# API runs at https://localhost:7001
```

### 3. Get Access Token

Visit Andy.Auth.Server and login:
- URL: https://localhost:7088/Account/Login
- Email: test@andy.local
- Password: Test123!

Or use OAuth flow:

```bash
# Authorization Code Flow (with PKCE)
curl -X POST "https://localhost:7088/connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=YOUR_AUTH_CODE" \
  -d "client_id=andy-docs-api" \
  -d "redirect_uri=https://localhost:7001/callback" \
  -d "code_verifier=YOUR_CODE_VERIFIER"
```

### 4. Call Protected API

```bash
# Get books (requires authentication)
curl -X GET "https://localhost:7001/api/books" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# Get user profile
curl -X GET "https://localhost:7001/api/books/profile" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

Expected response:
```json
{
  "userId": "user-id-here",
  "email": "test@andy.local",
  "name": "Test User"
}
```

## Benefits of Migration

| Feature | Before (Manual) | After (Andy.Auth) |
|---------|----------------|-------------------|
| **Lines of Code** | ~110 lines | ~55 lines |
| **Configuration** | Hardcoded in code | Centralized in appsettings.json |
| **Type Safety** | Manual validation | Strongly-typed options |
| **Multi-Provider** | Not supported | Switch providers with config |
| **User Service** | Custom implementation | Built-in ICurrentUserService |
| **Testability** | Difficult to mock | Easy to mock |
| **Maintenance** | Manual updates | Library handles updates |
| **Error Handling** | Custom events needed | Built-in validation |

## Switching to Azure AD (Production)

To switch to Azure AD in production, just update configuration:

```json
{
  "AndyAuth": {
    "Provider": "AzureAD",
    "AzureAd": {
      "Instance": "https://login.microsoftonline.com/",
      "TenantId": "your-tenant-id",
      "ClientId": "your-client-id",
      "Audience": "api://your-client-id"
    }
  }
}
```

No code changes required!

## Troubleshooting

### Issue: "No authenticationScheme was specified"

**Solution:** Ensure `AddAndyAuth()` is called before building the app.

### Issue: "Authority is required"

**Solution:** Add `Authority` to `appsettings.json`:
```json
{
  "AndyAuth": {
    "Authority": "https://localhost:7088"
  }
}
```

### Issue: Token validation fails

**Solution:**
1. Verify Andy.Auth.Server is running
2. Check Authority URL is correct
3. Ensure token hasn't expired
4. Verify audience matches

## Next Steps

1. ✅ Install Andy.Auth library
2. ✅ Update appsettings.json
3. ✅ Replace manual JWT configuration
4. ✅ Replace IUserContext with ICurrentUserService
5. ✅ Update controllers
6. ✅ Test locally
7. 🚀 Deploy to production

## Resources

- [Andy.Auth Library Documentation](../../docs/LIBRARY.md)
- [Andy.Auth.Server Documentation](../../docs/DEPLOYMENT.md)
- [ASP.NET Core Authentication](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/)

---

**Estimated Migration Time:** 15-30 minutes
**Code Reduction:** 50% fewer lines
**Complexity Reduction:** 95% simpler authentication setup
