# Testing Guide

Testing documentation for Andy Auth Server.

## Test Overview

**Current Status:**
- .NET Unit/Integration Tests: 129/129 passed (100%)
- E2E Browser Tests (Playwright): 48/60 passed (80%)
- Python OAuth Tests: 42/42 passed (100%)
- Last Updated: 2026-01-15

## Test Structure

```
tests/
├── Andy.Auth.Server.Tests/     # .NET unit/integration tests (xUnit)
│   ├── AccountControllerTests.cs
│   ├── AuthorizationControllerTests.cs
│   ├── AdminControllerTests.cs
│   ├── DbSeederTests.cs
│   ├── OAuthIntegrationTests.cs
│   ├── UsersApiControllerTests.cs
│   ├── McpUsersControllerTests.cs
│   └── CustomWebApplicationFactory.cs
│
├── Andy.Auth.E2E.Tests/        # Playwright E2E browser tests
│   ├── E2ETestServer.cs        # Custom test server with real HTTP
│   ├── E2ETestBase.cs          # Base class with Playwright setup
│   ├── LoginLogoutTests.cs     # Authentication flows
│   ├── DateFormattingTests.cs  # UTC to local time conversion
│   ├── UserManagementTests.cs  # Admin user management
│   ├── SessionManagementTests.cs
│   ├── PasswordChangeTests.cs
│   └── AdminDashboardTests.cs
│
├── Andy.Auth.Tests/            # Additional .NET tests
│
└── oauth-python/               # Python OAuth compliance tests
    ├── config.py               # Environment configuration
    ├── run_all_tests.py        # Main test runner
    ├── test_authorization_code.py
    ├── test_client_credentials.py
    ├── test_discovery.py
    ├── test_dynamic_registration.py
    └── test_token_operations.py
```

## Running Tests

### All .NET Tests (Unit + E2E)

```bash
# Run all tests (recommended)
dotnet test

# Quick stats (minimal output)
dotnet test --no-build -v minimal

# Verbose output with test names
dotnet test -v normal

# Run with code coverage
dotnet test --collect:"XPlat Code Coverage"
```

### Unit/Integration Tests Only

```bash
# Run unit and integration tests (fast, no browser)
dotnet test tests/Andy.Auth.Server.Tests

# Run specific test class
dotnet test --filter "FullyQualifiedName~DbSeederTests"

# Run specific test
dotnet test --filter "FullyQualifiedName~LoginPage_WithValidCredentials"
```

### E2E Browser Tests (Playwright)

```bash
# First time setup - install Playwright browsers
pwsh tests/Andy.Auth.E2E.Tests/bin/Debug/net8.0/playwright.ps1 install
# Or on Linux/macOS without PowerShell:
dotnet build tests/Andy.Auth.E2E.Tests
./tests/Andy.Auth.E2E.Tests/bin/Debug/net8.0/playwright.sh install

# Run E2E tests only
dotnet test tests/Andy.Auth.E2E.Tests

# Run E2E tests with verbose output
dotnet test tests/Andy.Auth.E2E.Tests -v normal

# Run specific E2E test file
dotnet test tests/Andy.Auth.E2E.Tests --filter "FullyQualifiedName~LoginLogoutTests"

# Run E2E tests in headed mode (see browser)
# Set PWDEBUG=1 or modify E2ETestBase.cs Headless option
```

### Python OAuth Tests

```bash
cd tests/oauth-python

# Install dependencies (one time)
pip install -r requirements.txt

# Run against local server
ANDY_AUTH_TEST_PASSWORD="Test123!" python3 run_all_tests.py --env local

# Run against UAT
ANDY_AUTH_TEST_PASSWORD="Test123!" python3 run_all_tests.py --env uat

# Generate HTML report
ANDY_AUTH_TEST_PASSWORD="Test123!" python3 run_all_tests.py --env uat --html report.html
```

## Test Categories

### .NET Unit/Integration Tests (129 tests)

| Category | Tests | Description |
|----------|-------|-------------|
| DbSeederTests | 9 | Database seeding, client creation |
| AccountControllerTests | 16 | Login, registration, logout |
| AuthorizationControllerTests | 22 | OAuth authorization flows |
| AdminControllerTests | 28 | Admin dashboard, user management |
| UsersApiControllerTests | 21 | REST API for user management |
| McpUsersControllerTests | 12 | MCP tools for AI integration |
| OAuthIntegrationTests | 21 | Integration with WebApplicationFactory |

### E2E Browser Tests (60 tests)

| Category | Tests | Description |
|----------|-------|-------------|
| LoginLogoutTests | 9 | Authentication flows, redirects |
| DateFormattingTests | 13 | UTC to local time conversion in browser |
| UserManagementTests | 11 | Admin user CRUD operations |
| SessionManagementTests | 8 | Session list and management |
| PasswordChangeTests | 10 | Forced password change flows |
| AdminDashboardTests | 9 | Admin pages, consents |

### Python OAuth Tests (42 tests)

| Category | Tests | Description |
|----------|-------|-------------|
| Discovery & JWKS | 9 | OpenID Connect discovery validation |
| Client Credentials | 6 | Client credentials flow |
| Authorization Code | 10 | Authorization code flow with PKCE |
| Token Operations | 10 | Introspection, revocation, refresh |
| Dynamic Registration | 7 | RFC 7591/7592 DCR compliance |

## Test Credentials

**Test User (Development/UAT only):**
- Email: `test@andy.local`
- Password: `Test123!`

**E2E Test Users (seeded automatically):**
- Admin: `admin@test.com` / `Admin123!`
- User: `user@test.com` / `User123!`
- Must Change Password: `mustchange@test.com` / `TempPass123!`

**OAuth Clients:**
- `andy-docs-api` - Confidential client with secret
- `wagram-web` - Public SPA client
- `claude-desktop` - Public desktop client

## Environment Configuration

The Python tests use environment variables:

```bash
# Required
ANDY_AUTH_TEST_PASSWORD=Test123!

# Optional (for admin tests)
ANDY_AUTH_ADMIN_PASSWORD=your-admin-password
ANDY_AUTH_CLIENT_SECRET=andy-docs-secret
```

Copy `tests/oauth-python/.env.example` to `.env` and fill in values.

## Test Technologies

- **xUnit** - .NET test framework
- **Moq** - Mocking framework
- **FluentAssertions** - Assertion library
- **Playwright** - Browser automation for E2E tests
- **requests** - Python HTTP client
- **python-dotenv** - Environment configuration

## Writing New Tests

### .NET Unit Test Example

```csharp
[Fact]
public async Task Method_WithValidInput_ShouldSucceed()
{
    // Arrange
    var mockUserManager = CreateMockUserManager();
    var controller = new AccountController(mockUserManager.Object);

    // Act
    var result = await controller.Login(validModel);

    // Assert
    Assert.IsType<RedirectToActionResult>(result);
}
```

### E2E Test Example (Playwright)

```csharp
public class MyTests : E2ETestBase
{
    [Fact]
    public async Task LoginPage_WithValidCredentials_ShouldRedirect()
    {
        // Navigate to login page
        await NavigateToAsync("/Account/Login");

        // Fill in form
        await Page.FillAsync("input[name='Email']", "admin@test.com");
        await Page.FillAsync("input[name='Password']", "Admin123!");
        await Page.ClickAsync("button[type='submit']");

        // Wait and verify redirect
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
        Assert.DoesNotContain("/Account/Login", Page.Url);
    }
}
```

### Python OAuth Test Example

```python
def test_token_introspection(runner: TestRunner, client: OAuthClient, token: str):
    response = client.post("/connect/introspect", data={
        "token": token,
        "client_id": config.client_id,
        "client_secret": config.client_secret
    })

    runner.add_result(TestResult(
        name="Token Introspection",
        passed=response.status_code == 200,
        duration_ms=response.elapsed.total_seconds() * 1000
    ))
```

## Troubleshooting

**Local tests fail with "Connection refused"**
- Start the local server: `dotnet run` in `src/Andy.Auth.Server`

**Python tests fail with import errors**
- Install dependencies: `pip install -r requirements.txt`

**Tests timeout**
- Check server is running and accessible
- Verify network connectivity to UAT

**E2E tests fail with "Playwright browsers not installed"**
- Run the Playwright install script (see E2E Browser Tests section above)
- Ensure you have write access to the browser installation directory

**E2E tests fail with "executable doesn't exist" errors**
- Rebuild the test project: `dotnet build tests/Andy.Auth.E2E.Tests`
- Run Playwright install again after rebuilding

**E2E tests hanging or slow**
- E2E tests start a real HTTP server and browser; they take longer than unit tests
- Check for leftover browser processes if tests were interrupted
- Ensure no firewall is blocking localhost connections

**E2E date formatting tests failing**
- These tests verify JavaScript runs in the browser
- Failures may indicate static files not being served correctly
- Check that wwwroot content is accessible

---

**Last Updated:** 2026-01-15
