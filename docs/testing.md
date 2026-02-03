# Testing Guide

Testing documentation for Andy Auth Server.

## Test Overview

**Current Status:**
- .NET Unit Tests: 54/54 passed (100%)
- Python OAuth Tests: 42/42 passed (100%)
- Last Updated: 2025-12-16

## Test Structure

```
tests/
├── Andy.Auth.Server.Tests/     # .NET unit tests (xUnit)
│   ├── AccountControllerTests.cs
│   ├── AuthorizationControllerTests.cs
│   ├── DbSeederTests.cs
│   ├── OAuthIntegrationTests.cs
│   └── CustomWebApplicationFactory.cs
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

### .NET Unit Tests

```bash
# Run all tests
dotnet test

# Run with detailed output
dotnet test --verbosity normal

# Run specific test class
dotnet test --filter "FullyQualifiedName~DbSeederTests"

# Run with code coverage
dotnet test --collect:"XPlat Code Coverage"
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

### .NET Unit Tests (54 tests)

| Category | Tests | Description |
|----------|-------|-------------|
| DbSeederTests | 9 | Database seeding, client creation |
| AccountControllerTests | 16 | Login, registration, logout |
| AuthorizationControllerTests | 22 | OAuth authorization flows |
| OAuthIntegrationTests | 7 | Integration with WebApplicationFactory |

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

---

**Last Updated:** 2025-12-16
