# Testing Guide for Andy.Auth

This document describes the testing strategy and how to run tests for Andy.Auth.

## Test Structure

```
tests/Andy.Auth.Tests/
├── Extensions/                   # Tests for extension methods
│   └── ServiceCollectionExtensionsTests.cs
├── Helpers/                      # Test utilities and factories
│   └── TestClaimsPrincipalFactory.cs
├── Integration/                  # Integration tests
│   └── AuthenticationIntegrationTests.cs
├── Providers/                    # Provider-specific tests
│   ├── AndyAuthProviderTests.cs
│   ├── AzureAdProviderTests.cs
│   └── ClerkProviderTests.cs
└── Services/                     # Service tests
    └── CurrentUserServiceTests.cs
```

## Test Coverage

### Unit Tests (42 tests)

#### Provider Tests (27 tests)
- **AndyAuthProvider** (9 tests)
  - Provider name validation
  - JWT Bearer configuration with valid/invalid options
  - User claims extraction from ClaimsPrincipal
  - OAuth metadata generation
  - Error handling for missing configuration

- **AzureAdProvider** (10 tests)
  - Provider name validation
  - Azure AD specific configuration
  - Azure AD claim mapping (oid, tid, upn)
  - Custom instance support
  - Error handling for missing tenant/client ID

- **ClerkProvider** (8 tests)
  - Provider name validation
  - Dual handler configuration (JWT + opaque tokens)
  - User claims extraction
  - OAuth metadata generation
  - Error handling for missing domain

#### Service Tests (7 tests)
- **CurrentUserService**
  - User ID extraction from authenticated context
  - User claims extraction
  - Authentication status checking
  - Error handling for missing/unauthenticated users

#### Extension Tests (8 tests)
- **ServiceCollectionExtensions**
  - Provider registration (AndyAuth, AzureAD, Clerk)
  - Configuration binding from appsettings
  - Configuration via Action<T>
  - Service registration verification
  - Custom provider error handling

### Integration Tests (7 tests)

- Full authentication pipeline validation
- Protected vs public endpoints
- CurrentUserService integration
- Multi-provider configuration at runtime
- HTTP status code validation (401 Unauthorized, 200 OK)

## Running Tests

### Run All Tests

```bash
cd /Users/samibengrine/Devel/rivoli-ai/andy-auth
dotnet test
```

### Run with Detailed Output

```bash
dotnet test --verbosity normal
```

### Run Specific Test Category

```bash
# Unit tests only
dotnet test --filter "FullyQualifiedName~Andy.Auth.Tests.Providers"

# Integration tests only
dotnet test --filter "FullyQualifiedName~Andy.Auth.Tests.Integration"
```

### Generate Code Coverage Report

```bash
dotnet test --collect:"XPlat Code Coverage"
```

## Test Technologies

- **xUnit**: Testing framework
- **Moq**: Mocking framework for dependencies
- **FluentAssertions**: Assertion library for readable tests
- **Microsoft.AspNetCore.TestHost**: Integration testing

## Writing New Tests

### Unit Test Example

```csharp
[Fact]
public async Task MyTest_WithValidInput_ShouldSucceed()
{
    // Arrange
    var provider = new MyProvider();
    var input = new MyInput { Value = "test" };

    // Act
    var result = await provider.ProcessAsync(input);

    // Assert
    result.Should().NotBeNull();
    result.Value.Should().Be("test");
}
```

### Integration Test Example

```csharp
[Fact]
public async Task MyEndpoint_WithAuthentication_ShouldReturn200()
{
    // Arrange
    using var host = await CreateTestHost(authOptions);
    var client = host.GetTestClient();

    // Act
    var response = await client.GetAsync("/api/my-endpoint");

    // Assert
    response.StatusCode.Should().Be(HttpStatusCode.OK);
}
```

## Test Results

**Current Status:**
- ✅ Total Tests: 49
- ✅ Passed: 49
- ❌ Failed: 0
- ⚠️ Skipped: 0
- 📊 Code Coverage: TBD

## Continuous Integration

Tests are automatically run on:
- Every push to main/develop branches
- Every pull request
- Before NuGet package publication

See `.github/workflows/build.yml` for CI configuration.

## Best Practices

1. **Arrange-Act-Assert Pattern**: Structure all tests clearly
2. **One Assertion Per Test**: Focus on testing one thing
3. **Descriptive Names**: Use `MethodName_Scenario_ExpectedResult` format
4. **Test Both Success and Failure**: Include error handling tests
5. **Use Test Factories**: Leverage helpers like `TestClaimsPrincipalFactory`
6. **Mock External Dependencies**: Use Moq for dependencies like IHttpContextAccessor
7. **Integration Tests**: Validate full workflows end-to-end

## Adding Tests for New Providers

When adding a new authentication provider:

1. Create `MyProviderTests.cs` in `Providers/` folder
2. Test all interface methods:
   - `Name` property
   - `ConfigureAuthentication()`
   - `GetUserClaimsAsync()`
   - `GetOAuthMetadata()`
3. Add error handling tests for invalid configuration
4. Add integration test in `AuthenticationIntegrationTests.cs`
5. Update `ServiceCollectionExtensionsTests.cs` to include new provider

## Troubleshooting

### Tests Fail with "HttpContext not available"
- Ensure `IHttpContextAccessor` is mocked in unit tests
- For integration tests, use `TestServer` and `CreateTestHost()`

### Provider-specific configuration errors
- Check that all required configuration properties are set
- Use fluent assertions to validate exception messages

### Integration tests timeout
- Ensure TestServer is properly disposed
- Check that authentication middleware is configured before authorization

## Future Improvements

- [ ] Add performance benchmarks
- [ ] Increase code coverage to >90%
- [ ] Add mutation testing
- [ ] Add load testing for authentication flows
- [ ] Mock JWT token generation for realistic integration tests
