# DCR controller tests fail after Embedded-mode merge: `Mock<IConfiguration>` doesn't satisfy `GetSection().Get<string[]>()`

## Problem

Commit 5776dc1 ("Add Embedded deployment mode for OpenIddict") added an `IConfiguration` constructor parameter to `DynamicClientRegistrationController` so it can read the `OpenIddict:Resources` list from config (the same list `Program.cs` registers at startup, single source of truth).

The accompanying test update wires the new parameter with a Moq default:

```csharp
new Mock<Microsoft.Extensions.Configuration.IConfiguration>().Object
```

But the production code path now calls:

```csharp
_configuration.GetSection("OpenIddict:Resources").Get<string[]>() ?? Array.Empty<string>();
```

`GetSection` on a Moq-default `IConfiguration` returns `null`, and `Get<string[]>()` then throws `ArgumentNullException`. The `?? Array.Empty<string>()` fallback never gets a chance to fire.

Net effect: **4 DCR tests now fail on a fresh checkout of `main`**:

- `Andy.Auth.Server.Tests.Controllers.DynamicClientRegistrationControllerTests.Register_*` (×4)

Pre-existing failures (6 SessionTrackingMiddleware, 3 Postgres-required, 1 IPv6 loopback) are unrelated.

## Fix

Replace the `Mock<IConfiguration>` with a real empty configuration — `IConfiguration` is a value-shaped interface that's cheap to build:

```csharp
var configuration = new ConfigurationBuilder().Build();
```

Two call sites, both in `tests/Andy.Auth.Server.Tests/DynamicClientRegistrationControllerTests.cs`:
- Line 66 (the shared ctor in `IDisposable` setup)
- Line 508 (the in-test factory inside the `_DisablesAuthorizationCodeFlowFor*` cases)

For the call sites that want to assert specific MCP resources land on the descriptor, swap to:

```csharp
var configuration = new ConfigurationBuilder()
    .AddInMemoryCollection(new Dictionary<string, string?>
    {
        ["OpenIddict:Resources:0"] = "https://localhost:5101/mcp",
    })
    .Build();
```

## Acceptance criteria

- [ ] `dotnet test tests/Andy.Auth.Server.Tests` passes for all 4 previously-failing `DynamicClientRegistrationControllerTests` cases.
- [ ] No new red tests introduced.
- [ ] At least one new test asserts the empty-resources path — i.e. an `IConfiguration` with no `OpenIddict:Resources` section produces zero resource permissions on the descriptor and doesn't throw. This is the regression-prevention test for the bug this issue fixes.
- [ ] At least one new test asserts the populated-resources path — `OpenIddict:Resources = ["https://localhost:5101/mcp"]` produces exactly one resource permission with the right prefix.
- [ ] No `Mock<IConfiguration>` in `DynamicClientRegistrationControllerTests.cs` after the fix.

## Files touched

- `tests/Andy.Auth.Server.Tests/DynamicClientRegistrationControllerTests.cs` — replace 2 mocks, add 2 tests.

## Notes

- This is a pure test-side fix; production code at `DynamicClientRegistrationController.cs:209` is correct as written.
- The new tests double as the missing coverage flagged in the post-merge review (empty-resources fallback was untested under Development too — same mechanism).
- Discovered during post-merge review of 5776dc1 on 2026-05-05.
