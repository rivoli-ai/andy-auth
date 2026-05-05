# Cross-mode test factory: extract `EnvironmentWebApplicationFactory`

## Problem

`EmbeddedModeIntegrationTests` and `ProductionModeIntegrationTests` each carry a private inner `WebApplicationFactory<Program>` subclass (~30 lines of boilerplate each) doing the same env-var injection trick — Program.cs reads `builder.Configuration` before the factory's `ConfigureAppConfiguration` callbacks run, so config has to be set via environment variables. The two inner classes differ only in the env-var values they inject.

The post-merge review's recommendation #5 ("cross-mode integration test matrix — parametrize EmbeddedWebApplicationFactory on env name") wants this consolidated. Without consolidation, each new mode-specific test class would re-paste the same boilerplate.

## Fix

Extract a shared `EnvironmentWebApplicationFactory` taking:
- `environmentName` (Development / Docker / Embedded / Production / Staging / UAT)
- `dbPath` (SQLite db path; required so DbSeeder doesn't need Postgres)
- `issuer` (the OpenIddict:Issuer URL — Production requires non-default to override the placeholder)
- `keysPath` (nullable; used only for Embedded + Production-with-persisted-keys)
- `useEphemeralKeys` (bool; only meaningful for Production)

Refactor `EmbeddedModeIntegrationTests` and `ProductionModeIntegrationTests` to use it. Behaviour identical, ~60 LOC of dup gone.

Demonstrate the parametrization works by adding one cross-mode parity test that asserts the OIDC discovery document advertises `code_challenge_methods_supported: ["S256"]` and `issuer == configured` under three different env names (PKCE coverage already exists at the options level via `PkceEnforcementTests`, but a cross-mode end-to-end smoke is the visible value of this refactor).

## Acceptance criteria

- [ ] New `tests/Andy.Auth.Server.Tests/EnvironmentWebApplicationFactory.cs` exposes the constructor surface above.
- [ ] `EmbeddedModeIntegrationTests` no longer defines a private `EmbeddedWebApplicationFactory`; uses the shared one.
- [ ] `ProductionModeIntegrationTests` no longer defines a private `ProductionWebApplicationFactory`; uses the shared one.
- [ ] One new mode-parity test (Theory or per-env Facts) asserts the OIDC discovery contract under each of Embedded + Production-with-keys.
- [ ] Existing test count and pass count preserved (no regressions).

## Out of scope

- Full auth-code flow tests parametrized per env. The TestServer needs a pre-authenticated session to complete the auth-code flow, and the existing `OAuthIntegrationTests.ClaudeDesktopClient_AuthorizationCodeFlowWithPKCE_ShouldSucceed` already dodges the auth step. Adding auth-code completion is a much bigger lift; would warrant its own story.
- **Docker-mode signing-key gap** (separate finding). Program.cs's `if (IsEmbedded()) { … } else if (IsDevelopment() || Staging || UAT) { … } else if (IsProduction()) { … }` doesn't match `ASPNETCORE_ENVIRONMENT=Docker` — the block is silently skipped, OpenIddict ends up with no signing/encryption keys, and any token-issuance request fails at runtime. Docker is the env name `docker-compose.yml` should set per `HostEnvironmentExtensions`'s comment, but no real deployment uses it today. To fix in a separate issue.

## Files touched

- `tests/Andy.Auth.Server.Tests/EnvironmentWebApplicationFactory.cs` (new)
- `tests/Andy.Auth.Server.Tests/EmbeddedModeIntegrationTests.cs` (drops inner factory)
- `tests/Andy.Auth.Server.Tests/ProductionModeIntegrationTests.cs` (drops inner factory)
- `tests/Andy.Auth.Server.Tests/CrossModeDiscoveryTests.cs` (new — the parity smoke)
