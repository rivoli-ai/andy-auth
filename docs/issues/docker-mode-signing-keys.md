# Docker mode: silently fails to configure OpenIddict signing keys

## Problem

`Program.cs:188-235` configures OpenIddict signing/encryption keys with this branching:

```csharp
if (builder.Environment.IsEmbedded()) { /* persisted RSA */ }
else if (builder.Environment.IsDevelopment() || IsEnvironment("Staging") || IsEnvironment("UAT")) { /* ephemeral */ }
else if (builder.Environment.IsProduction()) { /* persisted or ephemeral */ }
```

`ASPNETCORE_ENVIRONMENT=Docker` matches **none** of those — `IsDevelopment()` returns false, `IsProduction()` returns false, and `IsEmbedded()` returns false. The whole block is silently skipped. OpenIddict ends up with no signing/encryption keys configured. Boot succeeds; `/connect/token` and JWKS endpoint requests fail at runtime.

`docker-compose.yml:29` currently sets `ASPNETCORE_ENVIRONMENT=Development`, so the bug is masked in practice. But:

- `Configuration/HostEnvironmentExtensions.cs` declares `DockerEnvironmentName = "Docker"` and an `IsDocker()` helper — explicitly an expected mode.
- The class doc comment lists Docker as one of three deployment modes alongside Development and Embedded.
- A reader expecting "the three modes work" would set `ENV=Docker` and hit a silent runtime failure with no obvious diagnostic.

## Fix

Add `|| builder.Environment.IsDocker()` to the existing Development/Staging/UAT branch. Docker compose stacks share the trust model of local development (ephemeral keys are fine — devs re-auth on container respin), and the `IsLocalOrEmbedded()` / transport-security / HTTPS-redirect code paths already treat any non-Production env as local.

```csharp
else if (builder.Environment.IsDevelopment() ||
         builder.Environment.IsDocker() ||
         builder.Environment.IsEnvironment("Staging") ||
         builder.Environment.IsEnvironment("UAT"))
```

## Acceptance criteria

- [ ] `ASPNETCORE_ENVIRONMENT=Docker` boots without throwing and serves a valid JWKS doc.
- [ ] One new test in `CrossModeDiscoveryTests` (or a dedicated `DockerModeIntegrationTests`) boots Docker env via `EnvironmentWebApplicationFactory` and asserts the discovery doc + jwks endpoint return 200.
- [ ] `docker-compose.yml` is **not** changed in this PR. Switching the compose file to `ASPNETCORE_ENVIRONMENT=Docker` is a separate decision (it would also surface the missing `appsettings.Docker.json` and the Swagger-gating-on-IsDevelopment trade-off).

## Out of scope

- Creating `appsettings.Docker.json` (CORS allowlist, ports, etc.). compose still uses Development, so the existing appsettings inheritance works.
- Switching compose to `ENV=Docker`. Same reason.
- Symlink-pivot defence on the keys path. Separate hardening item.

## Files touched

- `src/Andy.Auth.Server/Program.cs` — add `IsDocker()` to the keys-block conditional.
- `tests/Andy.Auth.Server.Tests/CrossModeDiscoveryTests.cs` — add Docker as a Theory case.
