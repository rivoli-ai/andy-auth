# Post-Embedded-merge cleanup: ternary bug, dead config, stale wagram CORS, pre-existing test bug

## Context

The post-merge review of 5776dc1 ("Add Embedded deployment mode for OpenIddict") surfaced four small, independent issues that fit cleanly into a single cleanup PR. None are tied to Embedded mode itself — they're long-standing bugs that the review brought to the surface. Bundled here to avoid four near-empty PRs.

## Items

### 1. Consent-type ternary bug (`DynamicClientRegistrationController.cs:158-160`)

```csharp
descriptor.ConsentType = _settings.RequireAdminApproval
    ? OpenIddictConstants.ConsentTypes.Explicit
    : OpenIddictConstants.ConsentTypes.Explicit;
```

Both branches return `Explicit`, so flipping `RequireAdminApproval` toggles nothing. The non-admin-approval branch should be `ConsentTypes.Implicit` (matching the seeded `andy-docs-web` client at `DbSeeder.cs:347`, which uses Implicit because it's a trusted first-party SPA).

**Fix**: change the false branch to `OpenIddictConstants.ConsentTypes.Implicit`. Add a unit test asserting both branches produce the documented consent type.

### 2. Stale `wagram.ai` CORS allowlist entries

Commit 261d6bb ("strip dead wagram-* URLs") cleaned non-CORS references but missed the `Cors:Origins` arrays:

- `src/Andy.Auth.Server/appsettings.json` lines 24-25
- `src/Andy.Auth.Server/appsettings.UAT.json` lines 14-15
- `src/Andy.Auth.Server/appsettings.Production.json` lines 14-15

These are dead origins — the wagram domain is no longer used. Allowing CORS credentials to a domain we don't control is a low-grade security smell.

**Fix**: remove every `wagram.ai` / `wagram-uat.vercel.app` line from the three CORS allowlists.

### 3. Dead `DcrSettings.Default*Lifetime` config (`DcrSettings.cs:53-58`)

```csharp
public TimeSpan DefaultAccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(60);
public TimeSpan DefaultRefreshTokenLifetime { get; set; } = TimeSpan.FromDays(14);
```

Neither property is read anywhere (`grep -rn "DefaultAccessTokenLifetime\|DefaultRefreshTokenLifetime" src/ tests/` returns only the declarations). Token lifetimes silently use OpenIddict defaults.

**Fix**: KISS — delete the dead properties + any config-stub entries in `appsettings*.json` that reference them. If lifetimes need to be tunable later, wire them at that point.

### 4. Pre-existing `Register_InvalidRedirectUri_ReturnsBadRequest` test bug

Discovered during #63's diagnosis: this test at `DynamicClientRegistrationControllerTests.cs:198` constructs `strictSettings` without overriding `RequireInitialAccessToken`. `DcrSettings.RequireInitialAccessToken` defaults to `true`, so the controller short-circuits with 401 at the auth check before ever reaching the redirect-URI validation the test is asserting on. The test fails on `main` and predates 5776dc1 (verified by checking out 261d6bb).

**Fix**: add `RequireInitialAccessToken = false` to the `strictSettings` initializer. One line.

## Acceptance criteria

- [ ] DCR consent-type ternary returns `Implicit` when `RequireAdminApproval = false`
- [ ] Test asserts both branches of the consent-type ternary produce the documented value
- [ ] Zero occurrences of `wagram` in `src/Andy.Auth.Server/appsettings*.json`
- [ ] `DcrSettings.DefaultAccessTokenLifetime` and `DefaultRefreshTokenLifetime` deleted (or wired — pick one)
- [ ] `Register_InvalidRedirectUri_ReturnsBadRequest` passes
- [ ] Full server suite has 11 - (3 fixed by #64 - any new) reds. Concretely: after this PR + #64, expected reds drop to 10 (this PR clears the pre-existing `Register_InvalidRedirectUri` red).

## Files touched

- `src/Andy.Auth.Server/Controllers/DynamicClientRegistrationController.cs`
- `src/Andy.Auth.Server/Configuration/DcrSettings.cs`
- `src/Andy.Auth.Server/appsettings.json`
- `src/Andy.Auth.Server/appsettings.UAT.json`
- `src/Andy.Auth.Server/appsettings.Production.json`
- `tests/Andy.Auth.Server.Tests/DynamicClientRegistrationControllerTests.cs`

## Notes

- Bundled to avoid four near-empty PRs. Each item is independent; if review prefers split, the branch can be split into four cherry-picks.
- Discovered during post-merge review of 5776dc1.
