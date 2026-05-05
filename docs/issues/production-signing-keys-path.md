# Production: load OpenIddict signing keys from disk so JWKS survives redeploy

## Problem

`Program.cs:227-232` is currently a placeholder for the Production branch. If `OpenIddict:UseEphemeralKeys != true` it throws `InvalidOperationException("Production environment requires explicit configuration...")`. There is no real persisted-key path — every UAT/Prod deploy is forced into ephemeral keys, which means every container restart rotates JWKS and invalidates every cached JWT held by every consumer.

The deploy story #59 (E3-S4 — Deploy andy-auth to Railway) calls for `OpenIddict__SigningKeys__Path = /data/keys` on a Railway volume, and explicitly notes "rotating keys breaks every issued token." That's the same mechanism Embedded mode already uses (`PersistedDevelopmentKeys.AddPersistedDevelopmentKeys`) — the helper is general-purpose RSA-on-disk, the `Development` in its name is historic.

## Fix

In the Production branch of `Program.cs`, prefer a persisted-keys path:

1. If `OpenIddict:SigningKeys:Path` is set → call `AddPersistedDevelopmentKeys(path)` (same helper Embedded uses). JWKS `kid` stable across restarts.
2. Else if `OpenIddict:UseEphemeralKeys=true` → ephemeral keys (current Railway-pod fallback for stateless deploys).
3. Else → hard-fail boot with a message that documents both options.

## Acceptance criteria

- [ ] Production branch in `Program.cs` accepts `OpenIddict:SigningKeys:Path` and uses it to persist RSA signing+encryption keys via the existing `AddPersistedDevelopmentKeys` helper.
- [ ] When the path is set, JWKS `kid` survives a process restart (integration test against `WebApplicationFactory<Program>` with Production env).
- [ ] When neither `SigningKeys:Path` nor `UseEphemeralKeys=true` is set, boot fails with a message that lists both paths.
- [ ] `appsettings.Production.json` does NOT add a placeholder for the path. Reasoning: the existing `Issuer = SET_VIA_ENVIRONMENT_VARIABLE` placeholder fails loudly at boot via `new Uri(...)`, but a string placeholder for a directory path would silently `Directory.CreateDirectory("SET_VIA_ENVIRONMENT_VARIABLE")` — fail-quiet, the wrong behaviour. The Program.cs throw with both options listed is the documentation.
- [ ] `OpenIddict:UseEphemeralKeys=true` continues to work as the explicit opt-out for stateless Railway pods.

## Files touched

- `src/Andy.Auth.Server/Program.cs` — extend the Production branch (lines 227-232).
- `src/Andy.Auth.Server/Configuration/PersistedDevelopmentKeys.cs` — minor doc-comment touch-up acknowledging Production reuse (no rename — out of scope).
- `src/Andy.Auth.Server/appsettings.Production.json` — add the placeholder.
- `tests/Andy.Auth.Server.Tests/ProductionModeIntegrationTests.cs` — new file mirroring `EmbeddedModeIntegrationTests` for the Production env.

## Notes

- Could rename `PersistedDevelopmentKeys` → `PersistedSigningKeys` for accuracy. Deferred — the rename has surface area (file, class, method, tests) that doesn't fit this PR's scope.
- True X.509 PFX-from-vault support is a separate future story. The deploy story (#59) chose Railway-volume RSA, which is what this PR enables.
- Symlink/permission hardening on the keys path is also covered by the existing #46-adjacent review note; out of scope here.
