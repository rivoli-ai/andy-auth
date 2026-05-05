# [CRITICAL] PKCE not required for public OAuth clients (#46)

Spec captured in repo for the existing GitHub issue #46.

## Finding (from #46)

`src/Andy.Auth.Server/Program.cs:168-171`; seeded public clients in `src/Andy.Auth.Server/Data/DbSeeder.cs`. OpenIddict server does not call `RequireProofKeyForCodeExchange()`; public clients (conductor-mac, cline, roo, chatgpt, claude-desktop, kilocode, continue-dev, andy-agentic-web, andy-subscription-web, andy-subscription-cli, andy-narration-web) use the auth-code flow without a mandatory `code_challenge`. Only `andy-docs-web` enforces PKCE via a per-client `Requirements.Features.ProofKeyForCodeExchange` block.

Public clients with loopback / custom-scheme redirects are exposed to authorization-code interception on-device. From the platform security audit 2026-04-21 (rivoli-ai/conductor#800).

## Approach

Two options surfaced during planning:

1. **Per-client**: add `Requirements.ProofKeyForCodeExchange` to each public client descriptor (12 hardcoded + DCR + manifest-driven path).
2. **Server-wide**: call `options.RequireProofKeyForCodeExchange()` in the OpenIddict server block. This is what #46's "Fix" line recommends.

Going with **server-wide** because:
- It's #46's own recommended fix.
- Per OAuth 2.1 / RFC 9700, PKCE is recommended for ALL clients regardless of type, not just public.
- Single-point-of-truth: a future hardcoded client added in `DbSeeder` or via DCR cannot accidentally bypass PKCE.
- Existing tests (`tests/oauth-python/*.py`, `OAuthIntegrationTests.cs`) already send `code_challenge` + `code_verifier`, so the server-wide flip should not regress green tests.

The `andy-docs-web` per-client Requirements block becomes redundant but stays in place — it documents the intent at the client level and costs nothing.

## Acceptance criteria

- [ ] `options.RequireProofKeyForCodeExchange()` called in the OpenIddict server block at `Program.cs:130-`.
- [ ] OIDC discovery doc continues to advertise `code_challenge_methods_supported: ["S256"]`.
- [ ] An authorization request without `code_challenge` returns the OAuth error `invalid_request` (HTTP 400 or 302 with `error=invalid_request` query param, depending on `response_mode`).
- [ ] An authorization request with `code_challenge_method=plain` is rejected (S256 only).
- [ ] All existing `OAuthIntegrationTests` pass — they already use PKCE.
- [ ] Issue #46 closed.

## Risk: confidential clients using authorization_code

The manifest-driven path (`DbSeeder.CreateOrUpdateClientAsync`) admits confidential clients with the `authorization_code` grant — e.g. `andy-issues-api` is `clientType: confidential` with `grantTypes: [authorization_code, refresh_token, client_credentials]`. Server-wide PKCE would force these to send `code_challenge` on the auth-code path. Per OAuth 2.1 this is correct; in practice these confidential clients are service-to-service and likely use `client_credentials` rather than the interactive auth-code flow, so no real regression. If a real consumer breaks, that's a fix at the consumer (it should be sending PKCE anyway).

## Files touched

- `src/Andy.Auth.Server/Program.cs` — add the one-line server option.
- `tests/Andy.Auth.Server.Tests/OAuthIntegrationTests.cs` (or new `PkceEnforcementTests.cs`) — add negative-path test for missing `code_challenge`.

## Notes

- Closes #46 (CRITICAL).
- The per-client `Requirements.Features.ProofKeyForCodeExchange` on `andy-docs-web` (DbSeeder.cs:337) becomes redundant but stays as a documentation marker.
