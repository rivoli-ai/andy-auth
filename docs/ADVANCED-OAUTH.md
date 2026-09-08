# Device authorization and pushed authorization requests

Device authorization is available at `/connect/device`, with browser approval at
`/connect/verify` and CLI polling at `/connect/token` using
`urn:ietf:params:oauth:grant-type:device_code`. Discover the URLs instead of deriving
them from an assumed hostname. The browser form sends the standard `user_code`
parameter and an explicit allow/deny decision; approval requires an active Identity
session and a valid antiforgery token. Issued tokens retain that exact session.
A revoked session cannot redeem an approved device code.

Configure `OpenIddict:AdvancedFlows:DeviceFlow:Enabled` (default `true`) and
`CodeLifetime` (default `00:10:00`, positive and at most 30 minutes). Disabling the
flow removes its endpoint and grant from discovery. Clients must have explicit
device-authorization and device-code-grant permissions. A manifest's `device_code`
grant supplies these. Poll according to `interval` when returned, or RFC 8628's
five-second default when omitted; respect `authorization_pending`, `access_denied`,
`expired_token` and HTTP rate-limit responses. A successfully redeemed device code
cannot be reused.

## Enable PAR

Set `OpenIddict:AdvancedFlows:PAR:Enabled=true` to expose `/connect/par`.
`RequestUriLifetime` defaults to `00:01:30`; it must be positive and no more than
ten minutes. PAR is disabled by default to allow existing registrations to migrate
before clients observe the new discovery metadata. Keep standard authorization
available unless a client explicitly requires PAR.

OpenIddict owns request validation, protected storage, expiry, client binding and
one-time authorization. Existing `TokenCleanupService` prunes expired request
artifacts with other OpenIddict tokens. No custom request-URI cryptography or
browser-supplied copy of pushed parameters is used. This follows
[OpenIddict's PAR configuration](https://documentation.openiddict.com/configuration/pushed-authorization-requests).

Before enabling in an existing deployment, ensure every authorization-code client
that will use PAR has `Permissions.Endpoints.PushedAuthorization` (`ept:par`).
Manifest seeding and new/admin-updated registrations grant it alongside the
authorization endpoint permission. Existing DCR registrations that predate this
change require an administrative permission update; merely enabling discovery
does not grant permissions. Test existing SDK clients before rollout because some
automatically prefer PAR when advertised. Disabled or unapproved DCR clients are
rejected before pushed state is created, and again by the ordinary authorization
and token gates.

A manifest client may set `requirePar: true` to require pushed requests for that
client. Enable PAR before activating such a client; direct authorization requests
will be rejected by OpenIddict. For applications managed directly through the
OpenIddict manager, use `Requirements.Features.PushedAuthorizationRequests`.

Send the usual authorization parameters and S256 PKCE challenge to `/connect/par`
as form data, authenticating confidential clients with their configured client
credentials. The response is HTTP 201 with `request_uri` and `expires_in`. Navigate
the browser to `/connect/authorize?client_id=...&request_uri=...`, then exchange the
resulting authorization code normally with the same redirect URI and PKCE verifier.

For explicit consent, validated client, redirect and scope metadata passes between
controllers in encrypted, subject-bound TempData. The browser return URL retains
only the original pushed-request reference, not a reconstructed copy of the pushed
parameters. The authorization server still validates the original request's actual
expiry and single-use state before issuance. Consent can approve a subset of scopes
or deny the request; a denied request cannot silently become approval.

Both initial `/connect/device` and `/connect/par` requests have a default 30-per-minute
IP rule. Token polling uses the token endpoint's rate rules. Hardened deployments
use the existing shared Redis processing strategy; keep those dependencies and
exact proxy trust configured when testing across replicas.

## Verification and remaining #15 scope

`DeviceFlowAcceptanceTests` exercises the actual approval form and CLI polling,
including denial, invalid decisions, CSRF, expiry, replay, session revocation and
disabling discovery. `PushedAuthorizationIntegrationTests` exercises real login,
implicit/explicit consent, scope reduction, denial, invalid client credentials and
permissions, DCR disablement, PKCE/redirect validation, URI expiry/tampering/client
binding, replay, required-PAR clients and the feature toggle.

These tests are server integration evidence. They do not claim real smart-TV,
production load, or deployed assistant acceptance. DPoP and CIBA remain separate
unfinished capabilities under #15; neither is advertised as supported.
