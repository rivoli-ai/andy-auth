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

## DPoP: bind access and refresh tokens to a client key

Set `OpenIddict:AdvancedFlows:DPoP:Enabled=true` to advertise and accept
[RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) proofs. It is disabled by default.
`ProofLifetime` defaults to one minute (allowed: one second to five minutes), and
`RequireNonce` defaults to `true`. The authorization server and every protected
resource require an atomic, shared replay store; the supplied implementation uses
Redis `SET NX` with a bounded expiry. Configure the server's
`RateLimiting:RedisConnectionString` and each resource's Redis connection. Keep
these stores shared across replicas and protected against eviction of live proof
records. An unavailable replay store denies access with HTTP 503 and `Retry-After`.

Clients generate and retain their own RSA (2048–4096 bits, RS256) or P-256 (ES256)
private key. Send only the public JWK in each proof. The library's
`Andy.Auth.Dpop.DpopProof.Create` creates a fresh signed proof with `jti`, `iat`,
`htm` and `htu`; the target excludes query and fragment. At the token endpoint,
continue to supply normal client authentication, PKCE and grant parameters: DPoP
does not replace those checks. On `use_dpop_nonce`, read the `DPoP-Nonce` response
header and create a **new proof** with that nonce before retrying the request.
Nonce challenges occur before authorization-code consumption. The nonce is
short-lived, protected by the shared Data Protection ring and bound to the key.

Authorization-code clients should also send `dpop_jkt` (the base64url SHA-256 JWK
thumbprint) in the authorization request, including inside PAR. The code is then
bound to that key before token redemption. A successful proof-bearing token
request returns `token_type: DPoP` and an access token containing `cnf.jkt`.
Refresh tokens preserve the key binding: missing or different proofs are rejected.
A manifest client can set `requireDpop: true` (`ft:andy_dpop` in OpenIddict) to
reject token requests without a proof. Enable the feature before enabling that
requirement. Existing clients remain bearer clients until explicitly migrated.

At an API, send `Authorization: DPoP <access_token>` and a fresh `DPoP` header
whose proof includes `ath`, the SHA-256 hash of that exact access token. A bound
token used as `Bearer`, an unbound token used as `DPoP`, another key, wrong method,
wrong URI, stale proof or reused proof is rejected. The resource's ordinary JWT
signature, audience, lifetime, role and authorization policy checks still apply.
The server enforces this on its validation scheme and UserInfo endpoint. Token
exchange rejects sender-constrained subject tokens until an explicit delegation
profile can preserve their constraints; it cannot downgrade them to bearer tokens.

A resource using the public library registers replay protection and opts in:

```csharp
services.AddRedisDpopReplayProtection(configuration["Redis:ConnectionString"]!);
services.AddAndyAuth(options =>
{
    options.Authority = "https://auth.example";
    options.Audience = "urn:my-api";
    options.EnableDpop = true;
    options.RequireLiveSession = true; // high-risk user API
    options.IntrospectionClientId = "my-api";
    options.IntrospectionClientSecret = configuration["Auth:IntrospectionSecret"];
});
```

The resource must be an authorized audience/presenter with introspection
permission. For DPoP tokens, live-session enforcement authenticates the resource
at `/connect/introspect`; it never replays the user's token as a bearer credential
or requires their private key. Introspection reconciles current token/grant,
account, lockout, exact session and role authority. A revoked session denies the
next request; authority outages deny with 503. For ordinary bearer tokens the
existing `/auth/session` check remains in use. Shared revocation-event denial
checks can also be enabled with `CheckRevocationNotifications`.

Client request example (reuse the private key, never the proof):

```csharp
var proof = DpopProof.Create(signingCredentials, "GET", resourceUri, accessToken);
using var request = new HttpRequestMessage(HttpMethod.Get, resourceUri);
request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
request.Headers.Add("DPoP", proof);
using var response = await httpClient.SendAsync(request);
```

TLS termination must preserve the canonical external HTTPS origin/path through
explicitly trusted forwarding. A rewrite to a different origin/path invalidates
`htu`; do not bypass that check. CORS exposes `DPoP-Nonce` and `WWW-Authenticate`.
The supplied resource validator does not require resource-server nonces; the
nonce requirement above applies to the authorization server.

`DpopProofTests` checks signed malformed proofs and public-key handling;
`DpopIntegrationTests` exercises real grants, native introspection, a separate
consumer, revocation, UserInfo, wrong-key refresh, outage behavior and 100 racing
proof submissions across independent Redis connections. These are automated
acceptance tests, not a protocol certification or a claim of deployed adoption.
