# Revocation and logout profile

This is the Andy Auth revocation contract tracked by issue #172. It defines
what the authorization server guarantees and what resource servers must do
when they need a shorter revocation window than an offline JWT can provide.

## Token and client classes

| Class | Credential | Maximum stale-access window | Required enforcement |
|---|---|---:|---|
| High-risk user API (administration, destructive writes, secrets, billing) | signed JWT access token + reference refresh token | immediate while Andy Auth is reachable; otherwise fail closed; 5 minutes absolute | Validate the JWT and call `GET /auth/session` for every privileged request. Never perform the operation from cached session truth. |
| Standard user API / native or browser client | signed JWT access token + reference refresh token | 5 minutes absolute | Validate the JWT. Reconcile `GET /auth/session` on launch, after foregrounding, before sensitive work, and after an authentication error. Gate privileged operations as high-risk. |
| Delegated service call (RFC 8693) | signed exchanged JWT | no later than the subject token; therefore at most 5 minutes under the default profile | Validate `aud`, `act`, scopes, expiry, and `session_id`; high-risk targets also resolve session truth. |
| Machine-to-machine client credentials | signed JWT access token, no user session | 5 minutes | Validate JWT audience/scope. Disable the client and rotate its credential to stop renewal; use gateway deny-listing when sub-five-minute recall is required. |

`OpenIddict:AccessTokenLifetime` is explicitly 5 minutes and
`OpenIddict:RefreshTokenLifetime` is 14 days. Refresh tokens are opaque
reference tokens stored by OpenIddict. User grants carry `session_id`; token
redemption fails when that exact session is missing, expired, revoked, or owned
by another user. Deployments may shorten these values. Increasing the access
token lifetime expands the offline revocation window and requires a security
review.

## Logout and revocation behavior

- `POST /Account/Logout` is CSRF-protected and account-wide. It revokes all
  OpenIddict tokens and authorizations for the user, revokes every tracked
  session, rotates the ASP.NET Identity security stamp, then clears the cookie.
- `/connect/logout` is session-scoped. It revokes the `session_id` bound to the
  current Identity cookie, then clears that cookie. Other device sessions stay
  active. Refresh artifacts bound to the revoked session cannot be redeemed.
- A single-session or revoke-all-other action marks those server-side sessions
  revoked. Their bound authorization-code, device-code, refresh-token, and
  token-exchange flows fail at redemption. Already-issued JWTs remain bounded
  by the rules in the table above.
- Disabling, suspending, expiring, or deleting a user invokes the same
  account-wide access revoker as `/Account/Logout`.
- RFC 7009 `/connect/revoke` revokes the presented stored token. Callers should
  revoke refresh tokens during client-side disconnect even though server-side
  session revocation remains authoritative.

Consent is not deleted by logout: a remembered consent is an approval record,
not an active credential. Account-wide revocation invalidates its current
OpenIddict authorization; subsequent issuance still requires a live login and
the normal consent policy.

## Authenticated session truth

`GET /auth/session` is a bearer-authenticated, authoritative state read. Its
responses use `Cache-Control: no-store, no-cache, max-age=0`; intermediaries and
clients must not reuse a prior 200. A 410 response includes `subject`,
`sessionId`, and `revokedAt`, allowing clients to reconcile the revocation
watermark without treating an older observation as newer state.

The endpoint reads token and authorization status directly from the database, bypassing
process-local entity caches. Revoked entries return 401. It also checks account lockout
and session inactivity. The `roles` response contains only roles already present in the
token that the account still holds; it does not disclose additional memberships.

Session truth uses HTTP pull. Optional [durable signed revocation events](operations/revocation-events.md)
use a transactional outbox and HTTPS SET delivery; #33 tracks the optional NATS
transport. Push never replaces fresh session truth for high-risk operations.

## Failure policy

| Result | Meaning | Required behavior |
|---|---|---|
| `200 authenticated:true` | session is currently active | continue |
| `200 authenticated:false` | no active session | stop protected work and reauthenticate |
| `401 invalid_token` | token/account is permanently invalid | sign out; do not retry with the same credential |
| `410 session_revoked` | exact session was revoked | sign out; do not retry with the same credential |
| `503 temporarily_unavailable` | truth cannot currently be established | retry with backoff; do not sign the user out solely because of the outage |

High-risk and privileged operations fail closed on 503: they must not execute
until fresh session truth is available. A standard client may keep its local UI
state during a transient outage, but it must not convert that into permission to
perform privileged work.

## Local privileged API enforcement

`/api/users`, `/api/groups`, `/mcp/tools/users`, and `/mcp` share the `LiveAdmin`
bearer policy. Each request rechecks the stored token/authorization status, account lifecycle, lockout, current Admin
membership, and the token's exact server session (including expiry, inactivity,
and subject binding). Missing session claims never fall back to a different live
session or to the machine-token profile. Revoked authority returns 403; truth-store
failures return 503 with `Retry-After: 5`. Responses are not cacheable. Normal OAuth
authentication still rejects invalid or expired tokens before privileged execution.

These checks enforce the high-risk profile locally. Other consuming resources
must enable equivalent fresh truth enforcement. The consumer option below and the
signed event receiver are tested integrations, not evidence of an existing deployed
cross-resource rollout.

## Consuming resource enforcement

Configure the public `Andy.Auth` library for a high-risk user API:

```csharp
services.AddAndyAuth(options =>
{
    options.Authority = "https://auth.example.com/";
    options.Audience = "sensitive-api";
    options.RequireLiveSession = true;
});
```

With normal authentication/authorization middleware and protected endpoints, each
validated bearer request fetches fresh HTTPS session truth. The exact subject and
`session_id` must match, and every role in the token must still be current. There is
no cached allowance. A missing session is rejected; machine-only endpoints need a
separate scheme/profile. Existing custom bearer events are preserved and cannot
replace the live check. The client does not follow redirects, limits response size,
and times out after five seconds. Permanent denial returns 401; malformed responses,
timeouts, and upstream failures return 503 with `Retry-After: 5` and `no-store`.

Andy.Auth validates access token types (`at+jwt` or legacy `JWT`) and uses zero expiry
clock skew. Its previous five-minute grace would have doubled the documented default
offline window. Keep resource and issuer clocks synchronized, and configure other
JWT libraries without an expiry grace if they claim the same five-minute absolute
profile. Security Event Tokens are not accepted as access credentials.

`LiveAdminApiIntegrationTests` now includes an independent consuming resource using
this public option and real cookie/PKCE-issued tokens. It verifies token/grant and
cross-replica revocation, single/all-session revocation, both logout paths, disable,
delete, lockout, role removal, session expiry/inactivity, subject mismatch, missing
sessions, and truth-store outage. Separate library tests cover response confusion,
wrong token types/audiences, expired tokens, timeout, and custom event preservation.
This proves the integration behavior; each deployed resource must adopt the option
(or equivalent mandatory enforcement) before claiming the high-risk profile.
