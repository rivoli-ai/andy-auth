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

The endpoint is currently HTTP pull. Durable authenticated push notifications
will use the transactional outbox and NATS work tracked by #33; consumers must
not treat that future push channel as more authoritative than a fresh session
truth read.

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
