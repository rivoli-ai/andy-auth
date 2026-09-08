# Durable revocation events

Andy Auth can deliver signed Security Event Tokens (SETs) over HTTPS. This is the
authenticated revocation-event alternative in #172, using RFC 8417 and RFC 8935.
It is not the OIDC back-channel logout protocol. NATS remains an optional transport
tracked by #33. High-risk resources must continue to require fresh session truth;
push delivery is an additional denial signal, never an authorization signal.

## Transmitter configuration

Apply the database migration, then configure trusted recipients:

```json
{
  "RevocationDelivery": {
    "Enabled": true,
    "Targets": [
      { "Audience": "sensitive-api-events", "Endpoint": "https://api.example.com/auth/events" }
    ]
  }
}
```

Only operator configuration supplies targets. Dynamic registration and browser
parameters cannot select delivery addresses. Each audience is unique. Endpoints
must be absolute HTTPS URLs without credentials, query, or fragment; redirects
are never followed. Internal HTTPS recipients are allowed when the operator has
approved them. Normal TLS certificate validation remains enabled.

An outbox row is saved in the same transaction as session revocation/removal,
account disable/deletion, or security-stamp change. It has no user/session foreign
key, so account deletion cannot erase an undelivered event. Both synchronous and
asynchronous saves capture events. Bulk SQL that bypasses tracked EF changes is
not a notification API: application revocation paths must use the existing services.
Token-only or authorization-only revocations are reconciled by mandatory live
checks; this event profile communicates session invalidation.

The worker starts after migration/seeding readiness. It polls once per second,
leases up to 32 due messages using guarded database updates, and allows five seconds
per HTTPS delivery. Only an empty 202 acknowledgment removes a row. Lost acknowledgments
and expired worker leases can cause duplicate delivery. Retries retain the same `jti`.
Transport failures, 408, 429, and 5xx retry with backoff from five seconds to five minutes.
Other refusals, including redirects, retain the row for operator repair. A missing
recipient configuration pauses its rows without blocking configured recipients.

## Receiver integration

A consuming ASP.NET Core service uses the public Andy.Auth library:

```csharp
// Supply IDistributedCache from a shared durable provider, for example the
// Microsoft.Extensions.Caching.StackExchangeRedis package. Configure persistence
// and eviction as described below; process-local receipt storage is insufficient.
services.AddStackExchangeRedisCache(options =>
    options.Configuration = configuration.GetConnectionString("RevocationRedis"));

services.AddAndyRevocationReceiver(options =>
{
    options.Authority = "https://auth.example.com/"; // exact canonical SET issuer
    options.Audience = "sensitive-api-events";
});
services.AddAndyAuth(options =>
{
    options.Authority = "https://auth.example.com/";
    options.Audience = "sensitive-api";
    options.CheckRevocationNotifications = true;
    options.RequireLiveSession = true; // mandatory for high-risk user APIs
});

// With normal authentication/authorization middleware:
app.MapAndyRevocationEvents("/auth/events");
```

The API and event audiences serve different purposes. The event receiver validates
RS256 signatures against the configured authority's HTTPS discovery/JWKS, exact
issuer, event audience, `secevent+jwt` type, stable event ID, delivery freshness, and
the supported event payload. Unknown signing keys trigger metadata refresh and a
retryable 503. Event tokens are never bearer access credentials. Requests are bounded
to 32 KiB. Incorrect payloads are rejected; storage failure returns 503 and never
acknowledges receipt. Configure trusted forwarding middleware if TLS terminates at
a proxy; the receiver requires an HTTPS request scheme.

Receipt writes a denial for the exact issuer/session. Duplicate receipt performs the
same idempotent write and returns the same empty 202. It can extend a denial but
cannot restore access or repeat another business action. `CheckRevocationNotifications`
checks that shared denial on every authenticated user-token request and fails closed
on storage failure. A session identifier is required; machine-only resources need a
separate authentication scheme/profile. The store may also be supplied by implementing
`IRevokedSessionStore` with equivalent shared durable and idempotent semantics.

The default distributed-cache adapter rejects `MemoryDistributedCache` outside
Development/Testing. Use persistent Redis (or equivalent durable storage) shared by
all receiver replicas, with no eviction of revocation entries and backup/recovery that
preserves them. An acknowledgment is a durability promise: do not configure an ephemeral
cache, silent cache fallback, or a backend that reports missing values when unavailable.
Default denial retention is 31 days; it must cover the maximum affected credential
lifetime plus any accepted clock skew. A recipient starting without prior history must
reconcile active sessions or wait out pre-existing tokens before claiming push coverage.

## Operations and repair

Inspect `RevocationOutbox` for pending rows and `LastError`. Warnings identify the
message ID and recipient without logging tokens or private keys. Successful rows are
removed. Permanent failures have `NextAttemptAtUtc` set to the maximum timestamp and
remain available for repair; transient failures keep their due time and attempt count.
After correcting a recipient or deployment problem, requeue selected rows in the
database by setting `NextAttemptAtUtc` to current UTC and clearing `LeaseToken` and
`LeaseUntilUtc`. Preserve the row ID so repeated delivery stays idempotent. Requeue
only rows whose failure has been understood; do not silently delete pending events.

The worker uses the current valid RSA signing certificate and publishes no separate
secret. Retain signing overlap according to [key rotation](key-rotation.md). Disabling
delivery stops new capture and pauses delivery; it does not retrospectively create
missed events when reenabled. High-risk live enforcement still applies during outages,
rollout, repair, or configuration changes. Notification latency is normally one poll
plus delivery time for an empty queue, but is not an immediate-revocation SLA: recipient
outage/backlog can extend it. The immediate high-risk bound comes from per-request truth.

Automated tests cover transactional rollback, hard deletion, real login/logout and
disable paths, cross-worker leasing, retry backoff, lost acknowledgments, durable
receiver restart, duplicate receipt, dependency failure, forged/confused tokens,
key refresh, freshness and payload constraints. The PostgreSQL migration is also
verified on an isolated database. Deployed consumers must enable the enforcement
options before claiming this profile; tests do not assert an existing rollout did so.

References: [Security Event Tokens (RFC 8417)](https://www.rfc-editor.org/rfc/rfc8417),
[HTTPS push delivery (RFC 8935)](https://www.rfc-editor.org/rfc/rfc8935).
