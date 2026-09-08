# Production replica ingress acceptance

Run `python3 tests/deployment/replica_acceptance.py --image andy-auth:ci` after
`docker build --build-context certs=./certs -t andy-auth:ci .`.
Docker, Python 3, and OpenSSL are required. The container-smoke CI job runs this
scenario against its Production image. No platform account or real user is needed.

The fixture creates two Production auth instances with a shared SQLite database,
protected certificate bundles, and Data Protection ring. A shared Redis instance
holds atomic rate counters. HAProxy terminates TLS using a temporary certificate
trusted explicitly by the test client. The proxy overwrites caller forwarding headers
and is the only trusted forwarding address. Auth containers publish no host ports;
the backend and external networks are separate. All fixture resources use a unique
prefix and are removed in a `finally` block, including on assertion failure.

The assertions exercise both replicas, verify that spoofed forwarding headers cannot
change the observed client identity/scheme, exhaust one shared token-request allowance,
and prove a replica restart cannot restore that allowance. A private backend peer
cannot impersonate the trusted proxy; an external-network peer cannot reach the app
directly. Disconnecting one replica from Redis makes HAProxy remove it using `/ready`
while continuing to serve through the healthy replica. Reconnecting it restores service.
Stopping shared Redis removes both replicas and causes ingress to return 503.

## Operator contract

Apply the same invariants to the actual deployment:

- Configure exact ingress IP addresses (or tightly scoped ingress-only networks) in
  `ForwardedHeaders:KnownProxies` / `KnownNetworks`. Never trust all private peers.
- Overwrite incoming `X-Forwarded-For` and `X-Forwarded-Proto` at ingress. Expose only
  ingress externally and enforce backend isolation with the platform's network policy.
- Set `RateLimiting:RequireDistributed=true` and share the Redis connection across
  replicas. Redis failure must fail closed; do not switch to local counters on outage.
- Use `/ready` for traffic admission, requiring status 200. `/health` is only liveness.
  No fallback route may send requests to a replica that failed readiness.
- Supply identical protected key material and a durable shared Data Protection ring
  as described in [key rotation](key-rotation.md). The test's shared SQLite file is
  a fixture choice; provision the supported database/storage appropriate to deployment.
- Keep admin MFA and the short admin step-up lifetime enabled. The application tests
  cover enrollment, TOTP verification, expiry, session revocation, and stamp binding.

This fixture proves the controls in a reproducible deployment topology. It does not
assert that a particular existing platform deployment already has these settings.
Disable `Diagnostics:EnableClientInfoEndpoint` after completing deployment diagnostics.
The temporary test certificate passwords and fixture admin passwords are generated
per run; never use fixture keys or accounts as production provisioning material.
