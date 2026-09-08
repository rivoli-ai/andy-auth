# Service certificate authentication

The shared `Andy.Auth` library provides an opt-in service scheme and HTTP client
handler. This is the foundation for #44, not a statement that existing consumers
or hosted environments have migrated. User OIDC authentication remains separate.

## Receiving a service call

Register the existing bearer scheme, then:

```csharp
builder.Services.AddAndyServiceAuthentication(builder.Configuration);
```

Select `ServiceCertificateAuthentication.Scheme` on service-only endpoints, for
example with `[Authorize(AuthenticationSchemes = ServiceCertificateAuthentication.Scheme)]`.
Registration does not change the application's default authentication scheme.
Use `ConfigureAndyServiceTls` on a **dedicated HTTPS listener**, passing the
service options, its server certificate and the registered validator. The helper
requests certificates in `Both` mode and requires them in `ClientCertificate`
mode. Listener mode changes require restart; the application scheme reads current
options. Keep user-facing OAuth/browser traffic on its existing listener.

```json
{
  "Auth": {
    "Mode": "Both",
    "JwtScheme": "Bearer",
    "TrustBundlePath": "/run/service-pki/trust.pem",
    "AllowedClientIdentities": {
      "urn:andy:policies": "andy-policies"
    },
    "MaximumLeafLifetime": "00:05:00"
  }
}
```

The example identities must match actual registration identities. Allowlisting
maps a single URI SAN to `sub`, `client_id` and `NameIdentifier`; it grants no
roles. `service_identity`, `authentication_method=mtls`, `provider` (default
`andy-auth`) and the SHA-256 certificate digest identify the caller for auditing.
Resource authorization still applies. Forwarded certificate headers are ignored.
An invalid presented certificate never falls back to bearer authentication.
`Auth:RequireClientCertificate=true` overrides `Mode` to certificate-only.

Supply the complete explicit trust bundle: roots and all allowed intermediates.
A missing or withdrawn intermediate is not recovered from an OS cache. Production
requires online CRL validation; unavailable revocation information denies access.
The CA must publish CRLs and reject renewal of revoked leaves. An explicit
`AllowDevelopmentNoRevocation=true` is supported only in Development/Testing;
this flag fails closed in Production. Leaf validity defaults to at most five
minutes and cannot be configured above ten minutes, including CA backdating.

## Sending a service call

Configure `CertificatePath`, optional `PrivateKeyPath` (otherwise the certificate
file must also contain its key), `LocalServiceIdentity`, `ExpectedServerIdentity`
and `TrustBundlePath` under `Auth`. Use unencrypted PEM in a restricted workload
secret mount. No CA signing key belongs in these paths.

```csharp
builder.Services.AddHttpClient("rbac", client =>
    client.BaseAddress = new Uri("https://rbac.internal:7443"))
    .ConfigurePrimaryHttpMessageHandler<RotatingServiceCertificateHandler>();
```

This handler always uses mTLS. During migration, attach it only to certificate
clients; retain the existing bearer handler for explicit JWT rollback. It checks
the normal DNS hostname **and** the exact expected URI SAN. HTTPS redirects are
disabled. Publish certificate/key pairs through a versioned directory and an
atomic symlink replacement. New requests detect material changes and create a new
connection pool; old response streams finish before their pool is disposed.
Always dispose responses, including streamed responses. Invalid replacement
material fails the request rather than silently using an older certificate.
Connections have a one-minute maximum pooled lifetime. The receiver revalidates
the certificate on each authenticated request, including a reused connection.
On macOS, the platform temporarily imports private keys for TLS; disposal releases
them. Linux uses ephemeral key loading.

## Operations and outstanding rollout

The `Andy.Auth.ServiceCertificates` meter exposes
`andy.mtls.certificate.rotations`, `andy.mtls.authentication.rejected` (bounded
reason codes), and `andy.mtls.certificate.remaining` in seconds. Alert before
renewal stops, on certificate rejection and on unavailable CRLs. Do not log keys
or complete enrollment credentials.

Rollback requires explicitly choosing JWT mode and restoring the bearer client
handler; changing only the listener does not change endpoint policy. A compromised
issuer requires trust-bundle removal on every receiver, not just revoking one leaf.
See [ADR 0002](adr/0002-mtls-intra-ecosystem-s2s.md) for CA ownership, Conductor
proxy behavior and integration order. Linux acceptance verifies a newly published signed CRL rejects the next request
on the same TLS connection after the old CRL expires. CA automation, consumer
migrations and deployment coverage remain required before #44 can close.
