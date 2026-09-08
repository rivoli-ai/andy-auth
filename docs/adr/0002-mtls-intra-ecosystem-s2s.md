# ADR 0002: service certificates for intra-ecosystem calls

Status: implementation in progress under #44 / #177. This decision does not assert
that consumers or hosted deployments have migrated.

## Decision

Production trust belongs to an operator-controlled PKI. Auth receives only its
own workload certificate and narrowly scoped enrollment/renewal authority; it
must not hold a production root/intermediate signing key or credentials capable
of issuing another service's identity. The integration contract is a private
key plus short-lived PEM certificate, a public CA bundle, and automated
atomic material replacement. Vault, Venafi and managed CAs can supply this
contract without making their issuance APIs part of token authentication.

For opt-in local development and Docker/Conductor development bundles, use a
companion Smallstep CA. Bootstrap credentials are provisioner-scoped to one
registered service identity. Development CA state stays separate from the auth
application database and token-signing keys. A local development bundle is one
OS-user trust domain; it does not provide production process isolation.

Use one URI SAN from the service registration's audience, mapped by the receiving
service's explicit allowlist to its registered client/subject id. Ignore CN for
authorization. Require a trusted chain, leaf key usage, the relevant client/server
EKU, adequate key strength, current validity, and a bounded leaf lifetime (five
minutes by default; configuration cannot exceed ten minutes). Do not convert a
CA certificate, an ambiguous URI SAN, or an unregistered identity into a caller.
A certificate authenticates a service; existing resource/subject authorization
still decides what it may do. `/api/check` retains its end-user `SubjectId` body.

Active service-leaf revocation uses CRLs through the platform X.509 online
validator. Unknown/offline revocation denies access. Pin intermediate certificates
in the explicit trust bundle and reload it so issuer removal cannot be defeated
by an OS intermediate cache. Short leaf validity bounds residual access even
where a CRL response remains cached. CA renewal must reject revoked credentials.
The only no-revocation-check mode requires an explicit flag and a Development or
Testing host; it still checks chain, identity, purpose and short validity.
Smallstep's [active revocation configuration](https://smallstep.com/docs/step-ca/certificate-authority-server-production/)
and [CRL settings](https://smallstep.com/docs/step-ca/configuration/) are required:
its default passive revocation alone is not the production profile.

Machine calls use direct HTTPS service endpoints, including in Conductor. The
:9100 browser/UI proxy continues to carry user OIDC traffic. A terminating proxy
cannot preserve proof of the original client's private key merely by forwarding
a certificate header. Consequently, direct service connections are the default;
certificate-forwarding headers are never accepted by the shared validator.
Operators choosing proxy authentication must explicitly register the proxy as
its own service identity and accept that distinct audit boundary. Production
end-to-end mTLS can also use a TCP/TLS passthrough proxy.

Use `Auth:Mode = Jwt | Both | ClientCertificate` for S2S authentication. `Both`
chooses a presented certificate first and never falls back to bearer after a bad
certificate. Strict S2S endpoints reject bearer credentials in certificate-only
mode. User-facing OAuth endpoints retain their existing schemes. Dedicated
service listeners require client certificates in strict mode; mixed public/user
listeners must not accidentally require end users to enroll certificates.

Client rotation replaces the TLS connection pool for new requests while allowing
in-flight response bodies to complete. Root/leaf reloads fail closed on invalid
material; certificate headers and disabled server-name checks are not substitutes
for mTLS. Expose reload/failure metrics and expiry signals for operators.

## Integration order and acceptance

1. Shared validation, identity, listener and outbound rotation library; local CA
   bootstrap/renewal interface and negative/revocation tests in auth.
2. RBAC accepts `Both`, preserving subject/provider and active-service checks.
3. Policies is the reference client; verify actual `/api/check` calls with a
   certificate, rotation, revocation and bearer rollback.
4. Migrate remaining registered consumers and Conductor endpoint/certificate
   injection with their repository-specific tests and runbooks.
5. Enable certificate-only S2S after the inventory is accounted for. No blanket
   config flip is evidence that a service has migrated.

Use real TLS acceptance for missing/untrusted/expired/revoked certificates,
wrong URI identities, certificate precedence, renewal, root overlap, connection
reuse, streamed responses, and revocation on an already-open connection. Keep
this issue open until the cross-repository and deployment-mode work has evidence.
