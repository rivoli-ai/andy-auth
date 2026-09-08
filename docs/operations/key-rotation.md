# Production key protection and rotation

Production requires externally provisioned password-protected PFX certificates for
three separate purposes: OpenIddict signing, OpenIddict encryption, and encryption
of ASP.NET Data Protection keys. There is no automatic key generation or deletion.
Embedded mode retains its local PEM storage. Production rejects the old PEM path
and ephemeral-key override, including when protected certificates are also configured.

## Provisioning

Generate distinct RSA keys (at least 2048 bits, preferably 4096) and certificates
with your organization's certificate tooling. Export each private key in an encrypted,
password-protected PKCS#12/PFX bundle. Supply strong unique passwords through the
platform secret store, separately from the files. Never commit bundles or passwords.
Mount bundles read-only and restrict access to the auth service identity. Passwords
protect stored bundles; a compromised running auth process can still use its keys.
On Linux/Windows imports use ephemeral key storage; macOS uses its temporary keychain-backed certificate storage because it does not support ephemeral PFX imports.
This implementation is a protected-file provider, not a non-exportable HSM provider.

Every replica must mount the same durable read/write Data Protection directory
(shared filesystem supporting atomic file creation) and receive the same certificate
configuration. A separate local disk per replica does not satisfy this contract.
Provision the directory before startup. The application requires an absolute existing
path but cannot establish whether your storage is actually shared across machines.
Use a different ring and application name for each independent environment.

Set these settings via secret configuration (double underscores for environment variables):

```text
OpenIddict__Certificates__Signing__0__Path=/run/auth-keys/signing-current.pfx
OpenIddict__Certificates__Signing__0__Password=<secret>
OpenIddict__Certificates__Encryption__0__Path=/run/auth-keys/encryption-current.pfx
OpenIddict__Certificates__Encryption__0__Password=<different-secret>
DataProtection__Certificates__0__Path=/run/auth-keys/protection-current.pfx
DataProtection__Certificates__0__Password=<different-secret>
DataProtection__KeyRingPath=/shared/andy-auth/data-protection
DataProtection__ApplicationName=andy-auth-production
```

Missing protection, invalid passwords, missing RSA private keys, reused keys,
missing current signing/encryption certificates, or an invalid current Data Protection
certificate fail startup. Readiness must gate traffic until startup completes.
Remove `OpenIddict__SigningKeys__Path` and `OpenIddict__UseEphemeralKeys` from production.

## Planned signing/encryption rotation

1. Generate next certificates with unique keys, future `NotBefore`, and a later
   `NotAfter` than the current certificates. Add them as index 1 (or the next index)
   to the relevant certificate array; preserve current and retained certificates.
2. Deploy this complete bundle/configuration to every replica before activation.
   Verify all replicas expose the same signing KIDs at the JWKS endpoint and that
   the current key still signs tokens. Allow at least the longest consumer JWKS cache
   interval plus rollout time and clock skew for advance publication.
3. After `NotBefore`, restart/roll all replicas with the same configuration.
   OpenIddict orders certificates when it builds its options; this provider does not
   promise timed hot reload. The currently valid certificate with the latest expiry
   is preferred. Mixed rollout replicas can use old/new keys during overlap because
   every replica and consumer already has both public keys.
4. Prove a token issued before rollout still validates and a newly issued token
   uses the next KID. Verify old encrypted refresh tokens still redeem on another replica.
5. Retain old signing certificates in JWKS and old encryption private keys for the
   longest lifetime of ANY affected token (including refresh tokens), clock skew,
   and consumer cache interval after the last old-key issuance. Retired means no new
   issuance, not immediate removal. Remove only after that window and a verified backup.
   Monitor certificate expiry and schedule rotation early; issuance must never outlive
   the availability of a valid active certificate.

## Data Protection certificate rotation

Index 0 encrypts newly generated ring entries. Move the old certificate to index 1
and install the new currently valid certificate at index 0 on every replica. Keep all
old certificates for decrypting retained ring entries. ASP.NET manages its own key
lifetime; replacing the wrapping certificate does not re-encrypt existing entries.
Retain old wrapping keys for as long as any retained ring entry uses them. Do not
manually delete ring entries to accelerate rotation: that invalidates cookies and
other protected state. Application name and cookie configuration must stay identical
across replicas and restarts.

## Backup, restore, and emergency rotation

Back up the complete ring, certificate bundles, configuration/version manifest and
password references together. Store password recovery material separately under access
control. Test restoration in isolation: mount the restored ring, restore all retained
certificates/passwords, keep the application name, and prove an earlier protected
cookie and JWT remain readable/valid. Never generate replacement keys over lost files.

For suspected signing-key compromise, generate new keys, publish and activate on all
replicas, remove compromised signing keys, and invalidate affected sessions/tokens.
Consumers may cache compromised JWKS keys: force cache refresh/restart or block access
until every consumer has rejected the old KID. Key removal alone does not revoke a
JWT already trusted by a consumer. Coordinate with the revocation guarantees in #172.
For Data Protection compromise, revoke affected ring keys and sessions as part of an
incident rollout; expect forced sign-in. For encryption compromise, rotate encryption
keys and revoke affected refresh tokens; rotation cannot undo disclosure of old data.
Document the cutoff and verify rejection on each consumer before declaring recovery.

## Validation

`dotnet test tests/Andy.Auth.Server.Tests --filter 'FullyQualifiedName~ProductionKeyMaterialTests|FullyQualifiedName~ProductionModeIntegrationTests|FullyQualifiedName~ProductionReplicaKeyAcceptanceTests'`

The tests cover boot rejection, certificate selection/overlap, and token verification.
`ProductionReplicaKeyAcceptanceTests` starts independent Production application hosts
sharing protected certificate files, a durable key ring, and a database. It verifies
identical JWKS, cross-replica antiforgery and actual Identity cookies, authorization-code
and refresh redemption across hosts, old JWT validation and new signing KIDs during
rotation, and cookie/token/refresh recovery after deleting the original storage and
restoring its backup. Cookies issued before and after wrapping-key rotation both
survive recovery. These tests run in the normal server test suite.

This is automated application acceptance with TestServer HTTP transport. Operators
still verify their deployment mounts satisfy the shared-storage contract above;
network isolation, TLS termination, and ingress readiness routing belong to the
production topology acceptance in #174. No particular hosting provider is required
to reproduce the key-lifecycle acceptance tests.

References: [OpenIddict credential selection](https://documentation.openiddict.com/configuration/encryption-and-signing-credentials.html),
[ASP.NET Data Protection configuration](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/configuration/overview?view=aspnetcore-10.0).
