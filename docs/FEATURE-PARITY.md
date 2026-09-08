# IdentityServer capability assessment

Reviewed 2026-09-08; updated with the device-flow/PAR implementation under #15
(.NET 10, OpenIddict 7.2). This replaces the unsupported “90% parity” and
“ready for production” assertions in issue #9. A merged implementation, a
passing regression, and acceptance in a deployed environment are distinct facts.

Duende currently describes Community Edition as feature-equivalent to Standard;
its eligibility and packaging must be checked against the current vendor terms,
not the historical issue's assumptions. This assessment compares capabilities,
not license eligibility or a certification claim. See the vendor's
[Community Edition description](https://duendesoftware.com/products/communityedition)
and [IdentityServer documentation](https://docs.duendesoftware.com/identityserver/).

## Capability and evidence matrix

Paths below are relative to the repository root. Test names identify evidence,
not a claim of protocol certification or complete coverage of every deployment.

| Capability | Current Andy.Auth implementation | Evidence and remaining work |
| --- | --- | --- |
| Authorization code, PKCE, client credentials, refresh, discovery, introspection, revocation, UserInfo | Implemented through OpenIddict and application controllers | `OAuthIntegrationTests`, `PkceEnforcementTests`, `AndyDocsWebIntegrationTests`; real assistant/resource acceptance remains #7/#118 |
| JWT versus opaque tokens | JWT access tokens and reference refresh tokens are configured | `src/Andy.Auth.Server/Program.cs` calls `UseReferenceRefreshTokens`; it does not enable reference access tokens. The old blanket “reference tokens” checkbox overstated the deployed configuration |
| Device authorization | `/connect/device`, `/connect/verify`, code storage and token polling are implemented | `DeviceController`, `DeviceFlowTests`, `DeviceFlowAcceptanceTests`; real browser approval and CLI polling, denial, CSRF, replay, expiry and session revocation are covered. Actual smart-TV/deployment acceptance remains #15 |
| RFC 8693 exchange | Implemented with subject, actor, resource, scope, session and absolute lifetime checks | `TokenExchangeIntegrationTests`, `docs/testing/obo-regression.md`, PRs #186/#189; actual downstream acceptance remains #118 |
| PAR | Opt-in `/connect/par`, per-client permission/requirement, protected consent context, request expiry/client binding and replay enforcement | `PushedAuthorizationIntegrationTests`, `docs/ADVANCED-OAUTH.md`; migrate existing client permissions before enabling discovery |
| DPoP and CIBA | No DPoP proof enforcement/token binding or CIBA approval/notification implementation | #15 remains open for these capabilities; package support alone does not enable an application feature |
| Client administration and DCR | Admin client CRUD, secret management, scoped permissions, manifest registrations, IAT/RAT and reapproval controls exist | `AdminControllerTests`, `DynamicClientRegistrationControllerTests`; PR #190 fixes approved-baseline preservation, #198 packages consumer manifests |
| Local password accounts, MFA and lifecycle | Login, password hashing, TOTP/recovery, lockout, suspend/expire/delete and explicit account linking exist | `AccountControllerTests`, `TwoFactorControllerTests`, `ExternalRegistrationIntegrationTests`, `AdminAccessIntegrationTests`, browser MFA acceptance in PR #199 |
| Public signup and email verification | Registration is disabled by default; enabled registration requires confirmed email and does not sign in a new unverified account | No verification email sender, confirmation callback or resend workflow exists. #80 remains incomplete; a generic submitted response is not email delivery |
| External providers | Conditional Microsoft account/Entra configuration and explicit verified-identity linking policy exist | `Program.cs`, `ExternalLoginOptions`, `ExternalRegistrationIntegrationTests`; actual tenant/provider acceptance remains #81/#82. Google, GitHub and configurable generic OIDC providers are not registered |
| Browser and bearer sessions | Server session tracking and per-session revocation; interactive cookie enforcement; live local REST/MCP admin bearer enforcement | PRs #187/#200, `InteractiveSessionCookieEventsTests`, `LiveAdminApiIntegrationTests`. Offline downstream JWT validation still has the residual lifetime described in `docs/REVOCATION-PROFILE.md` |
| Logout/revocation notifications | Durable signed Security Event Tokens over HTTPS, with transactional capture, retries, shared consumer denial checks and mandatory live-check option | #172; `RevocationDeliveryIntegrationTests`, `RevocationReceiverTests`, and `LiveAdminApiIntegrationTests`. This is the authenticated-event alternative, not OIDC back-channel logout. See `docs/operations/revocation-events.md`; deployed adoption is separate acceptance. |
| Consent | Consent UI, durable grants, expiry and revocation exist | `ConsentControllerTests`, `ConsentGrantServiceTests`; removing a remembered choice is distinct from revoking credentials |
| Claims privacy | Email/profile/roles are projected according to granted scopes; profile aliases do not leak an ungranted email address | #173/PR #191, `TokenClaimsPrincipalFactoryTests`; this does not establish signup email delivery |
| Signing, encryption and Data Protection | Production requires protected certificate bundles, shared persistent Data Protection configuration and rotation overlap support | #175/PR #184, `ProductionKeyMaterialTests`, `ProductionModeIntegrationTests`, `docs/operations/key-rotation.md`; deployed rotation/replica acceptance remains outstanding |
| Proxy trust, throttling and readiness | Validated explicit proxy trust, readiness admission, Redis atomic rate counters and fail-closed outage behavior exist | #174/PRs #193/#196, `ForwardedProxyTrustConfigurationTests`, `DistributedRateLimitingTests`, `ReadinessCheckTests`; actual ingress isolation and replica routing are not verified by these fixtures |
| Interactive admin access | Hardened modes require a short-lived session-bound password/TOTP step-up cookie | #174/PR #197, `AdminAccessIntegrationTests`; production ingress acceptance remains separate |
| mTLS | No ecosystem certificate authentication/rotation substrate | #44 spans the CA interface, server/client libraries, Conductor proxy trust and multiple consuming repositories. OAuth client credentials are the current S2S mechanism |
| Diagnostics | Health/readiness, audit logging and OpenTelemetry registration exist | `HealthCheckTests`, `AuditLogIntegrationTests`, `Program.cs`; exporter configuration, alert delivery and actual operational monitoring remain deployment acceptance |
| FAPI and Windows authentication | No application conformance evidence or configured Windows authentication scheme | Do not claim FAPI compliance merely because constituent OAuth features exist |

Duende documents [PAR](https://docs.duendesoftware.com/identityserver/tokens/par/),
[proof-of-possession](https://docs.duendesoftware.com/identityserver/tokens/pop/),
[CIBA](https://docs.duendesoftware.com/identityserver/ui/ciba/), and
[client logout notifications](https://docs.duendesoftware.com/identityserver/ui/logout/notification/)
as distinct capabilities. Their presence in Duende's documentation is not evidence
that Andy.Auth implements them.

## Epic #177 reconciliation and execution order

The completed remediation children are #176, #169, #171, #170, #173 and #19.
Their PRs and verification are recorded in #177. #175 and #174 contain merged
implementation plus outstanding deployed acceptance; #172 has local enforcement
but still needs actual notification delivery and consumer enforcement.

The owner has now requested **all** children of #177, including the previously
P3 #15, #44 and this analysis. The analysis itself can close when this evidence
matrix is merged; doing so must not close the implementation children.

1. Device-flow browser/CLI acceptance and native PAR client policy, replay/expiry
   tests, feature configuration and discovery checks are implemented. Complete real
   deployed/client acceptance under #15. Add DPoP
   end-to-end proof binding and CIBA only with complete validation, replay state,
   approval and notification behavior; no advertisement before enforcement.
2. Roll out #172's tested authenticated event sender/receiver and mandatory live
   enforcement to consuming resources according to their revocation class.
3. #175/#174 automated acceptance is complete: PRs #204/#205 exercise independent
   Production hosts and a real TLS/container topology. Operators still verify their
   own shared mounts and ingress configuration; these tests do not assert a hosted rollout.
4. Implement #44's reusable certificate trust/identity contract and test both sides
   before migrating actual consumers. The issue explicitly requires cross-repo and
   deployment work; choosing a CA does not establish that migration is complete.

No percentage summarizes this matrix: features have different security impact,
and several rows include external integration that cannot be inferred from local
unit tests. Keep each issue open until its stated acceptance has evidence.
