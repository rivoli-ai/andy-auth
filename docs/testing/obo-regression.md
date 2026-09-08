# OBO issuance regression (#118)

Run the hermetic auth protocol regression:

```sh
dotnet test tests/Andy.Auth.Server.Tests/Andy.Auth.Server.Tests.csproj --filter FullyQualifiedName~OboIssuanceRegressionTests
```

It logs in the seeded ordinary user through the real cookie/antiforgery flow,
requests an authorization code with S256 PKCE, redeems it, and exchanges the issued
access token as `andy-containers-api` for `urn:andy-models-api`. No hand-signed subject
JWT, direct claims-factory call, or M2M fallback can satisfy the test. The test verifies
signature, issuer, type, lifetime and target audience using public discovery/JWKS,
then checks the stable user `sub`, separate actor `act.sub`, tenant, session binding
and scope/lifetime attenuation. Revoking the session must reject another exchange.

Both a fresh database and an existing scope missing the API client-id resource are
covered. The stale case runs the real seeder and requires it to repair the resources
before the same login/exchange chain succeeds. This catches the deployed-database
variant of the original bug, where new installations worked but existing scope rows
never picked up the extra audience. Existing negative tests remain in
`TokenExchangeIntegrationTests` for invalid tokens, unrelated audiences and excess scope.

The fixture CLI is public with a loopback callback and pre-prefixed scope permissions;
it is test-only and does not depend on the adjacent #168 manifest normalization change.

## Full deployment acceptance

This suite runs auth and exercises the containers client's wire contract. It does
not launch the containers proxy, models service or RBAC evaluator. Before closing
#118, use an isolated integration deployment to verify those components together:

1. Start auth with the actual service registration manifests and a narrowly allowed
   containers-to-models token-exchange policy. Test fresh and upgraded scope rows.
2. Seed an RBAC grant for the test user's stable auth subject under provider
   `andy-auth`, including the intended `model:execute` permission. Keep a second
   authenticated user without that grant as the negative control.
3. Sign in normally and perform the containers operation that calls models. Require
   the proxy's OBO path to succeed; any `[PROXY-OBO-FALLBACK]` is a test failure.
4. Assert models receives a validated JWT whose `sub` is the signed-in user and
   `act.sub` is `andy-containers-api`. Assert its permission check resolves that
   stable subject in RBAC and allows the granted user, while denying the control.
5. Revoke the interactive session and repeat. Auth must refuse another exchange;
   also measure how long already-issued tokens remain accepted by the deployed
   consumers. That residual window belongs to the revocation contract in #172.

Record service revisions, configuration, test command and results on #118. A decoded
JWT or a successful M2M call is not evidence of this cross-service acceptance.
