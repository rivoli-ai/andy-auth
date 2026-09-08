# External consumer registrations

One manifest per OAuth client is bundled into the server output and container. These use the existing registration wire format. Explicit configured paths win over bundled defaults, first by service name and then by client ID; Docker Compose mounts this directory after the sibling-service manifests. Updates preserve application IDs and grants.

Optional backward-compatible auth fields:

- `auth.registerAudience` (default `true`): set `false` for a consumer that uses existing API audiences and should not create a scope of its own.
- `auth.webClient.requirePkce` (default `false`): enforce PKCE for that client. The same option applies to API/CLI client entries.
- `auth.webClient.useConfiguredMcpResources` (default `false`): add the deployment's `OpenIddict:Resources` permissions. The same option applies to API/CLI client entries.

`andy-docs-web` replaces legacy `wagram-web`; the seeder removes the legacy row. Its local 4200/4202, Docker 6202, embedded 9100, and existing deployed callbacks are preserved. Narration and subscription retain their existing audience scope registration. Per-client redirect, scope, grant, PKCE, and MCP settings belong here rather than in `DbSeeder`.
