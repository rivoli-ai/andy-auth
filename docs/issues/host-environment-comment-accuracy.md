# `HostEnvironmentExtensions` doc comment: align with reality

## Context

The post-merge review of 5776dc1 flagged this as the last open item: "the `appsettings.Embedded.json` decision". On closer inspection, Embedded's bullet in `HostEnvironmentExtensions.cs:18-23` is **correct** ("All configuration is injected by Conductor at process start — no static appsettings file for this environment"). The actual mismatch is in the **Docker** bullet.

## Problem

`Configuration/HostEnvironmentExtensions.cs:14-16` says:

> Docker (ASPNETCORE_ENVIRONMENT=Docker): docker-compose stack. Ports offset +2000 from Development so both can coexist on one machine. **Config comes from appsettings.Docker.json + compose env.**

That last sentence is wrong on two counts:

1. **`appsettings.Docker.json` does not exist** in the repo. Docker mode is env-var driven (compose env vars), same as Embedded.
2. **`docker-compose.yml` currently sets `ASPNETCORE_ENVIRONMENT=Development`**, not `Docker`. The bug that #75/#76 just plugged was that `ENV=Docker` silently failed; now `ENV=Docker` works, but compose still uses `Development`.

The "three modes, three appsettings" mental model the comment implies doesn't match the codebase.

## Fix

Rewrite the Docker bullet to describe what's actually true after #76 landed:

- Docker is env-var driven (no static appsettings file).
- `docker-compose.yml` today sets `ENV=Development`; `ENV=Docker` is supported as of #76 but not yet adopted by the compose file.
- Trust model is local-development (ephemeral keys, transport security off).

Also tweak the lead-in line to drop "every Andy service" — this file is andy-auth-specific, the canonical contract lives in `andy-service-template/docs/ports.md`.

## Acceptance criteria

- [ ] Docker bullet describes env-var-driven config + the current compose state honestly.
- [ ] No claim that `appsettings.Docker.json` or `appsettings.Embedded.json` exist.
- [ ] Lead-in line acknowledges this file is the andy-auth copy of a contract, not the contract itself.

## Out of scope

- Creating `appsettings.Docker.json`. compose still uses Development; that decision belongs with whoever owns the deploy story.
- Switching compose to `ENV=Docker`. Same — bigger decision, surfaces Swagger gating.

## Files touched

- `src/Andy.Auth.Server/Configuration/HostEnvironmentExtensions.cs` — comment-only.
