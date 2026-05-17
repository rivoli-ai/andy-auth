---
title: Andy Auth Overview
slug: andy-auth-overview
order: 1
tags: [auth, identity, oidc]
---

# Andy Auth Overview

Andy Auth is the OAuth2/OIDC identity provider for the Andy ecosystem. It owns user identity, sessions, multi-factor authentication, and OAuth client registration, and it is the OpenIddict-backed authorization server every other Andy service trusts.

## What it does

- Issues access and refresh tokens for human sessions and machine-to-machine (M2M) clients.
- Hosts the discovery document at `/auth/.well-known/openid-configuration` so other services can locate the issuer, JWKS, and supported scopes without static configuration.
- Manages OAuth client registrations — every service that mints or accepts tokens has a client row here.
- Enforces MFA challenges (TOTP today; passkey/WebAuthn on the roadmap).
- Publishes session events on NATS so dependent services can react to sign-out and revocation.

## Key concepts

- **Audience** — every API has a URN audience (`urn:andy-rbac-api`, `urn:andy-tasks-api`, …). Tokens are minted with a specific audience and rejected by anything else.
- **Scopes** — fine-grained permissions inside an audience, like `tasks:write` or `rbac:roles:assign`.
- **M2M client** — service-to-service credentials, distinct from user sessions. Conductor reads M2M client secrets through `andy-settings`.

## Where it fits

Every other service depends on Andy Auth to validate bearer tokens. Andy Auth itself depends only on its own PostgreSQL database. If Auth is down, every protected endpoint in the fleet starts returning 401.

## Configuration

Provider keys, allowed callback URLs, and MFA policy live in `config/registration.json`. Conductor surfaces the read-only catalog in **Settings → Catalogs → Services → Andy Auth**.

## Troubleshooting

- **IDX10*** errors in service logs — JWT validation failed. Most often the audience or issuer mismatches; check the consuming service's `Authentication:Authority` setting against Auth's discovery doc.
- **`[API-AUTH-401]` repeating in Conductor logs** — the cached access token expired and refresh failed. Re-signing in usually unblocks; persistent failures point at a clock skew between Conductor and Auth.
- **`IDS2*` errors** — OpenIddict rejected the request shape. The error code tells you exactly which parameter is missing or malformed.
