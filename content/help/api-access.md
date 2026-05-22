---
title: "API Access"
order: 5
tags: [auth, api]
---

# API Access

Andy Auth provides secure API access for both user-facing applications and machine-to-machine (M2M) integrations.

## User-Facing API Access

For applications acting on behalf of a user, use the **Authorization Code Flow with PKCE**:

1. Redirect the user to Andy Auth's authorize endpoint.
2. The user authenticates and consents to the requested scopes.
3. Andy Auth redirects back with an authorization code.
4. Your application exchanges the code for access and refresh tokens.

### Required Parameters

- `client_id` — Your application's client ID.
- `redirect_uri` — Must match a registered redirect URI.
- `response_type=code`
- `scope` — Space-delimited list of requested scopes (e.g., `openid profile email`).
- `code_challenge` and `code_challenge_method=S256` — PKCE parameters.

## Machine-to-Machine (M2M) Access

For backend services and daemons that need to call APIs without a user present, use the **Client Credentials Flow**:

```http
POST /connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=your-client-id
&client_secret=your-client-secret
&scope=api:read api:write
```

M2M clients must be registered in Andy Auth with the **Client Credentials** grant type enabled. No user context is present in M2M tokens.

## Scopes

Scopes define what resources an access token can interact with. Common scopes include:

| Scope | Description |
|---|---|
| `openid` | Required for OIDC; returns an ID token. |
| `profile` | Access to basic profile claims (name, picture). |
| `email` | Access to the user's email address. |
| `offline_access` | Request a refresh token. |
| `api:read` | Read access to protected APIs. |
| `api:write` | Write access to protected APIs. |

## Token Validation

Resource APIs should validate access tokens by:

1. Verifying the JWT signature using Andy Auth's public signing keys.
2. Checking the `iss` (issuer), `aud` (audience), and `exp` (expiration) claims.
3. Ensuring required scopes are present.

The JWKS endpoint is available at `/.well-known/jwks`.

## Rate Limiting

Token endpoint requests are rate-limited to prevent abuse. If you exceed the limit, wait before retrying or contact an administrator to discuss increasing your quota.
