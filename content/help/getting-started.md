---
title: "Getting Started"
order: 1
tags: [onboarding, quickstart]
---

# Getting Started with Andy Auth

Andy Auth is the identity and access management platform for the Rivoli AI ecosystem. It provides authentication, authorization, and user management for all Rivoli services.

## What is Andy Auth?

Andy Auth is an OpenID Connect (OIDC) and OAuth 2.0 identity provider built on top of ASP.NET Core Identity and OpenIddict. It handles:

- **User Authentication** — Password-based login, social logins, and enterprise SSO.
- **Authorization** — Role-based access control (RBAC) and scope-based permissions.
- **Token Issuance** — JWT access tokens, identity tokens, and refresh tokens.
- **Client Management** — Registration and configuration of OAuth 2.0 / OIDC clients.

## Quick Start

1. **Create an account** — Visit the registration page and sign up with your email.
2. **Verify your email** — Click the verification link sent to your inbox.
3. **Log in** — Use your credentials to authenticate via the web portal or an API client.
4. **Access applications** — Once authenticated, you can access authorized Rivoli services.

## Supported Flows

Andy Auth supports the following OAuth 2.0 / OIDC flows:

- **Authorization Code Flow** with PKCE (recommended for web and mobile apps)
- **Client Credentials Flow** (for machine-to-machine communication)
- **Device Authorization Flow** (for input-constrained devices)
- **Refresh Token Flow** (for long-lived sessions)

## Next Steps

- Learn about [Authentication](authentication)
- Set up [Multi-Factor Authentication](mfa)
- Understand [Session Management](session-management)
- Explore [API Access](api-access)
