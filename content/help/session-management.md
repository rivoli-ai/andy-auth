---
title: "Session Management"
order: 4
tags: [auth, sessions]
---

# Session Management

Andy Auth manages user sessions securely using cookies, tokens, and refresh tokens. Understanding how sessions work helps you build secure applications.

## Cookie-Based Sessions

When you log in through the web portal, Andy Auth issues an encrypted authentication cookie. This cookie:

- Is **HttpOnly** (inaccessible to JavaScript)
- Uses the **SameSite** attribute to prevent CSRF
- Is bound to the **Secure** flag in production (HTTPS only)

The cookie session remains valid until you log out or it expires based on the configured sliding expiration policy.

## Token-Based Sessions

API and mobile clients use JWT access tokens and refresh tokens instead of cookies.

### Access Tokens

- Short-lived (typically 15–60 minutes)
- Signed by Andy Auth and verifiable by resource servers
- Contain claims such as `sub` (user ID), `email`, `roles`, and `scopes`

### Refresh Tokens

- Long-lived (configurable, typically days or weeks)
- Used to obtain new access tokens without re-authenticating
- Can be revoked by the user or an administrator at any time

## Session Lifecycle

1. **Login** — User authenticates; Andy Auth issues session cookie or tokens.
2. **Activity** — Access tokens are used to call APIs; refresh tokens renew access.
3. **Expiration** — Idle sessions expire based on policy; users must re-authenticate.
4. **Logout** — Sessions and tokens are invalidated on the server side.

## Revoking Sessions

Users can view and revoke active sessions from their **Account Settings > Security > Active Sessions**. Administrators can revoke sessions for any user from the admin dashboard.

## Best Practices

- Keep access token lifetimes short.
- Store refresh tokens securely (e.g., in the OS keychain for native apps).
- Implement proper logout to clear local state and notify Andy Auth.
- Monitor active sessions regularly and revoke unfamiliar ones.
