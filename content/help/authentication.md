---
title: "Authentication"
order: 2
tags: [auth, security]
---

# Authentication

Andy Auth supports multiple authentication methods to fit different user and application needs.

## Password Authentication

The most common method. Users register with an email and password, then log in via the sign-in page. Passwords are hashed using industry-standard algorithms (PBKDF2 / bcrypt) and never stored in plain text.

### Password Requirements

- Minimum 8 characters
- At least one uppercase letter, one lowercase letter, and one number
- Special characters recommended for stronger security

## Social Authentication

Andy Auth supports logging in via external identity providers:

- **Google**
- **Microsoft**
- **GitHub**

Social authentication uses standard OAuth 2.0 flows and securely links external accounts to your Andy Auth profile.

## Enterprise SSO

For organizations, Andy Auth supports SAML 2.0 and WS-Federation integrations with enterprise identity providers such as:

- Azure Active Directory / Entra ID
- Okta
- OneLogin
- Custom SAML 2.0 providers

## OpenID Connect (OIDC)

Andy Auth is a certified OIDC Provider. Applications can integrate using standard OIDC discovery and the authorization code flow with PKCE. The discovery endpoint is available at:

```
/.well-known/openid-configuration
```

## Security Best Practices

- Always use PKCE for public clients (mobile, SPAs).
- Use the Client Credentials flow only for confidential server-side clients.
- Rotate client secrets regularly.
- Enable MFA for privileged accounts (see [MFA](mfa)).
