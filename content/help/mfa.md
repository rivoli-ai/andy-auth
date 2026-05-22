---
title: "Multi-Factor Authentication"
order: 3
tags: [auth, security]
---

# Multi-Factor Authentication (MFA)

Multi-Factor Authentication adds an extra layer of security by requiring a second verification step in addition to your password.

## Why Use MFA?

Even if your password is compromised, an attacker cannot access your account without the second factor. MFA significantly reduces the risk of unauthorized access and is strongly recommended for all users, especially administrators.

## Supported MFA Methods

### Time-Based One-Time Password (TOTP)

The most common MFA method. After entering your password, you provide a 6-digit code from an authenticator app such as:

- Google Authenticator
- Microsoft Authenticator
- Authy
- 1Password

During setup, Andy Auth displays a QR code. Scan it with your authenticator app to begin generating codes.

### Recovery Codes

When you enable MFA, Andy Auth generates a set of single-use recovery codes. Store these in a safe place. If you lose access to your authenticator app, a recovery code can be used to regain access to your account.

## Enabling MFA

1. Log in to Andy Auth and go to your **Account Settings**.
2. Navigate to the **Security** tab.
3. Click **Enable Multi-Factor Authentication**.
4. Scan the QR code with your authenticator app.
5. Enter the verification code to confirm setup.
6. Save your recovery codes in a secure location.

## Disabling MFA

You can disable MFA from the same **Security** tab. You will be required to enter a current TOTP code or recovery code to confirm.

## Admin Enforcement

Organization administrators can require MFA for all members of their organization. When enforced, users without MFA configured will be prompted to set it up on their next login.
