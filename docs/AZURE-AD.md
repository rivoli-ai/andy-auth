# Azure AD / Microsoft Entra ID Integration

This guide explains how to configure Azure AD (Microsoft Entra ID) as an external authentication provider for Andy.Auth.

## Overview

Andy.Auth supports "Sign in with Microsoft" allowing users to authenticate using their Azure AD / Microsoft accounts. This enables:

- Enterprise Single Sign-On (SSO) integration
- Leveraging existing Azure AD identities
- Support for Microsoft 365 users
- Multi-tenant or single-tenant configurations

## Azure AD App Registration

### Step 1: Create App Registration

1. Go to the [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Active Directory** > **App registrations**
3. Click **New registration**
4. Configure the application:
   - **Name**: `Andy.Auth` (or your preferred name)
   - **Supported account types**: Choose based on your needs:
     - *Single tenant*: Only accounts in your organization
     - *Multi-tenant*: Accounts in any organizational directory
     - *Multi-tenant + personal*: Includes personal Microsoft accounts
   - **Redirect URI**: Select "Web" and enter your callback URL

### Step 2: Configure Redirect URIs

Add the following redirect URIs based on your environments:

| Environment | Redirect URI |
|------------|--------------|
| Development | `https://localhost:7088/signin-microsoft` |
| UAT | `https://auth-uat.yourdomain.com/signin-microsoft` |
| Production | `https://auth.yourdomain.com/signin-microsoft` |

To add redirect URIs:
1. Go to **Authentication** in your app registration
2. Under **Platform configurations** > **Web**, add the URIs
3. Click **Save**

### Step 3: Create Client Secret

1. Go to **Certificates & secrets**
2. Click **New client secret**
3. Add a description (e.g., "Andy.Auth Production")
4. Select an expiration period (recommended: 24 months)
5. Click **Add**
6. **Important**: Copy the secret value immediately - it won't be shown again

### Step 4: Configure API Permissions

1. Go to **API permissions**
2. Click **Add a permission** > **Microsoft Graph** > **Delegated permissions**
3. Add the following permissions:
   - `openid` (Sign users in)
   - `profile` (View users' basic profile)
   - `email` (View users' email address)
   - `User.Read` (Sign in and read user profile)
4. Click **Grant admin consent for [Your Organization]** if you're an admin

### Step 5: Note Your Configuration Values

From the **Overview** page, note:
- **Application (client) ID**: Your ClientId
- **Directory (tenant) ID**: Your TenantId (or use "common" for multi-tenant)

## Andy.Auth Configuration

### appsettings.json

Add the Azure AD configuration section:

```json
{
  "AzureAd": {
    "ClientId": "your-application-client-id",
    "ClientSecret": "your-client-secret",
    "TenantId": "common"
  }
}
```

### Configuration Options

| Setting | Description | Example |
|---------|-------------|---------|
| `ClientId` | Application (client) ID from Azure | `12345678-1234-1234-1234-123456789012` |
| `ClientSecret` | Client secret value | `abc123...` |
| `TenantId` | Tenant ID or "common" for multi-tenant | `common` or `your-tenant-id` |

### Tenant Options

- **`common`**: Allows any Azure AD account and personal Microsoft accounts
- **`organizations`**: Allows any Azure AD account (no personal accounts)
- **`consumers`**: Only personal Microsoft accounts
- **Specific Tenant ID**: Only accounts from that specific tenant

## Environment-Specific Configuration

### Development (appsettings.Development.json)

```json
{
  "AzureAd": {
    "ClientId": "dev-client-id",
    "ClientSecret": "dev-client-secret",
    "TenantId": "common"
  }
}
```

### Production (Environment Variables)

For production, use environment variables:

```bash
AzureAd__ClientId=your-production-client-id
AzureAd__ClientSecret=your-production-client-secret
AzureAd__TenantId=your-tenant-id
```

Or in Railway/cloud deployments, set these as secrets in your deployment configuration.

## How It Works

### User Flow

1. User clicks "Sign in with Microsoft" on the login page
2. User is redirected to Microsoft's login page
3. User authenticates with their Microsoft account
4. Microsoft redirects back to Andy.Auth with an authorization code
5. Andy.Auth exchanges the code for tokens and user info
6. If the user doesn't exist, a new account is created
7. If the user exists (by email), the Microsoft login is linked
8. User is signed in to Andy.Auth

### Account Linking

When a user signs in with Microsoft:

- **New user**: Account is automatically created with email from Azure AD
- **Existing user (same email)**: Microsoft login is linked to existing account
- **User can sign in with either**: Password or Microsoft SSO

### Claims Mapping

The following claims are mapped from Azure AD to Andy.Auth:

| Azure AD Claim | Andy.Auth Field |
|----------------|-----------------|
| `email` | `Email` |
| `name` | `FullName` |
| `picture` | `ProfilePictureUrl` |

## Security Considerations

### Client Secret Protection

- Never commit client secrets to source control
- Use environment variables or secret management services
- Rotate secrets periodically (before expiration)

### Token Security

- Tokens are validated using Microsoft's public keys
- HTTPS is required for all authentication flows
- Session cookies are HttpOnly and Secure

### Multi-Tenant Considerations

If using multi-tenant configuration:
- Any Azure AD user can potentially sign in
- Implement additional authorization checks if needed
- Consider using Conditional Access policies in Azure AD

## Troubleshooting

### Common Issues

**"Sign in with Microsoft" button not appearing**
- Verify `ClientId` and `ClientSecret` are configured
- Check application logs for configuration errors

**"Error from external provider" message**
- Verify redirect URI matches exactly in Azure portal
- Check that API permissions are granted
- Ensure client secret hasn't expired

**User creation fails**
- Azure AD must return an email claim
- Check API permissions include `email` scope

### Logging

Enable detailed logging in development:

```json
{
  "Logging": {
    "LogLevel": {
      "Microsoft.AspNetCore.Authentication": "Debug"
    }
  }
}
```

## Testing

### Local Development

1. Configure Azure AD app with localhost redirect URI
2. Set configuration in `appsettings.Development.json`
3. Run the application: `dotnet run`
4. Navigate to `/Account/Login`
5. Click "Sign in with Microsoft"
6. Authenticate with a test account

### Integration Tests

For automated testing, consider:
- Using a test Azure AD tenant
- Mocking the external authentication flow
- Testing account linking scenarios

## Related Documentation

- [Microsoft Identity Platform Documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/)
- [ASP.NET Core External Authentication](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/social/)
- [Andy.Auth Architecture](./ARCHITECTURE.md)
- [Andy.Auth Security](./SECURITY.md)
