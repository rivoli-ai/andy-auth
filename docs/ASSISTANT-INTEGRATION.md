# AI Assistant Integration Guide

This guide documents how to configure various AI assistants to work with Andy.Auth.Server for MCP (Model Context Protocol) authentication.

## Overview: MCP OAuth 2.1 Auto-Discovery

Andy.Auth.Server implements the MCP OAuth 2.1 specification which uses **automatic OAuth discovery**. MCP clients discover the authorization server through:

1. **Protected Resource Metadata** (RFC 9728): The MCP server advertises its auth requirements at `/.well-known/oauth-protected-resource`
2. **OAuth Authorization Server Metadata** (RFC 8414): The auth server publishes its configuration at `/.well-known/oauth-authorization-server`

This means most MCP clients **do not need manual OAuth configuration** - they discover everything automatically from the MCP server URL.

## Supported Assistants

Andy.Auth.Server provides OAuth 2.0 authentication for the following AI assistants:

| Assistant | Client Type | OAuth Support | Status |
|-----------|-------------|---------------|--------|
| Claude Desktop | Auto-registered (DCR) | Full OAuth 2.1 | Fully Supported |
| ChatGPT | Auto-registered (DCR) | Full OAuth 2.1 | Fully Supported |
| VS Code Copilot | Auto-registered (DCR) | Full OAuth 2.1 | Fully Supported |
| Cline (VS Code) | Auto-registered (DCR) | OAuth Discovery Only | Limited (URI handler issue) |
| Roo (VS Code) | Auto-registered (DCR) | OAuth Discovery Only | Limited (URI handler issue) |
| Continue.dev | Auto-registered (DCR) | OAuth Discovery Only | Limited (URI handler issue) |

**Note**: Cline, Roo, and Continue.dev can initiate OAuth flows but have issues with VS Code's custom URI handler (`vscode://`) stripping query parameters from callbacks. This is a known VS Code extension limitation, not an Andy.Auth issue.

## Dynamic Client Registration (DCR)

Andy.Auth.Server supports Dynamic Client Registration (RFC 7591/7592), which allows MCP clients to automatically register themselves. When a client connects:

1. Client discovers the DCR endpoint from OAuth metadata
2. Client registers itself with required redirect URIs
3. Server issues a `client_id` and `registration_access_token`
4. Client uses these for subsequent OAuth flows

### DCR Default Scopes

When clients register without specifying scopes, they receive all allowed scopes by default:
- `openid`
- `profile`
- `email`
- `offline_access`
- `roles`

## OAuth Configuration

### Common Settings

All assistant clients are configured as **public clients** (no client secret required) with:

- **Grant Types**: Authorization Code + Refresh Token
- **PKCE**: Required (S256)
- **Scopes**: Auto-discovered, typically `openid`, `email`, `profile`, `offline_access`
- **Consent**: Explicit (user consent screen shown)

### Authentication Endpoints

| Endpoint | URL |
|----------|-----|
| Authorization | `https://andy-auth-uat-api-production.up.railway.app/connect/authorize` |
| Token | `https://andy-auth-uat-api-production.up.railway.app/connect/token` |
| UserInfo | `https://andy-auth-uat-api-production.up.railway.app/connect/userinfo` |
| OpenID Discovery | `https://andy-auth-uat-api-production.up.railway.app/.well-known/openid-configuration` |
| OAuth AS Metadata | `https://andy-auth-uat-api-production.up.railway.app/.well-known/oauth-authorization-server` |
| DCR Endpoint | `https://andy-auth-uat-api-production.up.railway.app/connect/register` |

## Claude Desktop

Claude Desktop fully supports MCP OAuth 2.1 with auto-discovery.

### Configuration

Add the following to your Claude Desktop MCP configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "andy-docs": {
      "url": "https://andy-docs-uat.up.railway.app/mcp"
    }
  }
}
```

**That's it!** Claude Desktop auto-discovers OAuth settings from the MCP server's protected resource metadata. No manual OAuth configuration needed.

### Pre-registered Client Redirect URIs

If using the pre-seeded `claude-desktop` client:
- `https://claude.ai/api/mcp/auth_callback`
- `https://claude.com/api/mcp/auth_callback`
- `http://127.0.0.1/callback` (local development)
- `http://localhost/callback` (local development)

## ChatGPT

ChatGPT fully supports MCP OAuth 2.1 with auto-discovery.

### Configuration

In ChatGPT settings, add the MCP server URL:
```
https://andy-docs-uat.up.railway.app/mcp
```

ChatGPT handles OAuth discovery and authentication automatically.

### Pre-registered Client Redirect URIs

- `https://chat.openai.com/api/mcp/auth_callback`
- `https://chatgpt.com/api/mcp/auth_callback`

## VS Code Copilot

VS Code Copilot supports MCP OAuth 2.1 with auto-discovery.

### Configuration

In VS Code settings.json:

```json
{
  "github.copilot.chat.mcp.servers": {
    "andy-docs": {
      "url": "https://andy-docs-uat.up.railway.app/mcp"
    }
  }
}
```

Or via VS Code UI: Settings > Extensions > Copilot > MCP Servers

## Cline (VS Code Extension)

**Note**: Cline can initiate OAuth but has a known issue where VS Code's `vscode://` URI handler strips query parameters from callbacks, breaking the OAuth code exchange. See [Cline GitHub Issue #4523](https://github.com/cline/cline/issues/4523).

### Configuration (for reference)

In VS Code settings.json:

```json
{
  "cline.mcpServers": {
    "andy-docs": {
      "url": "https://andy-docs-uat.up.railway.app/mcp"
    }
  }
}
```

### Registered Redirect URIs

- `http://127.0.0.1/callback`
- `http://127.0.0.1:3000/callback`
- `http://127.0.0.1:8080/callback`
- `http://localhost/callback`
- `http://localhost:3000/callback`
- `http://localhost:8080/callback`
- `vscode://saoudrizwan.claude-dev/callback`
- `vscode://saoudrizwan.claude-dev/mcp-auth/callback/*`

## Roo (VS Code Extension)

**Note**: Same VS Code URI handler limitation as Cline. See [Roo GitHub Issues #7296, #8119](https://github.com/RooVetGit/Roo-Cline/issues/7296).

### Configuration

```json
{
  "roo-cline.mcpServers": {
    "andy-docs": {
      "url": "https://andy-docs-uat.up.railway.app/mcp"
    }
  }
}
```

### Registered Redirect URIs

- Same localhost patterns as Cline
- `vscode://roo-cline.roo-cline/callback`
- `vscode://roo-cline.roo-cline/mcp-auth/callback/*`

## Continue.dev

**Note**: Similar VS Code URI handler limitations apply.

### Configuration

In `.continue/config.json`:

```json
{
  "experimental": {
    "modelContextProtocolServers": [
      {
        "transport": {
          "type": "sse",
          "url": "https://andy-docs-uat.up.railway.app/mcp"
        }
      }
    ]
  }
}
```

### Registered Redirect URIs

- Localhost callbacks (various ports)
- `vscode://continue.continue/callback`
- `vscode://continue.continue/mcp-auth/callback/*`

## Testing Authentication

### 1. Test OpenID Discovery

```bash
curl https://andy-auth-uat-api-production.up.railway.app/.well-known/openid-configuration
```

### 2. Test Authorization Flow

Build an authorization URL:

```
https://andy-auth-uat-api-production.up.railway.app/connect/authorize?
  client_id=YOUR_CLIENT_ID&
  response_type=code&
  redirect_uri=YOUR_REDIRECT_URI&
  scope=openid%20email%20profile%20urn:andy-docs-api&
  code_challenge=YOUR_PKCE_CHALLENGE&
  code_challenge_method=S256&
  state=YOUR_STATE
```

### 3. Exchange Code for Token

```bash
curl -X POST https://andy-auth-uat-api-production.up.railway.app/connect/token \
  -d "grant_type=authorization_code" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "code=AUTHORIZATION_CODE" \
  -d "redirect_uri=YOUR_REDIRECT_URI" \
  -d "code_verifier=YOUR_PKCE_VERIFIER"
```

## Troubleshooting

### "Client application is not allowed to use the specified scope" (ID2051)

This error occurs when a client requests scopes it doesn't have permission for. For DCR-registered clients:

1. **Check DCR Settings**: Verify `AllowedScopes` in `appsettings.{Environment}.json` includes the requested scopes:
   ```json
   "DynamicClientRegistration": {
     "AllowedScopes": ["openid", "profile", "email", "offline_access", "roles"]
   }
   ```

2. **Re-register the client**: Delete the existing DCR client (via Admin UI or DCR DELETE endpoint) and let the MCP client re-register. New clients get all allowed scopes by default.

3. **Edit client permissions**: Use the Admin UI to manually add missing scope permissions to the client.

### "Invalid redirect_uri" Error

Ensure your redirect URI exactly matches one of the registered URIs for your client. Common issues:
- Trailing slashes mismatch
- HTTP vs HTTPS mismatch
- Port number differences
- For custom URI schemes (vscode://, cursor://), ensure the full path matches

### "Invalid client_id" Error

For DCR clients:
- The client may have been deleted or expired
- Let the MCP client re-register automatically

For pre-seeded clients:
- Verify the database has been seeded with the client configuration
- Check the client ID matches exactly (case-sensitive)

### VS Code Extension OAuth Not Working

**Symptom**: OAuth flow completes (user authenticates) but extension shows "still unauthenticated" or similar.

**Cause**: VS Code's custom URI handler (`vscode://`) has a known issue where query parameters are stripped from callback URLs. This affects Cline, Roo, and Continue.dev.

**Workarounds**:
1. Use Claude Desktop or ChatGPT instead (these work correctly)
2. Use VS Code Copilot's MCP integration (works correctly)
3. Wait for VS Code/extension updates to fix the URI handler

**Technical Details**: When OAuth redirects to `vscode://extension/callback?code=XXX&state=YYY`, VS Code only passes the path to the extension, discarding the query parameters. See:
- [Cline #4523](https://github.com/cline/cline/issues/4523)
- [Roo #7296](https://github.com/RooVetGit/Roo-Cline/issues/7296)

### Authorization Loops

If authentication keeps looping:
1. Clear browser cookies for the auth domain
2. Check token storage in the assistant
3. Verify refresh token handling
4. For DCR clients, try deleting and re-registering

### CORS Issues

The server allows CORS from:
- Localhost origins
- `*.claude.ai`
- `*.openai.com`
- `*.chatgpt.com`

If you encounter CORS errors, check the server logs and ensure your origin is allowed.

## Adding New Assistants

To add support for a new AI assistant:

1. **Identify Requirements**:
   - Redirect URI patterns used by the assistant
   - Any specific OAuth requirements (PKCE, etc.)
   - MCP transport type (SSE, HTTP, etc.)

2. **Update DbSeeder.cs**:
   Add a new client descriptor with appropriate:
   - Client ID
   - Redirect URIs
   - Permissions
   - Resource access

3. **Deploy and Test**:
   - Deploy the updated code
   - Restart to trigger database seeding
   - Test the authentication flow

4. **Document**:
   - Update this guide with configuration examples
   - Note any assistant-specific quirks

## Security Considerations

- All clients use PKCE for enhanced security
- Tokens are short-lived (1 hour) with refresh tokens
- Refresh tokens are rotated on use
- Token revocation is supported
- All traffic must use HTTPS in production

## Related Documentation

- [Andy.Auth Architecture](./ARCHITECTURE.md)
- [Azure AD Integration](./AZURE-AD.md)
- [Security Guide](./SECURITY.md)
