# AI Assistant Integration Guide

This guide documents how to configure various AI assistants to work with Andy.Auth.Server for MCP (Model Context Protocol) authentication.

## Supported Assistants

Andy.Auth.Server provides OAuth 2.0 authentication for the following AI assistants:

| Assistant | Client ID | Type | Status |
|-----------|-----------|------|--------|
| Claude Desktop | `claude-desktop` | Public | Supported |
| ChatGPT | `chatgpt` | Public | Supported |
| Cline (VS Code) | `cline` | Public | Supported |
| Roo (VS Code) | `roo` | Public | Supported |
| Continue.dev | `continue-dev` | Public | Supported |

## OAuth Configuration

### Common Settings

All assistant clients are configured as **public clients** (no client secret required) with:

- **Grant Types**: Authorization Code + Refresh Token
- **PKCE**: Required (S256 recommended)
- **Scopes**: `openid`, `email`, `profile`, `urn:lexipro-api`
- **Consent**: Implicit (no user consent screen)

### Authentication Endpoints

| Endpoint | URL |
|----------|-----|
| Authorization | `https://andy-auth-uat-api-production.up.railway.app/connect/authorize` |
| Token | `https://andy-auth-uat-api-production.up.railway.app/connect/token` |
| UserInfo | `https://andy-auth-uat-api-production.up.railway.app/connect/userinfo` |
| Discovery | `https://andy-auth-uat-api-production.up.railway.app/.well-known/openid-configuration` |

## Claude Desktop

### Configuration

Add the following to your Claude Desktop MCP configuration (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "lexipro": {
      "url": "https://lexipro-uat.up.railway.app/mcp",
      "transport": "sse",
      "auth": {
        "type": "oauth",
        "client_id": "claude-desktop",
        "authorization_url": "https://andy-auth-uat-api-production.up.railway.app/connect/authorize",
        "token_url": "https://andy-auth-uat-api-production.up.railway.app/connect/token",
        "scopes": ["openid", "email", "profile", "urn:lexipro-api"]
      }
    }
  }
}
```

### Redirect URIs

- `https://claude.ai/api/mcp/auth_callback`
- `https://claude.com/api/mcp/auth_callback`
- `http://127.0.0.1/callback` (local development)
- `http://localhost/callback` (local development)

## ChatGPT

### Configuration

ChatGPT MCP integration uses the following OAuth settings:

- **Client ID**: `chatgpt`
- **Authorization URL**: `https://andy-auth-uat-api-production.up.railway.app/connect/authorize`
- **Token URL**: `https://andy-auth-uat-api-production.up.railway.app/connect/token`
- **Scopes**: `openid email profile urn:lexipro-api`

### Redirect URIs

- `https://chat.openai.com/api/mcp/auth_callback`
- `https://chatgpt.com/api/mcp/auth_callback`

## Cline (VS Code Extension)

### Configuration

Cline (formerly Claude Dev) can be configured to use MCP servers with OAuth authentication.

In your VS Code settings or Cline configuration:

```json
{
  "mcpServers": {
    "lexipro": {
      "url": "https://lexipro-uat.up.railway.app/mcp",
      "auth": {
        "type": "oauth",
        "client_id": "cline",
        "authorization_url": "https://andy-auth-uat-api-production.up.railway.app/connect/authorize",
        "token_url": "https://andy-auth-uat-api-production.up.railway.app/connect/token",
        "scopes": ["openid", "email", "profile", "urn:lexipro-api"]
      }
    }
  }
}
```

### Redirect URIs

- `http://127.0.0.1/callback`
- `http://127.0.0.1:3000/callback`
- `http://127.0.0.1:8080/callback`
- `http://localhost/callback`
- `http://localhost:3000/callback`
- `http://localhost:8080/callback`
- `vscode://saoudrizwan.claude-dev/callback`

## Roo (VS Code Extension)

### Configuration

Similar to Cline, Roo can be configured for MCP OAuth:

- **Client ID**: `roo`
- **Redirect URIs**: Same localhost patterns as Cline
- **VS Code Protocol**: `vscode://roo-cline.roo-cline/callback`

## Continue.dev

### Configuration

Continue.dev supports MCP servers with OAuth authentication:

- **Client ID**: `continue-dev`
- **Configuration File**: `.continue/config.json` or VS Code settings

```json
{
  "mcpServers": [
    {
      "name": "lexipro",
      "url": "https://lexipro-uat.up.railway.app/mcp",
      "auth": {
        "type": "oauth",
        "client_id": "continue-dev",
        "authorization_url": "https://andy-auth-uat-api-production.up.railway.app/connect/authorize",
        "token_url": "https://andy-auth-uat-api-production.up.railway.app/connect/token",
        "scopes": ["openid", "email", "profile", "urn:lexipro-api"]
      }
    }
  ]
}
```

### Redirect URIs

- Localhost callbacks (various ports)
- `vscode://continue.continue/callback`

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
  scope=openid%20email%20profile%20urn:lexipro-api&
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

### "Invalid redirect_uri" Error

Ensure your redirect URI exactly matches one of the registered URIs for your client. Common issues:
- Trailing slashes mismatch
- HTTP vs HTTPS mismatch
- Port number differences

### "Invalid client_id" Error

Verify you're using the correct client ID for your assistant. The database must be seeded with the client configuration.

### Authorization Loops

If authentication keeps looping:
1. Clear browser cookies for the auth domain
2. Check token storage in the assistant
3. Verify refresh token handling

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
