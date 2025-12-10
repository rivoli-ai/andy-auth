# MCP Authorization Flow Testing

This directory contains a comprehensive test script that validates andy-auth's support for the Model Context Protocol (MCP) OAuth 2.1 authorization flow.

## Overview

The Model Context Protocol requires OAuth 2.1 with specific security features for authorization. This test script validates that andy-auth implements all required features according to:

- [MCP Authorization Specification (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
- [MCP Authorization Tutorial](https://modelcontextprotocol.io/docs/tutorials/security/authorization)

## What Gets Tested

The script validates the complete OAuth 2.1 flow with all MCP requirements:

### 1. **Authorization Server Discovery (RFC 8414)**
   - ✅ Fetches `/.well-known/openid-configuration`
   - ✅ Validates all required OAuth endpoints are present
   - ✅ Confirms Dynamic Client Registration endpoint availability

### 2. **Dynamic Client Registration (RFC 7591)**
   - ✅ Registers a new OAuth client without pre-registration
   - ✅ Obtains client credentials dynamically
   - ✅ Receives registration access token for client management

### 3. **Authorization Code Flow with PKCE (OAuth 2.1)**
   - ✅ Generates PKCE code verifier and challenge (S256 method)
   - ✅ Initiates authorization flow with PKCE parameters
   - ✅ Exchanges authorization code for tokens with PKCE verifier

### 4. **Resource Parameter Support (RFC 8707)**
   - ✅ Includes `resource` parameter in authorization request
   - ✅ Includes `resource` parameter in token request
   - ✅ Validates token audience binding to specific MCP server

### 5. **Token Operations**
   - ✅ Token introspection to validate token metadata
   - ✅ Audience binding verification (confused deputy prevention)
   - ✅ Refresh token flow for long-lived sessions
   - ✅ Token revocation and immediate invalidation

### 6. **MCP Server Request (Simulated)**
   - ✅ Demonstrates Bearer token usage in Authorization header
   - ✅ Shows how MCP clients would make authenticated requests

### 7. **Cleanup**
   - ✅ Deletes dynamically registered client
   - ✅ Cleans up test artifacts

## Prerequisites

### Required Tools
- `curl` - HTTP client
- `jq` - JSON processor
- `base64` - Base64 encoding
- `openssl` - Cryptographic operations (for PKCE)

Install on macOS:
```bash
brew install curl jq openssl
```

Install on Ubuntu/Debian:
```bash
apt-get install curl jq openssl
```

### Running Environments

#### Local Testing
- Andy-auth running on `https://localhost:7088`
- MCP server running on `https://localhost:7001` (optional)

#### UAT Testing (Railway)
- Andy-auth deployed at `https://andy-auth-uat-api-production.up.railway.app`
- Lexipro MCP server at `https://lexipro-uat.up.railway.app`

## Usage

### Local Testing
```bash
./test-mcp-auth-flow.sh local
```

### UAT Testing (Railway)
```bash
./test-mcp-auth-flow.sh uat
```

## Interactive Steps

The script is semi-automated. It will:

1. **Automatically execute** most steps (discovery, registration, token operations)
2. **Pause for manual authorization** when you need to log in with a browser
3. **Display an authorization URL** for you to open
4. **Prompt you** to enter the authorization code from the redirect

### Example Flow

```
==================================================
STEP 3: Authorization Code Flow with PKCE
==================================================
[INFO] Authorization URL:
https://localhost:7088/connect/authorize?response_type=code&client_id=...

[WARNING] MANUAL STEP REQUIRED:
1. Open the authorization URL in your browser
2. Log in with your credentials
3. Grant consent if prompted
4. Copy the authorization code from the redirect URL

The redirect URL will look like:
  http://localhost:3000/callback?code=AUTHORIZATION_CODE&state=...

Enter the authorization code: [PASTE CODE HERE]
```

## Test Output

### Console Output
The script provides colored, step-by-step output showing:
- 🔵 **[INFO]** - Informational messages
- 🟢 **[✓]** - Success messages
- 🟡 **[WARNING]** - Warnings (non-fatal)
- 🔴 **[✗]** - Errors (fatal)

### JSON Report
After completion, the script generates a JSON test report:

```
mcp-auth-test-report-{env}-{timestamp}.json
```

Example report:
```json
{
  "test_timestamp": "2025-12-08T10:30:00Z",
  "environment": "local",
  "authorization_server": "https://localhost:7088",
  "mcp_server": "https://localhost:7001",
  "resource": "https://localhost:7001/mcp",
  "tests": {
    "discovery": "PASS",
    "dynamic_client_registration": "PASS",
    "pkce_support": "PASS",
    "resource_parameter": "PASS",
    "token_exchange": "PASS",
    "token_introspection": "PASS",
    "audience_binding": "PASS",
    "refresh_token": "PASS",
    "token_revocation": "PASS",
    "client_cleanup": "PASS"
  },
  "endpoints": {
    "authorization": "https://localhost:7088/connect/authorize",
    "token": "https://localhost:7088/connect/token",
    "registration": "https://localhost:7088/connect/register",
    "introspection": "https://localhost:7088/connect/introspect",
    "revocation": "https://localhost:7088/connect/revoke"
  }
}
```

## MCP Compliance Checklist

Based on the MCP specification, andy-auth implements:

### Core Requirements
- [x] **OAuth 2.1** authorization framework
- [x] **RFC 8414** - Authorization Server Metadata
- [x] **RFC 7591** - Dynamic Client Registration Protocol
- [x] **RFC 8707** - Resource Parameter (audience binding)
- [x] **PKCE** (Proof Key for Code Exchange) - OAuth 2.1 requirement

### Security Features
- [x] **Audience Binding** - Tokens issued for specific MCP servers
- [x] **Reference Tokens** - Opaque tokens with immediate revocation
- [x] **Token Introspection** - Server-side token validation
- [x] **HTTPS Enforcement** - Production environments only
- [x] **Localhost Development** - HTTP allowed for local testing

### Token Validation
- [x] Tokens validated against intended audience (RFC 8707)
- [x] No token passthrough (prevents confused deputy)
- [x] Session security with non-deterministic IDs
- [x] Proper token expiration and cleanup

### Client Registration
- [x] Public clients (PKCE required, no client secret)
- [x] Confidential clients (client secret for server-to-server)
- [x] Dynamic registration without initial access token (configurable)
- [x] Registration access tokens for client management

## Troubleshooting

### Issue: "Failed to fetch discovery document"
**Solution**: Ensure andy-auth is running on the expected URL
```bash
# For local
curl -k https://localhost:7088/.well-known/openid-configuration

# For UAT
curl https://andy-auth-uat-api-production.up.railway.app/.well-known/openid-configuration
```

### Issue: "Client registration failed"
**Solution**: Check DCR settings in `appsettings.json`:
```json
{
  "DynamicClientRegistration": {
    "Enabled": true,
    "RequireInitialAccessToken": false,
    "RequireAdminApproval": false
  }
}
```

### Issue: "Token exchange failed - PKCE validation error"
**Cause**: PKCE verifier doesn't match the challenge
**Solution**: Ensure you're using the same code verifier that generated the challenge

### Issue: "Token audience not bound to resource"
**Cause**: Resource parameter not registered in andy-auth
**Solution**: Add your MCP server to `Program.cs`:
```csharp
options.RegisterResources(
    "https://your-mcp-server.com/mcp"
);
```

### Issue: "MCP server returned 401"
**Expected**: This is normal if the MCP server is not configured to accept tokens yet
**Solution**: Configure your MCP server to:
1. Validate tokens via introspection endpoint
2. Check audience matches its own URL
3. Accept Bearer tokens in Authorization header

## Security Considerations

### Local Development
- Uses self-signed certificates (`-k` flag for curl)
- Allows HTTP for localhost redirect URIs
- Ephemeral signing keys (tokens invalid after restart)

### UAT/Production
- Requires HTTPS for all endpoints
- Uses proper TLS certificates
- Reference tokens stored in database
- Immediate token revocation capability

### PKCE Implementation
- Code verifier: 43-character random string (Base64URL)
- Code challenge: SHA-256 hash of verifier (Base64URL)
- Challenge method: S256 (plain not allowed)

## MCP Server Integration

To integrate an MCP server with andy-auth:

### 1. Protected Resource Metadata
Create `/.well-known/oauth-protected-resource` endpoint:
```json
{
  "resource": "https://your-mcp-server.com/mcp",
  "authorization_servers": [
    "https://andy-auth-uat-api-production.up.railway.app"
  ],
  "scopes_supported": ["openid", "profile", "email"]
}
```

### 2. WWW-Authenticate Header
Return 401 with proper header for unauthorized requests:
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="mcp",
  resource_metadata="https://your-mcp-server.com/.well-known/oauth-protected-resource"
```

### 3. Token Validation
Validate tokens using introspection endpoint:
```bash
curl -X POST https://andy-auth-uat-api-production.up.railway.app/connect/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=ACCESS_TOKEN&client_id=YOUR_CLIENT_ID"
```

### 4. Audience Verification
Ensure token audience (`aud` claim) matches your server's resource URI:
```javascript
if (token.aud !== "https://your-mcp-server.com/mcp") {
  return 403; // Forbidden - token not for this server
}
```

## References

- [MCP Specification - Authorization](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
- [MCP Authorization Tutorial](https://modelcontextprotocol.io/docs/tutorials/security/authorization)
- [RFC 6749 - OAuth 2.0](https://tools.ietf.org/html/rfc6749)
- [OAuth 2.1 Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13)
- [RFC 7591 - Dynamic Client Registration](https://tools.ietf.org/html/rfc7591)
- [RFC 8414 - Authorization Server Metadata](https://tools.ietf.org/html/rfc8414)
- [RFC 8707 - Resource Indicators](https://tools.ietf.org/html/rfc8707)
- [RFC 7009 - Token Revocation](https://tools.ietf.org/html/rfc7009)
- [RFC 7662 - Token Introspection](https://tools.ietf.org/html/rfc7662)

## License

This test script is part of the andy-auth project and follows the same license.
