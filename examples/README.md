# Andy Auth Examples

This directory contains example applications demonstrating how to integrate Andy Auth with various programming languages and frameworks.

## Available Examples

| Example | Language/Framework | Description |
|---------|-------------------|-------------|
| [csharp-web](./csharp-web/) | C# / ASP.NET Core | .NET 8 web app with OpenID Connect |
| [python-flask](./python-flask/) | Python / Flask | Flask web app with OAuth 2.0 + PKCE |
| [javascript-express](./javascript-express/) | JavaScript / Express | Express.js web app with OAuth 2.0 + PKCE |
| [typescript-express](./typescript-express/) | TypeScript / Express | TypeScript Express web app with type safety |
| [java-spring](./java-spring/) | Java / Spring Boot | Spring Boot with Spring Security OAuth |
| [go-oauth](./go-oauth/) | Go | Standard library web server with oauth2 package |
| [rust-oauth](./rust-oauth/) | Rust / Axum | Axum web framework with oauth2 crate |

## Prerequisites

All examples require:

1. Andy Auth server running (default: https://localhost:7088)
2. A registered OAuth client (or use Dynamic Client Registration)

## Quick Start

### 1. Register a Client

Before running any example, register an OAuth client in Andy Auth:

**Option A: Using Dynamic Client Registration (DCR)**
```bash
curl -X POST https://localhost:7088/connect/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My Example App",
    "redirect_uris": ["http://localhost:8080/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "client_secret_basic"
  }'
```

**Option B: Using the Admin Dashboard**
1. Go to https://localhost:7088/admin/clients
2. Click "Add Client"
3. Configure redirect URIs and grant types

### 2. Configure the Example

Each example uses environment variables for configuration:

```bash
export ANDY_AUTH_SERVER=https://localhost:7088
export CLIENT_ID=your-client-id
export CLIENT_SECRET=your-client-secret
```

### 3. Run the Example

See the README in each example directory for specific instructions.

## Features Demonstrated

All examples demonstrate:

- **OAuth 2.0 Authorization Code Flow** - The standard flow for web applications
- **PKCE (Proof Key for Code Exchange)** - Enhanced security for public clients
- **OpenID Connect** - User authentication and identity claims
- **Session Management** - Secure token storage and session handling
- **UserInfo Endpoint** - Fetching user profile information

## Common Endpoints

Each example implements these endpoints:

| Endpoint | Description |
|----------|-------------|
| `/` | Home page showing login status |
| `/login` | Initiates the OAuth flow |
| `/callback` | Handles the OAuth callback |
| `/logout` | Logs out the user |
| `/profile` | Returns user claims as JSON |
| `/tokens` | Returns token information |

## Documentation

For more detailed tutorials and explanations, see the Andy Auth documentation:

- [Python Tutorial](/docs/tutorials/python.html)
- [C# / .NET Tutorial](/docs/tutorials/csharp.html)
- [JavaScript Tutorial](/docs/tutorials/javascript.html)
- [TypeScript Tutorial](/docs/tutorials/typescript.html)
- [Java Tutorial](/docs/tutorials/java.html)
- [Go Tutorial](/docs/tutorials/go.html)
- [Rust Tutorial](/docs/tutorials/rust.html)

## Security Notes

These examples are for demonstration purposes. For production use:

1. **Use HTTPS** - Always use TLS in production
2. **Secure Session Keys** - Use strong, randomly generated session secrets
3. **Validate Tokens** - Implement proper JWT validation
4. **Store Secrets Securely** - Never commit secrets to version control
5. **Set Secure Cookie Flags** - Enable `Secure` and `HttpOnly` flags

## Contributing

To add a new example:

1. Create a new directory with a descriptive name
2. Include a README.md with setup and running instructions
3. Implement the common endpoints listed above
4. Ensure PKCE support is included
5. Add the example to this README's table
