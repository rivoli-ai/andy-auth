# TypeScript / Express Example

This example demonstrates how to integrate Andy Auth with a Node.js Express application using TypeScript and OAuth 2.0 with PKCE.

## Prerequisites

- Node.js 18+
- Andy Auth server running (default: https://localhost:7088)

## Setup

1. Install dependencies:

```bash
cd examples/typescript-express
npm install
```

2. Register your client in Andy Auth or use Dynamic Client Registration

3. Set environment variables (optional):

```bash
export ANDY_AUTH_SERVER=https://localhost:7088
export CLIENT_ID=my-ts-app
export REDIRECT_URI=http://localhost:3000/callback
```

## Running

Development mode:
```bash
npm run dev
```

Production:
```bash
npm run build
npm start
```

The application will start at http://localhost:3000

## Features Demonstrated

- Type-safe OAuth 2.0 implementation
- PKCE code challenge generation
- Session type extensions
- OpenID Connect discovery

## Documentation

See the full tutorial at: `/docs/tutorials/typescript.html`
