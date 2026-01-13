# Java / Spring Boot Example

This example demonstrates how to integrate Andy Auth with a Spring Boot application using Spring Security OAuth 2.0.

## Prerequisites

- Java 17+
- Maven 3.8+
- Andy Auth server running (default: https://localhost:7088)

## Setup

1. Register your client in Andy Auth or use Dynamic Client Registration

2. Set environment variables (optional):

```bash
export ANDY_AUTH_SERVER=https://localhost:7088
export CLIENT_ID=my-java-app
export CLIENT_SECRET=your-client-secret
```

## Running

```bash
cd examples/java-spring
mvn spring-boot:run
```

The application will start at http://localhost:8080

## Features Demonstrated

- Spring Security OAuth 2.0 Client
- OpenID Connect auto-discovery
- OIDC logout handler
- Thymeleaf templates with security context
- Token and claims access

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `/` | Home page with login status |
| `/oauth2/authorization/andy-auth` | Initiates OAuth login |
| `/logout` | Logs out the user |
| `/profile` | Returns user claims as JSON |
| `/tokens` | Returns current token info |

## Documentation

See the full tutorial at: `/docs/tutorials/java.html`
