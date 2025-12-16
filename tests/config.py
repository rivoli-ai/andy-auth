"""
Andy Auth Test Configuration

Configuration for testing Andy Auth server in different environments.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class ClientConfig:
    """OAuth client configuration"""
    client_id: str
    client_secret: Optional[str]
    is_confidential: bool
    redirect_uris: List[str]
    scopes: List[str]
    supports_client_credentials: bool = False
    supports_authorization_code: bool = True
    supports_refresh_token: bool = True


@dataclass
class EnvironmentConfig:
    """Environment-specific configuration"""
    name: str
    base_url: str
    verify_ssl: bool
    test_username: str
    test_password: str
    admin_username: str
    admin_password: str
    rate_limit_delay: float = 0.5  # Seconds between requests


# Pre-registered OAuth clients
CLIENTS: Dict[str, ClientConfig] = {
    "lexipro-api": ClientConfig(
        client_id="lexipro-api",
        client_secret="lexipro-secret-change-in-production",
        is_confidential=True,
        redirect_uris=[
            "https://localhost:7001/callback",
            "https://lexipro-api-uat.rivoli.ai/callback",
            "https://lexipro-api.rivoli.ai/callback"
        ],
        scopes=["openid", "profile", "email", "roles", "urn:lexipro-api"],
        supports_client_credentials=True,
        supports_authorization_code=True,
        supports_refresh_token=True
    ),
    "wagram-web": ClientConfig(
        client_id="wagram-web",
        client_secret=None,
        is_confidential=False,
        redirect_uris=[
            "https://localhost:4200/callback",
            "https://wagram-uat.vercel.app/callback",
            "https://wagram.ai/callback"
        ],
        scopes=["openid", "profile", "email", "roles", "urn:lexipro-api"],
        supports_client_credentials=False,
        supports_authorization_code=True,
        supports_refresh_token=True
    ),
    "claude-desktop": ClientConfig(
        client_id="claude-desktop",
        client_secret=None,
        is_confidential=False,
        redirect_uris=[
            "https://claude.ai/api/mcp/auth_callback",
            "http://127.0.0.1/callback",
            "http://localhost/callback"
        ],
        scopes=["openid", "profile", "email", "urn:lexipro-api"],
        supports_client_credentials=False,
        supports_authorization_code=True,
        supports_refresh_token=True
    ),
    "chatgpt": ClientConfig(
        client_id="chatgpt",
        client_secret=None,
        is_confidential=False,
        redirect_uris=[
            "https://chat.openai.com/api/mcp/auth_callback",
            "https://chatgpt.com/api/mcp/auth_callback",
            "http://127.0.0.1/callback"
        ],
        scopes=["openid", "profile", "email", "urn:lexipro-api"],
        supports_client_credentials=False,
        supports_authorization_code=True,
        supports_refresh_token=True
    ),
    "cline": ClientConfig(
        client_id="cline",
        client_secret=None,
        is_confidential=False,
        redirect_uris=[
            "http://127.0.0.1/callback",
            "http://localhost/callback",
            "vscode://saoudrizwan.claude-dev/callback"
        ],
        scopes=["openid", "profile", "email", "urn:lexipro-api"],
        supports_client_credentials=False,
        supports_authorization_code=True,
        supports_refresh_token=True
    ),
    "roo": ClientConfig(
        client_id="roo",
        client_secret=None,
        is_confidential=False,
        redirect_uris=[
            "http://127.0.0.1/callback",
            "http://localhost/callback",
            "vscode://roo-cline.roo-cline/callback"
        ],
        scopes=["openid", "profile", "email", "urn:lexipro-api"],
        supports_client_credentials=False,
        supports_authorization_code=True,
        supports_refresh_token=True
    ),
    "continue-dev": ClientConfig(
        client_id="continue-dev",
        client_secret=None,
        is_confidential=False,
        redirect_uris=[
            "http://127.0.0.1/callback",
            "http://localhost/callback",
            "vscode://continue.continue/callback"
        ],
        scopes=["openid", "profile", "email", "urn:lexipro-api"],
        supports_client_credentials=False,
        supports_authorization_code=True,
        supports_refresh_token=True
    ),
}

# Environment configurations
ENVIRONMENTS: Dict[str, EnvironmentConfig] = {
    "local": EnvironmentConfig(
        name="Local Development",
        base_url="https://localhost:7088",
        verify_ssl=False,
        test_username="test@andy.local",
        test_password="Test123!",
        admin_username="sam@rivoli.ai",
        admin_password="REDACTED_ADMIN_PASSWORD"
    ),
    "uat": EnvironmentConfig(
        name="UAT (Railway)",
        base_url="https://andy-auth-uat-api-production.up.railway.app",
        verify_ssl=True,
        test_username="test@andy.local",  # Test user created in UAT
        test_password="Test123!",
        admin_username="sam@rivoli.ai",
        admin_password="REDACTED_ADMIN_PASSWORD",
        rate_limit_delay=2.5  # Increased rate limits: 30 req/min for most endpoints
    ),
}

# MCP Resource servers for token audience testing
MCP_RESOURCES = [
    "https://lexipro-uat.up.railway.app/mcp",
    "https://lexipro-api.rivoli.ai/mcp",
    "https://localhost:7001/mcp",
    "https://localhost:5154/mcp",
]

# Expected OAuth discovery endpoints
EXPECTED_DISCOVERY_ENDPOINTS = [
    "authorization_endpoint",
    "token_endpoint",
    "issuer",
    "jwks_uri",
]

# Expected grant types
EXPECTED_GRANT_TYPES = [
    "authorization_code",
    "refresh_token",
    "client_credentials",
]

# Expected scopes
EXPECTED_SCOPES = [
    "openid",
    "profile",
    "email",
    "roles",
    "offline_access",
]


def get_environment(env_name: str) -> EnvironmentConfig:
    """Get environment configuration by name"""
    if env_name not in ENVIRONMENTS:
        raise ValueError(f"Unknown environment: {env_name}. Available: {list(ENVIRONMENTS.keys())}")
    return ENVIRONMENTS[env_name]


def get_client(client_id: str) -> ClientConfig:
    """Get client configuration by ID"""
    if client_id not in CLIENTS:
        raise ValueError(f"Unknown client: {client_id}. Available: {list(CLIENTS.keys())}")
    return CLIENTS[client_id]


def get_redirect_uri_for_env(client: ClientConfig, env: EnvironmentConfig) -> str:
    """Get appropriate redirect URI for client and environment"""
    if env.name == "Local Development":
        # Prefer localhost URIs for local testing
        for uri in client.redirect_uris:
            if "localhost" in uri or "127.0.0.1" in uri:
                return uri
    else:
        # For UAT: prefer vercel/production URIs, or fallback to localhost
        preferred_domains = ["vercel.app", "wagram.ai", "rivoli.ai"]
        for domain in preferred_domains:
            for uri in client.redirect_uris:
                if domain in uri:
                    return uri
        # Fallback to localhost URIs which should be registered
        for uri in client.redirect_uris:
            if "localhost" in uri or "127.0.0.1" in uri:
                return uri
    # Final fallback to first URI
    return client.redirect_uris[0]
