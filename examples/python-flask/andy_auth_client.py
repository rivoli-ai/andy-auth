"""
Andy Auth OAuth 2.0 Client with PKCE support.

This module provides a reusable client for authenticating with Andy Auth.
"""
import secrets
import hashlib
import base64
from urllib.parse import urlencode
import requests


class AndyAuthClient:
    """OAuth 2.0 client for Andy Auth with PKCE support."""

    def __init__(self, client_id: str, redirect_uri: str, auth_server: str):
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.auth_server = auth_server.rstrip('/')

        # Discover endpoints
        self._discover_endpoints()

    def _discover_endpoints(self):
        """Fetch OpenID Connect discovery document."""
        response = requests.get(
            f"{self.auth_server}/.well-known/openid-configuration",
            verify=False  # Set to True in production
        )
        response.raise_for_status()
        config = response.json()

        self.authorization_endpoint = config['authorization_endpoint']
        self.token_endpoint = config['token_endpoint']
        self.userinfo_endpoint = config['userinfo_endpoint']
        self.introspection_endpoint = config.get('introspection_endpoint')
        self.end_session_endpoint = config.get('end_session_endpoint')

    def generate_pkce(self) -> tuple[str, str]:
        """Generate PKCE code verifier and challenge."""
        # Generate random code verifier (43-128 characters)
        code_verifier = secrets.token_urlsafe(64)

        # Create code challenge using S256
        digest = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(digest).decode().rstrip('=')

        return code_verifier, code_challenge

    def get_authorization_url(
        self,
        scope: str = "openid profile email",
        state: str = None
    ) -> tuple[str, str, str]:
        """
        Generate authorization URL with PKCE.

        Returns:
            tuple: (authorization_url, state, code_verifier)
        """
        code_verifier, code_challenge = self.generate_pkce()
        state = state or secrets.token_urlsafe(32)

        params = {
            'client_id': self.client_id,
            'response_type': 'code',
            'redirect_uri': self.redirect_uri,
            'scope': scope,
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }

        url = f"{self.authorization_endpoint}?{urlencode(params)}"
        return url, state, code_verifier

    def exchange_code(self, code: str, code_verifier: str) -> dict:
        """Exchange authorization code for tokens."""
        response = requests.post(
            self.token_endpoint,
            data={
                'grant_type': 'authorization_code',
                'client_id': self.client_id,
                'code': code,
                'redirect_uri': self.redirect_uri,
                'code_verifier': code_verifier
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            verify=False  # Set to True in production
        )
        response.raise_for_status()
        return response.json()

    def refresh_token(self, refresh_token: str) -> dict:
        """Use refresh token to get new access token."""
        response = requests.post(
            self.token_endpoint,
            data={
                'grant_type': 'refresh_token',
                'client_id': self.client_id,
                'refresh_token': refresh_token
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            verify=False  # Set to True in production
        )
        response.raise_for_status()
        return response.json()

    def get_userinfo(self, access_token: str) -> dict:
        """Get user information using access token."""
        response = requests.get(
            self.userinfo_endpoint,
            headers={'Authorization': f'Bearer {access_token}'},
            verify=False  # Set to True in production
        )
        response.raise_for_status()
        return response.json()


# Usage example
if __name__ == "__main__":
    client = AndyAuthClient(
        client_id="my-python-app",
        redirect_uri="http://localhost:5000/callback",
        auth_server="https://localhost:7088"
    )

    # Step 1: Get authorization URL
    auth_url, state, code_verifier = client.get_authorization_url()
    print(f"Visit: {auth_url}")
    print(f"State: {state}")
    print(f"Code Verifier (save this): {code_verifier}")

    # Step 2: After redirect, exchange code
    # authorization_code = input("Enter authorization code: ")
    # tokens = client.exchange_code(authorization_code, code_verifier)
    # print(f"Access Token: {tokens['access_token']}")
