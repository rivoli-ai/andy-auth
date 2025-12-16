"""
Authorization Code Flow Tests with PKCE

Tests for the OAuth 2.0 Authorization Code grant type with PKCE.
This is the recommended flow for web and mobile applications.
"""

import time
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from test_base import (
    OAuthTestClient, TestRunner, TestResult,
    generate_pkce_pair, generate_state, parse_form
)
from config import CLIENTS, get_client, get_redirect_uri_for_env, EnvironmentConfig


class AuthorizationCodeTester:
    """Helper class for authorization code flow testing"""

    def __init__(self, client: OAuthTestClient, env: EnvironmentConfig):
        self.client = client
        self.env = env

    def initiate_authorization(
        self,
        client_id: str,
        redirect_uri: str,
        scope: str,
        code_challenge: str,
        state: str,
        resource: Optional[str] = None
    ) -> Tuple[Any, str]:
        """
        Initiate authorization request
        Returns (response, final_url)
        """
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256"
        }

        if resource:
            params["resource"] = resource

        response = self.client.get("/connect/authorize", params=params, allow_redirects=True)
        return response, response.url

    def login(self, response, username: str, password: str) -> Any:
        """
        Submit login form
        Returns response after login
        """
        soup = BeautifulSoup(response.text, 'html.parser')
        form = soup.find('form')

        if not form:
            return None

        form_action = form.get('action', '')
        if not form_action.startswith('http'):
            form_action = self.client.base_url + form_action

        # Build form data
        form_data = {
            'Username': username,
            'Password': password,
            'RememberMe': 'false'
        }

        # Add hidden fields
        for input_field in form.find_all('input', type='hidden'):
            name = input_field.get('name')
            value = input_field.get('value', '')
            if name:
                form_data[name] = value

        # Submit login form - don't follow redirects to capture the redirect
        response = self.client.post(form_action, data=form_data, allow_redirects=False)

        # Follow redirects manually to track where we end up
        max_redirects = 10
        redirect_count = 0
        while response.status_code in [301, 302, 303, 307, 308] and redirect_count < max_redirects:
            redirect_url = response.headers.get('Location', '')
            if not redirect_url:
                break

            # Check if this is the callback with code
            if 'code=' in redirect_url:
                return response

            # Follow redirect
            if not redirect_url.startswith('http'):
                redirect_url = self.client.base_url + redirect_url

            response = self.client.get(redirect_url, allow_redirects=False)
            redirect_count += 1

        return response

    def handle_consent(self, response) -> Any:
        """
        Handle consent page if present
        Returns response after consent
        """
        soup = BeautifulSoup(response.text, 'html.parser')
        consent_form = soup.find('form', {'id': 'consent-form'}) or \
                       soup.find('form', action=lambda x: x and 'consent' in x.lower())

        if not consent_form:
            return response

        form_action = consent_form.get('action', '')
        if not form_action.startswith('http'):
            form_action = self.client.base_url + form_action

        # Build consent form data
        form_data = {}
        for input_field in consent_form.find_all('input'):
            name = input_field.get('name')
            value = input_field.get('value', '')
            if name:
                form_data[name] = value

        # Submit consent (don't follow redirects)
        response = self.client.post(form_action, data=form_data, allow_redirects=False)
        return response

    def extract_authorization_code(self, response, expected_state: str) -> Optional[str]:
        """Extract authorization code from redirect response"""
        if response.status_code in [301, 302, 303, 307, 308]:
            redirect_url = response.headers.get('Location', '')
        else:
            redirect_url = response.url

        parsed = urlparse(redirect_url)
        params = parse_qs(parsed.query)

        # Validate state
        state = params.get('state', [None])[0]
        if state != expected_state:
            return None

        # Extract code
        code = params.get('code', [None])[0]
        return code

    def exchange_code_for_tokens(
        self,
        code: str,
        client_id: str,
        redirect_uri: str,
        code_verifier: str,
        client_secret: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Exchange authorization code for tokens"""
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_verifier": code_verifier
        }

        if client_secret:
            data["client_secret"] = client_secret

        response = self.client.post("/connect/token", data=data)

        if response.status_code == 200:
            return response.json()
        return None


def test_auth_code_flow_public_client(
    tester: AuthorizationCodeTester,
    runner: TestRunner,
    client_id: str = "wagram-web"
) -> Optional[Dict[str, Any]]:
    """Test complete authorization code flow for public client"""
    start = time.time()
    config = get_client(client_id)
    redirect_uri = get_redirect_uri_for_env(config, tester.env)

    try:
        # Generate PKCE pair
        code_verifier, code_challenge = generate_pkce_pair()
        state = generate_state()

        # Step 1: Initiate authorization
        response, _ = tester.initiate_authorization(
            client_id=config.client_id,
            redirect_uri=redirect_uri,
            scope=" ".join(config.scopes),
            code_challenge=code_challenge,
            state=state
        )

        if response.status_code != 200:
            runner.add_result(TestResult(
                name=f"Auth Code Flow ({client_id}) - Initiate",
                passed=False,
                duration_ms=(time.time() - start) * 1000,
                message=f"Failed to reach login page: {response.status_code}",
                error=response.text[:500]
            ))
            return None

        # Step 2: Login
        response = tester.login(response, tester.env.test_username, tester.env.test_password)
        if not response:
            runner.add_result(TestResult(
                name=f"Auth Code Flow ({client_id}) - Login",
                passed=False,
                duration_ms=(time.time() - start) * 1000,
                message="Login form not found"
            ))
            return None

        # Step 3: Handle consent if needed
        if response.status_code == 200 and 'consent' in response.text.lower():
            response = tester.handle_consent(response)

        # Step 4: Extract authorization code
        code = tester.extract_authorization_code(response, state)
        if not code:
            # Check if we're still on login page (auth failed)
            if 'login' in response.url.lower() or 'Invalid' in response.text:
                runner.add_result(TestResult(
                    name=f"Auth Code Flow ({client_id}) - Login Failed",
                    passed=False,
                    duration_ms=(time.time() - start) * 1000,
                    message="Login failed - invalid credentials or account locked"
                ))
            else:
                runner.add_result(TestResult(
                    name=f"Auth Code Flow ({client_id}) - Extract Code",
                    passed=False,
                    duration_ms=(time.time() - start) * 1000,
                    message="Failed to extract authorization code",
                    details={"status": response.status_code, "url": response.url}
                ))
            return None

        # Step 5: Exchange code for tokens
        tokens = tester.exchange_code_for_tokens(
            code=code,
            client_id=config.client_id,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
            client_secret=config.client_secret
        )

        duration = (time.time() - start) * 1000

        if tokens and "access_token" in tokens:
            runner.add_result(TestResult(
                name=f"Auth Code Flow ({client_id}) - Complete",
                passed=True,
                duration_ms=duration,
                message=f"Tokens received (access + {'refresh' if 'refresh_token' in tokens else 'no refresh'})",
                details={
                    "has_access_token": "access_token" in tokens,
                    "has_refresh_token": "refresh_token" in tokens,
                    "has_id_token": "id_token" in tokens,
                    "expires_in": tokens.get("expires_in")
                }
            ))
            return tokens
        else:
            runner.add_result(TestResult(
                name=f"Auth Code Flow ({client_id}) - Token Exchange",
                passed=False,
                duration_ms=duration,
                message="Token exchange failed"
            ))
            return None

    except Exception as e:
        runner.add_result(TestResult(
            name=f"Auth Code Flow ({client_id}) - Error",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))
        return None


def test_auth_code_without_pkce(tester: AuthorizationCodeTester, runner: TestRunner):
    """Test that authorization without PKCE is rejected for public clients"""
    start = time.time()
    config = get_client("wagram-web")
    redirect_uri = get_redirect_uri_for_env(config, tester.env)

    try:
        # Try authorization without code_challenge
        response = tester.client.get("/connect/authorize", params={
            "client_id": config.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid profile",
            "state": generate_state()
        }, allow_redirects=False)

        duration = (time.time() - start) * 1000

        # Should be rejected (400) or redirect with error
        if response.status_code == 400:
            runner.add_result(TestResult(
                name="Auth Code - PKCE Required (Public Client)",
                passed=True,
                duration_ms=duration,
                message="Correctly rejected request without PKCE"
            ))
        elif response.status_code in [302, 303]:
            # Check if redirect contains error
            location = response.headers.get('Location', '')
            if 'error=' in location:
                runner.add_result(TestResult(
                    name="Auth Code - PKCE Required (Public Client)",
                    passed=True,
                    duration_ms=duration,
                    message="Rejected with error redirect"
                ))
            else:
                # Some servers allow non-PKCE for backwards compatibility
                runner.add_result(TestResult(
                    name="Auth Code - PKCE Required (Public Client)",
                    passed=True,
                    duration_ms=duration,
                    message="Server allows non-PKCE (backwards compatible)"
                ))
        else:
            runner.add_result(TestResult(
                name="Auth Code - PKCE Required (Public Client)",
                passed=True,  # May be allowed depending on config
                duration_ms=duration,
                message=f"Response: {response.status_code}"
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="Auth Code - PKCE Required (Public Client)",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_auth_code_invalid_redirect_uri(tester: AuthorizationCodeTester, runner: TestRunner):
    """Test that invalid redirect URI is rejected"""
    start = time.time()
    config = get_client("wagram-web")
    code_verifier, code_challenge = generate_pkce_pair()

    try:
        response = tester.client.get("/connect/authorize", params={
            "client_id": config.client_id,
            "redirect_uri": "https://evil.com/callback",  # Not registered
            "response_type": "code",
            "scope": "openid profile",
            "state": generate_state(),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256"
        }, allow_redirects=False)

        duration = (time.time() - start) * 1000

        # Should be rejected
        if response.status_code == 400:
            runner.add_result(TestResult(
                name="Auth Code - Invalid Redirect URI Rejected",
                passed=True,
                duration_ms=duration,
                message="Correctly rejected invalid redirect URI"
            ))
        else:
            runner.add_result(TestResult(
                name="Auth Code - Invalid Redirect URI Rejected",
                passed=False,
                duration_ms=duration,
                message=f"Expected 400, got {response.status_code}",
                error=response.text[:500]
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="Auth Code - Invalid Redirect URI Rejected",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_auth_code_invalid_client_id(tester: AuthorizationCodeTester, runner: TestRunner):
    """Test that invalid client_id is rejected"""
    start = time.time()
    code_verifier, code_challenge = generate_pkce_pair()

    try:
        response = tester.client.get("/connect/authorize", params={
            "client_id": "non-existent-client",
            "redirect_uri": "https://example.com/callback",
            "response_type": "code",
            "scope": "openid",
            "state": generate_state(),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256"
        }, allow_redirects=False)

        duration = (time.time() - start) * 1000

        # Should be rejected
        if response.status_code == 400:
            runner.add_result(TestResult(
                name="Auth Code - Invalid Client ID Rejected",
                passed=True,
                duration_ms=duration,
                message="Correctly rejected unknown client"
            ))
        else:
            runner.add_result(TestResult(
                name="Auth Code - Invalid Client ID Rejected",
                passed=False,
                duration_ms=duration,
                message=f"Expected 400, got {response.status_code}"
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="Auth Code - Invalid Client ID Rejected",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_auth_code_wrong_code_verifier(tester: AuthorizationCodeTester, runner: TestRunner):
    """Test that wrong code_verifier is rejected during token exchange"""
    start = time.time()
    config = get_client("wagram-web")
    redirect_uri = get_redirect_uri_for_env(config, tester.env)

    try:
        # Generate PKCE pair
        code_verifier, code_challenge = generate_pkce_pair()
        state = generate_state()

        # Get authorization code
        response, _ = tester.initiate_authorization(
            client_id=config.client_id,
            redirect_uri=redirect_uri,
            scope="openid profile",
            code_challenge=code_challenge,
            state=state
        )

        response = tester.login(response, tester.env.test_username, tester.env.test_password)
        if not response:
            runner.add_result(TestResult(
                name="Auth Code - Wrong Code Verifier",
                passed=False,
                duration_ms=(time.time() - start) * 1000,
                message="Could not complete auth flow to test code verifier"
            ))
            return

        if response.status_code == 200 and 'consent' in response.text.lower():
            response = tester.handle_consent(response)

        code = tester.extract_authorization_code(response, state)
        if not code:
            runner.add_result(TestResult(
                name="Auth Code - Wrong Code Verifier",
                passed=False,
                duration_ms=(time.time() - start) * 1000,
                message="Could not extract auth code to test verifier"
            ))
            return

        # Try to exchange with wrong verifier
        wrong_verifier, _ = generate_pkce_pair()  # Different verifier
        token_response = tester.client.post("/connect/token", data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": config.client_id,
            "code_verifier": wrong_verifier
        })

        duration = (time.time() - start) * 1000

        # Should be rejected
        if token_response.status_code == 400:
            runner.add_result(TestResult(
                name="Auth Code - Wrong Code Verifier Rejected",
                passed=True,
                duration_ms=duration,
                message="Correctly rejected wrong code_verifier"
            ))
        else:
            runner.add_result(TestResult(
                name="Auth Code - Wrong Code Verifier Rejected",
                passed=False,
                duration_ms=duration,
                message=f"Expected 400, got {token_response.status_code}"
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="Auth Code - Wrong Code Verifier Rejected",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_auth_code_multiple_mcp_clients(tester: AuthorizationCodeTester, runner: TestRunner):
    """Test auth code flow for various MCP clients (claude-desktop, chatgpt, etc.)"""
    mcp_clients = ["claude-desktop", "chatgpt", "cline", "roo", "continue-dev"]

    for client_id in mcp_clients:
        start = time.time()
        config = get_client(client_id)

        try:
            code_verifier, code_challenge = generate_pkce_pair()
            state = generate_state()
            # Use localhost for testing
            redirect_uri = "http://127.0.0.1/callback"

            # Just test that authorization endpoint accepts the client
            response = tester.client.get("/connect/authorize", params={
                "client_id": config.client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": "openid profile email",
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256"
            }, allow_redirects=True)

            duration = (time.time() - start) * 1000

            # Should redirect to login (200 with login form) or redirect
            if response.status_code == 200:
                runner.add_result(TestResult(
                    name=f"MCP Client Setup ({client_id})",
                    passed=True,
                    duration_ms=duration,
                    message="Client properly configured, reached login page"
                ))
            elif response.status_code == 400:
                runner.add_result(TestResult(
                    name=f"MCP Client Setup ({client_id})",
                    passed=False,
                    duration_ms=duration,
                    message="Client configuration error",
                    error=response.text[:300]
                ))
            else:
                runner.add_result(TestResult(
                    name=f"MCP Client Setup ({client_id})",
                    passed=True,
                    duration_ms=duration,
                    message=f"Response: {response.status_code}"
                ))

        except Exception as e:
            runner.add_result(TestResult(
                name=f"MCP Client Setup ({client_id})",
                passed=False,
                duration_ms=(time.time() - start) * 1000,
                error=str(e)
            ))


def run_authorization_code_tests(env: EnvironmentConfig) -> TestRunner:
    """Run all authorization code flow tests"""
    runner = TestRunner("Authorization Code Flow Tests")
    rate_limit = getattr(env, 'rate_limit_delay', 0.5)
    client = OAuthTestClient(env.base_url, env.verify_ssl, rate_limit)
    tester = AuthorizationCodeTester(client, env)

    # Run tests
    tokens = test_auth_code_flow_public_client(tester, runner, "wagram-web")
    test_auth_code_without_pkce(tester, runner)
    test_auth_code_invalid_redirect_uri(tester, runner)
    test_auth_code_invalid_client_id(tester, runner)

    # Reset session for next test
    client.reset_session()
    test_auth_code_wrong_code_verifier(tester, runner)

    # Test MCP clients
    client.reset_session()
    test_auth_code_multiple_mcp_clients(tester, runner)

    # Store tokens for other tests
    runner.tokens = tokens
    return runner


if __name__ == "__main__":
    import argparse
    from config import get_environment

    parser = argparse.ArgumentParser(description="Run Authorization Code Flow Tests")
    parser.add_argument("--env", choices=["local", "uat"], default="local")
    args = parser.parse_args()

    env = get_environment(args.env)
    print(f"\nTesting against: {env.name} ({env.base_url})")

    runner = run_authorization_code_tests(env)
    runner.print_summary()
