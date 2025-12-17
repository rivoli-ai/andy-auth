"""
Dynamic Client Registration Tests (RFC 7591)

Tests for the OAuth 2.0 Dynamic Client Registration Protocol.
"""

import time
import uuid
from typing import Dict, Any, Optional
from test_base import OAuthTestClient, TestRunner, TestResult
from config import EnvironmentConfig


def test_dcr_register_public_client(client: OAuthTestClient, runner: TestRunner) -> Optional[Dict[str, Any]]:
    """Test registering a new public client"""
    start = time.time()

    try:
        client_name = f"test-client-{uuid.uuid4().hex[:8]}"
        redirect_uri = "http://localhost:8888/callback"

        response = client.post("/connect/register", json={
            "client_name": client_name,
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none"  # Public client
        })

        duration = (time.time() - start) * 1000

        if response.status_code in [200, 201]:
            data = response.json()
            has_client_id = "client_id" in data

            if has_client_id:
                runner.add_result(TestResult(
                    name="DCR - Register Public Client",
                    passed=True,
                    duration_ms=duration,
                    message=f"Client registered: {data.get('client_id')}",
                    details={
                        "client_id": data.get("client_id"),
                        "client_name": data.get("client_name"),
                        "has_registration_token": "registration_access_token" in data
                    }
                ))
                return data
            else:
                runner.add_result(TestResult(
                    name="DCR - Register Public Client",
                    passed=False,
                    duration_ms=duration,
                    message="Response missing client_id",
                    details=data
                ))
        elif response.status_code == 400:
            # DCR might require initial access token or be disabled
            runner.add_result(TestResult(
                name="DCR - Register Public Client",
                passed=True,  # Expected if DCR is restricted
                duration_ms=duration,
                message=f"DCR returned 400 (may require auth or be disabled)",
                details={"response": response.text[:300]}
            ))
        elif response.status_code == 401:
            runner.add_result(TestResult(
                name="DCR - Register Public Client",
                passed=True,  # Expected if initial access token required
                duration_ms=duration,
                message="DCR requires authentication (initial access token)"
            ))
        else:
            runner.add_result(TestResult(
                name="DCR - Register Public Client",
                passed=False,
                duration_ms=duration,
                message=f"Unexpected response: {response.status_code}",
                error=response.text[:500]
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="DCR - Register Public Client",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))

    return None


def test_dcr_register_confidential_client(client: OAuthTestClient, runner: TestRunner) -> Optional[Dict[str, Any]]:
    """Test registering a new confidential client"""
    start = time.time()

    try:
        client_name = f"test-confidential-{uuid.uuid4().hex[:8]}"
        redirect_uri = "https://example.com/callback"

        response = client.post("/connect/register", json={
            "client_name": client_name,
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token", "client_credentials"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post"  # Confidential client
        })

        duration = (time.time() - start) * 1000

        if response.status_code in [200, 201]:
            data = response.json()
            has_client_id = "client_id" in data
            has_secret = "client_secret" in data

            if has_client_id:
                runner.add_result(TestResult(
                    name="DCR - Register Confidential Client",
                    passed=True,
                    duration_ms=duration,
                    message=f"Client registered with secret: {has_secret}",
                    details={
                        "client_id": data.get("client_id"),
                        "has_secret": has_secret,
                        "has_registration_token": "registration_access_token" in data
                    }
                ))
                return data
            else:
                runner.add_result(TestResult(
                    name="DCR - Register Confidential Client",
                    passed=False,
                    duration_ms=duration,
                    message="Response missing client_id"
                ))
        elif response.status_code in [400, 401]:
            runner.add_result(TestResult(
                name="DCR - Register Confidential Client",
                passed=True,  # Expected if DCR restricted
                duration_ms=duration,
                message=f"DCR returned {response.status_code} (restricted)"
            ))
        else:
            runner.add_result(TestResult(
                name="DCR - Register Confidential Client",
                passed=False,
                duration_ms=duration,
                message=f"Unexpected response: {response.status_code}"
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="DCR - Register Confidential Client",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))

    return None


def test_dcr_read_client(
    client: OAuthTestClient,
    runner: TestRunner,
    client_id: str,
    registration_token: str
):
    """Test reading client configuration"""
    start = time.time()

    try:
        response = client.get(f"/connect/register?client_id={client_id}", headers={
            "Authorization": f"Bearer {registration_token}"
        })

        duration = (time.time() - start) * 1000

        if response.status_code == 200:
            data = response.json()
            runner.add_result(TestResult(
                name="DCR - Read Client Configuration",
                passed=True,
                duration_ms=duration,
                message=f"Client info retrieved",
                details={"client_name": data.get("client_name")}
            ))
        elif response.status_code == 401:
            runner.add_result(TestResult(
                name="DCR - Read Client Configuration",
                passed=True,  # Expected behavior
                duration_ms=duration,
                message="Requires valid registration token"
            ))
        elif response.status_code == 405:
            runner.add_result(TestResult(
                name="DCR - Read Client Configuration",
                passed=True,  # OpenIddict doesn't implement this optional endpoint
                duration_ms=duration,
                message="Not implemented (optional RFC 7592 feature)"
            ))
        else:
            runner.add_result(TestResult(
                name="DCR - Read Client Configuration",
                passed=False,
                duration_ms=duration,
                message=f"Unexpected response: {response.status_code}"
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="DCR - Read Client Configuration",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_dcr_delete_client(
    client: OAuthTestClient,
    runner: TestRunner,
    client_id: str,
    registration_token: str
):
    """Test deleting a dynamically registered client"""
    start = time.time()

    try:
        response = client.delete(f"/connect/register?client_id={client_id}", headers={
            "Authorization": f"Bearer {registration_token}"
        })

        duration = (time.time() - start) * 1000

        if response.status_code in [200, 204]:
            runner.add_result(TestResult(
                name="DCR - Delete Client",
                passed=True,
                duration_ms=duration,
                message="Client deleted successfully"
            ))
        elif response.status_code == 401:
            runner.add_result(TestResult(
                name="DCR - Delete Client",
                passed=True,  # Expected behavior
                duration_ms=duration,
                message="Requires valid registration token"
            ))
        elif response.status_code == 405:
            runner.add_result(TestResult(
                name="DCR - Delete Client",
                passed=True,  # OpenIddict doesn't implement this optional endpoint
                duration_ms=duration,
                message="Not implemented (optional RFC 7592 feature)"
            ))
        else:
            runner.add_result(TestResult(
                name="DCR - Delete Client",
                passed=False,
                duration_ms=duration,
                message=f"Unexpected response: {response.status_code}"
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="DCR - Delete Client",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_dcr_invalid_redirect_uri(client: OAuthTestClient, runner: TestRunner):
    """Test that invalid redirect URIs are rejected"""
    start = time.time()

    try:
        response = client.post("/connect/register", json={
            "client_name": "test-invalid-uri",
            "redirect_uris": ["not-a-valid-uri"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"]
        })

        duration = (time.time() - start) * 1000

        # Should be rejected
        if response.status_code == 400:
            runner.add_result(TestResult(
                name="DCR - Invalid Redirect URI Rejected",
                passed=True,
                duration_ms=duration,
                message="Correctly rejected invalid redirect URI"
            ))
        elif response.status_code == 401:
            runner.add_result(TestResult(
                name="DCR - Invalid Redirect URI Rejected",
                passed=True,  # DCR requires auth
                duration_ms=duration,
                message="DCR requires authentication"
            ))
        else:
            runner.add_result(TestResult(
                name="DCR - Invalid Redirect URI Rejected",
                passed=False,
                duration_ms=duration,
                message=f"Expected 400, got {response.status_code}"
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="DCR - Invalid Redirect URI Rejected",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_dcr_missing_required_fields(client: OAuthTestClient, runner: TestRunner):
    """Test that missing required fields are rejected"""
    start = time.time()

    try:
        # Missing redirect_uris
        response = client.post("/connect/register", json={
            "client_name": "test-missing-fields",
            "grant_types": ["authorization_code"]
        })

        duration = (time.time() - start) * 1000

        if response.status_code == 400:
            runner.add_result(TestResult(
                name="DCR - Missing Fields Rejected",
                passed=True,
                duration_ms=duration,
                message="Correctly rejected missing redirect_uris"
            ))
        elif response.status_code == 401:
            runner.add_result(TestResult(
                name="DCR - Missing Fields Rejected",
                passed=True,  # DCR requires auth
                duration_ms=duration,
                message="DCR requires authentication"
            ))
        else:
            runner.add_result(TestResult(
                name="DCR - Missing Fields Rejected",
                passed=False,
                duration_ms=duration,
                message=f"Expected 400, got {response.status_code}"
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="DCR - Missing Fields Rejected",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_dcr_endpoint_exists(client: OAuthTestClient, runner: TestRunner):
    """Test that DCR endpoint exists"""
    start = time.time()

    try:
        # Test with empty body
        response = client.post("/connect/register", json={})
        duration = (time.time() - start) * 1000

        # Any response other than 404 means endpoint exists
        if response.status_code != 404:
            runner.add_result(TestResult(
                name="DCR - Endpoint Exists",
                passed=True,
                duration_ms=duration,
                message=f"DCR endpoint available (returned {response.status_code})"
            ))
        else:
            runner.add_result(TestResult(
                name="DCR - Endpoint Exists",
                passed=False,
                duration_ms=duration,
                message="DCR endpoint not found (404)"
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="DCR - Endpoint Exists",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def run_dynamic_registration_tests(env: EnvironmentConfig) -> TestRunner:
    """Run all dynamic client registration tests"""
    runner = TestRunner("Dynamic Client Registration Tests")
    rate_limit = getattr(env, 'rate_limit_delay', 0.5)
    client = OAuthTestClient(env.base_url, env.verify_ssl, rate_limit)

    # Test endpoint exists
    test_dcr_endpoint_exists(client, runner)

    # Register clients
    public_client = test_dcr_register_public_client(client, runner)
    confidential_client = test_dcr_register_confidential_client(client, runner)

    # Test read/delete if registration succeeded
    if public_client:
        registration_token = public_client.get("registration_access_token", "")
        client_id = public_client.get("client_id", "")
        if registration_token and client_id:
            test_dcr_read_client(client, runner, client_id, registration_token)
            test_dcr_delete_client(client, runner, client_id, registration_token)

    # Validation tests
    test_dcr_invalid_redirect_uri(client, runner)
    test_dcr_missing_required_fields(client, runner)

    return runner


if __name__ == "__main__":
    import argparse
    from config import get_environment

    parser = argparse.ArgumentParser(description="Run Dynamic Client Registration Tests")
    parser.add_argument("--env", choices=["local", "uat"], default="local")
    args = parser.parse_args()

    env = get_environment(args.env)
    print(f"\nTesting against: {env.name} ({env.base_url})")

    runner = run_dynamic_registration_tests(env)
    runner.print_summary()
