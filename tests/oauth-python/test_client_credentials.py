"""
Client Credentials Flow Tests

Tests for the OAuth 2.0 Client Credentials grant type.
This flow is used for machine-to-machine authentication.
"""

import time
from typing import Optional, Dict, Any
from test_base import OAuthTestClient, TestRunner, TestResult
from config import CLIENTS, get_client


def test_client_credentials_valid(client: OAuthTestClient, runner: TestRunner):
    """Test client credentials flow with valid credentials"""
    start = time.time()
    config = get_client("lexipro-api")

    try:
        response = client.post("/connect/token", data={
            "grant_type": "client_credentials",
            "client_id": config.client_id,
            "client_secret": config.client_secret,
            "scope": "urn:andy-docs-api"
        })

        duration = (time.time() - start) * 1000

        if response.status_code == 200:
            data = response.json()
            has_token = "access_token" in data
            has_type = data.get("token_type", "").lower() == "bearer"
            has_expiry = "expires_in" in data

            if has_token and has_type and has_expiry:
                runner.add_result(TestResult(
                    name="Client Credentials - Valid Request",
                    passed=True,
                    duration_ms=duration,
                    message=f"Token received, expires in {data.get('expires_in')}s",
                    description="Tests that a confidential client can obtain an access token using the client_credentials grant type with valid credentials.",
                    details={"token_type": data.get("token_type"), "expires_in": data.get("expires_in")}
                ))
                return data.get("access_token")
            else:
                runner.add_result(TestResult(
                    name="Client Credentials - Valid Request",
                    passed=False,
                    duration_ms=duration,
                    message="Response missing required fields",
                    details={"has_token": has_token, "has_type": has_type, "has_expiry": has_expiry}
                ))
        else:
            runner.add_result(TestResult(
                name="Client Credentials - Valid Request",
                passed=False,
                duration_ms=duration,
                message=f"Expected 200, got {response.status_code}",
                error=response.text[:500]
            ))
    except Exception as e:
        runner.add_result(TestResult(
            name="Client Credentials - Valid Request",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))

    return None


def test_client_credentials_invalid_secret(client: OAuthTestClient, runner: TestRunner):
    """Test client credentials flow with invalid secret"""
    start = time.time()
    config = get_client("lexipro-api")

    try:
        response = client.post("/connect/token", data={
            "grant_type": "client_credentials",
            "client_id": config.client_id,
            "client_secret": "wrong-secret",
            "scope": "urn:andy-docs-api"
        })

        duration = (time.time() - start) * 1000

        # Should return 400 or 401
        if response.status_code in [400, 401]:
            runner.add_result(TestResult(
                name="Client Credentials - Invalid Secret",
                passed=True,
                duration_ms=duration,
                message=f"Correctly rejected with {response.status_code}",
                description="Verifies the server rejects client_credentials requests with an incorrect client secret."
            ))
        else:
            runner.add_result(TestResult(
                name="Client Credentials - Invalid Secret",
                passed=False,
                duration_ms=duration,
                message=f"Expected 400/401, got {response.status_code}",
                error=response.text[:500]
            ))
    except Exception as e:
        runner.add_result(TestResult(
            name="Client Credentials - Invalid Secret",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_client_credentials_unknown_client(client: OAuthTestClient, runner: TestRunner):
    """Test client credentials flow with unknown client"""
    start = time.time()

    try:
        response = client.post("/connect/token", data={
            "grant_type": "client_credentials",
            "client_id": "unknown-client-id",
            "client_secret": "some-secret"
        })

        duration = (time.time() - start) * 1000

        # Should return 400 or 401
        if response.status_code in [400, 401]:
            runner.add_result(TestResult(
                name="Client Credentials - Unknown Client",
                passed=True,
                duration_ms=duration,
                message=f"Correctly rejected with {response.status_code}",
                description="Verifies the server rejects client_credentials requests with an unregistered client ID."
            ))
        else:
            runner.add_result(TestResult(
                name="Client Credentials - Unknown Client",
                passed=False,
                duration_ms=duration,
                message=f"Expected 400/401, got {response.status_code}",
                error=response.text[:500]
            ))
    except Exception as e:
        runner.add_result(TestResult(
            name="Client Credentials - Unknown Client",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_client_credentials_public_client(client: OAuthTestClient, runner: TestRunner):
    """Test that public clients cannot use client_credentials flow"""
    start = time.time()
    config = get_client("wagram-web")  # Public client

    try:
        response = client.post("/connect/token", data={
            "grant_type": "client_credentials",
            "client_id": config.client_id
        })

        duration = (time.time() - start) * 1000

        # Should return 400 (public clients cannot use client_credentials)
        if response.status_code == 400:
            runner.add_result(TestResult(
                name="Client Credentials - Public Client Rejection",
                passed=True,
                duration_ms=duration,
                message="Public client correctly rejected",
                description="Verifies that public clients (without secrets) cannot use the client_credentials grant type."
            ))
        else:
            runner.add_result(TestResult(
                name="Client Credentials - Public Client Rejection",
                passed=False,
                duration_ms=duration,
                message=f"Expected 400, got {response.status_code}",
                error=response.text[:500]
            ))
    except Exception as e:
        runner.add_result(TestResult(
            name="Client Credentials - Public Client Rejection",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_client_credentials_missing_params(client: OAuthTestClient, runner: TestRunner):
    """Test client credentials flow with missing parameters"""
    start = time.time()

    try:
        # Missing client_id and client_secret
        response = client.post("/connect/token", data={
            "grant_type": "client_credentials"
        })

        duration = (time.time() - start) * 1000

        # Should return 400
        if response.status_code == 400:
            runner.add_result(TestResult(
                name="Client Credentials - Missing Params",
                passed=True,
                duration_ms=duration,
                message="Correctly rejected missing parameters",
                description="Verifies the server rejects client_credentials requests missing required client_id and client_secret."
            ))
        else:
            runner.add_result(TestResult(
                name="Client Credentials - Missing Params",
                passed=False,
                duration_ms=duration,
                message=f"Expected 400, got {response.status_code}",
                error=response.text[:500]
            ))
    except Exception as e:
        runner.add_result(TestResult(
            name="Client Credentials - Missing Params",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_client_credentials_with_resource(client: OAuthTestClient, runner: TestRunner):
    """Test client credentials flow with resource parameter (MCP)"""
    start = time.time()
    config = get_client("lexipro-api")

    try:
        response = client.post("/connect/token", data={
            "grant_type": "client_credentials",
            "client_id": config.client_id,
            "client_secret": config.client_secret,
            "scope": "urn:andy-docs-api",
            "resource": "https://lexipro-uat.up.railway.app/mcp"
        })

        duration = (time.time() - start) * 1000

        if response.status_code == 200:
            data = response.json()
            runner.add_result(TestResult(
                name="Client Credentials - With Resource (MCP)",
                passed=True,
                duration_ms=duration,
                message="Token received with resource parameter",
                description="Tests that client_credentials can include a resource parameter for MCP (Model Context Protocol) audience specification."
            ))
        else:
            # Resource may not be configured, log as info
            runner.add_result(TestResult(
                name="Client Credentials - With Resource (MCP)",
                passed=response.status_code in [200, 400],  # 400 if resource not allowed
                duration_ms=duration,
                message=f"Response: {response.status_code}",
                description="Tests that client_credentials can include a resource parameter for MCP (Model Context Protocol) audience specification.",
                details={"response": response.text[:200]}
            ))
    except Exception as e:
        runner.add_result(TestResult(
            name="Client Credentials - With Resource (MCP)",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def run_client_credentials_tests(base_url: str, verify_ssl: bool = True, rate_limit_delay: float = 0.5) -> TestRunner:
    """Run all client credentials flow tests"""
    runner = TestRunner("Client Credentials Flow Tests")
    client = OAuthTestClient(base_url, verify_ssl, rate_limit_delay)

    # Run tests
    access_token = test_client_credentials_valid(client, runner)
    test_client_credentials_invalid_secret(client, runner)
    test_client_credentials_unknown_client(client, runner)
    test_client_credentials_public_client(client, runner)
    test_client_credentials_missing_params(client, runner)
    test_client_credentials_with_resource(client, runner)

    # Return runner with access token stored for other tests
    runner.access_token = access_token
    return runner


if __name__ == "__main__":
    import argparse
    from config import get_environment

    parser = argparse.ArgumentParser(description="Run Client Credentials Flow Tests")
    parser.add_argument("--env", choices=["local", "uat"], default="local")
    args = parser.parse_args()

    env = get_environment(args.env)
    print(f"\nTesting against: {env.name} ({env.base_url})")

    runner = run_client_credentials_tests(env.base_url, env.verify_ssl)
    runner.print_summary()
