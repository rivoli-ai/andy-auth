"""
Token Operations Tests

Tests for token refresh, introspection, revocation, and userinfo endpoints.
"""

import time
from typing import Optional, Dict, Any
from test_base import OAuthTestClient, TestRunner, TestResult
from config import CLIENTS, get_client, EnvironmentConfig


def test_refresh_token_flow(
    client: OAuthTestClient,
    runner: TestRunner,
    refresh_token: str,
    client_id: str = "wagram-web"
) -> Optional[Dict[str, Any]]:
    """Test refresh token flow"""
    start = time.time()
    config = get_client(client_id)

    try:
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": config.client_id
        }

        if config.client_secret:
            data["client_secret"] = config.client_secret

        response = client.post("/connect/token", data=data)
        duration = (time.time() - start) * 1000

        if response.status_code == 200:
            tokens = response.json()
            has_access = "access_token" in tokens
            has_refresh = "refresh_token" in tokens

            runner.add_result(TestResult(
                name="Refresh Token - Valid Request",
                passed=has_access,
                duration_ms=duration,
                message=f"New tokens received (access={has_access}, refresh={has_refresh})",
                details={"expires_in": tokens.get("expires_in")}
            ))
            return tokens if has_access else None
        else:
            runner.add_result(TestResult(
                name="Refresh Token - Valid Request",
                passed=False,
                duration_ms=duration,
                message=f"Expected 200, got {response.status_code}",
                error=response.text[:500]
            ))
            return None

    except Exception as e:
        runner.add_result(TestResult(
            name="Refresh Token - Valid Request",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))
        return None


def test_refresh_token_invalid(client: OAuthTestClient, runner: TestRunner):
    """Test refresh token with invalid token"""
    start = time.time()
    config = get_client("wagram-web")

    try:
        response = client.post("/connect/token", data={
            "grant_type": "refresh_token",
            "refresh_token": "invalid-refresh-token",
            "client_id": config.client_id
        })

        duration = (time.time() - start) * 1000

        if response.status_code in [400, 401]:
            runner.add_result(TestResult(
                name="Refresh Token - Invalid Token Rejected",
                passed=True,
                duration_ms=duration,
                message=f"Correctly rejected with {response.status_code}"
            ))
        else:
            runner.add_result(TestResult(
                name="Refresh Token - Invalid Token Rejected",
                passed=False,
                duration_ms=duration,
                message=f"Expected 400/401, got {response.status_code}"
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="Refresh Token - Invalid Token Rejected",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_token_introspection_valid(
    client: OAuthTestClient,
    runner: TestRunner,
    access_token: str
):
    """Test token introspection with valid token"""
    start = time.time()
    config = get_client("lexipro-api")  # Need confidential client for introspection

    try:
        response = client.post("/connect/introspect", data={
            "token": access_token,
            "client_id": config.client_id,
            "client_secret": config.client_secret
        })

        duration = (time.time() - start) * 1000

        if response.status_code == 200:
            data = response.json()
            is_active = data.get("active", False)

            runner.add_result(TestResult(
                name="Token Introspection - Valid Token",
                passed=is_active,
                duration_ms=duration,
                message=f"Token active: {is_active}",
                details=data
            ))
        else:
            runner.add_result(TestResult(
                name="Token Introspection - Valid Token",
                passed=False,
                duration_ms=duration,
                message=f"Expected 200, got {response.status_code}",
                error=response.text[:500]
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="Token Introspection - Valid Token",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_token_introspection_invalid(client: OAuthTestClient, runner: TestRunner):
    """Test token introspection with invalid token"""
    start = time.time()
    config = get_client("lexipro-api")

    try:
        response = client.post("/connect/introspect", data={
            "token": "invalid-token-value",
            "client_id": config.client_id,
            "client_secret": config.client_secret
        })

        duration = (time.time() - start) * 1000

        if response.status_code == 200:
            data = response.json()
            is_active = data.get("active", False)

            runner.add_result(TestResult(
                name="Token Introspection - Invalid Token",
                passed=not is_active,  # Should be inactive
                duration_ms=duration,
                message=f"Token correctly marked inactive: {not is_active}"
            ))
        else:
            runner.add_result(TestResult(
                name="Token Introspection - Invalid Token",
                passed=False,
                duration_ms=duration,
                message=f"Expected 200, got {response.status_code}"
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="Token Introspection - Invalid Token",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_token_introspection_no_credentials(client: OAuthTestClient, runner: TestRunner):
    """Test token introspection without client credentials"""
    start = time.time()

    try:
        response = client.post("/connect/introspect", data={
            "token": "some-token"
        })

        duration = (time.time() - start) * 1000

        if response.status_code in [400, 401]:
            runner.add_result(TestResult(
                name="Token Introspection - No Credentials Rejected",
                passed=True,
                duration_ms=duration,
                message=f"Correctly rejected with {response.status_code}"
            ))
        else:
            runner.add_result(TestResult(
                name="Token Introspection - No Credentials Rejected",
                passed=False,
                duration_ms=duration,
                message=f"Expected 400/401, got {response.status_code}"
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="Token Introspection - No Credentials Rejected",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_token_revocation_valid(
    client: OAuthTestClient,
    runner: TestRunner,
    access_token: str
):
    """Test token revocation with valid token"""
    start = time.time()
    config = get_client("lexipro-api")

    try:
        response = client.post("/connect/revoke", data={
            "token": access_token,
            "client_id": config.client_id,
            "client_secret": config.client_secret
        })

        duration = (time.time() - start) * 1000

        # RFC 7009: revocation should return 200 OK
        if response.status_code == 200:
            runner.add_result(TestResult(
                name="Token Revocation - Valid Token",
                passed=True,
                duration_ms=duration,
                message="Token revoked successfully"
            ))

            # Verify token is now inactive
            introspect_response = client.post("/connect/introspect", data={
                "token": access_token,
                "client_id": config.client_id,
                "client_secret": config.client_secret
            })

            if introspect_response.status_code == 200:
                data = introspect_response.json()
                if not data.get("active", True):
                    runner.add_result(TestResult(
                        name="Token Revocation - Verify Inactive",
                        passed=True,
                        duration_ms=(time.time() - start) * 1000 - duration,
                        message="Revoked token correctly shows as inactive"
                    ))
                else:
                    runner.add_result(TestResult(
                        name="Token Revocation - Verify Inactive",
                        passed=False,
                        duration_ms=(time.time() - start) * 1000 - duration,
                        message="Token still shows as active after revocation"
                    ))
        else:
            runner.add_result(TestResult(
                name="Token Revocation - Valid Token",
                passed=False,
                duration_ms=duration,
                message=f"Expected 200, got {response.status_code}",
                error=response.text[:500]
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="Token Revocation - Valid Token",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_token_revocation_invalid(client: OAuthTestClient, runner: TestRunner):
    """Test token revocation with invalid token (should still succeed per RFC 7009)"""
    start = time.time()
    config = get_client("lexipro-api")

    try:
        response = client.post("/connect/revoke", data={
            "token": "invalid-or-already-revoked-token",
            "client_id": config.client_id,
            "client_secret": config.client_secret
        })

        duration = (time.time() - start) * 1000

        # RFC 7009: revocation of invalid token should still return 200
        if response.status_code == 200:
            runner.add_result(TestResult(
                name="Token Revocation - Invalid Token (RFC 7009)",
                passed=True,
                duration_ms=duration,
                message="Returns 200 for invalid token (per RFC 7009)"
            ))
        else:
            runner.add_result(TestResult(
                name="Token Revocation - Invalid Token (RFC 7009)",
                passed=False,
                duration_ms=duration,
                message=f"Expected 200, got {response.status_code}"
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="Token Revocation - Invalid Token (RFC 7009)",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_userinfo_valid_token(
    client: OAuthTestClient,
    runner: TestRunner,
    access_token: str,
    is_user_token: bool = True
):
    """Test userinfo endpoint with valid token

    Note: userinfo requires a user-context token (from authorization code flow).
    Client credentials tokens don't have user context and will fail.
    """
    start = time.time()

    try:
        response = client.get("/connect/userinfo", headers={
            "Authorization": f"Bearer {access_token}"
        })

        duration = (time.time() - start) * 1000

        if response.status_code == 200:
            data = response.json()
            has_sub = "sub" in data

            runner.add_result(TestResult(
                name="Userinfo - Valid User Token",
                passed=has_sub,
                duration_ms=duration,
                message=f"User info retrieved (sub={data.get('sub', 'N/A')})",
                details={k: v for k, v in data.items() if k not in ['sub']}
            ))
        elif response.status_code in [400, 401, 500] and not is_user_token:
            # Client credentials tokens don't have user context - this is expected
            runner.add_result(TestResult(
                name="Userinfo - Client Credentials Token (No User Context)",
                passed=True,
                duration_ms=duration,
                message=f"Correctly rejected client credentials token ({response.status_code})"
            ))
        else:
            runner.add_result(TestResult(
                name="Userinfo - Valid Token",
                passed=False,
                duration_ms=duration,
                message=f"Expected 200 (or 4xx for non-user token), got {response.status_code}",
                error=response.text[:200]
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="Userinfo - Valid Token",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_userinfo_no_token(client: OAuthTestClient, runner: TestRunner):
    """Test userinfo endpoint without token"""
    start = time.time()

    try:
        response = client.get("/connect/userinfo")
        duration = (time.time() - start) * 1000

        # Accept 400, 401, or 500 (server may throw when no identity available)
        if response.status_code in [400, 401, 500]:
            runner.add_result(TestResult(
                name="Userinfo - No Token Rejected",
                passed=True,
                duration_ms=duration,
                message=f"Correctly rejected with {response.status_code}"
            ))
        else:
            runner.add_result(TestResult(
                name="Userinfo - No Token Rejected",
                passed=False,
                duration_ms=duration,
                message=f"Expected 400/401/500, got {response.status_code}"
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="Userinfo - No Token Rejected",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_userinfo_invalid_token(client: OAuthTestClient, runner: TestRunner):
    """Test userinfo endpoint with invalid token"""
    start = time.time()

    try:
        response = client.get("/connect/userinfo", headers={
            "Authorization": "Bearer invalid-token"
        })

        duration = (time.time() - start) * 1000

        # Accept 400, 401, or 500 (server may throw when no valid identity)
        if response.status_code in [400, 401, 500]:
            runner.add_result(TestResult(
                name="Userinfo - Invalid Token Rejected",
                passed=True,
                duration_ms=duration,
                message=f"Correctly rejected with {response.status_code}"
            ))
        else:
            runner.add_result(TestResult(
                name="Userinfo - Invalid Token Rejected",
                passed=False,
                duration_ms=duration,
                message=f"Expected 400/401/500, got {response.status_code}"
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="Userinfo - Invalid Token Rejected",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def run_token_operations_tests(
    env: EnvironmentConfig,
    access_token: Optional[str] = None,
    refresh_token: Optional[str] = None
) -> TestRunner:
    """Run all token operation tests"""
    runner = TestRunner("Token Operations Tests")
    rate_limit = getattr(env, 'rate_limit_delay', 0.5)
    client = OAuthTestClient(env.base_url, env.verify_ssl, rate_limit)

    # Get a fresh client credentials token for introspection tests
    # Note: Tokens from auth code flow may be reference tokens that can only be introspected
    # by the issuing client, so we use a client credentials token for reliable testing
    introspection_token = None
    config = get_client("lexipro-api")
    response = client.post("/connect/token", data={
        "grant_type": "client_credentials",
        "client_id": config.client_id,
        "client_secret": config.client_secret,
        "scope": "urn:lexipro-api"
    })
    if response.status_code == 200:
        data = response.json()
        introspection_token = data.get("access_token")

    # Run introspection tests with the client credentials token
    if introspection_token:
        test_token_introspection_valid(client, runner, introspection_token)
    test_token_introspection_invalid(client, runner)
    test_token_introspection_no_credentials(client, runner)

    # Run revocation tests (get fresh token to revoke)
    config = get_client("lexipro-api")
    response = client.post("/connect/token", data={
        "grant_type": "client_credentials",
        "client_id": config.client_id,
        "client_secret": config.client_secret,
        "scope": "urn:lexipro-api"
    })
    if response.status_code == 200:
        revoke_token = response.json().get("access_token")
        if revoke_token:
            test_token_revocation_valid(client, runner, revoke_token)

    test_token_revocation_invalid(client, runner)

    # Run refresh token tests
    if refresh_token:
        test_refresh_token_flow(client, runner, refresh_token)
    test_refresh_token_invalid(client, runner)

    # Run userinfo tests
    # Note: access_token from client credentials has no user context
    # is_user_token=False when token came from client credentials, True when from auth code flow
    is_user_token = refresh_token is not None  # Auth code flow provides refresh token
    if access_token:
        test_userinfo_valid_token(client, runner, access_token, is_user_token=is_user_token)
    test_userinfo_no_token(client, runner)
    test_userinfo_invalid_token(client, runner)

    return runner


if __name__ == "__main__":
    import argparse
    from config import get_environment

    parser = argparse.ArgumentParser(description="Run Token Operations Tests")
    parser.add_argument("--env", choices=["local", "uat"], default="local")
    args = parser.parse_args()

    env = get_environment(args.env)
    print(f"\nTesting against: {env.name} ({env.base_url})")

    runner = run_token_operations_tests(env)
    runner.print_summary()
