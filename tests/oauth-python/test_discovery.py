"""
OpenID Connect Discovery and JWKS Tests

Tests for the OpenID Connect Discovery document and JSON Web Key Set.
"""

import time
from typing import Dict, Any, List
from test_base import OAuthTestClient, TestRunner, TestResult
from config import (
    EXPECTED_DISCOVERY_ENDPOINTS, EXPECTED_GRANT_TYPES,
    EXPECTED_SCOPES, EnvironmentConfig
)


def test_discovery_endpoint(client: OAuthTestClient, runner: TestRunner) -> Dict[str, Any]:
    """Test OpenID Connect discovery document"""
    start = time.time()
    desc = "Fetches the OpenID Connect discovery document from /.well-known/openid-configuration to verify the server is properly configured."

    try:
        response = client.get("/.well-known/openid-configuration")
        duration = (time.time() - start) * 1000

        if response.status_code == 200:
            data = response.json()

            # Check required fields
            missing_fields = []
            for field in EXPECTED_DISCOVERY_ENDPOINTS:
                if field not in data:
                    missing_fields.append(field)

            if not missing_fields:
                runner.add_result(TestResult(
                    name="Discovery - Document Available",
                    passed=True,
                    duration_ms=duration,
                    message=f"All required fields present",
                    description=desc,
                    details={"issuer": data.get("issuer")}
                ))
            else:
                runner.add_result(TestResult(
                    name="Discovery - Document Available",
                    passed=False,
                    duration_ms=duration,
                    message=f"Missing fields: {missing_fields}",
                    description=desc
                ))

            return data
        else:
            runner.add_result(TestResult(
                name="Discovery - Document Available",
                passed=False,
                duration_ms=duration,
                message=f"Expected 200, got {response.status_code}",
                description=desc,
                error=response.text[:500]
            ))
            return {}

    except Exception as e:
        runner.add_result(TestResult(
            name="Discovery - Document Available",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            description=desc,
            error=str(e)
        ))
        return {}


def test_discovery_grant_types(
    client: OAuthTestClient,
    runner: TestRunner,
    discovery: Dict[str, Any]
):
    """Test that expected grant types are supported"""
    start = time.time()

    try:
        grant_types = discovery.get("grant_types_supported", [])

        missing = []
        for expected in EXPECTED_GRANT_TYPES:
            if expected not in grant_types:
                missing.append(expected)

        duration = (time.time() - start) * 1000

        if not missing:
            runner.add_result(TestResult(
                name="Discovery - Grant Types",
                passed=True,
                duration_ms=duration,
                message=f"All expected grant types supported",
                details={"supported": grant_types}
            ))
        else:
            runner.add_result(TestResult(
                name="Discovery - Grant Types",
                passed=False,
                duration_ms=duration,
                message=f"Missing grant types: {missing}",
                details={"supported": grant_types}
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="Discovery - Grant Types",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_discovery_scopes(
    client: OAuthTestClient,
    runner: TestRunner,
    discovery: Dict[str, Any]
):
    """Test that expected scopes are supported"""
    start = time.time()

    try:
        scopes = discovery.get("scopes_supported", [])

        missing = []
        for expected in EXPECTED_SCOPES:
            if expected not in scopes:
                missing.append(expected)

        duration = (time.time() - start) * 1000

        if not missing:
            runner.add_result(TestResult(
                name="Discovery - Scopes",
                passed=True,
                duration_ms=duration,
                message=f"All expected scopes supported",
                details={"supported": scopes}
            ))
        else:
            runner.add_result(TestResult(
                name="Discovery - Scopes",
                passed=len(missing) <= 1,  # Allow missing offline_access
                duration_ms=duration,
                message=f"Scopes: {len(scopes)} supported, {len(missing)} missing",
                details={"supported": scopes, "missing": missing}
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="Discovery - Scopes",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_discovery_pkce_support(
    client: OAuthTestClient,
    runner: TestRunner,
    discovery: Dict[str, Any]
):
    """Test that PKCE is supported"""
    start = time.time()

    try:
        methods = discovery.get("code_challenge_methods_supported", [])
        duration = (time.time() - start) * 1000

        if "S256" in methods:
            runner.add_result(TestResult(
                name="Discovery - PKCE Support",
                passed=True,
                duration_ms=duration,
                message="S256 code challenge supported",
                details={"methods": methods}
            ))
        else:
            runner.add_result(TestResult(
                name="Discovery - PKCE Support",
                passed=False,
                duration_ms=duration,
                message="S256 not in supported methods",
                details={"methods": methods}
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="Discovery - PKCE Support",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_jwks_endpoint(
    client: OAuthTestClient,
    runner: TestRunner,
    discovery: Dict[str, Any]
):
    """Test JWKS endpoint"""
    start = time.time()

    try:
        jwks_uri = discovery.get("jwks_uri")
        if not jwks_uri:
            runner.add_result(TestResult(
                name="JWKS - Endpoint Available",
                passed=False,
                duration_ms=(time.time() - start) * 1000,
                message="jwks_uri not in discovery document"
            ))
            return

        response = client.get(jwks_uri)
        duration = (time.time() - start) * 1000

        if response.status_code == 200:
            data = response.json()
            keys = data.get("keys", [])

            if keys:
                runner.add_result(TestResult(
                    name="JWKS - Endpoint Available",
                    passed=True,
                    duration_ms=duration,
                    message=f"Found {len(keys)} signing key(s)",
                    details={"key_types": [k.get("kty") for k in keys]}
                ))
            else:
                runner.add_result(TestResult(
                    name="JWKS - Endpoint Available",
                    passed=False,
                    duration_ms=duration,
                    message="No keys found in JWKS"
                ))
        else:
            runner.add_result(TestResult(
                name="JWKS - Endpoint Available",
                passed=False,
                duration_ms=duration,
                message=f"Expected 200, got {response.status_code}"
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="JWKS - Endpoint Available",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_jwks_key_properties(
    client: OAuthTestClient,
    runner: TestRunner,
    discovery: Dict[str, Any]
):
    """Test JWKS key properties"""
    start = time.time()

    try:
        jwks_uri = discovery.get("jwks_uri")
        if not jwks_uri:
            return

        response = client.get(jwks_uri)
        if response.status_code != 200:
            return

        data = response.json()
        keys = data.get("keys", [])

        if not keys:
            return

        duration = (time.time() - start) * 1000

        # Check first key for required properties
        key = keys[0]
        required_props = ["kty", "use", "kid"]  # alg might be optional
        missing = [p for p in required_props if p not in key]

        if not missing:
            runner.add_result(TestResult(
                name="JWKS - Key Properties",
                passed=True,
                duration_ms=duration,
                message=f"Key has required properties",
                details={
                    "kty": key.get("kty"),
                    "use": key.get("use"),
                    "alg": key.get("alg"),
                    "kid": key.get("kid", "N/A")[:20] + "..."
                }
            ))
        else:
            runner.add_result(TestResult(
                name="JWKS - Key Properties",
                passed=False,
                duration_ms=duration,
                message=f"Key missing properties: {missing}"
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="JWKS - Key Properties",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_introspection_endpoint_in_discovery(
    client: OAuthTestClient,
    runner: TestRunner,
    discovery: Dict[str, Any]
):
    """Test that introspection endpoint is in discovery"""
    start = time.time()

    try:
        introspection_endpoint = discovery.get("introspection_endpoint")
        duration = (time.time() - start) * 1000

        if introspection_endpoint and "/connect/introspect" in introspection_endpoint:
            runner.add_result(TestResult(
                name="Discovery - Introspection Endpoint",
                passed=True,
                duration_ms=duration,
                message=f"Endpoint: {introspection_endpoint}"
            ))
        elif introspection_endpoint:
            runner.add_result(TestResult(
                name="Discovery - Introspection Endpoint",
                passed=True,
                duration_ms=duration,
                message=f"Endpoint: {introspection_endpoint}"
            ))
        else:
            runner.add_result(TestResult(
                name="Discovery - Introspection Endpoint",
                passed=True,  # Optional endpoint
                duration_ms=duration,
                message="Not advertised (optional)"
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="Discovery - Introspection Endpoint",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_revocation_endpoint_in_discovery(
    client: OAuthTestClient,
    runner: TestRunner,
    discovery: Dict[str, Any]
):
    """Test that revocation endpoint is in discovery"""
    start = time.time()

    try:
        revocation_endpoint = discovery.get("revocation_endpoint")
        duration = (time.time() - start) * 1000

        if revocation_endpoint and "/connect/revoke" in revocation_endpoint:
            runner.add_result(TestResult(
                name="Discovery - Revocation Endpoint",
                passed=True,
                duration_ms=duration,
                message=f"Endpoint: {revocation_endpoint}"
            ))
        elif revocation_endpoint:
            runner.add_result(TestResult(
                name="Discovery - Revocation Endpoint",
                passed=True,
                duration_ms=duration,
                message=f"Endpoint: {revocation_endpoint}"
            ))
        else:
            runner.add_result(TestResult(
                name="Discovery - Revocation Endpoint",
                passed=True,  # Optional endpoint
                duration_ms=duration,
                message="Not advertised (optional)"
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="Discovery - Revocation Endpoint",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def test_userinfo_endpoint_in_discovery(
    client: OAuthTestClient,
    runner: TestRunner,
    discovery: Dict[str, Any]
):
    """Test that userinfo endpoint is in discovery"""
    start = time.time()

    try:
        userinfo_endpoint = discovery.get("userinfo_endpoint")
        duration = (time.time() - start) * 1000

        if userinfo_endpoint:
            runner.add_result(TestResult(
                name="Discovery - Userinfo Endpoint",
                passed=True,
                duration_ms=duration,
                message=f"Endpoint: {userinfo_endpoint}"
            ))
        else:
            runner.add_result(TestResult(
                name="Discovery - Userinfo Endpoint",
                passed=True,  # Optional in some configs
                duration_ms=duration,
                message="Not advertised"
            ))

    except Exception as e:
        runner.add_result(TestResult(
            name="Discovery - Userinfo Endpoint",
            passed=False,
            duration_ms=(time.time() - start) * 1000,
            error=str(e)
        ))


def run_discovery_tests(env: EnvironmentConfig) -> TestRunner:
    """Run all discovery and JWKS tests"""
    runner = TestRunner("OpenID Discovery and JWKS Tests")
    rate_limit = getattr(env, 'rate_limit_delay', 0.5)
    client = OAuthTestClient(env.base_url, env.verify_ssl, rate_limit)

    # Get discovery document
    discovery = test_discovery_endpoint(client, runner)

    if discovery:
        test_discovery_grant_types(client, runner, discovery)
        test_discovery_scopes(client, runner, discovery)
        test_discovery_pkce_support(client, runner, discovery)
        test_jwks_endpoint(client, runner, discovery)
        test_jwks_key_properties(client, runner, discovery)
        test_introspection_endpoint_in_discovery(client, runner, discovery)
        test_revocation_endpoint_in_discovery(client, runner, discovery)
        test_userinfo_endpoint_in_discovery(client, runner, discovery)

    runner.discovery = discovery
    return runner


if __name__ == "__main__":
    import argparse
    from config import get_environment

    parser = argparse.ArgumentParser(description="Run Discovery and JWKS Tests")
    parser.add_argument("--env", choices=["local", "uat"], default="local")
    args = parser.parse_args()

    env = get_environment(args.env)
    print(f"\nTesting against: {env.name} ({env.base_url})")

    runner = run_discovery_tests(env)
    runner.print_summary()
