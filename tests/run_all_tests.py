#!/usr/bin/env python3
"""
Andy Auth Comprehensive Test Suite

This script runs all OAuth tests against the Andy Auth server.
It can test both local development and UAT environments.

Usage:
    python run_all_tests.py --env local
    python run_all_tests.py --env uat
    python run_all_tests.py --env local --html report.html
    python run_all_tests.py --env uat --verbose
"""

import argparse
import sys
import json
from datetime import datetime
from typing import List, Dict, Any
from dataclasses import asdict

from config import get_environment, EnvironmentConfig
from test_base import TestRunner, TestSuiteResult, TestResult

# Import test suites
from test_discovery import run_discovery_tests
from test_client_credentials import run_client_credentials_tests
from test_authorization_code import run_authorization_code_tests
from test_token_operations import run_token_operations_tests
from test_dynamic_registration import run_dynamic_registration_tests


def generate_html_report(
    env: EnvironmentConfig,
    suites: List[TestSuiteResult],
    output_file: str
):
    """Generate HTML test report"""
    total_tests = sum(s.total_count for s in suites)
    total_passed = sum(s.passed_count for s in suites)
    total_failed = sum(s.failed_count for s in suites)
    overall_rate = (total_passed / total_tests * 100) if total_tests > 0 else 0

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Andy Auth Test Report - {env.name}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        header h1 {{
            font-size: 2em;
            margin-bottom: 10px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .summary-card h3 {{
            font-size: 2.5em;
            margin-bottom: 5px;
        }}
        .summary-card.passed h3 {{ color: #10b981; }}
        .summary-card.failed h3 {{ color: #ef4444; }}
        .summary-card.total h3 {{ color: #6366f1; }}
        .summary-card.rate h3 {{ color: #f59e0b; }}
        .suite {{
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .suite-header {{
            background: #f8f9fa;
            padding: 15px 20px;
            border-bottom: 1px solid #e9ecef;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }}
        .suite-header:hover {{
            background: #e9ecef;
        }}
        .suite-header h2 {{
            font-size: 1.2em;
            color: #374151;
        }}
        .suite-stats {{
            display: flex;
            gap: 15px;
            font-size: 0.9em;
        }}
        .stat {{
            padding: 5px 12px;
            border-radius: 20px;
        }}
        .stat.passed {{
            background: #d1fae5;
            color: #065f46;
        }}
        .stat.failed {{
            background: #fee2e2;
            color: #991b1b;
        }}
        .test-list {{
            padding: 0;
            list-style: none;
        }}
        .test-item {{
            padding: 15px 20px;
            border-bottom: 1px solid #f3f4f6;
            display: flex;
            align-items: flex-start;
            gap: 15px;
        }}
        .test-item:last-child {{
            border-bottom: none;
        }}
        .test-status {{
            width: 24px;
            height: 24px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
        }}
        .test-status.pass {{
            background: #10b981;
            color: white;
        }}
        .test-status.fail {{
            background: #ef4444;
            color: white;
        }}
        .test-info {{
            flex: 1;
        }}
        .test-name {{
            font-weight: 600;
            color: #1f2937;
        }}
        .test-message {{
            color: #6b7280;
            font-size: 0.9em;
            margin-top: 3px;
        }}
        .test-error {{
            color: #ef4444;
            font-size: 0.85em;
            margin-top: 5px;
            padding: 8px;
            background: #fef2f2;
            border-radius: 5px;
            font-family: monospace;
        }}
        .test-duration {{
            color: #9ca3af;
            font-size: 0.85em;
            white-space: nowrap;
        }}
        .env-info {{
            background: #e0e7ff;
            color: #3730a3;
            padding: 10px 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 0.9em;
        }}
        .timestamp {{
            color: rgba(255,255,255,0.8);
            font-size: 0.9em;
        }}
        @media (max-width: 600px) {{
            .summary {{
                grid-template-columns: 1fr 1fr;
            }}
            .suite-header {{
                flex-direction: column;
                gap: 10px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Andy Auth Test Report</h1>
            <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>

        <div class="env-info">
            <strong>Environment:</strong> {env.name} | <strong>URL:</strong> {env.base_url}
        </div>

        <div class="summary">
            <div class="summary-card total">
                <h3>{total_tests}</h3>
                <p>Total Tests</p>
            </div>
            <div class="summary-card passed">
                <h3>{total_passed}</h3>
                <p>Passed</p>
            </div>
            <div class="summary-card failed">
                <h3>{total_failed}</h3>
                <p>Failed</p>
            </div>
            <div class="summary-card rate">
                <h3>{overall_rate:.1f}%</h3>
                <p>Success Rate</p>
            </div>
        </div>
"""

    for suite in suites:
        html += f"""
        <div class="suite">
            <div class="suite-header">
                <h2>{suite.name}</h2>
                <div class="suite-stats">
                    <span class="stat passed">{suite.passed_count} passed</span>
                    <span class="stat failed">{suite.failed_count} failed</span>
                </div>
            </div>
            <ul class="test-list">
"""
        for result in suite.results:
            status_class = "pass" if result.passed else "fail"
            icon = "&#10003;" if result.passed else "&#10007;"
            error_html = ""
            if result.error:
                error_html = f'<div class="test-error">{result.error[:300]}</div>'

            html += f"""
                <li class="test-item">
                    <div class="test-status {status_class}">{icon}</div>
                    <div class="test-info">
                        <div class="test-name">{result.name}</div>
                        <div class="test-message">{result.message}</div>
                        {error_html}
                    </div>
                    <div class="test-duration">{result.duration_ms:.0f}ms</div>
                </li>
"""

        html += """
            </ul>
        </div>
"""

    html += """
    </div>
</body>
</html>
"""

    with open(output_file, 'w') as f:
        f.write(html)

    print(f"\nHTML report saved to: {output_file}")


def generate_json_report(
    env: EnvironmentConfig,
    suites: List[TestSuiteResult],
    output_file: str
):
    """Generate JSON test report"""
    report = {
        "environment": {
            "name": env.name,
            "base_url": env.base_url
        },
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total": sum(s.total_count for s in suites),
            "passed": sum(s.passed_count for s in suites),
            "failed": sum(s.failed_count for s in suites),
            "success_rate": sum(s.passed_count for s in suites) / max(sum(s.total_count for s in suites), 1) * 100
        },
        "suites": []
    }

    for suite in suites:
        suite_data = {
            "name": suite.name,
            "total": suite.total_count,
            "passed": suite.passed_count,
            "failed": suite.failed_count,
            "success_rate": suite.success_rate,
            "results": []
        }
        for result in suite.results:
            suite_data["results"].append({
                "name": result.name,
                "passed": result.passed,
                "duration_ms": result.duration_ms,
                "message": result.message,
                "error": result.error
            })
        report["suites"].append(suite_data)

    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"JSON report saved to: {output_file}")


def run_all_tests(env: EnvironmentConfig, verbose: bool = False) -> List[TestSuiteResult]:
    """Run all test suites"""
    suites: List[TestSuiteResult] = []

    print("\n" + "=" * 80)
    print(f"ANDY AUTH COMPREHENSIVE TEST SUITE")
    print(f"Environment: {env.name} ({env.base_url})")
    print("=" * 80)

    # 1. Discovery and JWKS tests
    print("\n[1/5] Running Discovery & JWKS tests...")
    discovery_runner = run_discovery_tests(env)
    if verbose:
        discovery_runner.print_summary()
    suites.append(discovery_runner.get_suite_result())
    print(f"      {discovery_runner.get_suite_result().passed_count}/{discovery_runner.get_suite_result().total_count} passed")

    # 2. Client Credentials tests
    print("\n[2/5] Running Client Credentials tests...")
    rate_limit = getattr(env, 'rate_limit_delay', 0.5)
    cc_runner = run_client_credentials_tests(env.base_url, env.verify_ssl, rate_limit)
    if verbose:
        cc_runner.print_summary()
    suites.append(cc_runner.get_suite_result())
    print(f"      {cc_runner.get_suite_result().passed_count}/{cc_runner.get_suite_result().total_count} passed")

    # 3. Authorization Code Flow tests
    print("\n[3/5] Running Authorization Code Flow tests...")
    auth_runner = run_authorization_code_tests(env)
    if verbose:
        auth_runner.print_summary()
    suites.append(auth_runner.get_suite_result())
    print(f"      {auth_runner.get_suite_result().passed_count}/{auth_runner.get_suite_result().total_count} passed")

    # Get tokens from auth flow for token operation tests
    access_token = None
    refresh_token = None
    if hasattr(auth_runner, 'tokens') and auth_runner.tokens:
        access_token = auth_runner.tokens.get('access_token')
        refresh_token = auth_runner.tokens.get('refresh_token')

    # 4. Token Operations tests
    print("\n[4/5] Running Token Operations tests...")
    token_runner = run_token_operations_tests(env, access_token, refresh_token)
    if verbose:
        token_runner.print_summary()
    suites.append(token_runner.get_suite_result())
    print(f"      {token_runner.get_suite_result().passed_count}/{token_runner.get_suite_result().total_count} passed")

    # 5. Dynamic Client Registration tests
    print("\n[5/5] Running Dynamic Client Registration tests...")
    dcr_runner = run_dynamic_registration_tests(env)
    if verbose:
        dcr_runner.print_summary()
    suites.append(dcr_runner.get_suite_result())
    print(f"      {dcr_runner.get_suite_result().passed_count}/{dcr_runner.get_suite_result().total_count} passed")

    return suites


def print_final_summary(suites: List[TestSuiteResult]):
    """Print final summary of all test suites"""
    total_tests = sum(s.total_count for s in suites)
    total_passed = sum(s.passed_count for s in suites)
    total_failed = sum(s.failed_count for s in suites)
    overall_rate = (total_passed / total_tests * 100) if total_tests > 0 else 0

    print("\n" + "=" * 80)
    print("FINAL SUMMARY")
    print("=" * 80)

    for suite in suites:
        status = "PASS" if suite.failed_count == 0 else "FAIL"
        icon = "\u2713" if suite.failed_count == 0 else "\u2717"
        print(f"  [{status}] {icon} {suite.name}: {suite.passed_count}/{suite.total_count} ({suite.success_rate:.1f}%)")

    print("-" * 80)
    print(f"  TOTAL: {total_passed}/{total_tests} tests passed ({overall_rate:.1f}%)")

    if total_failed > 0:
        print(f"\n  FAILED TESTS:")
        for suite in suites:
            for result in suite.results:
                if not result.passed:
                    print(f"    - [{suite.name}] {result.name}")
                    if result.error:
                        print(f"      Error: {result.error[:100]}...")

    print("=" * 80)

    if total_failed == 0:
        print("\n\u2713 ALL TESTS PASSED!")
    else:
        print(f"\n\u2717 {total_failed} TEST(S) FAILED")

    return total_failed == 0


def main():
    parser = argparse.ArgumentParser(
        description="Run Andy Auth comprehensive test suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_all_tests.py --env local              # Test local server
  python run_all_tests.py --env uat                # Test UAT server
  python run_all_tests.py --env uat --html report.html  # Generate HTML report
  python run_all_tests.py --env local --json results.json  # Generate JSON report
  python run_all_tests.py --env local --verbose    # Show detailed output
        """
    )
    parser.add_argument(
        "--env",
        choices=["local", "uat"],
        default="local",
        help="Environment to test (default: local)"
    )
    parser.add_argument(
        "--html",
        metavar="FILE",
        help="Generate HTML report to specified file"
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Generate JSON report to specified file"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed test output"
    )

    args = parser.parse_args()

    # Get environment config
    env = get_environment(args.env)

    # Run all tests
    suites = run_all_tests(env, args.verbose)

    # Generate reports if requested
    if args.html:
        generate_html_report(env, suites, args.html)

    if args.json:
        generate_json_report(env, suites, args.json)

    # Print final summary
    all_passed = print_final_summary(suites)

    # Exit with appropriate code
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
