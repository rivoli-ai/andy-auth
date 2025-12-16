"""
Base test utilities for Andy Auth tests
"""

import hashlib
import base64
import secrets
import json
from typing import Dict, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs

# Disable SSL warnings for local development
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class TestResult:
    """Result of a single test"""
    name: str
    passed: bool
    duration_ms: float
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class TestSuiteResult:
    """Result of a test suite"""
    name: str
    results: list
    started_at: datetime
    ended_at: Optional[datetime] = None

    @property
    def passed_count(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed_count(self) -> int:
        return sum(1 for r in self.results if not r.passed)

    @property
    def total_count(self) -> int:
        return len(self.results)

    @property
    def success_rate(self) -> float:
        if not self.results:
            return 0.0
        return (self.passed_count / self.total_count) * 100


class OAuthTestClient:
    """HTTP client for OAuth testing with session management"""

    def __init__(self, base_url: str, verify_ssl: bool = True, rate_limit_delay: float = 0.5):
        self.base_url = base_url.rstrip('/')
        self.verify_ssl = verify_ssl
        self.rate_limit_delay = rate_limit_delay
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self._last_request_time = 0

    def _wait_for_rate_limit(self):
        """Wait to respect rate limits"""
        import time
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self._last_request_time = time.time()

    def get(self, path: str, **kwargs) -> requests.Response:
        """Make GET request"""
        self._wait_for_rate_limit()
        url = f"{self.base_url}{path}" if path.startswith('/') else path
        return self.session.get(url, **kwargs)

    def post(self, path: str, **kwargs) -> requests.Response:
        """Make POST request"""
        self._wait_for_rate_limit()
        url = f"{self.base_url}{path}" if path.startswith('/') else path
        return self.session.post(url, **kwargs)

    def delete(self, path: str, **kwargs) -> requests.Response:
        """Make DELETE request"""
        self._wait_for_rate_limit()
        url = f"{self.base_url}{path}" if path.startswith('/') else path
        return self.session.delete(url, **kwargs)

    def reset_session(self):
        """Reset the session (clear cookies, etc.)"""
        self.session = requests.Session()
        self.session.verify = self.verify_ssl


def generate_pkce_pair() -> Tuple[str, str]:
    """Generate PKCE code verifier and challenge"""
    # Generate code verifier (43-128 characters)
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

    # Generate code challenge (SHA256 hash of verifier)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).decode('utf-8').rstrip('=')

    return code_verifier, code_challenge


def generate_state() -> str:
    """Generate a random state parameter"""
    return secrets.token_urlsafe(32)


def parse_form(html: str) -> Tuple[Optional[str], Dict[str, str]]:
    """
    Parse HTML form and extract action URL and hidden fields
    Returns (action_url, form_data)
    """
    soup = BeautifulSoup(html, 'html.parser')
    form = soup.find('form')

    if not form:
        return None, {}

    action = form.get('action', '')
    form_data = {}

    # Extract hidden fields
    for input_field in form.find_all('input'):
        name = input_field.get('name')
        if name:
            form_data[name] = input_field.get('value', '')

    return action, form_data


def extract_code_from_redirect(response: requests.Response, expected_state: str) -> Optional[str]:
    """
    Extract authorization code from redirect response
    Returns None if not found or state mismatch
    """
    if response.status_code not in [301, 302, 303, 307, 308]:
        # Check if we got a direct redirect URL in final URL
        if 'code=' in response.url:
            parsed = urlparse(response.url)
            params = parse_qs(parsed.query)
        else:
            return None
    else:
        redirect_url = response.headers.get('Location', '')
        parsed = urlparse(redirect_url)
        params = parse_qs(parsed.query)

    # Validate state
    state = params.get('state', [None])[0]
    if state != expected_state:
        return None

    # Extract code
    code = params.get('code', [None])[0]
    return code


def format_json(data: Any) -> str:
    """Format data as pretty JSON string"""
    return json.dumps(data, indent=2, default=str)


def truncate_token(token: str, length: int = 20) -> str:
    """Truncate token for display"""
    if len(token) <= length:
        return token
    return f"{token[:length]}..."


class TestRunner:
    """Run tests and collect results"""

    def __init__(self, suite_name: str):
        self.suite_name = suite_name
        self.results: list = []
        self.started_at = datetime.now()

    def add_result(self, result: TestResult):
        """Add a test result"""
        self.results.append(result)

    def get_suite_result(self) -> TestSuiteResult:
        """Get the complete suite result"""
        return TestSuiteResult(
            name=self.suite_name,
            results=self.results,
            started_at=self.started_at,
            ended_at=datetime.now()
        )

    def print_summary(self):
        """Print summary of test results"""
        suite = self.get_suite_result()

        print("\n" + "=" * 80)
        print(f"TEST SUITE: {suite.name}")
        print("=" * 80)
        print(f"Total: {suite.total_count} | Passed: {suite.passed_count} | Failed: {suite.failed_count}")
        print(f"Success Rate: {suite.success_rate:.1f}%")
        print("-" * 80)

        for result in self.results:
            status = "PASS" if result.passed else "FAIL"
            icon = "\u2713" if result.passed else "\u2717"
            print(f"  [{status}] {icon} {result.name} ({result.duration_ms:.0f}ms)")
            if result.message:
                print(f"         {result.message}")
            if result.error:
                print(f"         ERROR: {result.error}")

        print("=" * 80)

        return suite.failed_count == 0
