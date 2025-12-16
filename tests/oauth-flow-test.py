#!/usr/bin/env python3
"""
OAuth Authorization Code Flow Test Script

This script simulates the Wagram OAuth flow:
1. Initiates authorization request
2. Logs in with test credentials
3. Handles consent (if needed)
4. Exchanges authorization code for tokens
5. Tests userinfo endpoint with access token

Usage:
    python oauth-flow-test.py --env local
    python oauth-flow-test.py --env uat
"""

import argparse
import hashlib
import base64
import secrets
import requests
from urllib.parse import urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
import json
import sys

# Disable SSL warnings for local development
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class OAuthFlowTester:
    def __init__(self, base_url, client_id, redirect_uri, username, password):
        self.base_url = base_url.rstrip('/')
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for local testing

    def generate_pkce_pair(self):
        """Generate PKCE code verifier and challenge"""
        # Generate code verifier (43-128 characters)
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

        # Generate code challenge (SHA256 hash of verifier)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')

        return code_verifier, code_challenge

    def step1_initiate_authorization(self, code_challenge, state):
        """Step 1: Initiate authorization request"""
        print("\n" + "="*80)
        print("STEP 1: Initiating Authorization Request")
        print("="*80)

        auth_params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'scope': 'openid profile email roles',
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }

        auth_url = f"{self.base_url}/connect/authorize"
        print(f"Authorization URL: {auth_url}")
        print(f"Parameters: {json.dumps(auth_params, indent=2)}")

        response = self.session.get(auth_url, params=auth_params, allow_redirects=True)
        print(f"Response Status: {response.status_code}")
        print(f"Final URL: {response.url}")

        return response

    def step2_login(self, response):
        """Step 2: Login with credentials"""
        print("\n" + "="*80)
        print("STEP 2: Logging In")
        print("="*80)

        # Parse the login form
        soup = BeautifulSoup(response.text, 'html.parser')
        form = soup.find('form')

        if not form:
            print("ERROR: No login form found!")
            print("Response content preview:")
            print(response.text[:500])
            return None

        # Extract form action and method
        form_action = form.get('action', '')
        if not form_action.startswith('http'):
            form_action = self.base_url + form_action

        print(f"Login Form Action: {form_action}")

        # Build form data
        form_data = {
            'Username': self.username,
            'Password': self.password,
            'RememberMe': 'false'
        }

        # Add hidden fields (like __RequestVerificationToken)
        for input_field in form.find_all('input', type='hidden'):
            name = input_field.get('name')
            value = input_field.get('value', '')
            if name:
                form_data[name] = value

        print(f"Form Data: {json.dumps({k: '***' if k == 'Password' else v for k, v in form_data.items()}, indent=2)}")

        # Submit login form
        response = self.session.post(form_action, data=form_data, allow_redirects=True)
        print(f"Response Status: {response.status_code}")
        print(f"Final URL: {response.url}")

        return response

    def step3_handle_consent(self, response):
        """Step 3: Handle consent page (if present)"""
        print("\n" + "="*80)
        print("STEP 3: Handling Consent (if needed)")
        print("="*80)

        # Check if we're on a consent page
        soup = BeautifulSoup(response.text, 'html.parser')
        consent_form = soup.find('form', {'id': 'consent-form'}) or soup.find('form', action=lambda x: x and 'consent' in x.lower())

        if not consent_form:
            print("No consent page detected - implicit consent or already consented")
            return response

        print("Consent page detected - submitting consent")

        form_action = consent_form.get('action', '')
        if not form_action.startswith('http'):
            form_action = self.base_url + form_action

        # Build consent form data
        form_data = {}
        for input_field in consent_form.find_all('input'):
            name = input_field.get('name')
            value = input_field.get('value', '')
            if name:
                form_data[name] = value

        # Submit consent
        response = self.session.post(form_action, data=form_data, allow_redirects=False)
        print(f"Response Status: {response.status_code}")

        # Follow redirect if present
        if response.status_code in [301, 302, 303, 307, 308]:
            redirect_url = response.headers.get('Location')
            print(f"Following redirect to: {redirect_url}")
            response = self.session.get(redirect_url, allow_redirects=False)

        return response

    def step4_extract_authorization_code(self, response, expected_state):
        """Step 4: Extract authorization code from callback"""
        print("\n" + "="*80)
        print("STEP 4: Extracting Authorization Code")
        print("="*80)

        # The response should be a redirect to the callback URL
        if response.status_code not in [301, 302, 303, 307, 308]:
            print(f"ERROR: Expected redirect, got {response.status_code}")
            print(f"Final URL: {response.url}")
            return None

        # Extract authorization code from redirect Location header
        redirect_url = response.headers.get('Location', '')
        print(f"Redirect URL: {redirect_url}")

        parsed = urlparse(redirect_url)
        params = parse_qs(parsed.query)

        # Validate state
        state = params.get('state', [None])[0]
        if state != expected_state:
            print(f"ERROR: State mismatch! Expected: {expected_state}, Got: {state}")
            return None

        # Extract authorization code
        code = params.get('code', [None])[0]
        if not code:
            print("ERROR: No authorization code in redirect!")
            print(f"Query params: {params}")
            return None

        print(f"Authorization Code: {code[:20]}...")
        print(f"State validated: {state}")

        return code

    def step5_exchange_code_for_tokens(self, code, code_verifier):
        """Step 5: Exchange authorization code for access token"""
        print("\n" + "="*80)
        print("STEP 5: Exchanging Code for Tokens")
        print("="*80)

        token_url = f"{self.base_url}/connect/token"
        print(f"Token URL: {token_url}")

        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri,
            'client_id': self.client_id,
            'code_verifier': code_verifier
        }

        print(f"Token Request: {json.dumps({k: v[:20] + '...' if k in ['code', 'code_verifier'] else v for k, v in token_data.items()}, indent=2)}")

        response = self.session.post(token_url, data=token_data)
        print(f"Response Status: {response.status_code}")

        if response.status_code != 200:
            print(f"ERROR: Token request failed!")
            print(f"Response: {response.text}")
            return None

        tokens = response.json()
        print(f"Access Token: {tokens.get('access_token', '')[:30]}...")
        print(f"Token Type: {tokens.get('token_type')}")
        print(f"Expires In: {tokens.get('expires_in')} seconds")
        print(f"Refresh Token: {'Yes' if tokens.get('refresh_token') else 'No'}")

        return tokens

    def step6_test_userinfo(self, access_token):
        """Step 6: Test userinfo endpoint with access token"""
        print("\n" + "="*80)
        print("STEP 6: Testing Userinfo Endpoint")
        print("="*80)

        userinfo_url = f"{self.base_url}/connect/userinfo"
        print(f"Userinfo URL: {userinfo_url}")

        headers = {
            'Authorization': f'Bearer {access_token}'
        }

        response = self.session.get(userinfo_url, headers=headers)
        print(f"Response Status: {response.status_code}")

        if response.status_code != 200:
            print(f"ERROR: Userinfo request failed!")
            print(f"Response: {response.text}")
            return None

        userinfo = response.json()
        print(f"Userinfo Response:")
        print(json.dumps(userinfo, indent=2))

        return userinfo

    def run_full_flow(self):
        """Run the complete OAuth flow"""
        print("\n" + "="*80)
        print("OAUTH AUTHORIZATION CODE FLOW TEST")
        print("="*80)
        print(f"Base URL: {self.base_url}")
        print(f"Client ID: {self.client_id}")
        print(f"Redirect URI: {self.redirect_uri}")
        print(f"Username: {self.username}")

        # Generate PKCE pair
        code_verifier, code_challenge = self.generate_pkce_pair()
        state = secrets.token_urlsafe(32)

        try:
            # Step 1: Initiate authorization
            response = self.step1_initiate_authorization(code_challenge, state)
            if not response:
                return False

            # Step 2: Login
            response = self.step2_login(response)
            if not response:
                return False

            # Step 3: Handle consent
            response = self.step3_handle_consent(response)
            if not response:
                return False

            # Step 4: Extract authorization code
            code = self.step4_extract_authorization_code(response, state)
            if not code:
                return False

            # Step 5: Exchange code for tokens
            tokens = self.step5_exchange_code_for_tokens(code, code_verifier)
            if not tokens:
                return False

            # Step 6: Test userinfo
            userinfo = self.step6_test_userinfo(tokens['access_token'])
            if not userinfo:
                return False

            print("\n" + "="*80)
            print("✓ OAUTH FLOW TEST PASSED!")
            print("="*80)
            return True

        except Exception as e:
            print("\n" + "="*80)
            print(f"✗ OAUTH FLOW TEST FAILED!")
            print(f"Error: {str(e)}")
            print("="*80)
            import traceback
            traceback.print_exc()
            return False


def main():
    parser = argparse.ArgumentParser(description='Test OAuth Authorization Code Flow')
    parser.add_argument('--env', choices=['local', 'uat'], required=True,
                       help='Environment to test (local or uat)')
    parser.add_argument('--username', default='test@andy.local',
                       help='Username for login (default: test@andy.local)')
    parser.add_argument('--password', default='Test123!',
                       help='Password for login (default: Test123!)')

    args = parser.parse_args()

    # Configure based on environment
    if args.env == 'local':
        base_url = 'https://localhost:7088'
        redirect_uri = 'https://localhost:4200/callback'
    else:  # uat
        base_url = 'https://andy-auth-uat-api.up.railway.app'
        redirect_uri = 'https://wagram-uat.vercel.app/callback'

    client_id = 'wagram-web'

    # Create tester and run flow
    tester = OAuthFlowTester(base_url, client_id, redirect_uri, args.username, args.password)
    success = tester.run_full_flow()

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
