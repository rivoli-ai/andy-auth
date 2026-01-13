"""
Flask application demonstrating Andy Auth OAuth 2.0 integration.

Run with: python app.py
"""
import os
from flask import Flask, redirect, url_for, session, request, jsonify
from andy_auth_client import AndyAuthClient

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Configuration
ANDY_AUTH_SERVER = os.environ.get('ANDY_AUTH_SERVER', 'https://localhost:7088')
CLIENT_ID = os.environ.get('CLIENT_ID', 'my-python-app')
REDIRECT_URI = os.environ.get('REDIRECT_URI', 'http://localhost:5000/callback')

# Initialize OAuth client
auth_client = AndyAuthClient(
    client_id=CLIENT_ID,
    redirect_uri=REDIRECT_URI,
    auth_server=ANDY_AUTH_SERVER
)


@app.route('/')
def index():
    """Home page showing login status."""
    user = session.get('user')
    if user:
        return f'''
        <h1>Andy Auth Python Example</h1>
        <p>Welcome, {user.get("name", user.get("email", "User"))}!</p>
        <ul>
            <li><a href="/profile">View Profile</a></li>
            <li><a href="/tokens">View Tokens</a></li>
            <li><a href="/logout">Logout</a></li>
        </ul>
        '''
    return '''
    <h1>Andy Auth Python Example</h1>
    <p>You are not logged in.</p>
    <a href="/login">Login with Andy Auth</a>
    '''


@app.route('/login')
def login():
    """Initiate OAuth login flow."""
    auth_url, state, code_verifier = auth_client.get_authorization_url(
        scope="openid profile email"
    )

    # Store state and code_verifier in session for verification
    session['oauth_state'] = state
    session['code_verifier'] = code_verifier

    return redirect(auth_url)


@app.route('/callback')
def callback():
    """Handle OAuth callback."""
    # Verify state
    state = request.args.get('state')
    if state != session.get('oauth_state'):
        return 'Invalid state parameter', 400

    # Check for errors
    error = request.args.get('error')
    if error:
        error_description = request.args.get('error_description', 'Unknown error')
        return f'OAuth error: {error} - {error_description}', 400

    # Exchange code for tokens
    code = request.args.get('code')
    code_verifier = session.get('code_verifier')

    try:
        tokens = auth_client.exchange_code(code, code_verifier)
        session['tokens'] = tokens

        # Get user info
        user_info = auth_client.get_userinfo(tokens['access_token'])
        session['user'] = user_info

    except Exception as e:
        return f'Token exchange failed: {str(e)}', 400

    # Clean up
    session.pop('oauth_state', None)
    session.pop('code_verifier', None)

    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    """Log out the user."""
    session.clear()
    return redirect(url_for('index'))


@app.route('/profile')
def profile():
    """Show user profile."""
    user = session.get('user')
    if not user:
        return redirect(url_for('login'))
    return jsonify(user)


@app.route('/tokens')
def tokens():
    """Show current tokens (for debugging)."""
    tokens = session.get('tokens')
    if not tokens:
        return redirect(url_for('login'))
    # Don't expose full tokens in production
    return jsonify({
        'access_token': tokens.get('access_token', '')[:20] + '...',
        'token_type': tokens.get('token_type'),
        'expires_in': tokens.get('expires_in'),
        'scope': tokens.get('scope'),
        'has_refresh_token': 'refresh_token' in tokens,
        'has_id_token': 'id_token' in tokens
    })


@app.route('/refresh')
def refresh():
    """Refresh the access token."""
    tokens = session.get('tokens')
    if not tokens or 'refresh_token' not in tokens:
        return redirect(url_for('login'))

    try:
        new_tokens = auth_client.refresh_token(tokens['refresh_token'])
        session['tokens'] = new_tokens
        return jsonify({'status': 'Token refreshed successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


if __name__ == '__main__':
    # Disable SSL verification warnings for development
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    app.run(host='0.0.0.0', port=5000, debug=True)
