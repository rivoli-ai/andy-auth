/**
 * Express.js OAuth 2.0 example with Andy Auth
 *
 * Run with: node server.js
 */
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');

const app = express();

// Configuration
const config = {
    andyAuthServer: process.env.ANDY_AUTH_SERVER || 'https://localhost:7088',
    clientId: process.env.CLIENT_ID || 'my-js-app',
    clientSecret: process.env.CLIENT_SECRET || '',
    redirectUri: process.env.REDIRECT_URI || 'http://localhost:3000/callback',
    port: process.env.PORT || 3000
};

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'dev-secret-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Set to true in production with HTTPS
}));

// Discovery cache
let discoveryDoc = null;

/**
 * Fetch OpenID Connect discovery document
 */
async function getDiscovery() {
    if (discoveryDoc) return discoveryDoc;

    const response = await fetch(
        `${config.andyAuthServer}/.well-known/openid-configuration`,
        {
            headers: { 'Accept': 'application/json' },
            // In production, remove this and use proper certificates
            ...(process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0' ? {} : {})
        }
    );

    if (!response.ok) {
        throw new Error(`Discovery failed: ${response.statusText}`);
    }

    discoveryDoc = await response.json();
    return discoveryDoc;
}

/**
 * Generate PKCE code verifier and challenge
 */
function generatePKCE() {
    const codeVerifier = crypto.randomBytes(64).toString('base64url');
    const codeChallenge = crypto
        .createHash('sha256')
        .update(codeVerifier)
        .digest('base64url');

    return { codeVerifier, codeChallenge };
}

/**
 * Generate random state
 */
function generateState() {
    return crypto.randomBytes(32).toString('base64url');
}

// Routes
app.get('/', (req, res) => {
    const user = req.session.user;

    if (user) {
        res.send(`
            <h1>Andy Auth JavaScript Example</h1>
            <p>Welcome, ${user.name || user.email || 'User'}!</p>
            <ul>
                <li><a href="/profile">View Profile</a></li>
                <li><a href="/tokens">View Tokens</a></li>
                <li><a href="/logout">Logout</a></li>
            </ul>
        `);
    } else {
        res.send(`
            <h1>Andy Auth JavaScript Example</h1>
            <p>You are not logged in.</p>
            <a href="/login">Login with Andy Auth</a>
        `);
    }
});

app.get('/login', async (req, res) => {
    try {
        const discovery = await getDiscovery();
        const { codeVerifier, codeChallenge } = generatePKCE();
        const state = generateState();

        // Store in session
        req.session.oauthState = state;
        req.session.codeVerifier = codeVerifier;

        // Build authorization URL
        const params = new URLSearchParams({
            client_id: config.clientId,
            response_type: 'code',
            redirect_uri: config.redirectUri,
            scope: 'openid profile email',
            state: state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256'
        });

        res.redirect(`${discovery.authorization_endpoint}?${params}`);
    } catch (error) {
        res.status(500).send(`Login failed: ${error.message}`);
    }
});

app.get('/callback', async (req, res) => {
    try {
        const { code, state, error, error_description } = req.query;

        // Check for errors
        if (error) {
            return res.status(400).send(`OAuth error: ${error} - ${error_description}`);
        }

        // Verify state
        if (state !== req.session.oauthState) {
            return res.status(400).send('Invalid state parameter');
        }

        const discovery = await getDiscovery();
        const codeVerifier = req.session.codeVerifier;

        // Exchange code for tokens
        const tokenResponse = await fetch(discovery.token_endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: config.clientId,
                client_secret: config.clientSecret,
                code: code,
                redirect_uri: config.redirectUri,
                code_verifier: codeVerifier
            })
        });

        if (!tokenResponse.ok) {
            const errorText = await tokenResponse.text();
            throw new Error(`Token exchange failed: ${errorText}`);
        }

        const tokens = await tokenResponse.json();
        req.session.tokens = tokens;

        // Get user info
        const userResponse = await fetch(discovery.userinfo_endpoint, {
            headers: {
                'Authorization': `Bearer ${tokens.access_token}`
            }
        });

        if (userResponse.ok) {
            req.session.user = await userResponse.json();
        }

        // Clean up
        delete req.session.oauthState;
        delete req.session.codeVerifier;

        res.redirect('/');
    } catch (error) {
        res.status(500).send(`Callback failed: ${error.message}`);
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/profile', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    res.json(req.session.user);
});

app.get('/tokens', (req, res) => {
    if (!req.session.tokens) {
        return res.redirect('/login');
    }

    const tokens = req.session.tokens;
    res.json({
        access_token: tokens.access_token?.substring(0, 20) + '...',
        token_type: tokens.token_type,
        expires_in: tokens.expires_in,
        scope: tokens.scope,
        has_refresh_token: !!tokens.refresh_token,
        has_id_token: !!tokens.id_token
    });
});

// Start server
app.listen(config.port, () => {
    console.log(`Server running at http://localhost:${config.port}`);
    console.log(`Andy Auth Server: ${config.andyAuthServer}`);
});
