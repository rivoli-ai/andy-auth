/**
 * Express.js OAuth 2.0 example with Andy Auth (TypeScript)
 */
import express, { Request, Response } from 'express';
import session from 'express-session';
import crypto from 'crypto';

// Extend session type
declare module 'express-session' {
    interface SessionData {
        oauthState?: string;
        codeVerifier?: string;
        tokens?: TokenResponse;
        user?: UserInfo;
    }
}

interface TokenResponse {
    access_token: string;
    token_type: string;
    expires_in?: number;
    refresh_token?: string;
    id_token?: string;
    scope?: string;
}

interface UserInfo {
    sub: string;
    name?: string;
    email?: string;
    [key: string]: unknown;
}

interface DiscoveryDocument {
    authorization_endpoint: string;
    token_endpoint: string;
    userinfo_endpoint: string;
    introspection_endpoint?: string;
    end_session_endpoint?: string;
}

// Configuration
const config = {
    andyAuthServer: process.env.ANDY_AUTH_SERVER || 'https://localhost:7088',
    clientId: process.env.CLIENT_ID || 'my-ts-app',
    clientSecret: process.env.CLIENT_SECRET || '',
    redirectUri: process.env.REDIRECT_URI || 'http://localhost:3000/callback',
    port: parseInt(process.env.PORT || '3000', 10)
};

const app = express();

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'dev-secret-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Set to true in production
}));

// Discovery cache
let discoveryDoc: DiscoveryDocument | null = null;

async function getDiscovery(): Promise<DiscoveryDocument> {
    if (discoveryDoc) return discoveryDoc;

    const response = await fetch(
        `${config.andyAuthServer}/.well-known/openid-configuration`
    );

    if (!response.ok) {
        throw new Error(`Discovery failed: ${response.statusText}`);
    }

    discoveryDoc = await response.json() as DiscoveryDocument;
    return discoveryDoc;
}

function generatePKCE(): { codeVerifier: string; codeChallenge: string } {
    const codeVerifier = crypto.randomBytes(64).toString('base64url');
    const codeChallenge = crypto
        .createHash('sha256')
        .update(codeVerifier)
        .digest('base64url');

    return { codeVerifier, codeChallenge };
}

function generateState(): string {
    return crypto.randomBytes(32).toString('base64url');
}

// Routes
app.get('/', (req: Request, res: Response) => {
    const user = req.session.user;

    if (user) {
        res.send(`
            <h1>Andy Auth TypeScript Example</h1>
            <p>Welcome, ${user.name || user.email || 'User'}!</p>
            <ul>
                <li><a href="/profile">View Profile</a></li>
                <li><a href="/tokens">View Tokens</a></li>
                <li><a href="/logout">Logout</a></li>
            </ul>
        `);
    } else {
        res.send(`
            <h1>Andy Auth TypeScript Example</h1>
            <p>You are not logged in.</p>
            <a href="/login">Login with Andy Auth</a>
        `);
    }
});

app.get('/login', async (req: Request, res: Response) => {
    try {
        const discovery = await getDiscovery();
        const { codeVerifier, codeChallenge } = generatePKCE();
        const state = generateState();

        req.session.oauthState = state;
        req.session.codeVerifier = codeVerifier;

        const params = new URLSearchParams({
            client_id: config.clientId,
            response_type: 'code',
            redirect_uri: config.redirectUri,
            scope: 'openid profile email',
            state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256'
        });

        res.redirect(`${discovery.authorization_endpoint}?${params}`);
    } catch (error) {
        res.status(500).send(`Login failed: ${(error as Error).message}`);
    }
});

app.get('/callback', async (req: Request, res: Response) => {
    try {
        const { code, state, error, error_description } = req.query;

        if (error) {
            return res.status(400).send(`OAuth error: ${error} - ${error_description}`);
        }

        if (state !== req.session.oauthState) {
            return res.status(400).send('Invalid state parameter');
        }

        const discovery = await getDiscovery();
        const codeVerifier = req.session.codeVerifier!;

        const tokenResponse = await fetch(discovery.token_endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: config.clientId,
                client_secret: config.clientSecret,
                code: code as string,
                redirect_uri: config.redirectUri,
                code_verifier: codeVerifier
            })
        });

        if (!tokenResponse.ok) {
            throw new Error(`Token exchange failed: ${await tokenResponse.text()}`);
        }

        const tokens = await tokenResponse.json() as TokenResponse;
        req.session.tokens = tokens;

        const userResponse = await fetch(discovery.userinfo_endpoint, {
            headers: { 'Authorization': `Bearer ${tokens.access_token}` }
        });

        if (userResponse.ok) {
            req.session.user = await userResponse.json() as UserInfo;
        }

        delete req.session.oauthState;
        delete req.session.codeVerifier;

        res.redirect('/');
    } catch (error) {
        res.status(500).send(`Callback failed: ${(error as Error).message}`);
    }
});

app.get('/logout', (req: Request, res: Response) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

app.get('/profile', (req: Request, res: Response) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    res.json(req.session.user);
});

app.get('/tokens', (req: Request, res: Response) => {
    if (!req.session.tokens) {
        return res.redirect('/login');
    }

    const tokens = req.session.tokens;
    res.json({
        access_token: tokens.access_token.substring(0, 20) + '...',
        token_type: tokens.token_type,
        expires_in: tokens.expires_in,
        scope: tokens.scope,
        has_refresh_token: !!tokens.refresh_token,
        has_id_token: !!tokens.id_token
    });
});

app.listen(config.port, () => {
    console.log(`Server running at http://localhost:${config.port}`);
});
