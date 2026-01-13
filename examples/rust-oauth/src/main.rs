use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Json, Router,
};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, TokenResponse,
    TokenUrl,
};
use serde::{Deserialize, Serialize};
use std::{env, sync::Arc};
use tower_sessions::{MemoryStore, Session, SessionManagerLayer};

#[derive(Clone)]
struct AppState {
    oauth_client: BasicClient,
    userinfo_url: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct UserInfo {
    sub: String,
    name: Option<String>,
    email: Option<String>,
    #[serde(flatten)]
    extra: serde_json::Value,
}

fn get_env(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() {
    let auth_server = get_env("ANDY_AUTH_SERVER", "https://localhost:7088");
    let client_id = get_env("CLIENT_ID", "my-rust-app");
    let client_secret = get_env("CLIENT_SECRET", "");
    let redirect_url = get_env("REDIRECT_URL", "http://localhost:3000/callback");
    let port = get_env("PORT", "3000");

    let oauth_client = BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new(format!("{}/connect/authorize", auth_server)).expect("Invalid auth URL"),
        Some(TokenUrl::new(format!("{}/connect/token", auth_server)).expect("Invalid token URL")),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url).expect("Invalid redirect URL"));

    let state = AppState {
        oauth_client,
        userinfo_url: format!("{}/connect/userinfo", auth_server),
    };

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store);

    let app = Router::new()
        .route("/", get(home))
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/logout", get(logout))
        .route("/profile", get(profile))
        .route("/tokens", get(tokens))
        .with_state(Arc::new(state))
        .layer(session_layer);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .expect("Failed to bind");
    println!("Server running on http://localhost:{}", port);
    axum::serve(listener, app).await.expect("Server failed");
}

async fn home(session: Session) -> Html<String> {
    let user: Option<UserInfo> = session.get("user").await.unwrap_or(None);

    let html = match user {
        Some(u) => {
            let name = u.name.as_deref().unwrap_or(u.email.as_deref().unwrap_or("User"));
            format!(
                r#"<!DOCTYPE html>
<html>
<head><title>Andy Auth Rust Example</title></head>
<body>
    <h1>Andy Auth Rust Example</h1>
    <p>Welcome, {}!</p>
    <ul>
        <li><a href="/profile">View Profile</a></li>
        <li><a href="/tokens">View Token Info</a></li>
        <li><a href="/logout">Logout</a></li>
    </ul>
</body>
</html>"#,
                name
            )
        }
        None => r#"<!DOCTYPE html>
<html>
<head><title>Andy Auth Rust Example</title></head>
<body>
    <h1>Andy Auth Rust Example</h1>
    <p>You are not logged in.</p>
    <a href="/login">Login with Andy Auth</a>
</body>
</html>"#
            .to_string(),
    };

    Html(html)
}

async fn login(State(state): State<Arc<AppState>>, session: Session) -> Response {
    // Generate PKCE challenge
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate authorization URL
    let (auth_url, csrf_token) = state
        .oauth_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(oauth2::Scope::new("openid".to_string()))
        .add_scope(oauth2::Scope::new("profile".to_string()))
        .add_scope(oauth2::Scope::new("email".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    // Store PKCE verifier and CSRF token in session
    let _ = session
        .insert("pkce_verifier", pkce_verifier.secret().clone())
        .await;
    let _ = session
        .insert("csrf_token", csrf_token.secret().clone())
        .await;

    Redirect::to(auth_url.as_str()).into_response()
}

#[derive(Deserialize)]
struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn callback(
    State(state): State<Arc<AppState>>,
    session: Session,
    Query(params): Query<CallbackParams>,
) -> Response {
    // Check for error response
    if let Some(error) = params.error {
        let desc = params.error_description.unwrap_or_default();
        return Html(format!(
            "<h1>OAuth Error</h1><p>{}: {}</p><a href=\"/\">Go back</a>",
            error, desc
        ))
        .into_response();
    }

    let code = match params.code {
        Some(c) => c,
        None => {
            return Html("<h1>Error</h1><p>Missing authorization code</p>").into_response();
        }
    };

    let param_state = match params.state {
        Some(s) => s,
        None => {
            return Html("<h1>Error</h1><p>Missing state parameter</p>").into_response();
        }
    };

    // Verify CSRF token
    let stored_csrf: Option<String> = session.get("csrf_token").await.unwrap_or(None);
    match stored_csrf {
        Some(csrf) if csrf == param_state => {}
        _ => {
            return Html("<h1>Error</h1><p>Invalid CSRF token</p>").into_response();
        }
    }

    // Get PKCE verifier
    let verifier: String = match session.get("pkce_verifier").await.unwrap_or(None) {
        Some(v) => v,
        None => {
            return Html("<h1>Error</h1><p>Missing PKCE verifier</p>").into_response();
        }
    };

    let pkce_verifier = PkceCodeVerifier::new(verifier);

    // Exchange code for token
    let token_result = match state
        .oauth_client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            return Html(format!(
                "<h1>Error</h1><p>Token exchange failed: {}</p>",
                e
            ))
            .into_response();
        }
    };

    // Get user info
    let client = reqwest::Client::new();
    let user_info: UserInfo = match client
        .get(&state.userinfo_url)
        .bearer_auth(token_result.access_token().secret())
        .send()
        .await
    {
        Ok(resp) => match resp.json().await {
            Ok(info) => info,
            Err(e) => {
                return Html(format!(
                    "<h1>Error</h1><p>Failed to parse user info: {}</p>",
                    e
                ))
                .into_response();
            }
        },
        Err(e) => {
            return Html(format!(
                "<h1>Error</h1><p>Failed to get user info: {}</p>",
                e
            ))
            .into_response();
        }
    };

    // Store user in session
    let _ = session.insert("user", user_info).await;
    let _ = session.insert("has_access_token", true).await;
    let _ = session
        .insert(
            "has_refresh_token",
            token_result.refresh_token().is_some(),
        )
        .await;
    let _ = session.remove::<String>("csrf_token").await;
    let _ = session.remove::<String>("pkce_verifier").await;

    Redirect::to("/").into_response()
}

async fn logout(session: Session) -> Redirect {
    let _ = session.flush().await;
    Redirect::to("/")
}

async fn profile(session: Session) -> Response {
    let user: Option<UserInfo> = session.get("user").await.unwrap_or(None);

    match user {
        Some(u) => Json(u).into_response(),
        None => (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "not_authenticated"})),
        )
            .into_response(),
    }
}

#[derive(Serialize)]
struct TokenInfo {
    has_access_token: bool,
    has_refresh_token: bool,
}

async fn tokens(session: Session) -> Response {
    let user: Option<UserInfo> = session.get("user").await.unwrap_or(None);

    if user.is_none() {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "not_authenticated"})),
        )
            .into_response();
    }

    let has_access_token: bool = session
        .get("has_access_token")
        .await
        .unwrap_or(None)
        .unwrap_or(false);
    let has_refresh_token: bool = session
        .get("has_refresh_token")
        .await
        .unwrap_or(None)
        .unwrap_or(false);

    Json(TokenInfo {
        has_access_token,
        has_refresh_token,
    })
    .into_response()
}
