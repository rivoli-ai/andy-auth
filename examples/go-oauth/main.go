package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

var (
	oauthConfig *oauth2.Config
	store       *sessions.CookieStore
)

func init() {
	// Register types for session storage
	gob.Register(map[string]interface{}{})

	// Get configuration from environment
	authServer := getEnv("ANDY_AUTH_SERVER", "https://localhost:7088")
	clientID := getEnv("CLIENT_ID", "my-go-app")
	clientSecret := getEnv("CLIENT_SECRET", "")
	redirectURL := getEnv("REDIRECT_URL", "http://localhost:8080/callback")
	sessionKey := getEnv("SESSION_KEY", "super-secret-key-change-in-production")

	oauthConfig = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"openid", "profile", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  authServer + "/connect/authorize",
			TokenURL: authServer + "/connect/token",
		},
	}

	store = sessions.NewCookieStore([]byte(sessionKey))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func main() {
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/callback", callbackHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/profile", profileHandler)
	http.HandleFunc("/tokens", tokensHandler)

	port := getEnv("PORT", "8080")
	log.Printf("Server starting on http://localhost:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "auth-session")
	user, ok := session.Values["user"].(map[string]interface{})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if ok && user != nil {
		name := "User"
		if n, ok := user["name"].(string); ok && n != "" {
			name = n
		} else if email, ok := user["email"].(string); ok {
			name = email
		}
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Andy Auth Go Example</title></head>
<body>
    <h1>Andy Auth Go Example</h1>
    <p>Welcome, %s!</p>
    <ul>
        <li><a href="/profile">View Profile</a></li>
        <li><a href="/tokens">View Token Info</a></li>
        <li><a href="/logout">Logout</a></li>
    </ul>
</body>
</html>`, name)
	} else {
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Andy Auth Go Example</title></head>
<body>
    <h1>Andy Auth Go Example</h1>
    <p>You are not logged in.</p>
    <a href="/login">Login with Andy Auth</a>
</body>
</html>`)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "auth-session")

	// Generate PKCE code verifier and challenge
	verifier := generateCodeVerifier()
	challenge := generateCodeChallenge(verifier)

	// Generate state for CSRF protection
	state := generateState()

	// Store in session
	session.Values["code_verifier"] = verifier
	session.Values["oauth_state"] = state
	if err := session.Save(r, w); err != nil {
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	// Build authorization URL with PKCE
	url := oauthConfig.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "auth-session")

	// Check for error response
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		errDesc := r.URL.Query().Get("error_description")
		http.Error(w, fmt.Sprintf("OAuth error: %s - %s", errMsg, errDesc), http.StatusBadRequest)
		return
	}

	// Verify state
	state := r.URL.Query().Get("state")
	savedState, _ := session.Values["oauth_state"].(string)
	if state != savedState {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Get code verifier
	verifier, _ := session.Values["code_verifier"].(string)
	if verifier == "" {
		http.Error(w, "Missing code verifier", http.StatusBadRequest)
		return
	}

	// Exchange code for token with PKCE verifier
	code := r.URL.Query().Get("code")
	token, err := oauthConfig.Exchange(context.Background(), code,
		oauth2.SetAuthURLParam("code_verifier", verifier),
	)
	if err != nil {
		http.Error(w, "Token exchange failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Get user info
	client := oauthConfig.Client(context.Background(), token)
	resp, err := client.Get(oauthConfig.Endpoint.AuthURL[:len(oauthConfig.Endpoint.AuthURL)-len("/connect/authorize")] + "/connect/userinfo")
	if err != nil {
		http.Error(w, "Failed to get user info: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		http.Error(w, "Failed to decode user info: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Store in session
	session.Values["user"] = userInfo
	session.Values["access_token"] = token.AccessToken
	session.Values["token_expiry"] = token.Expiry.String()
	if token.RefreshToken != "" {
		session.Values["has_refresh_token"] = true
	}
	delete(session.Values, "code_verifier")
	delete(session.Values, "oauth_state")

	if err := session.Save(r, w); err != nil {
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "auth-session")
	session.Options.MaxAge = -1
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "auth-session")
	user, ok := session.Values["user"].(map[string]interface{})
	if !ok || user == nil {
		http.Error(w, `{"error": "not_authenticated"}`, http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func tokensHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "auth-session")
	_, ok := session.Values["user"].(map[string]interface{})
	if !ok {
		http.Error(w, `{"error": "not_authenticated"}`, http.StatusUnauthorized)
		return
	}

	tokenInfo := map[string]interface{}{
		"has_access_token": session.Values["access_token"] != nil,
	}

	if token, ok := session.Values["access_token"].(string); ok && len(token) > 20 {
		tokenInfo["access_token_preview"] = token[:20] + "..."
	}
	if expiry, ok := session.Values["token_expiry"].(string); ok {
		tokenInfo["expires_at"] = expiry
	}
	tokenInfo["has_refresh_token"] = session.Values["has_refresh_token"] == true

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenInfo)
}

// PKCE helpers
func generateCodeVerifier() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
