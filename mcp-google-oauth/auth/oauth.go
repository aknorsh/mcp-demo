package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// jwtSecret is generated at startup and shared within the auth package.
var jwtSecret []byte

func init() {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate JWT secret: " + err.Error())
	}
	jwtSecret = b
}

// GoogleTokens holds tokens received from Google. Never exposed to clients.
type GoogleTokens struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	Email        string
}

var (
	sessionMu sync.Mutex
	sessions  = map[string]string{} // state -> redirect_uri
)

var (
	codeMu    sync.Mutex
	codeStore = map[string]string{} // codeB -> userID
)

var (
	tokenMu    sync.Mutex
	tokenStore = map[string]GoogleTokens{} // userID -> GoogleTokens
)

// AuthorizeHandler redirects to Google's authorization endpoint.
// PKCE params from the client are NOT forwarded to Google because we perform
// the token exchange server-side (with client_secret) in CallbackHandler.
func AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	redirectURI := q.Get("redirect_uri")

	sessionMu.Lock()
	sessions[state] = redirectURI
	sessionMu.Unlock()

	resourceURL := os.Getenv("RESOURCE_URL")
	clientID := os.Getenv("GOOGLE_CLIENT_ID")

	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", resourceURL+"/callback")
	params.Set("response_type", "code")
	params.Set("scope", "openid email profile")
	params.Set("state", state)
	params.Set("access_type", "offline")

	googleAuthURL := "https://accounts.google.com/o/oauth2/v2/auth?" + params.Encode()
	http.Redirect(w, r, googleAuthURL, http.StatusFound)
}

// CallbackHandler receives code(A) from Google, exchanges it for Google tokens
// server-side, stores them internally, and redirects the client with a new code(B).
func CallbackHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	codeA := q.Get("code")
	state := q.Get("state")

	sessionMu.Lock()
	redirectURI, ok := sessions[state]
	delete(sessions, state)
	sessionMu.Unlock()

	if !ok {
		http.Error(w, "unknown state", http.StatusBadRequest)
		return
	}

	// Exchange code(A) with Google.
	googleTokens, err := exchangeWithGoogle(codeA)
	if err != nil {
		log.Printf("Google token exchange failed: %v", err)
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}

	// Extract userID and email from id_token.
	userID, email, err := extractSubAndEmail(googleTokens.IDToken)
	if err != nil {
		log.Printf("extractSubAndEmail failed: %v", err)
		http.Error(w, "invalid id_token", http.StatusInternalServerError)
		return
	}
	googleTokens.Email = email

	// Store Google tokens internally; they never leave the server.
	tokenMu.Lock()
	tokenStore[userID] = googleTokens
	tokenMu.Unlock()

	// Issue a one-time code(B) for the client.
	codeB := generateRandom(32)
	codeMu.Lock()
	codeStore[codeB] = userID
	codeMu.Unlock()

	// Redirect client with code(B) only.
	target, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	params := target.Query()
	params.Set("code", codeB)
	params.Set("state", state)
	target.RawQuery = params.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

// TokenHandler consumes code(B) and issues a proprietary JWT to the client.
// Google tokens are never included in the response.
func TokenHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	codeB := r.FormValue("code")

	// Consume code(B) → userID (one-time use).
	codeMu.Lock()
	userID, ok := codeStore[codeB]
	delete(codeStore, codeB)
	codeMu.Unlock()

	if !ok {
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}

	myJWT, err := issueJWT(userID)
	if err != nil {
		log.Printf("issueJWT failed: %v", err)
		http.Error(w, "token issue failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": myJWT,
		"token_type":   "Bearer",
		"expires_in":   3600,
		// refresh_token and id_token are intentionally omitted.
	})
}

// RegisterHandler implements RFC 7591 Dynamic Client Registration.
// Claude Code requires this endpoint. Since we proxy to Google (which doesn't
// support DCR), we ignore the request body and return our pre-configured
// Google Client ID as-is.
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req map[string]any
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("register decode error: %v", err)
	}

	clientID := os.Getenv("GOOGLE_CLIENT_ID")

	redirectURIs, _ := req["redirect_uris"].([]any)
	if redirectURIs == nil {
		redirectURIs = []any{}
	}

	resp := map[string]any{
		"client_id":                  clientID,
		"redirect_uris":              redirectURIs,
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// exchangeWithGoogle exchanges an authorization code for Google tokens using client_secret.
func exchangeWithGoogle(codeA string) (GoogleTokens, error) {
	resourceURL := os.Getenv("RESOURCE_URL")
	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")

	params := url.Values{}
	params.Set("grant_type", "authorization_code")
	params.Set("code", codeA)
	params.Set("redirect_uri", resourceURL+"/callback")
	params.Set("client_id", clientID)
	params.Set("client_secret", clientSecret)

	resp, err := http.PostForm("https://oauth2.googleapis.com/token", params)
	if err != nil {
		return GoogleTokens{}, fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return GoogleTokens{}, fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return GoogleTokens{}, fmt.Errorf("google token error %d: %s", resp.StatusCode, body)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return GoogleTokens{}, fmt.Errorf("parse token response: %w", err)
	}

	return GoogleTokens{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		IDToken:      tokenResp.IDToken,
	}, nil
}

// extractSubAndEmail parses a Google id_token and returns the sub and email claims.
// Signature verification is skipped because the token was received directly from
// Google's token endpoint (trusted channel).
func extractSubAndEmail(idToken string) (sub, email string, err error) {
	token, _, err := new(jwt.Parser).ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		return "", "", fmt.Errorf("parse id_token: %w", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", fmt.Errorf("invalid id_token claims type")
	}
	sub, _ = claims["sub"].(string)
	email, _ = claims["email"].(string)
	if sub == "" {
		return "", "", fmt.Errorf("sub claim missing from id_token")
	}
	return sub, email, nil
}

// generateRandom returns a URL-safe base64-encoded random string from n bytes.
func generateRandom(n int) string {
	b := make([]byte, n)
	rand.Read(b) //nolint:errcheck // crypto/rand.Read never returns an error on supported platforms
	return base64.RawURLEncoding.EncodeToString(b)
}

// issueJWT issues a proprietary HMAC-SHA256 signed JWT with sub=userID, exp=1h.
func issueJWT(userID string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": userID,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}
