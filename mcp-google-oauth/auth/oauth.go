package auth

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
)

var (
	sessionMu sync.Mutex
	sessions  = map[string]string{} // state -> redirect_uri
)

func AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	redirectURI := q.Get("redirect_uri")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")

	// セッションにredirect_uriを保存
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
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", codeChallengeMethod)
	params.Set("state", state)
	params.Set("access_type", "offline")

	googleAuthURL := "https://accounts.google.com/o/oauth2/v2/auth?" + params.Encode()
	http.Redirect(w, r, googleAuthURL, http.StatusFound)
}

func CallbackHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := q.Get("code")
	state := q.Get("state")

	sessionMu.Lock()
	redirectURI, ok := sessions[state]
	delete(sessions, state)
	sessionMu.Unlock()

	if !ok {
		http.Error(w, "unknown state", http.StatusBadRequest)
		return
	}

	target, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}

	params := target.Query()
	params.Set("code", code)
	params.Set("state", state)
	target.RawQuery = params.Encode()

	http.Redirect(w, r, target.String(), http.StatusFound)
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

func TokenHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	resourceURL := os.Getenv("RESOURCE_URL")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")

	params := url.Values{}
	params.Set("grant_type", r.FormValue("grant_type"))
	params.Set("code", r.FormValue("code"))
	params.Set("redirect_uri", resourceURL+"/callback")
	params.Set("code_verifier", r.FormValue("code_verifier"))
	params.Set("client_id", r.FormValue("client_id"))
	params.Set("client_secret", clientSecret)

	resp, err := http.PostForm("https://oauth2.googleapis.com/token", params)
	if err != nil {
		log.Printf("token proxy error: %v", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("token read error: %v", err)
		http.Error(w, "read error", http.StatusInternalServerError)
		return
	}

	// id_tokenをaccess_tokenとして返す（Claude CodeがBearer tokenとして使えるように）
	var tokenResp map[string]any
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		log.Printf("token parse error: %v", err)
		http.Error(w, "parse error", http.StatusInternalServerError)
		return
	}

	if idToken, ok := tokenResp["id_token"].(string); ok {
		tokenResp["access_token"] = idToken
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	if err := json.NewEncoder(w).Encode(tokenResp); err != nil {
		log.Printf("token encode error: %v", err)
	}

}
