package auth

import (
	"encoding/json"
	"net/http"
	"os"
)

func ProtectedResourceMetadataHandler(w http.ResponseWriter, r *http.Request) {
	resourceURL := os.Getenv("RESOURCE_URL")
	resp := map[string]any{
		"resource":             resourceURL,
		"authorization_servers": []string{resourceURL},
		"scopes_supported":     []string{"openid", "email", "profile"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func AuthorizationServerMetadataHandler(w http.ResponseWriter, r *http.Request) {
	resourceURL := os.Getenv("RESOURCE_URL")
	resp := map[string]any{
		"issuer":                           resourceURL,
		"authorization_endpoint":           resourceURL + "/authorize",
		"token_endpoint":                   resourceURL + "/token",
		"registration_endpoint":            resourceURL + "/register",
		"response_types_supported":         []string{"code"},
		"grant_types_supported":            []string{"authorization_code"},
		"code_challenge_methods_supported": []string{"S256"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
