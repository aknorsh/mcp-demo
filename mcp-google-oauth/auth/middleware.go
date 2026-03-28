package auth

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

type Middleware struct {
	resourceURL string
	clientID    string
	jwks        keyfunc.Keyfunc
}

func NewMiddleware(resourceURL, clientID string) (*Middleware, error) {
	jwks, err := keyfunc.NewDefault([]string{"https://www.googleapis.com/oauth2/v3/certs"})
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS: %w", err)
	}
	return &Middleware{
		resourceURL: resourceURL,
		clientID:    clientID,
		jwks:        jwks,
	}, nil
}

var skipPaths = []string{
	"/.well-known/",
	"/authorize",
	"/callback",
	"/token",
	"/register",
}

func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for _, prefix := range skipPaths {
			if strings.HasPrefix(path, prefix) {
				next.ServeHTTP(w, r)
				return
			}
		}

		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, m.resourceURL))
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		token, err := jwt.Parse(tokenStr, m.jwks.Keyfunc,
			jwt.WithIssuer("https://accounts.google.com"),
			jwt.WithExpirationRequired(),
		)
		if err != nil || !token.Valid {
			log.Printf("JWT validation error: %v", err)
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "invalid claims", http.StatusUnauthorized)
			return
		}

		// aud検証
		audValid := false
		switch aud := claims["aud"].(type) {
		case string:
			audValid = aud == m.clientID
		case []any:
			for _, a := range aud {
				if s, ok := a.(string); ok && s == m.clientID {
					audValid = true
					break
				}
			}
		}
		if !audValid {
			http.Error(w, "invalid audience", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), contextKeyClaims, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type contextKey string

const contextKeyClaims contextKey = "claims"

// EmailFromContext returns the authenticated user's email from the JWT claims.
func EmailFromContext(ctx context.Context) string {
	claims, ok := ctx.Value(contextKeyClaims).(jwt.MapClaims)
	if !ok {
		return ""
	}
	email, _ := claims["email"].(string)
	return email
}
