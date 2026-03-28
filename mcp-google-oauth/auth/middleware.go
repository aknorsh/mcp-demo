package auth

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type Middleware struct {
	resourceURL string
}

// NewMiddleware creates a Middleware that verifies proprietary JWTs issued by TokenHandler.
// clientID is accepted for API compatibility but is no longer used for JWT verification.
func NewMiddleware(resourceURL, clientID string) (*Middleware, error) {
	return &Middleware{resourceURL: resourceURL}, nil
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

		// Verify proprietary JWT signed with our own HMAC secret.
		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return jwtSecret, nil
		}, jwt.WithExpirationRequired())
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

		userID, _ := claims["sub"].(string)

		// Retrieve Google tokens (stored server-side) to obtain the user's email.
		tokenMu.Lock()
		gTokens, found := tokenStore[userID]
		tokenMu.Unlock()

		if !found {
			http.Error(w, "user session not found", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), contextKeyEmail, gTokens.Email)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type contextKey string

const contextKeyEmail contextKey = "email"

// EmailFromContext returns the authenticated user's email address.
func EmailFromContext(ctx context.Context) string {
	email, _ := ctx.Value(contextKeyEmail).(string)
	return email
}
