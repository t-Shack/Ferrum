package api

import (
	"net/http"
	"strings"

	"github.com/t-Shack/Ferrum/internal/token"
)

// requireAuth is middleware that validates a JWT from the Authorization header.
// If the token is valid, it passes the verified claims downstream and
// enforces the access policy for the requested resource.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeError(w, http.StatusUnauthorized, "missing authorization header")
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "authorization header must use Bearer scheme")
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		claims, err := token.Verify(s.tokenKey, tokenString)
		if err != nil {
			if err == token.ErrExpiredToken {
				writeError(w, http.StatusUnauthorized, "token has expired")
				return
			}
			writeError(w, http.StatusUnauthorized, "invalid token")
			return
		}

		path := r.URL.Path
		if strings.HasPrefix(path, "/secrets/") {
			path = "/secrets/"
		}

		if !isAuthorized(claims.Role, r.Method, path) {
			writeError(w, http.StatusForbidden, "insufficient permissions")
			return
		}

		r.Header.Set("X-Subject", claims.Subject)
		r.Header.Set("X-Role", claims.Role)

		next(w, r)
	}
}
