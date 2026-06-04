package api

import (
	"net/http"
	"strings"

	"github.com/t-Shack/Ferrum/internal/token"
)

// requireAuth is middleware that validates a JWT from the Authorization header.
// If the token is valid, the request proceeds. Otherwise it returns 401.
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

		r.Header.Set("X-Subject", claims.Subject)
		r.Header.Set("X-Role", claims.Role)

		next(w, r)
	}
}
