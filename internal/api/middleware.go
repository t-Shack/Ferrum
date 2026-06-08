package api

import (
	"net/http"
	"strings"

	"github.com/t-Shack/Ferrum/internal/token"
)

// responseRecorder wraps http.ResponseWriter to capture the status code.
type responseRecorder struct {
	http.ResponseWriter
	status int
}

// WriteHeader captures the status code before passing it to the real writer.
func (rr *responseRecorder) WriteHeader(status int) {
	rr.status = status
	rr.ResponseWriter.WriteHeader(status)
}

// requireAuth validates the JWT, enforces RBAC, and logs the request.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeError(w, http.StatusUnauthorized, "missing authorization header")
			s.logRequest("anonymous", "", r.Method, r.URL.Path, http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "authorization header must use Bearer scheme")
			s.logRequest("anonymous", "", r.Method, r.URL.Path, http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		claims, err := token.Verify(s.tokenKey, tokenString)
		if err != nil {
			if err == token.ErrExpiredToken {
				writeError(w, http.StatusUnauthorized, "token has expired")
				s.logRequest("anonymous", "", r.Method, r.URL.Path, http.StatusUnauthorized)
				return
			}
			writeError(w, http.StatusUnauthorized, "invalid token")
			s.logRequest("anonymous", "", r.Method, r.URL.Path, http.StatusUnauthorized)
			return
		}

		path := r.URL.Path
		if strings.HasPrefix(path, "/secrets/") {
			path = "/secrets/"
		}

		if !isAuthorized(claims.Role, r.Method, path) {
			writeError(w, http.StatusForbidden, "insufficient permissions")
			s.logRequest(claims.Subject, claims.Role, r.Method, r.URL.Path, http.StatusForbidden)
			return
		}

		r.Header.Set("X-Subject", claims.Subject)
		r.Header.Set("X-Role", claims.Role)

		rr := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
		next(rr, r)

		s.logRequest(claims.Subject, claims.Role, r.Method, r.URL.Path, rr.status)
	}
}

// logRequest writes an audit entry if the logger is available.
func (s *Server) logRequest(subject, role, method, path string, status int) {
	if s.audit == nil {
		return
	}
	s.audit.Log(subject, role, method, path, status)
}
