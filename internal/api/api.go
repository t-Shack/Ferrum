package api

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/t-Shack/Ferrum/internal/audit"
	"github.com/t-Shack/Ferrum/internal/store"
	"github.com/t-Shack/Ferrum/internal/token"
)

const tokenTTL = 1 * time.Hour

// credentials holds the single hardcoded admin user for this version.
// Real credential storage comes in a later version.
var credentials = map[string]string{
	"admin":  "ferrum-admin-password",
	"reader": "ferrum-reader-password",
}

// Server holds the router and all dependencies the handlers need.
type Server struct {
	mux      *http.ServeMux
	store    *store.Store
	tokenKey []byte
	audit    *audit.Logger
}

// New creates a new Server, wires up all routes, and returns it.
func New(st *store.Store, tokenKey []byte, auditLogger *audit.Logger) *Server {
	s := &Server{
		mux:      http.NewServeMux(),
		store:    st,
		tokenKey: tokenKey,
		audit:    auditLogger,
	}
	s.routes()
	return s
}

// ServeHTTP makes Server implement the http.Handler interface.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// routes registers all API endpoints.
func (s *Server) routes() {
	s.mux.HandleFunc("/auth", s.handleAuth)
	s.mux.HandleFunc("/secrets", s.requireAuth(s.handleSecrets))
	s.mux.HandleFunc("/secrets/", s.requireAuth(s.handleSecretByKey))
}

// writeJSON encodes v as JSON and writes it to the response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response with a single "error" field.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// handleAuth handles POST /auth and issues a signed JWT on valid credentials.
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	expectedPassword, ok := credentials[body.Username]
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if subtle.ConstantTimeCompare([]byte(expectedPassword), []byte(body.Password)) != 1 {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	role, ok := map[string]string{
		"admin":  roleAdmin,
		"reader": roleReader,
	}[body.Username]
	if !ok {
		writeError(w, http.StatusInternalServerError, "role not configured")
		return
	}
	tokenString, err := token.Issue(s.tokenKey, body.Username, role, tokenTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to issue token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"token": tokenString})
}

// handleSecrets routes POST /secrets and GET /secrets.
func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.createSecret(w, r)
	case http.MethodGet:
		s.listSecrets(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleSecretByKey routes GET /secrets/{key} and DELETE /secrets/{key}.
func (s *Server) handleSecretByKey(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/secrets/")
	if key == "" {
		writeError(w, http.StatusBadRequest, "missing secret key in path")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getSecret(w, r, key)
	case http.MethodDelete:
		s.deleteSecret(w, r, key)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// createSecret handles POST /secrets.
func (s *Server) createSecret(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if body.Key == "" || body.Value == "" {
		writeError(w, http.StatusBadRequest, "key and value are required")
		return
	}

	if err := s.store.Set(body.Key, body.Value); err != nil {
		if err == store.ErrAlreadyExists {
			writeError(w, http.StatusConflict, "secret already exists")
			return
		}
		if err == store.ErrInvalidKey {
			writeError(w, http.StatusBadRequest, "invalid secret key")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to store secret")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"message": "secret stored successfully"})
}

// getSecret handles GET /secrets/{key}.
func (s *Server) getSecret(w http.ResponseWriter, r *http.Request, key string) {
	secret, err := s.store.Get(key)
	if err != nil {
		if err == store.ErrNotFound {
			writeError(w, http.StatusNotFound, "secret not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to retrieve secret")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"key":   secret.Key,
		"value": secret.Value,
	})
}

// deleteSecret handles DELETE /secrets/{key}.
func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request, key string) {
	if err := s.store.Delete(key); err != nil {
		if err == store.ErrNotFound {
			writeError(w, http.StatusNotFound, "secret not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to delete secret")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "secret deleted successfully"})
}

// listSecrets handles GET /secrets.
func (s *Server) listSecrets(w http.ResponseWriter, r *http.Request) {
	secrets := s.store.List()

	keys := make([]string, 0, len(secrets))
	for _, s := range secrets {
		keys = append(keys, s.Key)
	}

	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}
