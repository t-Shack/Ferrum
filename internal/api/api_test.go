package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/t-Shack/Ferrum/internal/store"
)

func testStoreKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

func testTokenKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 50)
	}
	return key
}

func cleanup(t *testing.T) {
	t.Helper()
	os.RemoveAll("data/secrets")
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.New(testStoreKey())
	if err != nil {
		t.Fatalf("store.New() error: %v", err)
	}
	return New(st, testTokenKey())
}

func getTestToken(t *testing.T, srv *Server) string {
	t.Helper()
	body := `{"username":"admin","password":"ferrum-admin-password"}`
	req := httptest.NewRequest(http.MethodPost, "/auth", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("auth failed: status %d", rec.Code)
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	return resp["token"]
}

func TestAuth_ValidCredentials(t *testing.T) {
	srv := newTestServer(t)

	body := `{"username":"admin","password":"ferrum-admin-password"}`
	req := httptest.NewRequest(http.MethodPost, "/auth", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["token"] == "" {
		t.Error("expected token in response, got empty string")
	}
}

func TestAuth_InvalidCredentials(t *testing.T) {
	srv := newTestServer(t)

	tests := []struct {
		name string
		body string
	}{
		{name: "wrong password", body: `{"username":"admin","password":"wrong"}`},
		{name: "unknown user", body: `{"username":"ghost","password":"anything"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth", bytes.NewBufferString(tt.body))
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestSecrets_RequiresAuth(t *testing.T) {
	defer cleanup(t)
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated request: status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestCreateAndGetSecret_Authenticated(t *testing.T) {
	defer cleanup(t)
	srv := newTestServer(t)
	tok := getTestToken(t, srv)

	createReq := httptest.NewRequest(http.MethodPost, "/secrets",
		bytes.NewBufferString(`{"key":"db_pass","value":"hunter2"}`))
	createReq.Header.Set("Authorization", "Bearer "+tok)
	createRec := httptest.NewRecorder()
	srv.ServeHTTP(createRec, createReq)

	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d", createRec.Code, http.StatusCreated)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/secrets/db_pass", nil)
	getReq.Header.Set("Authorization", "Bearer "+tok)
	getRec := httptest.NewRecorder()
	srv.ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusOK {
		t.Fatalf("get status = %d, want %d", getRec.Code, http.StatusOK)
	}

	var resp map[string]string
	json.NewDecoder(getRec.Body).Decode(&resp)
	if resp["value"] != "hunter2" {
		t.Errorf("value = %q, want %q", resp["value"], "hunter2")
	}
}

func TestCreateSecret_Unauthenticated(t *testing.T) {
	defer cleanup(t)
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/secrets",
		bytes.NewBufferString(`{"key":"db_pass","value":"hunter2"}`))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}
