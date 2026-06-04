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

func getToken(t *testing.T, srv *Server, username, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	req := httptest.NewRequest(http.MethodPost, "/auth", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("auth failed for %q: status %d body %s", username, rec.Code, rec.Body.String())
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
			req := httptest.NewRequest(http.MethodPost, "/auth",
				bytes.NewBufferString(tt.body))
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
		t.Errorf("unauthenticated request: status = %d, want %d",
			rec.Code, http.StatusUnauthorized)
	}
}

func TestAdminCanCreateAndReadSecret(t *testing.T) {
	defer cleanup(t)
	srv := newTestServer(t)
	tok := getToken(t, srv, "admin", "ferrum-admin-password")

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
}

func TestReaderCanReadButNotCreate(t *testing.T) {
	defer cleanup(t)
	srv := newTestServer(t)

	adminTok := getToken(t, srv, "admin", "ferrum-admin-password")
	createReq := httptest.NewRequest(http.MethodPost, "/secrets",
		bytes.NewBufferString(`{"key":"shared_key","value":"secret123"}`))
	createReq.Header.Set("Authorization", "Bearer "+adminTok)
	srv.ServeHTTP(httptest.NewRecorder(), createReq)

	readerTok := getToken(t, srv, "reader", "ferrum-reader-password")

	getReq := httptest.NewRequest(http.MethodGet, "/secrets/shared_key", nil)
	getReq.Header.Set("Authorization", "Bearer "+readerTok)
	getRec := httptest.NewRecorder()
	srv.ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusOK {
		t.Errorf("reader GET status = %d, want %d", getRec.Code, http.StatusOK)
	}

	postReq := httptest.NewRequest(http.MethodPost, "/secrets",
		bytes.NewBufferString(`{"key":"new_key","value":"val"}`))
	postReq.Header.Set("Authorization", "Bearer "+readerTok)
	postRec := httptest.NewRecorder()
	srv.ServeHTTP(postRec, postReq)

	if postRec.Code != http.StatusForbidden {
		t.Errorf("reader POST status = %d, want %d", postRec.Code, http.StatusForbidden)
	}
}

func TestReaderCannotDelete(t *testing.T) {
	defer cleanup(t)
	srv := newTestServer(t)

	adminTok := getToken(t, srv, "admin", "ferrum-admin-password")
	createReq := httptest.NewRequest(http.MethodPost, "/secrets",
		bytes.NewBufferString(`{"key":"to_delete","value":"val"}`))
	createReq.Header.Set("Authorization", "Bearer "+adminTok)
	srv.ServeHTTP(httptest.NewRecorder(), createReq)

	readerTok := getToken(t, srv, "reader", "ferrum-reader-password")

	delReq := httptest.NewRequest(http.MethodDelete, "/secrets/to_delete", nil)
	delReq.Header.Set("Authorization", "Bearer "+readerTok)
	delRec := httptest.NewRecorder()
	srv.ServeHTTP(delRec, delReq)

	if delRec.Code != http.StatusForbidden {
		t.Errorf("reader DELETE status = %d, want %d", delRec.Code, http.StatusForbidden)
	}
}
