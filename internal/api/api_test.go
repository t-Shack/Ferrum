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

func testKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

func cleanup(t *testing.T) {
	t.Helper()
	os.RemoveAll("data/secrets")
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.New(testKey())
	if err != nil {
		t.Fatalf("store.New() error: %v", err)
	}
	return New(st)
}

func TestCreateSecret(t *testing.T) {
	defer cleanup(t)
	srv := newTestServer(t)

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{name: "valid secret", body: `{"key":"db_pass","value":"hunter2"}`, wantStatus: http.StatusCreated},
		{name: "duplicate key", body: `{"key":"db_pass","value":"other"}`, wantStatus: http.StatusConflict},
		{name: "missing value", body: `{"key":"db_pass"}`, wantStatus: http.StatusBadRequest},
		{name: "invalid json", body: `not json`, wantStatus: http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBufferString(tt.body))
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestGetSecret(t *testing.T) {
	defer cleanup(t)
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBufferString(`{"key":"api_key","value":"secret123"}`))
	srv.ServeHTTP(httptest.NewRecorder(), req)

	tests := []struct {
		name       string
		path       string
		wantStatus int
		wantValue  string
	}{
		{name: "existing key", path: "/secrets/api_key", wantStatus: http.StatusOK, wantValue: "secret123"},
		{name: "missing key", path: "/secrets/ghost", wantStatus: http.StatusNotFound, wantValue: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			if tt.wantValue != "" {
				var resp map[string]string
				json.NewDecoder(rec.Body).Decode(&resp)
				if resp["value"] != tt.wantValue {
					t.Errorf("value = %q, want %q", resp["value"], tt.wantValue)
				}
			}
		})
	}
}

func TestDeleteSecret(t *testing.T) {
	defer cleanup(t)
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBufferString(`{"key":"temp","value":"val"}`))
	srv.ServeHTTP(httptest.NewRecorder(), req)

	req = httptest.NewRequest(http.MethodDelete, "/secrets/temp", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Delete status = %d, want %d", rec.Code, http.StatusOK)
	}

	req = httptest.NewRequest(http.MethodGet, "/secrets/temp", nil)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("Get after Delete status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	defer cleanup(t)
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodPut, "/secrets", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}
