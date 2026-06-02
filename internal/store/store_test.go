package store

import (
	"os"
	"testing"
)

// testKey returns a deterministic 32-byte encryption key for tests.
func testKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

// cleanup removes the secrets directory after each test.
func cleanup(t *testing.T) {
	t.Helper()
	os.RemoveAll(secretsDir)
}

func TestStore_SetAndGet(t *testing.T) {
	defer cleanup(t)

	s, err := New(testKey())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	tests := []struct {
		name      string
		key       string
		value     string
		expectErr error
	}{
		{name: "store new secret", key: "db_pass", value: "hunter2", expectErr: nil},
		{name: "duplicate key", key: "db_pass", value: "other", expectErr: ErrAlreadyExists},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.Set(tt.key, tt.value)
			if err != tt.expectErr {
				t.Errorf("Set(%q, %q) error = %v, want %v", tt.key, tt.value, err, tt.expectErr)
			}
		})
	}

	got, err := s.Get("db_pass")
	if err != nil {
		t.Fatalf("Get() unexpected error: %v", err)
	}
	if got.Value != "hunter2" {
		t.Errorf("Get() value = %q, want %q", got.Value, "hunter2")
	}
}

func TestStore_Persistence(t *testing.T) {
	defer cleanup(t)

	key := testKey()

	s1, err := New(key)
	if err != nil {
		t.Fatalf("first New() error: %v", err)
	}

	if err := s1.Set("api_key", "supersecret"); err != nil {
		t.Fatalf("Set() error: %v", err)
	}

	s2, err := New(key)
	if err != nil {
		t.Fatalf("second New() error: %v", err)
	}

	got, err := s2.Get("api_key")
	if err != nil {
		t.Fatalf("Get() after reload error: %v", err)
	}
	if got.Value != "supersecret" {
		t.Errorf("Get() after reload = %q, want %q", got.Value, "supersecret")
	}
}

func TestStore_DeleteRemovesFromDisk(t *testing.T) {
	defer cleanup(t)

	s, err := New(testKey())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	if err := s.Set("temp_key", "temp_value"); err != nil {
		t.Fatalf("Set() error: %v", err)
	}

	if err := s.Delete("temp_key"); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	if _, err := os.Stat(secretPath("temp_key")); !os.IsNotExist(err) {
		t.Error("secret file still exists on disk after Delete()")
	}
}

func TestStore_GetNotFound(t *testing.T) {
	defer cleanup(t)

	s, err := New(testKey())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	_, err = s.Get("nonexistent")
	if err != ErrNotFound {
		t.Errorf("Get() error = %v, want ErrNotFound", err)
	}
}
