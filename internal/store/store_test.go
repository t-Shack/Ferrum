package store

import (
	"testing"
)

func TestStore_SetAndGet(t *testing.T) {
	s := New()

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
		t.Fatalf("Get(db_pass) unexpected error: %v", err)
	}
	if got.Value != "hunter2" {
		t.Errorf("Get(db_pass) value = %q, want %q", got.Value, "hunter2")
	}
}

func TestStore_GetNotFound(t *testing.T) {
	s := New()

	_, err := s.Get("nonexistent")
	if err != ErrNotFound {
		t.Errorf("Get(nonexistent) error = %v, want ErrNotFound", err)
	}
}

func TestStore_Delete(t *testing.T) {
	s := New()

	_ = s.Set("api_key", "abc123")

	err := s.Delete("api_key")
	if err != nil {
		t.Errorf("Delete(api_key) unexpected error: %v", err)
	}

	_, err = s.Get("api_key")
	if err != ErrNotFound {
		t.Errorf("after Delete, Get(api_key) error = %v, want ErrNotFound", err)
	}
}

func TestStore_List(t *testing.T) {
	s := New()

	_ = s.Set("key1", "val1")
	_ = s.Set("key2", "val2")

	list := s.List()
	if len(list) != 2 {
		t.Errorf("List() returned %d secrets, want 2", len(list))
	}
}
