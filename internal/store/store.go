package store

import (
	"errors"
	"sync"
)

// ErrNotFound is returned when a secret key does not exist in the store.
var ErrNotFound = errors.New("secret not found")

// ErrAlreadyExists is returned when a caller tries to create a key that already exists.
var ErrAlreadyExists = errors.New("secret already exists")

// Secret represents a single stored secret.
type Secret struct {
	Key   string
	Value string
}

// Store is a thread-safe in-memory secrets store.
type Store struct {
	mu      sync.RWMutex
	secrets map[string]Secret
}

// New creates and returns an initialised Store.
func New() *Store {
	return &Store{
		secrets: make(map[string]Secret),
	}
}

// Set stores a new secret. Returns ErrAlreadyExists if the key is taken.
func (s *Store) Set(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.secrets[key]; exists {
		return ErrAlreadyExists
	}

	s.secrets[key] = Secret{Key: key, Value: value}
	return nil
}

// Get retrieves a secret by key. Returns ErrNotFound if the key does not exist.
func (s *Store) Get(key string) (Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	secret, exists := s.secrets[key]
	if !exists {
		return Secret{}, ErrNotFound
	}

	return secret, nil
}

// Delete removes a secret by key. Returns ErrNotFound if the key does not exist.
func (s *Store) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.secrets[key]; !exists {
		return ErrNotFound
	}

	delete(s.secrets, key)
	return nil
}

// List returns all secrets currently in the store.
func (s *Store) List() []Secret {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]Secret, 0, len(s.secrets))
	for _, secret := range s.secrets {
		result = append(result, secret)
	}
	return result
}
