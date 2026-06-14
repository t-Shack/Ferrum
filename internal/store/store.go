package store

import (
	"errors"
	"sync"
)

// ErrNotFound is returned when a secret key does not exist in the store.
var ErrNotFound = errors.New("secret not found")

// ErrAlreadyExists is returned when a caller tries to create a key that already exists.
var ErrAlreadyExists = errors.New("secret already exists")

// ErrInvalidKey is returned when a secret key contains invalid characters or is empty.
var ErrInvalidKey = errors.New("invalid secret key")

// Secret represents a single stored secret.
type Secret struct {
	Key   string
	Value string
}

// Store is a thread-safe in-memory secrets store backed by encrypted disk persistence.
type Store struct {
	mu            sync.RWMutex
	secrets       map[string]Secret
	encryptionKey []byte
}

// New creates and returns an initialised Store, loading any existing secrets from disk.
func New(encryptionKey []byte) (*Store, error) {
	s := &Store{
		secrets:       make(map[string]Secret),
		encryptionKey: encryptionKey,
	}

	existing, err := loadFromDisk(encryptionKey)
	if err != nil {
		return nil, err
	}

	for _, secret := range existing {
		s.secrets[secret.Key] = secret
	}

	return s, nil
}

// Set stores a new secret in memory and persists it encrypted to disk.
func (s *Store) Set(key, value string) error {
	if !validKey(key) {
		return ErrInvalidKey
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.secrets[key]; exists {
		return ErrAlreadyExists
	}

	secret := Secret{Key: key, Value: value}

	if err := saveToDisk(s.encryptionKey, secret); err != nil {
		return err
	}

	s.secrets[key] = secret
	return nil
}

// Get retrieves a secret by key.
func (s *Store) Get(key string) (Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	secret, exists := s.secrets[key]
	if !exists {
		return Secret{}, ErrNotFound
	}

	return secret, nil
}

// Delete removes a secret from memory and from disk.
func (s *Store) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.secrets[key]; !exists {
		return ErrNotFound
	}

	if err := deleteFromDisk(key); err != nil {
		return err
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

// validKey returns true if the key is safe to use as a filename.
func validKey(key string) bool {
	if key == "" {
		return false
	}
	for _, c := range key {
		if c == '/' || c == '\\' || c == '.' || c == 0 {
			return false
		}
	}
	return true
}
