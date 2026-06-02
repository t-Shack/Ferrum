package store

import (
	"os"
	"path/filepath"

	"github.com/t-Shack/Ferrum/internal/crypto"
)

const secretsDir = "data/secrets"

// ensureDir creates the secrets directory if it does not already exist.
func ensureDir() error {
	return os.MkdirAll(secretsDir, 0700)
}

// secretPath returns the full file path for a given secret key.
func secretPath(key string) string {
	return filepath.Join(secretsDir, key+".secret")
}

// saveToDisk encrypts a secret value and writes it to disk.
func saveToDisk(encryptionKey []byte, s Secret) error {
	if err := ensureDir(); err != nil {
		return err
	}

	encrypted, err := crypto.Encrypt(encryptionKey, []byte(s.Value))
	if err != nil {
		return err
	}

	return os.WriteFile(secretPath(s.Key), encrypted, 0600)
}

// deleteFromDisk removes the file for a given secret key.
func deleteFromDisk(key string) error {
	err := os.Remove(secretPath(key))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// loadFromDisk reads all secret files from the secrets directory,
// decrypts each one, and returns them as a slice of Secrets.
func loadFromDisk(encryptionKey []byte) ([]Secret, error) {
	if err := ensureDir(); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(secretsDir)
	if err != nil {
		return nil, err
	}

	var secrets []Secret

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if filepath.Ext(name) != ".secret" {
			continue
		}

		data, err := os.ReadFile(filepath.Join(secretsDir, name))
		if err != nil {
			return nil, err
		}

		plaintext, err := crypto.Decrypt(encryptionKey, data)
		if err != nil {
			return nil, err
		}

		key := name[:len(name)-len(".secret")]
		secrets = append(secrets, Secret{Key: key, Value: string(plaintext)})
	}

	return secrets, nil
}
