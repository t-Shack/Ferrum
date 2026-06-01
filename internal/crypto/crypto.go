package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// ErrInvalidKeySize is returned when the provided key is not 32 bytes.
var ErrInvalidKeySize = errors.New("encryption key must be exactly 32 bytes")

// ErrCiphertextTooShort is returned when the ciphertext is shorter than the nonce size.
var ErrCiphertextTooShort = errors.New("ciphertext too short")

// Encrypt takes a 32-byte key and plaintext, and returns authenticated ciphertext.
// The output format is: nonce (12 bytes) + ciphertext.
func Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt takes a 32-byte key and the combined nonce+ciphertext produced by Encrypt,
// and returns the original plaintext. Returns an error if the data was tampered with.
func Decrypt(key []byte, data []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(data) < gcm.NonceSize() {
		return nil, ErrCiphertextTooShort
	}

	nonce := data[:gcm.NonceSize()]
	ciphertext := data[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
