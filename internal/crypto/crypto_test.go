package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	tests := []struct {
		name      string
		plaintext string
	}{
		{name: "simple secret", plaintext: "my_password_123"},
		{name: "empty string", plaintext: ""},
		{name: "long secret", plaintext: "this-is-a-very-long-secret-value-that-exceeds-one-block"},
		{name: "special characters", plaintext: "p@$$w0rd!#%^&*()"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := Encrypt(key, []byte(tt.plaintext))
			if err != nil {
				t.Fatalf("Encrypt() unexpected error: %v", err)
			}

			decrypted, err := Decrypt(key, encrypted)
			if err != nil {
				t.Fatalf("Decrypt() unexpected error: %v", err)
			}

			if !bytes.Equal(decrypted, []byte(tt.plaintext)) {
				t.Errorf("round trip failed: got %q, want %q", decrypted, tt.plaintext)
			}
		})
	}
}

func TestEncrypt_NonceIsUnique(t *testing.T) {
	key := make([]byte, 32)

	result1, err := Encrypt(key, []byte("same plaintext"))
	if err != nil {
		t.Fatalf("first Encrypt() error: %v", err)
	}

	result2, err := Encrypt(key, []byte("same plaintext"))
	if err != nil {
		t.Fatalf("second Encrypt() error: %v", err)
	}

	if bytes.Equal(result1, result2) {
		t.Error("two encryptions of the same plaintext produced identical output: nonce is not random")
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)

	encrypted, err := Encrypt(key, []byte("sensitive data"))
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	encrypted[len(encrypted)-1] ^= 0xFF

	_, err = Decrypt(key, encrypted)
	if err == nil {
		t.Error("Decrypt() should have failed on tampered ciphertext but did not")
	}
}

func TestEncrypt_InvalidKeySize(t *testing.T) {
	badKey := make([]byte, 16)
	_, err := Encrypt(badKey, []byte("test"))
	if err != ErrInvalidKeySize {
		t.Errorf("Encrypt() with 16-byte key: got %v, want ErrInvalidKeySize", err)
	}
}
