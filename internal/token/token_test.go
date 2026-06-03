package token

import (
	"testing"
	"time"
)

func testKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

func TestIssueAndVerify_RoundTrip(t *testing.T) {
	key := testKey()

	tests := []struct {
		name    string
		subject string
		role    string
		ttl     time.Duration
	}{
		{name: "admin token", subject: "admin", role: "admin", ttl: time.Hour},
		{name: "reader token", subject: "reader", role: "reader", ttl: 15 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString, err := Issue(key, tt.subject, tt.role, tt.ttl)
			if err != nil {
				t.Fatalf("Issue() error: %v", err)
			}

			claims, err := Verify(key, tokenString)
			if err != nil {
				t.Fatalf("Verify() error: %v", err)
			}

			if claims.Subject != tt.subject {
				t.Errorf("Subject = %q, want %q", claims.Subject, tt.subject)
			}
			if claims.Role != tt.role {
				t.Errorf("Role = %q, want %q", claims.Role, tt.role)
			}
		})
	}
}

func TestVerify_ExpiredToken(t *testing.T) {
	key := testKey()

	tokenString, err := Issue(key, "user", "reader", -time.Second)
	if err != nil {
		t.Fatalf("Issue() error: %v", err)
	}

	_, err = Verify(key, tokenString)
	if err != ErrExpiredToken {
		t.Errorf("Verify() error = %v, want ErrExpiredToken", err)
	}
}

func TestVerify_TamperedPayload(t *testing.T) {
	key := testKey()

	tokenString, err := Issue(key, "reader", "reader", time.Hour)
	if err != nil {
		t.Fatalf("Issue() error: %v", err)
	}

	parts := splitToken(tokenString)
	tampered := parts[0] + "." + parts[1] + "extra" + "." + parts[2]

	_, err = Verify(key, tampered)
	if err != ErrInvalidToken {
		t.Errorf("Verify() on tampered payload = %v, want ErrInvalidToken", err)
	}
}

func TestVerify_WrongKey(t *testing.T) {
	key1 := testKey()
	key2 := make([]byte, 32)
	for i := range key2 {
		key2[i] = byte(i + 10)
	}

	tokenString, err := Issue(key1, "user", "admin", time.Hour)
	if err != nil {
		t.Fatalf("Issue() error: %v", err)
	}

	_, err = Verify(key2, tokenString)
	if err != ErrInvalidToken {
		t.Errorf("Verify() with wrong key = %v, want ErrInvalidToken", err)
	}
}

func TestVerify_MalformedToken(t *testing.T) {
	key := testKey()

	tests := []struct {
		name  string
		token string
	}{
		{name: "empty string", token: ""},
		{name: "only two parts", token: "header.payload"},
		{name: "four parts", token: "a.b.c.d"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Verify(key, tt.token)
			if err != ErrInvalidToken {
				t.Errorf("Verify(%q) = %v, want ErrInvalidToken", tt.token, err)
			}
		})
	}
}

// splitToken is a test helper that splits a JWT into its three parts.
func splitToken(tokenString string) [3]string {
	var parts [3]string
	s := tokenString
	for i := 0; i < 3; i++ {
		idx := -1
		for j := 0; j < len(s); j++ {
			if s[j] == '.' {
				idx = j
				break
			}
		}
		if idx == -1 {
			parts[i] = s
			break
		}
		parts[i] = s[:idx]
		s = s[idx+1:]
	}
	return parts
}
