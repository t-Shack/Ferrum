package crypto

import "testing"

func TestGenerateID(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		n        int
		expected string
	}{
		{name: "basic case", prefix: "secret", n: 1, expected: "secret_1"},
		{name: "zero value", prefix: "key", n: 0, expected: "key_0"},
		{name: "negative becomes zero", prefix: "tok", n: -5, expected: "tok_0"},
		{name: "large number", prefix: "id", n: 999, expected: "id_999"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenerateID(tt.prefix, tt.n)
			if result != tt.expected {
				t.Errorf("GenerateID(%q, %d) = %q, want %q", tt.prefix, tt.n, result, tt.expected)
			}
		})
	}
}
