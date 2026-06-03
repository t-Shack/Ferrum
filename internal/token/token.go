package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// ErrInvalidToken is returned when a token cannot be parsed or verified.
var ErrInvalidToken = errors.New("invalid token")

// ErrExpiredToken is returned when a token's expiry time has passed.
var ErrExpiredToken = errors.New("token has expired")

// header represents the JWT header.
type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// Claims represents the JWT payload.
type Claims struct {
	Subject  string `json:"sub"`
	Role     string `json:"role"`
	IssuedAt int64  `json:"iat"`
	Expiry   int64  `json:"exp"`
}

// Issue creates and signs a new JWT for the given subject and role.
// The token expires after the given duration.
func Issue(secretKey []byte, subject, role string, ttl time.Duration) (string, error) {
	h := header{Alg: "HS256", Typ: "JWT"}

	headerJSON, err := json.Marshal(h)
	if err != nil {
		return "", err
	}

	now := time.Now()
	c := Claims{
		Subject:  subject,
		Role:     role,
		IssuedAt: now.Unix(),
		Expiry:   now.Add(ttl).Unix(),
	}

	claimsJSON, err := json.Marshal(c)
	if err != nil {
		return "", err
	}

	encodedHeader := base64url(headerJSON)
	encodedClaims := base64url(claimsJSON)

	signingInput := encodedHeader + "." + encodedClaims
	sig := sign(secretKey, signingInput)

	return signingInput + "." + sig, nil
}

// Verify parses and validates a JWT string.
// Returns the Claims if the token is valid and not expired.
func Verify(secretKey []byte, tokenString string) (Claims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return Claims{}, ErrInvalidToken
	}

	signingInput := parts[0] + "." + parts[1]
	expectedSig := sign(secretKey, signingInput)

	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return Claims{}, ErrInvalidToken
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrInvalidToken
	}

	var c Claims
	if err := json.Unmarshal(claimsJSON, &c); err != nil {
		return Claims{}, ErrInvalidToken
	}

	if time.Now().Unix() > c.Expiry {
		return Claims{}, ErrExpiredToken
	}

	return c, nil
}

// sign computes the HMAC-SHA256 signature of the input using the secret key.
// The result is Base64URL encoded without padding.
func sign(secretKey []byte, input string) string {
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(input))
	return base64url(mac.Sum(nil))
}

// base64url encodes data using Base64URL encoding without padding characters.
func base64url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
